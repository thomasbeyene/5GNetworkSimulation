#include "veins/modules/application/traci/TraCIDemo11p.h"

// Crypto++ headers
#include <cryptopp/osrng.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/sha.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/secblock.h>

using Veins::TraCIMobilityAccess;
using Veins::AnnotationManagerAccess;
using namespace CryptoPP;

const simsignalwrap_t TraCIDemo11p::parkingStateChangedSignal = simsignalwrap_t(TRACI_SIGNAL_PARKING_CHANGE_NAME);

Define_Module(TraCIDemo11p);

void TraCIDemo11p::initialize(int stage) {
    DemoBaseApplLayer::initialize(stage);
    if (stage == 0) {
        mobility = TraCIMobilityAccess().get(getParentModule());
        traci = mobility->getCommandInterface();
        traciVehicle = mobility->getVehicleCommandInterface();
        annotations = AnnotationManagerAccess().getIfExists();
        ASSERT(annotations);

        sentMessage = false;
        lastDroveAt = simTime();
        findHost()->subscribe(parkingStateChangedSignal, this);
        isParking = false;
        sendWhileParking = par("sendWhileParking").boolValue();

        // ECDH Key Generation
        AutoSeededRandomPool prng;
        dh = new ECDH<ECP>::Domain(ASN1::secp256r1());

        privateKey = SecByteBlock(dh->PrivateKeyLength());
        publicKey = SecByteBlock(dh->PublicKeyLength());
        dh->GenerateKeyPair(prng, privateKey, publicKey);

        // ECDSA Key Generation
        ecdsaPrivateKey.Initialize(prng, ASN1::secp256r1());
        ecdsaPrivateKey.MakePublicKey(ecdsaPublicKey);

        // Send the public key to other nodes
        sendPublicKey();
    }
}

void TraCIDemo11p::sendPublicKey() {
    // Serialize ECDH public key
    std::string publicKeyString(reinterpret_cast<const char*>(publicKey.data()), publicKey.size());

    // Serialize ECDSA public key
    std::string ecdsaPublicKeyString;
    ecdsaPublicKey.Save(StringSink(ecdsaPublicKeyString).Ref());

    WaveShortMessage* wsm = prepareWSM("public_key", (publicKeyString.size() + ecdsaPublicKeyString.size()) * 8, type_CCH, dataPriority, -1, 2);
    wsm->setWsmData((publicKeyString + ecdsaPublicKeyString).c_str()); // Combine both keys
    sendWSM(wsm);
}

void TraCIDemo11p::onData(WaveShortMessage* wsm) {
    std::string wsmType = wsm->getName();

    if (wsmType == "public_key") {
        // Extract ECDH public key
        std::string receivedData = wsm->getWsmData();
        std::string receivedECDHPublicKeyStr = receivedData.substr(0, dh->PublicKeyLength());
        receivedPublicKey = SecByteBlock(reinterpret_cast<const byte*>(receivedECDHPublicKeyStr.data()), receivedECDHPublicKeyStr.size());

        // Extract ECDSA public key
        std::string receivedECDSAPublicKeyStr = receivedData.substr(dh->PublicKeyLength());
        StringSource source(receivedECDSAPublicKeyStr, true /*pumpAll*/);
        receivedECDSAPublicKey.BERDecode(source);

        // Derive the shared secret
        deriveSharedSecret();

    } else if (wsmType == "data") {
        // Verify and decrypt the message
        if (!verifyAndDecryptMessage(wsm)) {
            EV_ERROR << "Message verification failed. Dropping the message." << std::endl;
            return;
        }

        std::string decryptedData = wsm->getWsmData();
        findHost()->getDisplayString().updateWith("r=16,green");
        annotations->scheduleErase(1, annotations->drawLine(wsm->getSenderPos(), mobility->getPositionAt(simTime()), "blue"));

        if (mobility->getRoadId()[0] != ':') {
            traciVehicle->changeRoute(decryptedData, 9999);
        }
        if (!sentMessage) {
            sendMessage(decryptedData);
        }
    }
}

void TraCIDemo11p::deriveSharedSecret() {
    sharedSecret = SecByteBlock(dh->AgreedValueLength());
    if (!dh->Agree(sharedSecret, privateKey, receivedPublicKey)) {
        throw std::runtime_error("Failed to reach shared secret.");
    }

    // Derive AES key from the shared secret
    aesKey = SecByteBlock(AES::DEFAULT_KEYLENGTH);
    HKDF<SHA256> hkdf;
    hkdf.DeriveKey(aesKey, aesKey.size(), sharedSecret, sharedSecret.size(), nullptr, 0, nullptr, 0);
}

void TraCIDemo11p::sendMessage(std::string blockedRoadId) {
    sentMessage = true;

    t_channel channel = dataOnSch ? type_SCH : type_CCH;
    WaveShortMessage* wsm = prepareWSM("data", dataLengthBits, channel, dataPriority, -1, 2);

    // Encrypt and sign the message
    encryptAndSignMessage(wsm, blockedRoadId);

    sendWSM(wsm);
}

void TraCIDemo11p::encryptAndSignMessage(WaveShortMessage* wsm, const std::string& data) {
    // Encrypt the message
    AutoSeededRandomPool prng;
    std::string plaintext = data;
    std::string ciphertext;

    byte iv[AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv)); // Generate a random IV

    CBC_Mode<AES>::Encryption encryption;
    encryption.SetKeyWithIV(aesKey, aesKey.size(), iv);

    StringSource(plaintext, true,
        new StreamTransformationFilter(encryption,
            new StringSink(ciphertext)
        )
    );

    // Sign the ciphertext
    std::string signature;
    ECDSA<ECP, SHA256>::Signer signer(ecdsaPrivateKey);
    StringSource ss(ciphertext, true,
        new SignerFilter(prng, signer,
            new StringSink(signature)
        )
    );

    // Store ciphertext, IV, and signature in the message
    wsm->setWsmData(ciphertext.c_str());
    wsm->addObject(new cStringObject("iv", std::string((const char*)iv, sizeof(iv))));
    wsm->addObject(new cStringObject("signature", signature));
}

bool TraCIDemo11p::verifyAndDecryptMessage(WaveShortMessage* wsm) {
    // Retrieve ciphertext, IV, and signature from the message
    std::string ciphertext = wsm->getWsmData();
    std::string iv = static_cast<cStringObject*>(wsm->getObject("iv"))->getValue();
    std::string signature = static_cast<cStringObject*>(wsm->getObject("signature"))->getValue();

    // Verify the signature
    ECDSA<ECP, SHA256>::Verifier verifier(receivedECDSAPublicKey);
    bool validSignature = verifier.VerifyMessage(
        (const byte*)ciphertext.data(), ciphertext.size(),
        (const byte*)signature.data(), signature.size()
    );

    if (!validSignature) {
        EV_ERROR << "Invalid signature!" << std::endl;
        return false;
    }

    // Decrypt the message
    std::string decryptedtext;

    CBC_Mode<AES>::Decryption decryption;
    decryption.SetKeyWithIV(aesKey, aesKey.size(), (byte*)iv.data());

    StringSource(ciphertext, true,
        new StreamTransformationFilter(decryption,
            new StringSink(decryptedtext)
        )
    );

    // Set the decrypted data back to the message
    wsm->setWsmData(decryptedtext.c_str());

    return true;
}

void TraCIDemo11p::receiveSignal(cComponent* source, simsignal_t signalID, cObject* obj, cObject* details) {
    Enter_Method_Silent();
    if (signalID == mobilityStateChangedSignal) {
        handlePositionUpdate(obj);
    } else if (signalID == parkingStateChangedSignal) {
        handleParkingUpdate(obj);
    }
}

void TraCIDemo11p::handleParkingUpdate(cObject* obj) {
    isParking = mobility->getParkingState();
    if (sendWhileParking == false) {
        if (isParking == true) {
            (FindModule<BaseConnectionManager*>::findGlobalModule())->unregisterNic(this->getParentModule()->getSubmodule("nic"));
        } else {
            Coord pos = mobility->getCurrentPosition();
            (FindModule<BaseConnectionManager*>::findGlobalModule())->registerNic(this->getParentModule()->getSubmodule("nic"), (ChannelAccess*) this->getParentModule()->getSubmodule("nic")->getSubmodule("phy80211p"), &pos);
        }
    }
}

void TraCIDemo11p::handlePositionUpdate(cObject* obj) {
    DemoBaseApplLayer::handlePositionUpdate(obj);

    // stopped for for at least 10s?
    if (mobility->getSpeed() < 1) {
        if (simTime() - lastDroveAt >= 10) {
            findHost()->getDisplayString().updateWith("r=16,red");
            if (!sentMessage) {
                sendMessage(mobility->getRoadId());
            }
        }
    } else {
        lastDroveAt = simTime();
    }
}

void TraCIDemo11p::sendWSM(WaveShortMessage* wsm) {
    if (isParking && !sendWhileParking) return;
    sendDelayedDown(wsm, individualOffset);
}
