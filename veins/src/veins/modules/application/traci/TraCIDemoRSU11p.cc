#include "veins/modules/application/traci/TraCIDemoRSU11p.h"
#include <cryptopp/osrng.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

using Veins::AnnotationManagerAccess;
using namespace CryptoPP;

Define_Module(TraCIDemoRSU11p);

void TraCIDemoRSU11p::initialize(int stage) {
    BaseWaveApplLayer::initialize(stage);
    if (stage == 0) {
        mobi = dynamic_cast<BaseMobility*> (getParentModule()->getSubmodule("mobility"));
        ASSERT(mobi);
        annotations = AnnotationManagerAccess().getIfExists();
        ASSERT(annotations);
        sentMessage = false;

        // Crypto++ Initialization
        AutoSeededRandomPool prng;

        // Generate ECDSA keys
        ecdsaPrivateKey.Initialize(prng, ASN1::secp256r1());
        ecdsaPrivateKey.MakePublicKey(ecdsaPublicKey);

        // Generate ECDH keys
        ecdhPrivateKey.Initialize(prng, ASN1::secp256r1());
        ecdhPrivateKey.MakePublicKey(ecdhPublicKey);
    }
}

void TraCIDemoRSU11p::onBeacon(WaveShortMessage* wsm) {
    // Placeholder for beacon handling
}

void TraCIDemoRSU11p::onData(WaveShortMessage* wsm) {
    findHost()->getDisplayString().updateWith("r=16,green");
    annotations->scheduleErase(1, annotations->drawLine(wsm->getSenderPos(), mobi->getCurrentPosition(), "blue"));

    if (!sentMessage) {
        // Example of encrypting data using AES-256
        std::string plaintext = wsm->getWsmData();
        std::string ciphertext = encryptAES(plaintext);

        // Sending encrypted message
        sendMessage(ciphertext);
    }
}

void TraCIDemoRSU11p::sendMessage(std::string encryptedData) {
    sentMessage = true;
    t_channel channel = dataOnSch ? type_SCH : type_CCH;
    WaveShortMessage* wsm = prepareWSM("data", dataLengthBits, channel, dataPriority, -1, 2);

    // Signing the encrypted data using ECDSA
    std::string signature = signDataECDSA(encryptedData);

    wsm->setWsmData((encryptedData + ":" + signature).c_str());
    sendWSM(wsm);
}

void TraCIDemoRSU11p::sendWSM(WaveShortMessage* wsm) {
    sendDelayedDown(wsm, individualOffset);
}

std::string TraCIDemoRSU11p::encryptAES(const std::string& plaintext) {
    AutoSeededRandomPool prng;
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());

    byte iv[AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    std::string ciphertext;

    try {
        CBC_Mode<AES>::Encryption encryption;
        encryption.SetKeyWithIV(key, key.size(), iv);

        StringSource(plaintext, true,
            new StreamTransformationFilter(encryption,
                new StringSink(ciphertext)
            )
        );
    }
    catch (const CryptoPP::Exception& e) {
        EV << "AES Encryption Error: " << e.what() << std::endl;
    }

    return ciphertext;
}

std::string TraCIDemoRSU11p::signDataECDSA(const std::string& data) {
    AutoSeededRandomPool prng;
    std::string signature;

    try {
        ECDSA<ECP, SHA256>::Signer signer(ecdsaPrivateKey);
        StringSource(data, true,
            new SignerFilter(prng, signer,
                new StringSink(signature)
            )
        );
    }
    catch (const CryptoPP::Exception& e) {
        EV << "ECDSA Signing Error: " << e.what() << std::endl;
    }

    return signature;
}
