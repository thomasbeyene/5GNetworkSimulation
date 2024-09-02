#include "veins/modules/application/traci/TraCIDemo11p.h"
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/secblock.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hkdf.h>
#include <map>

std::map<LAddress::L2Type, CryptoPP::SecByteBlock> sessionKeys;
std::map<LAddress::L2Type, CryptoPP::byte*> sessionIVs;
std::map<LAddress::L2Type, simtime_t> sessionTimestamps;
std::map<LAddress::L2Type, int> messageCounts;
int keyRotationThreshold = 100; // Number of messages after which the key should be rotated
simtime_t sessionDuration = 300; // Session duration in seconds (example: 5 minutes)

using namespace veins;

Define_Module(veins::TraCIDemo11p);

void TraCIDemo11p::initialize(int stage)
{
    DemoBaseApplLayer::initialize(stage);
    if (stage == 0) {
        //stage 0 - Here the vehicles still do not have the link layer id (myId)
        sentMessage = false;
        lastDroveAt = simTime();
        currentSubscribedServiceId = -1;

        // ECDSA key generation
        AutoSeededRandomPool prng;
        privateKey.Initialize(prng, ASN1::secp256r1());
        privateKey.MakePublicKey(publicKey);

        // ECDH key pair generation
        ecdhPrivateKey.Initialize(prng, ASN1::secp256r1());
        ecdhPrivateKey.MakePublicKey(ecdhPublicKey);

        // AES-256 key and IV generation
        key = SecByteBlock(32);  // 32 bytes for AES-256
        iv = new byte[16];       // AES block size is 16 bytes
        prng.GenerateBlock(key, key.size());
        prng.GenerateBlock(iv, 16);

    } else {
        //stage 1 - Here the vehicle already have the link layer ID (myId)
    }
}

std::string TraCIDemo11p::signMessage(TraCIDemo11pMessage* wsm)
{
    std::string message = std::to_string(wsm->getSenderAddress()) + ";" + wsm->getDemoData();
    // Encrypt the message with AES-256
    std::string encryptedMessage = AES256Encryption(message, key, iv);

    std::string signature;

    AutoSeededRandomPool prng;
    ECDSA<ECP, SHA256>::Signer signer(privateKey);

    // Sign message
    StringSource(message, true,
        new SignerFilter(prng, signer,
            new StringSink(signature)
        )
    );

    // Convert signature to hex for easy storage and transmission
    std::string signatureHex;
    StringSource(signature, true,
        new HexEncoder(
            new StringSink(signatureHex)
        )
    );

    std::cout << "Message: " << message << std::endl;
    std::cout << "Signature: " << signatureHex << std::endl;
    std::cout << "------------------------------" << std::endl;

    // Store the encrypted message in the WSM for transmission
    wsm->setDemoData(encryptedMessage);

    return signatureHex;
}

bool TraCIDemo11p::verifyMessage(TraCIDemo11pMessage* wsm, const std::string& signatureHex)
{
    std::string encryptedMessage = std::to_string(wsm->getSenderAddress()) + ";" + wsm->getDemoData();
    std::string signature;

    // Convert hex signature back to binary
    StringSource(signatureHex, true,
        new HexDecoder(
            new StringSink(signature)
        )
    );

    ECDSA<ECP, SHA256>::Verifier verifier(publicKey);

    // Verify signature
    bool result = false;
    StringSource(signature + encryptedMessage, true,
        new SignatureVerificationFilter(verifier,
            new ArraySink((byte*)&result, sizeof(result))
        )
    );

        if (result) {
        // If the signature is valid, decrypt the message
        std::string decryptedMessage = AES256Decryption(encryptedMessage, key, iv);
        std::cout << "Decrypted Message: " << decryptedMessage << std::endl;
    }


    return result;
}

void TraCIDemo11p::storeMsg(TraCIDemo11pMessage* wsm, const std::string& signature)
{
    // Get message fields
    int serialWsm = wsm->getSerial();
    LAddress::L2Type srcWsm = wsm->getSenderAddress();
    std::string dataWsm = wsm->getDemoData();

    msgRecord wsm1 = { serialWsm, srcWsm, dataWsm, signature };
    msgRec[signature] = wsm1;
}

void TraCIDemo11p::printAllReceivMsg(void)
{
    std::map<std::string, msgRecord>::iterator it;
    std::cout << "Received Messages" << myId << std::endl;
    std::cout << "MyID:        " << myId << std::endl;
    for(it = msgRec.begin(); it != msgRec.end(); ++it) {
        std::cout << "Signature: " << it->first << " | MSG content: " << it->second.data << std::endl;
        std::cout << "Serial >>>>> " << it->second.serial << std::endl;
        std::cout << "Src ID >>>>> " << it->second.srcId << std::endl;
        std::cout << "-------------" << std::endl;
    }
}

void TraCIDemo11p::onWSM(BaseFrame1609_4* frame)
{
    TraCIDemo11pMessage* wsm = check_and_cast<TraCIDemo11pMessage*>(frame);
    LAddress::L2Type senderAddress = wsm->getSenderAddress();
    simtime_t currentTime = simTime();

    findHost()->getDisplayString().setTagArg("i", 1, "green"); // if message was received and readable, car color = green

    // Check if the session has expired
    if (sessionKeys.find(senderAddress) != sessionKeys.end()) {
        if (currentTime - sessionTimestamps[senderAddress] > sessionDuration) {
            std::cout << "Session expired for sender: " << senderAddress << ". Establishing new session." << std::endl;
            // Remove the old session
            sessionKeys.erase(senderAddress);
            sessionIVs.erase(senderAddress);
            sessionTimestamps.erase(senderAddress);
            messageCounts.erase(senderAddress);
        }
    }

    if (sessionKeys.find(senderAddress) == sessionKeys.end()) { // If session not established yet
        receiveAndComputeSharedSecret(wsm);
    } else {
        // Optionally, implement key rotation based on message count or other policies
        messageCounts[senderAddress]++;
        if (messageCounts[senderAddress] >= keyRotationThreshold) {
            std::cout << "Rotating key for sender: " << senderAddress << std::endl;
            // Recompute shared secret and rotate key
            receiveAndComputeSharedSecret(wsm);
            messageCounts[senderAddress] = 0; // Reset the counter after key rotation
        }
    }

    // Encrypt, sign, and verify message after key exchange
    std::string signature = signMessage(wsm);
    storeMsg(wsm, signature);

    // Verification example
    if (verifyMessage(wsm, signature)) {
        std::cout << "Message verified successfully." << std::endl;
    } else {
        std::cout << "Message verification failed." << std::endl;
    }
}


void TraCIDemo11p::handleSelfMsg(cMessage* msg)
{
    if (TraCIDemo11pMessage* wsm = dynamic_cast<TraCIDemo11pMessage*>(msg)) {
        // Process received message
    } else {
        DemoBaseApplLayer::handleSelfMsg(msg);
    }
}

void TraCIDemo11p::handlePositionUpdate(cObject* obj)
{
    DemoBaseApplLayer::handlePositionUpdate(obj);

    // If stopped vehicle
    if (mobility->getSpeed() < 1) {
        // Vehicle stopped for at least 10s?
        if (simTime() - lastDroveAt >= 10 && sentMessage == false) {
            findHost()->getDisplayString().setTagArg("i", 1, "red");  // Car color = red
        }
    } else {
        lastDroveAt = simTime();
    }
}

std::string TraCIDemo11p::AES256Encryption(std::string &plain, CryptoPP::SecByteBlock key, CryptoPP::byte *iv) {
    std::string cipher;
    std::string output;

    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption e(key, key.size(), iv);

        CryptoPP::StringSource(plain, true,
            new CryptoPP::StreamTransformationFilter(e,
                new CryptoPP::StringSink(cipher)
            ) 
        ); 
    } catch (CryptoPP::Exception &exception) {
        std::cerr << exception.what() << std::endl;
        exit(1);
    }

    CryptoPP::StringSource(cipher, true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(output)
        ) 
    ); 
    return output;
}

std::string TraCIDemo11p::AES256Decryption(std::string &encoded, CryptoPP::SecByteBlock key, CryptoPP::byte *iv) {
    std::string cipher;
    std::string output;

    CryptoPP::StringSource(encoded, true,
        new CryptoPP::HexDecoder(
            new CryptoPP::StringSink(cipher)
        ) 
    ); 

    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption d(key, key.size(), iv);
        CryptoPP::StringSource(cipher, true,
            new CryptoPP::StreamTransformationFilter(d,
                new CryptoPP::StringSink(output)
            ) 
        ); 
    } catch (CryptoPP::Exception &exception) {
        std::cerr << exception.what() << std::endl;
        exit(1);
    }
    return output;
}

void TraCIDemo11p::exchangeKeys(TraCIDemo11pMessage* wsm)
{
    // Convert the public key to string (for transmission)
    std::string encodedPublicKey;
    StringSource(ecdhPublicKey, sizeof(ecdhPublicKey), true,
                 new HexEncoder(
                     new StringSink(encodedPublicKey)
                 ));

    // Sign the public key using the ECDSA private key
    std::string signature;
    AutoSeededRandomPool prng;
    ECDSA<ECP, SHA256>::Signer signer(privateKey);
    StringSource(encodedPublicKey, true,
                 new SignerFilter(prng, signer,
                                  new StringSink(signature)
                 ));

    // Convert the signature to hex for transmission
    std::string signatureHex;
    StringSource(signature, true,
                 new HexEncoder(
                     new StringSink(signatureHex)
                 ));

    // Combine the encoded public key and its signature for transmission
    std::string dataToSend = encodedPublicKey + ":" + signatureHex;
    wsm->setDemoData(dataToSend);
}

void TraCIDemo11p::receiveAndComputeSharedSecret(TraCIDemo11pMessage* wsm)
{
    LAddress::L2Type senderAddress = wsm->getSenderAddress();
    simtime_t currentTime = simTime();

    // Check if a session already exists with this sender
    if (sessionKeys.find(senderAddress) != sessionKeys.end()) {
        // Use the existing session key and IV
        key = sessionKeys[senderAddress];
        iv = sessionIVs[senderAddress];
        std::cout << "Using existing session key and IV for sender: " << senderAddress << std::endl;
        return;
    }

    // Extract the public key and signature from the received data
    std::string receivedData = wsm->getDemoData();
    size_t separatorPos = receivedData.find(':');
    if (separatorPos == std::string::npos) {
        throw std::runtime_error("Invalid message format: missing signature");
    }

    std::string receivedPublicKeyHex = receivedData.substr(0, separatorPos);
    std::string receivedSignatureHex = receivedData.substr(separatorPos + 1);

    // Convert the received public key from hex to a point
    CryptoPP::ECP::Point receivedPublicKey;
    StringSource(receivedPublicKeyHex, true,
                 new HexDecoder(
                     new ArraySink((byte*)&receivedPublicKey, sizeof(receivedPublicKey))
                 ));

    // Convert the received signature from hex to binary
    std::string receivedSignature;
    StringSource(receivedSignatureHex, true,
                 new HexDecoder(
                     new StringSink(receivedSignature)
                 ));

    // Verify the received public key's signature using the sender's ECDSA public key
    ECDSA<ECP, SHA256>::Verifier verifier(publicKey);
    bool result = false;
    StringSource(receivedPublicKeyHex + receivedSignature, true,
                 new SignatureVerificationFilter(verifier,
                     new ArraySink((byte*)&result, sizeof(result))
                 ));

    if (!result) {
        throw std::runtime_error("Failed to verify public key signature");
    }

    // Compute the shared secret
    SecByteBlock sharedSecret(ecdhPrivateKey.AgreedValueLength());
    if (!ecdhPrivateKey.Agree(sharedSecret, ecdhPrivateKey, receivedPublicKey)) {
        throw std::runtime_error("Failed to compute shared secret");
    }

    // Derive AES-256 key from the shared secret using HKDF (HMAC-based Extract-and-Expand Key Derivation Function)
    HKDF<SHA256> hkdf;
    key = SecByteBlock(32); // AES-256 key size
    hkdf.DeriveKey(key, key.size(), sharedSecret, sharedSecret.size(), nullptr, 0, nullptr, 0);

    // Generate a new IV
    iv = new byte[16]; // AES block size is 16 bytes
    AutoSeededRandomPool prng;
    prng.GenerateBlock(iv, 16);

    // Store the session key and IV for future use
    sessionKeys[senderAddress] = key;
    sessionIVs[senderAddress] = iv;
    sessionTimestamps[senderAddress] = currentTime; // Update the session timestamp
    std::cout << "Session key and IV stored for sender: " << senderAddress << std::endl;
}


