#pragma once
#include "veins/modules/application/ieee80211p/DemoBaseApplLayer.h"
#include "veins/modules/application/traci/TraCIDemo11pMessage_m.h"
#include <cryptopp/eccrypto.h>
#include <cryptopp/secblock.h>
#include <map>

namespace veins {
class VEINS_API TraCIDemo11p : public DemoBaseApplLayer {
public:
    void initialize(int stage) override;

protected:
    simtime_t lastDroveAt;
    bool sentMessage;
    int currentSubscribedServiceId;

    //Message record
    struct msgRecord {
       int serial;
       LAddress::L2Type srcId;
       std::string data;
    };

    //Message Table
    std::map<std::string, msgRecord> msgRec;

    // Cryptography-related members
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;
    CryptoPP::ECDH<CryptoPP::ECP>::PrivateKey ecdhPrivateKey;
    CryptoPP::ECDH<CryptoPP::ECP>::PublicKey ecdhPublicKey;
    CryptoPP::SecByteBlock key;
    CryptoPP::byte* iv;

    // Session management
    std::map<LAddress::L2Type, CryptoPP::SecByteBlock> sessionKeys;
    std::map<LAddress::L2Type, CryptoPP::byte*> sessionIVs;
    std::map<LAddress::L2Type, simtime_t> sessionTimestamps;
    std::map<LAddress::L2Type, int> messageCounts;
    int keyRotationThreshold;
    simtime_t sessionDuration;

protected:
    void onWSM(BaseFrame1609_4* wsm) override;
    void handleSelfMsg(cMessage* msg) override;
    void handlePositionUpdate(cObject* obj) override;
    void printAllReceivMsg(void);

    // Cryptographic methods
    std::string signMessage(TraCIDemo11pMessage* wsm);
    bool verifyMessage(TraCIDemo11pMessage* wsm, const std::string& signatureHex);
    void storeMsg(TraCIDemo11pMessage* wsm, const std::string& signature);
    std::string AES256Encryption(std::string& plain, CryptoPP::SecByteBlock key, CryptoPP::byte* iv);
    std::string AES256Decryption(std::string& encoded, CryptoPP::SecByteBlock key, CryptoPP::byte* iv);

    // Key exchange and session management
    void exchangeKeys(TraCIDemo11pMessage* wsm);
    void receiveAndComputeSharedSecret(TraCIDemo11pMessage* wsm);
};
}