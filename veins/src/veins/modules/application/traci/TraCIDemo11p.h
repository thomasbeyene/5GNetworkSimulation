#pragma once

#include "veins/modules/application/ieee80211p/DemoBaseApplLayer.h"
#include <cryptopp/eccrypto.h>
#include <cryptopp/secblock.h>
#include <string>

namespace veins {

class TraCIDemoRSU11p : public DemoBaseApplLayer {
public:
    void initialize(int stage) override;
    void onBeacon(WaveShortMessage* wsm) override;
    void onData(WaveShortMessage* wsm) override;

protected:
    void sendMessage(std::string encryptedData);
    void sendWSM(WaveShortMessage* wsm);
    std::string encryptAES(const std::string& plaintext);
    std::string signDataECDSA(const std::string& data);

    // Cryptography-related members
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey ecdsaPrivateKey;
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey ecdsaPublicKey;
    CryptoPP::ECDH<CryptoPP::ECP>::PrivateKey ecdhPrivateKey;
    CryptoPP::ECDH<CryptoPP::ECP>::PublicKey ecdhPublicKey;

    // Other members
    BaseMobility* mobi;
    AnnotationManager* annotations;
    bool sentMessage;
};

} // namespace veins
