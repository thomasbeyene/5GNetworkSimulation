#pragma once

#include "veins/modules/application/ieee80211p/DemoBaseApplLayer.h"
#include <cryptopp/eccrypto.h>
#include <cryptopp/aes.h>

namespace veins {

/**
 * Small RSU Demo using 11p with cryptographic enhancements.
 *
 * Modified by: dnatividade
 */
class VEINS_API TraCIDemoRSU11p : public DemoBaseApplLayer {
public:
    void initialize(int stage) override;

protected:
    void onBeacon(WaveShortMessage* wsm);
    void onData(WaveShortMessage* wsm);
    void sendMessage(std::string encryptedData);
    void sendWSM(WaveShortMessage* wsm);

    std::string encryptAES(const std::string& plaintext);
    std::string signDataECDSA(const std::string& data);

protected:
    int wsmSerial = 0; // Message serial number
    bool sentMessage = false; // Track if a message has been sent
    BaseMobility* mobi = nullptr; // Pointer to the mobility module
    AnnotationManager* annotations = nullptr; // Pointer to the annotation manager

    // Crypto++ variables
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey ecdsaPrivateKey;
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey ecdsaPublicKey;
    CryptoPP::ECDH<CryptoPP::ECP>::PrivateKey ecdhPrivateKey;
    CryptoPP::ECDH<CryptoPP::ECP>::PublicKey ecdhPublicKey;
};

} // namespace veins
