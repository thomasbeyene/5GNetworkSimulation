#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <iostream>
#include <string>

using namespace CryptoPP;

void GenerateKeys(ECDSA<ECP, SHA256>::PrivateKey& privateKey, ECDSA<ECP, SHA256>::PublicKey& publicKey) {
    AutoSeededRandomPool rng;
    privateKey.Initialize(rng, ASN1::secp256k1());
    privateKey.MakePublicKey(publicKey);
}

std::string SignMessage(const ECDSA<ECP, SHA256>::PrivateKey& privateKey, const std::string& message) {
    AutoSeededRandomPool rng;
    std::string signature;
    ECDSA<ECP, SHA256>::Signer signer(privateKey);

    StringSource ss1(message, true,
        new SignerFilter(rng, signer,
            new StringSink(signature)
        )
    );

    return signature;
}

bool VerifyMessage(const ECDSA<ECP, SHA256>::PublicKey& publicKey, const std::string& message, const std::string& signature) {
    ECDSA<ECP, SHA256>::Verifier verifier(publicKey);
    bool result = false;

    StringSource ss2(signature + message, true,
        new SignatureVerificationFilter(
            verifier, new ArraySink((byte*)&result, sizeof(result))
        )
    );

    return result;
}

int main() {
    ECDSA<ECP, SHA256>::PrivateKey privateKey;
    ECDSA<ECP, SHA256>::PublicKey publicKey;
    GenerateKeys(privateKey, publicKey);

    std::string message = "This is a message from Vehicle A";
    std::string signature = SignMessage(privateKey, message);

    bool verified = VerifyMessage(publicKey, message, signature);
    std::cout << "Signature Verified: " << (verified ? "Success" : "Failure") << std::endl;

    return 0;
}
