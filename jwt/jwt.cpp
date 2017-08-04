#include <vector>
#include <cstdint>
#include <functional>
#include <iostream>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <openssl/pem.h>

#include "cppcodec/base64_default_url.hpp"
#include "jwt.hpp"

using namespace std;
using namespace nlohmann;
using namespace cppcodec;

#if OPENSSL_VERSION_NUMBER < 0x10100000L

static void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)
{
    if (pr != NULL)
        *pr = sig->r;
    if (ps != NULL)
        *ps = sig->s;
}

static int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
    if (r == NULL || s == NULL)
        return 0;

    BN_clear_free(sig->r);
    BN_clear_free(sig->s);
    sig->r = r;
    sig->s = s;

    return 1;
}

#endif

namespace jwt {
    string signHMAC(const string& str, const string& key, const string& alg) {
        const EVP_MD* evp = nullptr;

        if (alg == "HS256") {
            evp = EVP_sha256();
        }
        else if (alg == "HS384") {
            evp = EVP_sha384();
        }
        else if (alg == "HS512") {
            evp = EVP_sha512();
        }
        else {
            return string();
        }

        vector<uint8_t> out(EVP_MAX_MD_SIZE);
        unsigned int len = 0;

        HMAC(evp, key.c_str(), key.length(), (const unsigned char*)str.c_str(), str.length(), out.data(), &len);

        return base64_url::encode(out.data(), len);
    }

    string signPEM(const string& str, const string& key, const string& alg) {
        class OnLeave : public vector<function<void()>> {
        public:
            ~OnLeave() {
                for (auto& fn : *this) {
                    fn();
                }
            }
        } onLeave;

#define SCOPE_EXIT(x) do { onLeave.push_back([&]() { x; }); } while(0)

        const EVP_MD* evp = nullptr;
        int type = 0;

        if (alg == "RS256") {
            evp = EVP_sha256();
            type = EVP_PKEY_RSA;
        }
        else if (alg == "RS384") {
            evp = EVP_sha384();
            type = EVP_PKEY_RSA;
        }
        else if (alg == "RS512") {
            evp = EVP_sha512();
            type = EVP_PKEY_RSA;
        }
        else if (alg == "ES256") {
            evp = EVP_sha256();
            type = EVP_PKEY_EC;
        }
        else if (alg == "ES384") {
            evp = EVP_sha384();
            type = EVP_PKEY_EC;
        }
        else if (alg == "ES512") {
            evp = EVP_sha512();
            type = EVP_PKEY_EC;
        }
        else {
            return string();
        }

        auto bufkey = BIO_new_mem_buf(key.c_str(), key.length());
        SCOPE_EXIT(if (bufkey) BIO_free(bufkey));

        if (!bufkey) {
            return string();
        }

        // Use OpenSSL's default passphrase callbacks if needed.
        auto pkey = PEM_read_bio_PrivateKey(bufkey, nullptr, nullptr, nullptr);
        SCOPE_EXIT(if (pkey) EVP_PKEY_free(pkey));

        if (!pkey) {
            return string();
        }

        auto pkeyType = EVP_PKEY_id(pkey);

        if (pkeyType != type) {
            return string();
        }

        auto mdctx = EVP_MD_CTX_create();
        SCOPE_EXIT(if (mdctx) EVP_MD_CTX_destroy(mdctx));

        if (!mdctx) {
            return string();
        }

        // Initialize the digest sign operation.
        if (EVP_DigestSignInit(mdctx, nullptr, evp, nullptr, pkey) != 1) {
            return string();
        }

        // Update the digest sign with the message.
        if (EVP_DigestSignUpdate(mdctx, str.c_str(), str.length()) != 1) {
            return string();
        }

        // Determin the size of the finalized digest sign.
        size_t siglen = 0;

        if (EVP_DigestSignFinal(mdctx, nullptr, &siglen) != 1) {
            return string();
        }

        // Finalize it.
        vector<uint8_t> sig(siglen);

        if (EVP_DigestSignFinal(mdctx, sig.data(), &siglen) != 1) {
            return string();
        }

        // For RSA, we are done.
        if (pkeyType == EVP_PKEY_RSA) {
            return base64_url::encode(sig.data(), siglen);
        }

        // For EC we need to convert.
        auto ecKey = EVP_PKEY_get1_EC_KEY(pkey);

        if (!ecKey) {
            return string();
        }

        auto degree = EC_GROUP_get_degree(EC_KEY_get0_group(ecKey));

        EC_KEY_free(ecKey);

        auto sigData = sig.data();
        auto ecSig = d2i_ECDSA_SIG(nullptr, (const unsigned char**)&sigData, siglen);
        SCOPE_EXIT(if (ecSig) ECDSA_SIG_free(ecSig));

        if (!ecSig) {
            return string();
        }

        const BIGNUM *ecSigR = nullptr;
        const BIGNUM *ecSigS = nullptr;

        ECDSA_SIG_get0(ecSig, &ecSigR, &ecSigS);

        auto rLen = BN_num_bytes(ecSigR);
        auto sLen = BN_num_bytes(ecSigS);
        auto bnLen = (degree + 7) / 8;

        if (rLen > bnLen || sLen > bnLen) {
            return string();
        }

        auto bufLen = 2 * bnLen;
        vector<uint8_t> rawBuf(bufLen, 0);

        BN_bn2bin(ecSigR, rawBuf.data() + bnLen - rLen);
        BN_bn2bin(ecSigS, rawBuf.data() + bnLen - sLen);

        return base64_url::encode(rawBuf.data(), bufLen);
    }

    bool verifyPEM(const string& str, const string& b64sig, const string& key, const string& alg) {
        class OnLeave : public vector<function<void()>> {
        public:
            ~OnLeave() {
                for (auto& fn : *this) {
                    fn();
                }
            }
        } onLeave;

#define SCOPE_EXIT(x) do { onLeave.push_back([&]() { x; }); } while(0)

        const EVP_MD* evp = nullptr;
        int type = 0;

        if (alg == "RS256") {
            evp = EVP_sha256();
            type = EVP_PKEY_RSA;
        }
        else if (alg == "RS384") {
            evp = EVP_sha384();
            type = EVP_PKEY_RSA;
        }
        else if (alg == "RS512") {
            evp = EVP_sha512();
            type = EVP_PKEY_RSA;
        }
        else if (alg == "ES256") {
            evp = EVP_sha256();
            type = EVP_PKEY_EC;
        }
        else if (alg == "ES384") {
            evp = EVP_sha384();
            type = EVP_PKEY_EC;
        }
        else if (alg == "ES512") {
            evp = EVP_sha512();
            type = EVP_PKEY_EC;
        }
        else {
            return false;
        }

        auto sig = base64_url::decode(b64sig);
        auto siglen = sig.size();

        if (sig.empty()) {
            return false;
        }

        auto bufkey = BIO_new_mem_buf(key.c_str(), key.length());
        SCOPE_EXIT(if (bufkey) BIO_free(bufkey));

        if (!bufkey) {
            return false;
        }

        // Use OpenSSL's default passphrase callbacks if needed.
        auto pkey = PEM_read_bio_PUBKEY(bufkey, nullptr, nullptr, nullptr);
        SCOPE_EXIT(if (pkey) EVP_PKEY_free(pkey));

        if (!pkey) {
            return false;
        }

        auto pkeyType = EVP_PKEY_id(pkey);

        if (pkeyType != type) {
            return false;
        }

        // Convert EC sigs back to ASN1.
        if (pkeyType == EVP_PKEY_EC) {
            auto ecSig = ECDSA_SIG_new();
            SCOPE_EXIT(if (ecSig) ECDSA_SIG_free(ecSig));

            if (!ecSig) {
                return false;
            }

            auto ecKey = EVP_PKEY_get1_EC_KEY(pkey);

            if (!ecKey) {
                return false;
            }

            auto degree = EC_GROUP_get_degree(EC_KEY_get0_group(ecKey));

            EC_KEY_free(ecKey);

            auto bnLen = (degree + 7) / 8;

            if (bnLen * 2 != siglen) {
                return false;
            }

            auto ecSigR = BN_bin2bn(sig.data(), bnLen, nullptr);
            auto ecSigS = BN_bin2bn(sig.data() + bnLen, bnLen, nullptr);

            if (!ecSigR || !ecSigS) {
                return false;
            }

            ECDSA_SIG_set0(ecSig, ecSigR, ecSigS);
            sig.clear();

            siglen = i2d_ECDSA_SIG(ecSig, nullptr);
            sig.resize(siglen, 0);

            auto p = sig.data();
            siglen = i2d_ECDSA_SIG(ecSig, &p);

            if (siglen == 0) {
                return false;
            }
        }

        auto mdctx = EVP_MD_CTX_create();
        SCOPE_EXIT(if (mdctx) EVP_MD_CTX_destroy(mdctx));

        if (EVP_DigestVerifyInit(mdctx, nullptr, evp, nullptr, pkey) != 1) {
            return false;
        }

        if (EVP_DigestVerifyUpdate(mdctx, str.c_str(), str.length()) != 1) {
            return false;
        }

        if (EVP_DigestVerifyFinal(mdctx, sig.data(), siglen) != 1) {
            return false;
        }

        return true;
    }

    string encode(const json& payload, const string& key, const string& alg) {
        // Create a JWT header defaulting to the HS256 alg if none is supplied.
        json header{
            {"typ", "JWT"},
            {"alg", alg.empty() ? "HS256" : alg }
        };
        auto headerStr = header.dump();
        auto encodedHeader = base64_url::encode(headerStr.c_str(), headerStr.length());

        // Encode the payload.
        auto payloadStr = payload.dump();
        auto encodedPayload = base64_url::encode(payloadStr.c_str(), payloadStr.length());

        // Sign it and return the final JWT.
        auto encodedToken = encodedHeader + "." + encodedPayload;
        const string& theAlg = header["alg"];

        if (theAlg == "none") {
            return encodedToken + ".";
        }
        else if (theAlg.find("HS") != string::npos) {
            return encodedToken + "." + signHMAC(encodedToken, key, theAlg);
        }

        return encodedToken + "." + signPEM(encodedToken, key, theAlg);
    }

    json decode(const string& jwt, const string& key, const set<string>& alg) {
        // Make sure the jwt we recieve looks like a jwt.
        auto firstPeriod = jwt.find_first_of('.');
        auto secondPeriod = jwt.find_first_of('.', firstPeriod + 1);

        if (firstPeriod == string::npos || secondPeriod == string::npos) {
            return json();
        }

        // Decode the header so we can get the alg used by the jwt.
        auto decodedHeader = base64_url::decode(jwt.substr(0, firstPeriod));
        string decodedHeaderStr{ decodedHeader.begin(), decodedHeader.end() };
        auto header = json::parse(decodedHeaderStr.c_str());
        const string& theAlg = header["alg"];

        // Make sure no key is supplied if the alg is none.
        if (theAlg == "none" && !key.empty()) {
            return json();
        }
        // Make sure the alg supplied is one we expect.
        else if (alg.count(theAlg) == 0 && !alg.empty()) {
            return json();
        }

        auto encodedToken = jwt.substr(0, secondPeriod);
        auto signature = jwt.substr(secondPeriod + 1);

        // Verify the signature.
        if (theAlg == "none") {
            // Nothing to do, no verification needed.
        }
        else if (theAlg.find("HS") != string::npos) {
            if (signature != signHMAC(encodedToken, key, theAlg)) {
                return json();
            }
        }
        else {
            if (!verifyPEM(encodedToken, signature, key, theAlg)) {
                return json();
            }
        }

        // Decode the payload since the jwt has been verified.
        auto decodedPayload = base64_url::decode(jwt.substr(firstPeriod + 1, secondPeriod - firstPeriod - 1));
        string decodedPayloadStr{ decodedPayload.begin(), decodedPayload.end() };
        auto payload = json::parse(decodedPayloadStr.c_str());

        return payload;
    }
}