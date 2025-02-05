// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KEYPQ_H
#define BITCOIN_KEYPQ_H

#include <pqpubkey.h>
#include <serialize.h>
#include <support/allocators/secure.h>
#include <uint256.h>

#include <stdexcept>
#include <vector>

#define PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES_   1281
#define PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES_   897
#define PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES_            690

/**
 * secure_allocator is defined in allocators.h
 * CPrivKey is a serialized private key, with all parameters included
 * (PRIVATE_KEY_SIZE bytes)
 */
typedef std::vector<unsigned char, secure_allocator<unsigned char> > PQCPrivKey;

/** An encapsulated private key. */
class PQCKey
{
public:
    /**
     * secp256k1:
     */
    static const unsigned int PRIVATE_KEY_SIZE            = PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES_;
    static const unsigned int COMPRESSED_PRIVATE_KEY_SIZE = PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES_;
    static const unsigned int PUB_KEY_SIZE            = PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES_;
    static const unsigned int SIGN_SIZE            = PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES_;
     /**
     * see www.keylength.com
     * script supports up to 75 for single byte push
     */
    static_assert(
        PRIVATE_KEY_SIZE >= COMPRESSED_PRIVATE_KEY_SIZE,
        "COMPRESSED_PRIVATE_KEY_SIZE is larger than PRIVATE_KEY_SIZE");

private:
    //! Whether this private key is valid. We check for correctness when modifying the key
    //! data, so fValid should always correspond to the actual state.
    bool fValid;

    //! Whether the public key corresponding to this private key is (to be) compressed.
    bool fCompressed;

    //! The actual byte data
    std::vector<unsigned char, secure_allocator<unsigned char> > keydata;
    //! The actual byte data
    std::vector<unsigned char, secure_allocator<unsigned char> > pubkeydata;

public:
    //! Construct an invalid private key.
    PQCKey() : fValid(false), fCompressed(false)
    {
        // Important: vch must be 32 bytes in length to not break serialization
        keydata.resize(PRIVATE_KEY_SIZE);
        pubkeydata.resize(PUB_KEY_SIZE);
    }

    friend bool operator==(const PQCKey& a, const PQCKey& b)
    {
        return a.fCompressed == b.fCompressed &&
            a.size() == b.size() &&
            memcmp(a.keydata.data(), b.keydata.data(), a.size()) == 0;
    }

    //! Initialize using begin and end iterators to byte data.
    template <typename T>
    void Set(const T pbegin, const T pend, bool fCompressedIn)
    {
        if (size_t(pend - pbegin) != keydata.size()) {
            fValid = false;
        } else if (true){//(Check(&pbegin[0])) {
            memcpy(keydata.data(), (unsigned char*)&pbegin[0], keydata.size());
            fValid = true;
            fCompressed = fCompressedIn;
        } else {
            fValid = false;
        }
    }
    //! Initialize using begin and end iterators to byte data.
    template <typename T>
    void Set(const T pbegin, const T pend, PQCPubKey pk, bool fCompressedIn)
    {
        if (size_t(pend - pbegin) != keydata.size()) {
            fValid = false;
        } else if (true){//(Check(&pbegin[0])) {
            fValid = true;
            memcpy(keydata.data(), (unsigned char*)&pbegin[0], keydata.size());
            memcpy(pubkeydata.data(), (unsigned char*)(pk.data() + 1), pubkeydata.size());
            fCompressed = fCompressedIn;
        } else {
            fValid = false;
        }
    }

    //! Simple read-only vector-like interface.
    unsigned int size() const { return (fValid ? keydata.size() : 0); }
    const unsigned char* begin() const { return keydata.data(); }
    const unsigned char* end() const { return keydata.data() + size(); }
    unsigned int pksize() const { return (fValid ? pubkeydata.size() : 0); }
    const unsigned char* pkbegin() const { return pubkeydata.data(); }
    const unsigned char* pkend() const { return pubkeydata.data() + pksize(); }

    //! Check whether this private key is valid.
    bool IsValid() const { return fValid; }

    //! Check whether the public key corresponding to this private key is (to be) compressed.
    bool IsCompressed() const { return fCompressed; }

    //! Generate a new private key using a cryptographic PRNG.
    void PQMakeNewKey(bool fCompressed);

    /**
     * Convert the private key to a CPrivKey (serialized OpenSSL private key data).
     * This is expensive.
     */
    PQCPrivKey GetPrivKey() const;

    /**
     * Compute the public key from a private key.
     * This is expensive.
     */
    PQCPubKey GetPubKey() const;

    /**
     * Create a DER-serialized signature.
     * The test_case parameter tweaks the deterministic nonce.
     */
    bool Sign(const uint256& hash, std::vector<unsigned char>& vchSig, bool grind = true, uint32_t test_case = 0) const;

    /**
     * Create a compact signature (65 bytes), which allows reconstructing the used public key.
     * The format is one header byte, followed by two times 32 bytes for the serialized r and s values.
     * The header byte: 0x1B = first key with even y, 0x1C = first key with odd y,
     *                  0x1D = second key with even y, 0x1E = second key with odd y,
     *                  add 0x04 for compressed keys.
     */
    bool SignCompact(const uint256& hash, std::vector<unsigned char>& vchSig) const;

    /**
     * Verify thoroughly whether a private key and a public key match.
     * This is done using a different mechanism than just regenerating it.
     */
    bool VerifyPubKey(const PQCPubKey& vchPubKey) const;

    //! Load private key and check that public key matches.
    bool Load(const PQCPrivKey& privkey, const PQCPubKey& vchPubKey, bool fSkipCheck);
};
/** Initialize the elliptic curve support. May not be called twice without calling ECC_Stop first. */
void ECC_Start();

/** Deinitialize the elliptic curve support. No-op if ECC_Start wasn't called first. */
void ECC_Stop();

/** Check that required EC support is available at runtime. */
bool ECC_InitSanityCheck();

#endif // BITCOIN_KEY_H
