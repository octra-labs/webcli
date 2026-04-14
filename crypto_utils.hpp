/*
    This file is part of Octra Wallet (webcli).

    Octra Wallet is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    Octra Wallet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Octra Wallet.  If not, see <http://www.gnu.org/licenses/>.

    This program is released under the GPL with the additional exemption
    that compiling, linking, and/or using OpenSSL is allowed.
    You are free to remove this exemption from derived works.

    Copyright 2025-2026 Octra Labs
              2025-2026 David A.
              2025-2026 Alex T.
              2025-2026 Vadim S.
              2025-2026 Julia L.
*/

#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <array>
#include <algorithm>
#ifndef _WIN32
#include <sys/mman.h>
#else
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif
#include <openssl/evp.h>
#include <openssl/hmac.h>

extern "C" {
#include "lib/tweetnacl.h"
extern void randombytes(unsigned char*, unsigned long long);
}

namespace octra {

namespace detail {

static inline uint32_t rotr(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

static inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

static inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint32_t sig0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

static inline uint32_t sig1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

static inline uint32_t gam0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

static inline uint32_t gam1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

} // namespace detail

inline std::array<uint8_t, 32> sha256(const uint8_t* data, size_t len) {
    using namespace detail;
    uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    uint64_t bitlen = (uint64_t)len * 8;

    auto compress = [&](const uint8_t* blk) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = ((uint32_t)blk[i * 4] << 24) |
                   ((uint32_t)blk[i * 4 + 1] << 16) |
                   ((uint32_t)blk[i * 4 + 2] << 8) |
                   blk[i * 4 + 3];
        for (int i = 16; i < 64; i++)
            w[i] = gam1(w[i - 2]) + w[i - 7] + gam0(w[i - 15]) + w[i - 16];

        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];

        for (int i = 0; i < 64; i++) {
            uint32_t t1 = hh + sig1(e) + ch(e, f, g) + K[i] + w[i];
            uint32_t t2 = sig0(a) + maj(a, b, c);
            hh = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    };

    size_t off = 0;
    while (off + 64 <= len) { compress(data + off); off += 64; }

    uint8_t pad[128];
    size_t rem = len - off;
    memcpy(pad, data + off, rem);
    pad[rem++] = 0x80;
    size_t padlen = (rem <= 56) ? 64 : 128;
    memset(pad + rem, 0, padlen - rem);
    for (int i = 0; i < 8; i++)
        pad[padlen - 1 - i] = (uint8_t)(bitlen >> (i * 8));
    for (size_t b = 0; b < padlen; b += 64)
        compress(pad + b);

    std::array<uint8_t, 32> out;
    for (int i = 0; i < 8; i++) {
        out[i * 4] = (uint8_t)(h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(h[i]);
    }
    return out;
}

inline std::array<uint8_t, 32> sha256(const std::string& s) {
    return sha256(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

inline std::string base64_encode(const uint8_t* data, size_t len) {
    static const char T[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string r;
    r.reserve((len + 2) / 3 * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = (uint32_t)data[i] << 16;
        if (i + 1 < len) n |= (uint32_t)data[i + 1] << 8;
        if (i + 2 < len) n |= data[i + 2];
        r += T[(n >> 18) & 63];
        r += T[(n >> 12) & 63];
        r += (i + 1 < len) ? T[(n >> 6) & 63] : '=';
        r += (i + 2 < len) ? T[n & 63] : '=';
    }
    return r;
}

inline std::vector<uint8_t> base64_decode(const std::string& s) {
    // Thread-safe: use a constexpr lookup table instead of lazy-initialized static
    static const int D[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1, 0,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };
    std::vector<uint8_t> r;
    r.reserve(s.size() * 3 / 4);
    for (size_t i = 0; i + 3 < s.size(); i += 4) {
        if (D[(uint8_t)s[i]] < 0 || D[(uint8_t)s[i+1]] < 0) continue;
        uint32_t n = (D[(uint8_t)s[i]] << 18) | (D[(uint8_t)s[i + 1]] << 12) |
                     (D[(uint8_t)s[i + 2]] << 6) | D[(uint8_t)s[i + 3]];
        r.push_back((n >> 16) & 0xFF);
        if (s[i + 2] != '=') r.push_back((n >> 8) & 0xFF);
        if (s[i + 3] != '=') r.push_back(n & 0xFF);
    }
    return r;
}

inline std::string base58_encode(const uint8_t* data, size_t len) {
    static const char A[] =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    size_t zeroes = 0;
    while (zeroes < len && data[zeroes] == 0) zeroes++;
    std::vector<uint8_t> buf(data, data + len);
    std::string result;
    while (!buf.empty()) {
        int carry = 0;
        std::vector<uint8_t> next;
        for (size_t i = 0; i < buf.size(); i++) {
            int val = carry * 256 + buf[i];
            int digit = val / 58;
            carry = val % 58;
            if (!next.empty() || digit > 0)
                next.push_back((uint8_t)digit);
        }
        result += A[carry];
        buf = next;
    }
    for (size_t i = 0; i < zeroes; i++) result += '1';
    std::reverse(result.begin(), result.end());
    return result;
}

inline std::string hex_encode(const uint8_t* data, size_t len) {
    static const char H[] = "0123456789abcdef";
    std::string r(len * 2, 0);
    for (size_t i = 0; i < len; i++) {
        r[i * 2] = H[data[i] >> 4];
        r[i * 2 + 1] = H[data[i] & 0xF];
    }
    return r;
}

inline std::vector<uint8_t> hex_decode(const std::string& s) {
    auto nib = [](char c) -> uint8_t {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + c - 'a';
        if (c >= 'A' && c <= 'F') return 10 + c - 'A';
        return 0;
    };
    std::vector<uint8_t> r(s.size() / 2);
    for (size_t i = 0; i < r.size(); i++)
        r[i] = (nib(s[i * 2]) << 4) | nib(s[i * 2 + 1]);
    return r;
}

inline void random_bytes(uint8_t* out, size_t len) {
    randombytes(out, len);
}

inline void ed25519_sk_to_curve25519(const uint8_t ed_sk[64], uint8_t x_sk[32]) {
    uint8_t h[64];
    crypto_hash(h, ed_sk, 32);
    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;
    memcpy(x_sk, h, 32);
}

inline void ed25519_pk_to_curve25519(const uint8_t ed_sk[64], uint8_t x_pk[32]) {
    uint8_t x_sk[32];
    ed25519_sk_to_curve25519(ed_sk, x_sk);
    crypto_scalarmult_base(x_pk, x_sk);
}

inline void secure_zero(void* ptr, size_t len) {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (len--) *p++ = 0;
}

inline bool try_mlock(void* ptr, size_t len) {
#if defined(__unix__) || defined(__APPLE__)
    return mlock(ptr, len) == 0;
#elif defined(_WIN32)
    return VirtualLock(ptr, len) != 0;
#else
    return false;
#endif
}

inline void keypair_from_seed(const uint8_t seed[32], uint8_t sk[64], uint8_t pk[32]) {
    crypto_sign_seed_keypair(pk, sk, seed);
}

inline std::array<uint8_t, 32> derive_key_from_pin(
    const std::string& pin, const uint8_t salt[32], int iterations = 600000) {
    std::array<uint8_t, 32> key;
    PKCS5_PBKDF2_HMAC(pin.c_str(), (int)pin.size(),
        salt, 32, iterations, EVP_sha256(), 32, key.data());
    return key;
}

inline std::vector<uint8_t> wallet_encrypt(
    const uint8_t* plaintext, size_t len, const std::string& pin) {
    uint8_t salt[32], nonce[12];
    random_bytes(salt, 32);
    random_bytes(nonce, 12);
    auto key = derive_key_from_pin(pin, salt);

    std::vector<uint8_t> out(32 + 12 + len + 16);
    memcpy(out.data(), salt, 32);
    memcpy(out.data() + 32, nonce, 12);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce);

    int outlen = 0;
    if (EVP_EncryptUpdate(ctx, out.data() + 44, &outlen, plaintext, (int)len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        secure_zero(key.data(), 32);
        throw std::runtime_error("wallet encryption failed (update)");
    }
    int finlen = 0;
    if (EVP_EncryptFinal_ex(ctx, out.data() + 44 + outlen, &finlen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        secure_zero(key.data(), 32);
        throw std::runtime_error("wallet encryption failed (final)");
    }
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out.data() + 44 + len);
    EVP_CIPHER_CTX_free(ctx);

    secure_zero(key.data(), 32);
    return out;
}

inline std::vector<uint8_t> wallet_decrypt(
    const uint8_t* data, size_t total_len, const std::string& pin) {
    if (total_len < 60) return {};
    const uint8_t* salt = data;
    const uint8_t* nonce = data + 32;
    const uint8_t* ct = data + 44;
    size_t ct_len = total_len - 60;
    const uint8_t* tag = data + 44 + ct_len;

    auto key = derive_key_from_pin(pin, salt);

    std::vector<uint8_t> plain(ct_len);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce);

    int outlen = 0;
    if (EVP_DecryptUpdate(ctx, plain.data(), &outlen, ct, (int)ct_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        secure_zero(key.data(), 32);
        return {};
    }
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag);
    int finlen = 0;
    int ret = EVP_DecryptFinal_ex(ctx, plain.data() + outlen, &finlen);
    EVP_CIPHER_CTX_free(ctx);
    secure_zero(key.data(), 32);

    if (ret <= 0) return {};
    plain.resize(outlen + finlen);
    return plain;
}


inline std::array<uint8_t, 64> hmac_sha512(const uint8_t* key, size_t key_len,
                                            const uint8_t* data, size_t data_len) {
    std::array<uint8_t, 64> out;
    unsigned int out_len = 64;
    HMAC(EVP_sha512(), key, (int)key_len, data, data_len, out.data(), &out_len);
    return out;
}

inline std::array<uint8_t, 32> derive_hd_seed(const uint8_t master_seed[64],
                                                uint32_t index,
                                                int hd_version = 2) {
    std::array<uint8_t, 32> result;
    const char* key = "Octra seed";
    const size_t key_len = 10;

    if (hd_version == 1 && index == 0) {
        // Legacy v1: derive via HMAC instead of raw copy for better key separation
        auto mac = hmac_sha512((const uint8_t*)key, key_len, master_seed, 64);
        memcpy(result.data(), mac.data(), 32);
    } else if (hd_version == 2 && index == 0) {
        auto mac = hmac_sha512((const uint8_t*)key, key_len, master_seed, 64);
        memcpy(result.data(), mac.data(), 32);
    } else {
        // Indexed derivation: append 4-byte little-endian index to master seed
        uint8_t data[68];
        memcpy(data, master_seed, 64);
        data[64] = (uint8_t)(index & 0xFF);
        data[65] = (uint8_t)((index >> 8) & 0xFF);
        data[66] = (uint8_t)((index >> 16) & 0xFF);
        data[67] = (uint8_t)((index >> 24) & 0xFF);
        auto mac = hmac_sha512((const uint8_t*)key, key_len, data, 68);
        memcpy(result.data(), mac.data(), 32);
        secure_zero(data, 68);
    }
    return result;
}


#include "lib/bip39_wordlist.hpp"

inline std::array<uint8_t, 64> mnemonic_to_seed(const std::string& mnemonic,
                                                  const std::string& passphrase = "") {
    std::string salt = "mnemonic" + passphrase;
    std::array<uint8_t, 64> seed;
    PKCS5_PBKDF2_HMAC(mnemonic.c_str(), (int)mnemonic.size(),
                       (const uint8_t*)salt.c_str(), (int)salt.size(),
                       2048, EVP_sha512(), 64, seed.data());
    return seed;
}

inline std::string generate_mnemonic_12() {
    uint8_t entropy[16];
    randombytes(entropy, 16);
    auto hash = sha256(entropy, 16);
    uint8_t bits[17]; // 128 + 8 = 136 bits available
    memcpy(bits, entropy, 16);
    bits[16] = hash[0];
    secure_zero(entropy, 16);

    std::string result;
    for (int i = 0; i < 12; i++) {
        int bit_pos = i * 11;
        int byte_idx = bit_pos / 8;
        int bit_off = bit_pos % 8;
        uint32_t val = ((uint32_t)bits[byte_idx] << 16) |
                       ((uint32_t)bits[byte_idx + 1] << 8);
        if (byte_idx + 2 < 17) val |= bits[byte_idx + 2];
        val = (val >> (24 - 11 - bit_off)) & 0x7FF;
        if (i > 0) result += " ";
        result += bip39::wordlist[val];
    }
    secure_zero(bits, 17);
    return result;
}

inline bool validate_mnemonic(const std::string& mnemonic) {
    std::vector<std::string> words;
    std::string w;
    for (char c : mnemonic) {
        if (c == ' ' || c == '\n' || c == '\t') {
            if (!w.empty()) { words.push_back(w); w.clear(); }
        } else {
            w += (char)tolower((unsigned char)c);
        }
    }
    if (!w.empty()) words.push_back(w);
    if (words.size() != 12 && words.size() != 15 &&
        words.size() != 18 && words.size() != 21 && words.size() != 24)
        return false;
    // Use binary search (O(log n)) instead of linear scan (O(n)) -- wordlist is sorted
    for (auto& word : words) {
        bool found = std::binary_search(
            bip39::wordlist, bip39::wordlist + 2048, word,
            [](const char* a, const std::string& b) { return std::string(a) < b; }
        );
        if (!found) return false;
    }
    return true;
}

inline bool looks_like_mnemonic(const std::string& input) {
    int spaces = 0;
    for (char c : input) if (c == ' ') spaces++;
    return spaces >= 11; // at least 12 words
}

} // namespace octra
