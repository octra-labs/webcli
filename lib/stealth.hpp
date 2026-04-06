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
#include <array>
#include <vector>
#include <optional>
#include <openssl/evp.h>
#include "../crypto_utils.hpp"

extern "C" {
#include "tweetnacl.h"
}

namespace octra {

inline std::array<uint8_t, 32> ecdh_shared_secret(const uint8_t our_sk[32],
                                                   const uint8_t their_pub[32]) {
    uint8_t raw[32];
    crypto_scalarmult(raw, our_sk, their_pub);
    auto result = sha256(raw, 32);
    secure_zero(raw, 32);
    return result;
}

inline std::array<uint8_t, 16> compute_stealth_tag(const std::array<uint8_t, 32>& shared) {
    const char* domain = "OCTRA_STEALTH_TAG_V1";
    std::vector<uint8_t> buf(32 + strlen(domain));
    memcpy(buf.data(), shared.data(), 32);
    memcpy(buf.data() + 32, domain, strlen(domain));
    auto h = sha256(buf.data(), buf.size());
    std::array<uint8_t, 16> tag;
    memcpy(tag.data(), h.data(), 16);
    return tag;
}

inline std::array<uint8_t, 32> compute_claim_secret(const std::array<uint8_t, 32>& shared) {
    const char* domain = "OCTRA_CLAIM_SECRET_V1";
    std::vector<uint8_t> buf(32 + strlen(domain));
    memcpy(buf.data(), shared.data(), 32);
    memcpy(buf.data() + 32, domain, strlen(domain));
    return sha256(buf.data(), buf.size());
}

inline std::array<uint8_t, 32> compute_claim_pub(const std::array<uint8_t, 32>& claim_secret,
                                                  const std::string& addr) {
    const char* domain = "OCTRA_CLAIM_BIND_V1";
    std::vector<uint8_t> buf(32 + addr.size() + strlen(domain));
    memcpy(buf.data(), claim_secret.data(), 32);
    memcpy(buf.data() + 32, addr.data(), addr.size());
    memcpy(buf.data() + 32 + addr.size(), domain, strlen(domain));
    return sha256(buf.data(), buf.size());
}

inline std::string encrypt_stealth_amount(const std::array<uint8_t, 32>& shared,
                                          uint64_t amount,
                                          const uint8_t blinding[32]) {
    uint8_t nonce[12];
    random_bytes(nonce, 12);

    uint8_t plaintext[40];
    for (int i = 0; i < 8; i++)
        plaintext[i] = (uint8_t)(amount >> (i * 8));
    memcpy(plaintext + 8, blinding, 32);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, shared.data(), nonce);

    uint8_t ciphertext[40];
    int outlen = 0;
    EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, 40);
    int finlen = 0;
    EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &finlen);

    uint8_t tag[16];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);

    uint8_t output[68];
    memcpy(output, nonce, 12);
    memcpy(output + 12, ciphertext, 40);
    memcpy(output + 52, tag, 16);
    return base64_encode(output, 68);
}

struct StealthDecrypted {
    uint64_t amount;
    std::array<uint8_t, 32> blinding;
};

inline std::optional<StealthDecrypted> decrypt_stealth_amount(
        const std::array<uint8_t, 32>& shared,
        const std::string& enc_b64) {
    auto raw = base64_decode(enc_b64);
    if (raw.size() != 68) return std::nullopt;

    const uint8_t* nonce = raw.data();
    const uint8_t* ciphertext = raw.data() + 12;
    const uint8_t* tag = raw.data() + 52;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, shared.data(), nonce);

    uint8_t plaintext[40];
    int outlen = 0;
    EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, 40);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag);
    int ret = EVP_DecryptFinal_ex(ctx, plaintext + outlen, &outlen);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) return std::nullopt;

    StealthDecrypted result;
    result.amount = 0;
    for (int i = 0; i < 8; i++)
        result.amount |= (uint64_t)plaintext[i] << (i * 8);
    memcpy(result.blinding.data(), plaintext + 8, 32);
    return result;
}

inline void derive_view_keypair(const uint8_t ed_sk[64],
                                uint8_t x_sk[32],
                                uint8_t x_pk[32]) {
    ed25519_sk_to_curve25519(ed_sk, x_sk);
    crypto_scalarmult_base(x_pk, x_sk);
}

} // namespace octra