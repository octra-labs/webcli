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
#include <stdexcept>
#include "../crypto_utils.hpp"

extern "C" {
#include "pvac_c_api.h"
}

namespace octra {

constexpr const char* HFHE_PREFIX = "hfhe_v1|";
constexpr const char* RP_PREFIX = "rp_v1|";
constexpr const char* ZKZP_PREFIX = "zkzp_v2|";

class PvacBridge {
    pvac_pubkey pk_ = nullptr;
    pvac_seckey sk_ = nullptr;

    std::vector<uint8_t> serialize_ptr(uint8_t*(*fn)(void*, size_t*), void* handle) {
        size_t len = 0;
        uint8_t* ptr = fn(handle, &len);
        std::vector<uint8_t> data(ptr, ptr + len);
        pvac_free_bytes(ptr);
        return data;
    }

public:
    PvacBridge() = default;
    PvacBridge(const PvacBridge&) = delete;
    PvacBridge& operator=(const PvacBridge&) = delete;

    ~PvacBridge() {
        if (pk_) pvac_free_pubkey(pk_);
        if (sk_) pvac_free_seckey(sk_);
    }

    void reset() {
        if (pk_) { pvac_free_pubkey(pk_); pk_ = nullptr; }
        if (sk_) { pvac_free_seckey(sk_); sk_ = nullptr; }
    }

    bool init(const std::string& priv_b64) {
        auto raw = base64_decode(priv_b64);
        if (raw.size() < 32) return false;
        uint8_t seed[32];
        memcpy(seed, raw.data(), 32);
        pvac_params prm = pvac_default_params();
        pvac_keygen_from_seed(prm, seed, &pk_, &sk_);
        pvac_free_params(prm);
        secure_zero(seed, 32);
        secure_zero(raw.data(), raw.size());
        return pk_ != nullptr && sk_ != nullptr;
    }

    pvac_pubkey pk() const { return pk_; }
    pvac_seckey sk() const { return sk_; }

    pvac_cipher encrypt(uint64_t value, const uint8_t seed[32]) {
        return pvac_enc_value_seeded(pk_, sk_, value, seed);
    }

    pvac_cipher encrypt_zero(const uint8_t seed[32]) {
        return pvac_enc_zero_seeded(pk_, sk_, seed);
    }

    uint64_t decrypt(pvac_cipher ct) {
        return pvac_dec_value(pk_, sk_, ct);
    }

    void decrypt_fp(pvac_cipher ct, uint64_t& lo, uint64_t& hi) {
        pvac_dec_value_fp(pk_, sk_, ct, &lo, &hi);
    }

    int64_t get_balance(const std::string& cipher_str) {
        if (cipher_str.empty() || cipher_str == "0") return 0;
        pvac_cipher ct = decode_cipher(cipher_str);
        if (!ct) return 0;
        uint64_t lo = 0, hi = 0;
        pvac_dec_value_fp(pk_, sk_, ct, &lo, &hi);
        pvac_free_cipher(ct);
        if (hi == 0) return static_cast<int64_t>(lo);
        __uint128_t p = (__uint128_t(1) << 127) - 1;
        __uint128_t val = (__uint128_t(hi) << 64) | lo;
        if (val > p / 2) return -static_cast<int64_t>(p - val);
        return static_cast<int64_t>(val);
    }

    pvac_cipher ct_add(pvac_cipher a, pvac_cipher b) {
        return pvac_ct_add(pk_, a, b);
    }

    pvac_cipher ct_sub(pvac_cipher a, pvac_cipher b) {
        return pvac_ct_sub(pk_, a, b);
    }

    std::array<uint8_t, 32> commit_ct(pvac_cipher ct) {
        std::array<uint8_t, 32> out;
        pvac_commit_ct(pk_, ct, out.data());
        return out;
    }

    std::array<uint8_t, 32> pedersen_commit(uint64_t amount, const uint8_t blinding[32]) {
        std::array<uint8_t, 32> out;
        pvac_pedersen_commit(amount, blinding, out.data());
        return out;
    }

    pvac_zero_proof make_zero_proof(pvac_cipher ct) {
        return pvac_make_zero_proof(pk_, sk_, ct);
    }

    pvac_zero_proof make_zero_proof_bound(pvac_cipher ct, uint64_t amount,
                                          const uint8_t blinding[32]) {
        return pvac_make_zero_proof_bound(pk_, sk_, ct, amount, blinding);
    }

    pvac_range_proof make_range_proof(pvac_cipher ct, uint64_t value) {
        return pvac_make_range_proof(pk_, sk_, ct, value);
    }

    std::vector<uint8_t> serialize_cipher(pvac_cipher ct) {
        return serialize_ptr(pvac_serialize_cipher, ct);
    }

    pvac_cipher deserialize_cipher(const uint8_t* data, size_t len) {
        return pvac_deserialize_cipher(data, len);
    }

    std::vector<uint8_t> serialize_pubkey() {
        return serialize_ptr(pvac_serialize_pubkey, pk_);
    }

    std::string serialize_pubkey_b64() {
        auto data = serialize_pubkey();
        return base64_encode(data.data(), data.size());
    }

    std::vector<uint8_t> serialize_range_proof(pvac_range_proof rp) {
        return serialize_ptr(pvac_serialize_range_proof, rp);
    }

    std::vector<uint8_t> serialize_zero_proof(pvac_zero_proof zp) {
        return serialize_ptr(pvac_serialize_zero_proof, zp);
    }

    std::string encode_cipher(pvac_cipher ct) {
        auto data = serialize_cipher(ct);
        return std::string(HFHE_PREFIX) + base64_encode(data.data(), data.size());
    }

    pvac_cipher decode_cipher(const std::string& s) {
        if (s.rfind(HFHE_PREFIX, 0) != 0) return nullptr;
        auto raw = base64_decode(s.substr(strlen(HFHE_PREFIX)));
        return pvac_deserialize_cipher(raw.data(), raw.size());
    }

    std::string encode_range_proof(pvac_range_proof rp) {
        auto data = serialize_range_proof(rp);
        return std::string(RP_PREFIX) + base64_encode(data.data(), data.size());
    }

    std::string encode_zero_proof(pvac_zero_proof zp) {
        auto data = serialize_zero_proof(zp);
        return std::string(ZKZP_PREFIX) + base64_encode(data.data(), data.size());
    }

    void free_cipher(pvac_cipher ct) { if (ct) pvac_free_cipher(ct); }
    void free_range_proof(pvac_range_proof rp) { if (rp) pvac_free_range_proof(rp); }
    void free_zero_proof(pvac_zero_proof zp) { if (zp) pvac_free_zero_proof(zp); }
};

}