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
#include <memory>
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
    static constexpr int64_t max_balance_raw_ = 1000000000000000LL;
    using PubkeyPtr = std::unique_ptr<void, decltype(&pvac_free_pubkey)>;

    static PubkeyPtr decode_pubkey(const std::string& value) {
        auto raw = base64_decode(value);
        return PubkeyPtr(
            pvac_deserialize_pubkey(raw.data(), raw.size()),
            &pvac_free_pubkey);
    }

    bool secret_profile(const PubkeyPtr& remote) const {
        return remote &&
            pvac_pubkey_matches_secret_profile(remote.get(), pk_, sk_) == 1;
    }

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
        reset();
        auto raw = base64_decode(priv_b64);
        if (raw.size() < 32) {
            if (!raw.empty()) secure_zero(raw.data(), raw.size());
            return false;
        }
        uint8_t seed[32];
        memcpy(seed, raw.data(), 32);
        pvac_params prm = pvac_default_params();
        pvac_keygen_from_seed(prm, seed, &pk_, &sk_);
        pvac_free_params(prm);
        secure_zero(seed, sizeof(seed));
        secure_zero(raw.data(), raw.size());
        return pk_ != nullptr && sk_ != nullptr;
    }

    bool init_public(const std::string& pubkey_b64) {
        reset();
        auto remote = decode_pubkey(pubkey_b64);
        if (!remote) return false;
        pk_ = remote.release();
        return true;
    }

    bool init_registered(const std::string& priv_b64,
                         const std::string& pubkey_b64) {
        if (!init(priv_b64)) return false;
        auto remote = decode_pubkey(pubkey_b64);
        if (!secret_profile(remote)) {
            reset();
            return false;
        }
        pvac_free_pubkey(pk_);
        pk_ = remote.release();
        return true;
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
        if (!ct) throw std::runtime_error("encrypted balance ciphertext is invalid");
        int64_t current = 0;
        int64_t legacy = 0;
        bool current_ok = pvac_dec_value_i64(pk_, sk_, ct, &current) != 0
            && current >= 0
            && current <= max_balance_raw_;
        bool legacy_ok = pvac_dec_value_legacy_i64(pk_, sk_, ct, &legacy) != 0
            && legacy >= 0
            && legacy <= max_balance_raw_;
        pvac_free_cipher(ct);
        if (current_ok && legacy_ok && current != legacy)
            throw std::runtime_error("encrypted balance mask profile is ambiguous");
        if (current_ok) return current;
        if (legacy_ok) return legacy;
        throw std::runtime_error("decrypted field value is outside balance range");
    }

    bool try_get_balance(const std::string& cipher_str, int64_t& value) {
        try {
            value = get_balance(cipher_str);
            return true;
        } catch (...) {
            value = 0;
            return false;
        }
    }

    bool try_get_legacy_v1_balance(const std::string& cipher_str,
                                   const std::string& pubkey_b64,
                                   int64_t& value) {
        value = 0;
        auto key_raw = base64_decode(pubkey_b64);
        pvac_pubkey legacy = pvac_deserialize_pubkey(key_raw.data(), key_raw.size());
        if (!legacy) return false;
        const bool profile_ok = pvac_pubkey_is_legacy_v1_profile(legacy, pk_) == 1;
        pvac_cipher ct = profile_ok ? decode_cipher(cipher_str) : nullptr;
        const bool decoded = ct &&
            pvac_dec_value_legacy_i64(legacy, sk_, ct, &value) != 0 &&
            value >= 0 && value <= max_balance_raw_;
        pvac_free_cipher(ct);
        pvac_free_pubkey(legacy);
        if (!decoded) value = 0;
        return decoded;
    }

    pvac_cipher ct_add(pvac_cipher a, pvac_cipher b) {
        return pvac_ct_add(pk_, a, b);
    }

    pvac_cipher ct_sub(pvac_cipher a, pvac_cipher b) {
        return pvac_ct_sub(pk_, a, b);
    }

    std::array<uint8_t, 32> commit_ct(pvac_cipher ct) {
        std::array<uint8_t, 32> out;
        size_t out_len = 0;
        int rc = pvac_commit_ct_v2(pk_, ct, out.data(), out.size(), &out_len);
        if (rc != 0 || out_len != out.size()) throw std::runtime_error("pvac_commit_ct_v2 failed");
        return out;
    }

    bool has_key_bound_material(pvac_cipher ct) {
        return pvac_cipher_has_key_bound_material(ct) == 1;
    }

    bool has_key_bound_material(const std::string& cipher_str) {
        pvac_cipher ct = decode_cipher(cipher_str);
        if (!ct) return false;
        bool ok = has_key_bound_material(ct);
        pvac_free_cipher(ct);
        return ok;
    }

    bool has_canonical_r_com(pvac_cipher ct) {
        return pvac_cipher_has_canonical_r_com(pk_, ct) == 1;
    }

    bool has_canonical_r_com(const std::string& cipher_str) {
        pvac_cipher ct = decode_cipher(cipher_str);
        if (!ct) return false;
        bool ok = has_canonical_r_com(ct);
        pvac_free_cipher(ct);
        return ok;
    }

    size_t base_layer_count(pvac_cipher ct) {
        return pvac_cipher_base_layer_count(ct);
    }

    size_t base_layer_count(const std::string& cipher_str) {
        pvac_cipher ct = decode_cipher(cipher_str);
        if (!ct) return 0;
        size_t count = base_layer_count(ct);
        pvac_free_cipher(ct);
        return count;
    }

    std::array<uint8_t, 32> pedersen_commit(uint64_t amount, const uint8_t blinding[32]) {
        std::array<uint8_t, 32> out;
        size_t out_len = 0;
        int rc = pvac_pedersen_commit_v2(amount, blinding, out.data(), out.size(), &out_len);
        if (rc != 0 || out_len != out.size()) throw std::runtime_error("pvac_pedersen_commit_v2 failed");
        return out;
    }

    std::array<uint8_t, 32> blinding_add(const std::array<uint8_t, 32>& a,
                                         const std::array<uint8_t, 32>& b) {
        std::array<uint8_t, 32> out;
        if (pvac_blinding_add(a.data(), b.data(), out.data()) != 0)
            throw std::runtime_error("pvac_blinding_add failed");
        return out;
    }

    std::array<uint8_t, 32> blinding_sub(const std::array<uint8_t, 32>& a,
                                         const std::array<uint8_t, 32>& b) {
        std::array<uint8_t, 32> out;
        if (pvac_blinding_sub(a.data(), b.data(), out.data()) != 0)
            throw std::runtime_error("pvac_blinding_sub failed");
        return out;
    }

    pvac_zero_proof make_zero_proof(pvac_cipher ct) {
        return pvac_make_zero_proof(pk_, sk_, ct);
    }

    pvac_zero_proof make_zero_proof_bound(pvac_cipher ct, uint64_t amount,
                                          const uint8_t blinding[32]) {
        return pvac_make_zero_proof_bound(pk_, sk_, ct, amount, blinding);
    }

    pvac_zero_proof make_bound_range_proof(pvac_cipher ct, uint64_t amount,
                                           const uint8_t blinding[32]) {
        return pvac_make_bound_range_proof(pk_, sk_, ct, amount, blinding);
    }

    bool verify_bound_range(
        pvac_cipher ct,
        pvac_zero_proof proof,
        const std::array<uint8_t, 32>& commitment) {
        return pvac_verify_bound_range_commitment(
            pk_,
            ct,
            proof,
            commitment.data()) != 0;
    }

    bool verify_zero_proof_bound(pvac_cipher ct,
                                 pvac_zero_proof proof,
                                 const std::array<uint8_t, 32>& commitment) {
        return pvac_verify_zero_bound(pk_, ct, proof, commitment.data()) != 0;
    }

    pvac_range_proof make_range_proof(pvac_cipher ct, uint64_t value) {
        return pvac_make_range_proof(pk_, sk_, ct, value);
    }

    std::vector<uint8_t> serialize_cipher(pvac_cipher ct) {
        return serialize_ptr(pvac_serialize_cipher, ct);
    }

    std::vector<uint8_t> serialize_cipher_public(pvac_cipher ct) {
        return serialize_ptr(pvac_serialize_cipher_public, ct);
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

    bool pubkey_extends_local(const std::string& legacy_b64) {
        auto raw = base64_decode(legacy_b64);
        pvac_pubkey legacy = pvac_deserialize_pubkey(raw.data(), raw.size());
        if (!legacy) return false;
        bool ok = pvac_pubkey_is_key_bound_extension(legacy, pk_) == 1;
        pvac_free_pubkey(legacy);
        return ok;
    }

    bool pubkey_matches_legacy_v1(const std::string& legacy_b64) {
        auto raw = base64_decode(legacy_b64);
        pvac_pubkey legacy = pvac_deserialize_pubkey(raw.data(), raw.size());
        if (!legacy) return false;
        bool ok = pvac_pubkey_is_legacy_v1_profile(legacy, pk_) == 1;
        pvac_free_pubkey(legacy);
        return ok;
    }

    bool pubkey_matches_secret_profile(const std::string& value) {
        auto remote = decode_pubkey(value);
        return secret_profile(remote);
    }

    bool try_get_balance_with_pubkey(const std::string& cipher_str,
                                     const std::string& pubkey_b64,
        int64_t& value) {
        value = 0;
        auto remote = decode_pubkey(pubkey_b64);
        pvac_cipher ct = secret_profile(remote)
            ? decode_cipher(cipher_str)
            : nullptr;
        const bool ok = ct &&
            pvac_dec_value_i64(remote.get(), sk_, ct, &value) != 0 &&
            value >= 0 &&
            value <= max_balance_raw_;
        pvac_free_cipher(ct);
        if (!ok) value = 0;
        return ok;
    }

    pvac_zero_proof make_zero_proof_bound_with_pubkey(
        const std::string& pubkey_b64,
        pvac_cipher ct,
        uint64_t amount,
        const uint8_t blinding[32]) {
        auto remote = decode_pubkey(pubkey_b64);
        if (!secret_profile(remote))
            throw std::runtime_error("registered pvac key profile is invalid");
        return pvac_make_zero_proof_bound(
            remote.get(),
            sk_,
            ct,
            amount,
            blinding);
    }

    pvac_zero_proof make_zero_proof_bound_key_switch_with_pubkey(
        const std::string& pubkey_b64,
        pvac_cipher ct,
        uint64_t amount,
        const uint8_t blinding[32]) {
        auto remote = decode_pubkey(pubkey_b64);
        if (!secret_profile(remote))
            throw std::runtime_error("registered pvac key profile is invalid");
        auto proof = pvac_make_zero_proof_bound_key_switch(
            remote.get(),
            sk_,
            ct,
            amount,
            blinding);
        if (!proof)
            throw std::runtime_error("key switch proof generation failed");
        return proof;
    }

    bool verify_zero_proof_bound_with_pubkey(
        const std::string& pubkey_b64,
        pvac_cipher ct,
        pvac_zero_proof proof,
        const std::array<uint8_t, 32>& commitment) {
        auto remote = decode_pubkey(pubkey_b64);
        return secret_profile(remote) &&
            pvac_verify_zero_bound(
                remote.get(),
                ct,
                proof,
                commitment.data()) != 0;
    }

    bool verify_zero_proof_bound_key_switch_with_pubkey(
        const std::string& pubkey_b64,
        pvac_cipher ct,
        pvac_zero_proof proof,
        const std::array<uint8_t, 32>& commitment) {
        auto remote = decode_pubkey(pubkey_b64);
        return secret_profile(remote) &&
            pvac_verify_zero_bound_key_switch(
                remote.get(),
                ct,
                proof,
                commitment.data()) != 0;
    }

    std::vector<uint8_t> serialize_range_proof(pvac_range_proof rp) {
        return serialize_ptr(pvac_serialize_range_proof, rp);
    }

    std::vector<uint8_t> serialize_zero_proof(pvac_zero_proof zp) {
        return serialize_ptr(pvac_serialize_zero_proof, zp);
    }

    std::vector<uint8_t> serialize_bound_range_proof(pvac_zero_proof zp) {
        return serialize_ptr(pvac_serialize_bound_range_proof, zp);
    }

    std::string encode_bound_cipher(pvac_cipher ct) {
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

    std::string encode_bound_range_proof(pvac_zero_proof zp) {
        auto data = serialize_bound_range_proof(zp);
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