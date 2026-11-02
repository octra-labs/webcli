// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once

#include <array>
#include <cstdint>
#include <limits>
#include <memory>
#include <stdexcept>
#include "json.hpp"
#include "../crypto_utils.hpp"

namespace octra {

struct FheInput {
    uint64_t value;
    bool proof;
};

inline int64_t fhe_signed_value(uint64_t lo, uint64_t hi) {
    const __uint128_t prime = (__uint128_t{1} << 127) - 1;
    const __uint128_t value = (__uint128_t{hi} << 64) | lo;
    const __uint128_t limit = __uint128_t{1} << 63;
    if (value < limit) return static_cast<int64_t>(lo);
    if (value < prime && prime - value <= limit) {
        const auto magnitude = static_cast<uint64_t>(prime - value);
        return magnitude == static_cast<uint64_t>(limit)
            ? std::numeric_limits<int64_t>::min() : -static_cast<int64_t>(magnitude);
    }
    throw std::domain_error("decrypted value is outside the signed 64-bit domain");
}

template<class Bridge>
nlohmann::json fhe_decrypt(Bridge& bridge, void* cipher) {
    const auto drop = [&bridge](void* value) { bridge.free_cipher(value); };
    const std::unique_ptr<void, decltype(drop)> owned(cipher, drop);
    uint64_t lo = 0;
    uint64_t hi = 0;
    bridge.decrypt_fp(owned.get(), lo, hi);
    const auto value = fhe_signed_value(lo, hi);
    return {{"value", value}, {"value_raw", std::to_string(value)}};
}

inline FheInput fhe_input(const nlohmann::json& body) {
    if (!body.is_object() || !body.contains("value") ||
        !body["value"].is_number_integer())
        throw std::invalid_argument("value must be an integer");
    const auto& value = body["value"];
    if ((!value.is_number_unsigned() && value.get<int64_t>() < 0) ||
        (value.is_number_unsigned() && value.get<uint64_t>() >
            static_cast<uint64_t>(std::numeric_limits<int64_t>::max())))
        throw std::invalid_argument("value must be between 0 and 9223372036854775807");
    if (body.contains("proof") && !body["proof"].is_boolean())
        throw std::invalid_argument("proof must be a boolean");
    return {value.get<uint64_t>(), body.value("proof", true)};
}

template<class Bridge>
nlohmann::json fhe_encrypt(Bridge& bridge, const FheInput& input,
    const std::array<uint8_t, 32>& seed,
    const std::array<uint8_t, 32>& blinding, int math = 0) {
    const auto drop = [&bridge](void* value) { bridge.free_cipher(value); };
    const std::unique_ptr<void, decltype(drop)> cipher(
        bridge.encrypt(input.value, seed.data()), drop);
    if (!cipher) throw std::runtime_error("encryption failed");
    const auto data = bridge.serialize_cipher_public(cipher.get());
    if (data.empty()) throw std::runtime_error("ciphertext serialization failed");
    nlohmann::json result = {{"ciphertext", base64_encode(data.data(), data.size())}};
    if (!input.proof) return result;
    const auto commitment = bridge.pedersen_commit(input.value, blinding.data());
    const auto release = [&bridge](void* value) { bridge.free_zero_proof(value); };
    const std::unique_ptr<void, decltype(release)> proof(
        bridge.make_cipher_proof(cipher.get(), input.value, blinding.data(), math), release);
    if (!proof) throw std::runtime_error("proof generation failed");
    const auto encoded = bridge.encode_zero_proof(proof.get());
    if (encoded.empty()) throw std::runtime_error("proof serialization failed");
    result["amount_commitment"] = base64_encode(commitment.data(), commitment.size());
    result["zero_proof"] = encoded;
    result["proof_kind"] = "bound_zero_v1";
    return result;
}

}