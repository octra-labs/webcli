// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once

#include <memory>
#include <stdexcept>
#include "pvac_bridge.hpp"
#include "json.hpp"
#include "rpc_state.hpp"
#include "tx_builder.hpp"

namespace octra {

inline bool proof_math(const nlohmann::json& status) {
    if (status.is_object()) {
        const auto mode = status.value("proof_math", nlohmann::json{});
        if (mode == "wide") return true;
        if (mode == "prior") return false;
    }
    throw std::runtime_error("network proof arithmetic is unavailable");
}

inline int proof_policy(const nlohmann::json& status) {
    const auto key = status.value("proof_key", nlohmann::json(false));
    if (!key.is_boolean()) throw std::runtime_error("network proof key policy is unavailable");
    return (proof_math(status) ? 1 : 0) | (key.get<bool>() ? 2 : 0);
}

inline void require_proof_policy(int prepared, int current) {
    if (prepared != current)
        throw RpcStateError("proof policy changed; nothing sent; prepare the transaction again");
}

inline bool profile_math(const nlohmann::json& runtime) {
    if (runtime.is_object() &&
        runtime.value("schema", nlohmann::json{}) == "octra-runtime-release-v1" &&
        runtime.value("chain_id", nlohmann::json{}) == "octra-devnet-9871-cluster" &&
        runtime.value("consensus_rules_id", nlohmann::json{}) == "finalized_rejection_commitment" &&
        runtime.value("consensus_profile", nlohmann::json{}) == 16) {
        const auto profile = runtime.value("runtime_profile_hash", nlohmann::json{});
        if (profile == "86a3e354b18cad2cd2ec35c63a61924aa78363fef2e93e1b5f5b37badd7d0c0c" ||
            profile == "1d46b19e336be6978b7a27b3fc04eda930cd58114858fd8a822c29c2e96ff13a")
            return true;
    }
    throw std::runtime_error("network proof arithmetic is unavailable");
}

inline bool cipher_route(const nlohmann::json& status) {
    return status.is_object() &&
        status.value("cipher_proof_rule", nlohmann::json{}) == "active" &&
        status.value("can_cipher_proof_migrate", nlohmann::json{}) == true &&
        (status.value("cipher_format", nlohmann::json{}) == "proven" ||
         (!status.contains("cipher_format") &&
          status.value("cipher_class", nlohmann::json{}) == "v3")) &&
        status.value("key_class", nlohmann::json{}) == "historical";
}

inline nlohmann::json cipher_migration(PvacBridge& wallet,
    const std::string& old_key, const std::string& source, int64_t amount) {
    if (amount < 0 || amount > 1000000000000000LL ||
        !wallet.pk() || !wallet.sk())
        throw std::runtime_error("migration amount or wallet key is invalid");
    int64_t opened = 0;
    if (!wallet.try_get_balance_with_pubkey(source, old_key, opened) ||
        opened != amount)
        throw std::runtime_error("registered key cannot open the migration source");
    using Cipher = std::unique_ptr<void, decltype(&pvac_free_cipher)>;
    using Proof = std::unique_ptr<void, decltype(&pvac_free_zero_proof)>;
    using Key = std::unique_ptr<void, decltype(&pvac_free_pubkey)>;
    const auto raw = base64_decode(old_key);
    Key key(pvac_deserialize_pubkey(raw.data(), raw.size()), pvac_free_pubkey);
    Cipher before(wallet.decode_cipher(source), pvac_free_cipher);
    if (!key || !before || !wallet.has_key_proof(before.get()))
        throw std::runtime_error("migration source proof material is invalid");
    std::array<uint8_t, 32> seed{}, blind{};
    random_bytes(seed.data(), seed.size());
    random_bytes(blind.data(), blind.size());
    const auto clear = [&] {
        secure_zero(seed.data(), seed.size());
        secure_zero(blind.data(), blind.size());
    };
    try {
        Cipher after(wallet.encrypt(static_cast<uint64_t>(amount), seed.data()), pvac_free_cipher);
        if (!after) throw std::runtime_error("migration encryption failed");
        const auto point = wallet.pedersen_commit(static_cast<uint64_t>(amount), blind.data());
        Proof old_proof(pvac_prove_amount(key.get(), wallet.sk(), before.get(),
            static_cast<uint64_t>(amount), blind.data(), PVAC_HISTORY, wallet.proof_policy()), pvac_free_zero_proof);
        if (!old_proof || !pvac_verify_amount(key.get(), before.get(),
                old_proof.get(), point.data(), PVAC_HISTORY, wallet.proof_policy()))
            throw std::runtime_error("historical ciphertext proof failed");
        Proof new_proof(pvac_prove_amount(wallet.pk(), wallet.sk(), after.get(),
            static_cast<uint64_t>(amount), blind.data(), PVAC_RANGE, wallet.proof_policy()), pvac_free_zero_proof);
        if (!new_proof || !pvac_verify_amount(wallet.pk(), after.get(),
                new_proof.get(), point.data(), PVAC_RANGE, wallet.proof_policy()))
            throw std::runtime_error("new ciphertext range proof failed");
        nlohmann::json result = {
            {"migration_mode", "cipher_proof"},
            {"source_cipher_hash", sha256_hex(source)},
            {"new_cipher", wallet.encode_proven_cipher(after.get())},
            {"old_zero_proof", wallet.encode_zero_proof(old_proof.get())},
            {"new_range_proof", wallet.encode_cipher_range(new_proof.get())},
            {"amount_commitment", base64_encode(point.data(), point.size())}
        };
        clear();
        return result;
    } catch (...) {
        clear();
        throw;
    }
}

}