#pragma once
#include <algorithm>
#include <array>
#include <string>
#include <vector>
#include "json.hpp"
#include "tx_builder.hpp"

namespace octra {

struct CircleHfheReceiptContext {
    std::string circle_id;
    std::string caller_addr;
    std::string key_id;
    std::string intent_id;
    std::string verb;
    std::string proof_kind;
    std::string policy_hash;
    std::string ciphertext_hash;
    std::string amount_commitment_hash;
};

inline std::string circle_hfhe_receipt_subject_v1(const CircleHfheReceiptContext& ctx) {
    return "octra_circle_hfhe_receipt_v1|" +
        ctx.verb + "|" +
        ctx.proof_kind + "|" +
        ctx.circle_id + "|" +
        ctx.caller_addr + "|" +
        ctx.key_id + "|" +
        ctx.intent_id + "|" +
        ctx.policy_hash + "|" +
        ctx.ciphertext_hash + "|" +
        ctx.amount_commitment_hash;
}

inline std::string circle_hfhe_receipt_subject(const CircleHfheReceiptContext& ctx) {
    return frame_v2(
        "octra_circle_hfhe_receipt_v2",
        {
            ctx.verb,
            ctx.proof_kind,
            ctx.circle_id,
            ctx.caller_addr,
            ctx.key_id,
            ctx.intent_id,
            ctx.policy_hash,
            ctx.ciphertext_hash,
            ctx.amount_commitment_hash
        });
}

inline bool circle_hfhe_receipt_v1_safe(const CircleHfheReceiptContext& ctx) {
    const std::array<std::string, 9> fields = {
        ctx.verb,
        ctx.proof_kind,
        ctx.circle_id,
        ctx.caller_addr,
        ctx.key_id,
        ctx.intent_id,
        ctx.policy_hash,
        ctx.ciphertext_hash,
        ctx.amount_commitment_hash
    };
    return std::all_of(fields.begin(), fields.end(), [](const std::string& field) {
        return field.find('|') == std::string::npos;
    });
}

inline std::string circle_hfhe_hash_b64_payload(const std::string& encoded,
                                                std::string& error) {
    auto raw = base64_decode(encoded);
    if (raw.empty()) {
        error = "invalid base64 payload";
        return "";
    }
    return hex_encode(sha256(raw.data(), raw.size()).data(), 32);
}

inline std::string circle_hfhe_hash_ciphertext(const std::string& ciphertext_b64,
                                               std::string& error) {
    return circle_hfhe_hash_b64_payload(ciphertext_b64, error);
}

inline std::string circle_hfhe_hash_commitment(const std::string& amount_commitment_b64,
                                               std::string& error) {
    auto raw = base64_decode(amount_commitment_b64);
    if (raw.size() != 32) {
        error = "invalid amount commitment";
        return "";
    }
    return hex_encode(sha256(raw.data(), raw.size()).data(), 32);
}

inline std::string derive_address_from_pubkey_b64(const std::string& pub_b64) {
    auto raw = base64_decode(pub_b64);
    if (raw.size() != 32) {
        return "";
    }
    auto h = sha256(raw.data(), raw.size());
    std::string b58 = base58_encode(h.data(), 32);
    while (b58.size() < 44) {
        b58 = "1" + b58;
    }
    return "oct" + b58;
}

inline bool ed25519_verify_detached(const std::string& message,
                                    const std::string& sig_b64,
                                    const std::string& pub_b64) {
    auto sig = base64_decode(sig_b64);
    auto pub = base64_decode(pub_b64);
    if (sig.size() != 64 || pub.size() != 32) {
      return false;
    }
    if (!ed25519_public_key_safe(pub.data())) {
      return false;
    }
    std::vector<unsigned char> signed_msg(sig.size() + message.size());
    std::memcpy(signed_msg.data(), sig.data(), sig.size());
    std::memcpy(signed_msg.data() + sig.size(), message.data(), message.size());
    std::vector<unsigned char> opened(message.size() + 64);
    unsigned long long opened_len = 0;
    return crypto_sign_open(
        opened.data(),
        &opened_len,
        signed_msg.data(),
        signed_msg.size(),
        pub.data()) == 0;
}

inline nlohmann::json make_circle_hfhe_receipt_json(const CircleHfheReceiptContext& ctx,
                                                    const std::string& signer_addr,
                                                    const std::string& signer_pub_b64,
                                                    const uint8_t signer_sk[64]) {
    nlohmann::json receipt;
    receipt["version"] = "octra_circle_hfhe_receipt_v2";
    receipt["verb"] = ctx.verb;
    receipt["proof_kind"] = ctx.proof_kind;
    receipt["circle_id"] = ctx.circle_id;
    receipt["caller_addr"] = ctx.caller_addr;
    receipt["key_id"] = ctx.key_id;
    receipt["intent_id"] = ctx.intent_id;
    receipt["policy_hash"] = ctx.policy_hash;
    receipt["ciphertext_hash"] = ctx.ciphertext_hash;
    receipt["amount_commitment_hash"] = ctx.amount_commitment_hash;
    receipt["signer_addr"] = signer_addr;
    receipt["signer_pubkey"] = signer_pub_b64;
    const std::string subject = circle_hfhe_receipt_subject(ctx);
    receipt["signature"] = ed25519_sign_detached(
        reinterpret_cast<const uint8_t*>(subject.data()),
        subject.size(),
        signer_sk);
    return receipt;
}

inline bool verify_circle_hfhe_receipt_json(const nlohmann::json& receipt,
                                            const CircleHfheReceiptContext& ctx,
                                            std::string& error) {
    if (!receipt.is_object()) {
        error = "proof_receipt must be an object";
        return false;
    }
    const std::string version = receipt.value("version", "");
    const std::string verb = receipt.value("verb", "");
    const std::string proof_kind = receipt.value("proof_kind", "");
    const std::string circle_id = receipt.value("circle_id", "");
    const std::string caller_addr = receipt.value("caller_addr", "");
    const std::string key_id = receipt.value("key_id", "");
    const std::string intent_id = receipt.value("intent_id", "");
    const std::string policy_hash = receipt.value("policy_hash", "");
    const std::string ciphertext_hash = receipt.value("ciphertext_hash", "");
    const std::string amount_commitment_hash = receipt.value("amount_commitment_hash", "");
    const std::string signer_addr = receipt.value("signer_addr", "");
    const std::string signer_pubkey = receipt.value("signer_pubkey", "");
    const std::string signature = receipt.value("signature", "");
    if (version != "octra_circle_hfhe_receipt_v1" &&
        version != "octra_circle_hfhe_receipt_v2") {
        error = "invalid proof receipt version";
        return false;
    }
    if (verb != ctx.verb || proof_kind != ctx.proof_kind || circle_id != ctx.circle_id ||
        caller_addr != ctx.caller_addr || key_id != ctx.key_id || intent_id != ctx.intent_id ||
        policy_hash != ctx.policy_hash || ciphertext_hash != ctx.ciphertext_hash ||
        amount_commitment_hash != ctx.amount_commitment_hash) {
        error = "proof receipt context mismatch";
        return false;
    }
    const std::string derived_addr = derive_address_from_pubkey_b64(signer_pubkey);
    if (derived_addr.empty() || derived_addr != signer_addr) {
        error = "proof receipt signer binding invalid";
        return false;
    }
    const bool legacy = version == "octra_circle_hfhe_receipt_v1";
    if (legacy && !circle_hfhe_receipt_v1_safe(ctx)) {
        error = "legacy proof receipt context is ambiguous";
        return false;
    }
    const std::string signed_subject = legacy
        ? circle_hfhe_receipt_subject_v1(ctx)
        : circle_hfhe_receipt_subject(ctx);
    if (!ed25519_verify_detached(signed_subject, signature, signer_pubkey)) {
        error = "proof receipt signature verification failed";
        return false;
    }
    return true;
}

}