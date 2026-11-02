// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <iomanip>
#include <locale>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <openssl/evp.h>
#include "json.hpp"

extern "C" {
#include "tweetnacl.h"
}

#include "../crypto_utils.hpp"

namespace octra {

class TxInputError : public std::invalid_argument {
public:
    using std::invalid_argument::invalid_argument;
};

struct Transaction {
    std::string from, to_, amount;
    int nonce;
    std::string ou;
    double timestamp;
    std::string op_type;
    std::string signature, public_key;
    std::string encrypted_data, message;
};

inline std::string format_timestamp(double ts) {
    if (!std::isfinite(ts)) throw TxInputError("transaction time is not finite");
    const auto format = [ts](int digits) {
        std::ostringstream out;
        out.imbue(std::locale::classic());
        out << std::setprecision(digits) << ts;
        return out.str();
    };
    std::string text = format(16);
    std::istringstream input(text);
    input.imbue(std::locale::classic());
    double decoded = 0;
    input >> decoded;
    if (!input || decoded != ts) text = format(17);
    if (text.find_first_of(".eE") == std::string::npos) text += ".0";
    return text;
}

inline std::string json_escape(const std::string& s) {
    std::string r;
    r.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '"':  r += "\\\""; break;
            case '\\': r += "\\\\"; break;
            case '\b': r += "\\b";  break;
            case '\f': r += "\\f";  break;
            case '\n': r += "\\n";  break;
            case '\r': r += "\\r";  break;
            case '\t': r += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20 || c == 0x7f) {
                    const char* hex = "0123456789abcdef";
                    const auto value = static_cast<unsigned char>(c);
                    r += "\\u00";
                    r += hex[value >> 4];
                    r += hex[value & 15];
                } else r += c;
        }
    }
    return r;
}

inline std::string decimal_text(const std::string& value) {
    if (value.empty() || value.find_first_not_of("0123456789") != std::string::npos)
        throw TxInputError("transaction amount and fee must use decimal whole units");
    const auto first = value.find_first_not_of('0');
    return first == std::string::npos ? "0" : value.substr(first);
}

inline std::string signing_json(const Transaction& tx) {
    std::string s = "{\"from\":\"" + json_escape(tx.from) + "\""
        ",\"to_\":\"" + json_escape(tx.to_) + "\""
        ",\"amount\":\"" + decimal_text(tx.amount) + "\""
        ",\"nonce\":" + std::to_string(tx.nonce) +
        ",\"ou\":\"" + decimal_text(tx.ou) + "\""
        ",\"timestamp\":" + format_timestamp(tx.timestamp) +
        ",\"op_type\":\"" + json_escape(tx.op_type.empty() ? "standard" : tx.op_type) + "\"";
    if (!tx.encrypted_data.empty())
        s += ",\"encrypted_data\":\"" + json_escape(tx.encrypted_data) + "\"";
    if (!tx.message.empty())
        s += ",\"message\":\"" + json_escape(tx.message) + "\"";
    s += "}";
    return s;
}

inline std::string ed25519_sign_detached(const uint8_t* msg, size_t len,
                                         const uint8_t sk[64]) {
    std::vector<uint8_t> sm(len + 64);
    unsigned long long smlen = 0;
    crypto_sign(sm.data(), &smlen, msg, len, sk);
    return base64_encode(sm.data(), 64);
}

inline void sign_transaction(Transaction& tx, const uint8_t sk[64]) {
    std::string msg = signing_json(tx);
    tx.signature = ed25519_sign_detached(
        reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), sk);
}

inline std::string hash_json(const Transaction& tx) {
    const auto optional = [](const std::string& value) {
        return value.empty() ? std::string("null") : "\"" + json_escape(value) + "\"";
    };
    return "{\"from\":\"" + json_escape(tx.from) + "\""
        ",\"to_\":\"" + json_escape(tx.to_) + "\""
        ",\"amount\":\"" + decimal_text(tx.amount) + "\""
        ",\"nonce\":" + std::to_string(tx.nonce) +
        ",\"ou\":\"" + decimal_text(tx.ou) + "\""
        ",\"timestamp\":" + format_timestamp(tx.timestamp) +
        ",\"signature\":\"" + json_escape(tx.signature) + "\""
        ",\"op_type\":\"" + json_escape(tx.op_type.empty() ? "standard" : tx.op_type) + "\""
        ",\"public_key\":" + optional(tx.public_key) +
        ",\"message\":" + optional(tx.message) +
        ",\"encrypted_data\":" + optional(tx.encrypted_data) + "}";
}

inline std::string tx_hash(const Transaction& tx) {
    const std::string msg = hash_json(tx);
    auto h = sha256(reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
    return hex_encode(h.data(), 32);
}

inline nlohmann::json build_tx_json(const Transaction& tx) {
    nlohmann::json j;
    j["from"] = tx.from;
    j["to_"] = tx.to_;
    j["amount"] = decimal_text(tx.amount);
    j["nonce"] = tx.nonce;
    j["ou"] = decimal_text(tx.ou);
    j["timestamp"] = tx.timestamp;
    j["signature"] = tx.signature;
    if (!tx.public_key.empty()) j["public_key"] = tx.public_key;
    if (!tx.op_type.empty()) j["op_type"] = tx.op_type;
    if (!tx.encrypted_data.empty()) j["encrypted_data"] = tx.encrypted_data;
    if (!tx.message.empty()) j["message"] = tx.message;
    return j;
}

inline std::string sign_balance_request(const std::string& addr,
                                        const uint8_t sk[64]) {
    std::string msg = "octra_encryptedBalance|" + addr;
    return ed25519_sign_detached(
        reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), sk);
}

inline std::string sha256_hex(const std::string& data) {
    unsigned char hash[32];
    unsigned int len = 0;
    EVP_Digest(data.data(), data.size(), hash, &len, EVP_sha256(), nullptr);
    std::string hex;
    hex.reserve(64);
    for (unsigned i = 0; i < 32; i++) {
        char buf[3];
        std::snprintf(buf, sizeof(buf), "%02x", hash[i]);
        hex += buf;
    }
    return hex;
}

inline std::string frame_v2(const std::string& domain,
                            const std::vector<std::string>& fields) {
    std::string out = domain;
    for (const auto& field : fields) {
        out += "|" + std::to_string(field.size()) + ":" + field;
    }
    return out;
}

inline std::string sign_circle_read_request(const std::string& op,
                                            const std::string& circle_id,
                                            const std::string& addr,
                                            const std::string& subject,
                                            const uint8_t sk[64]) {
    const std::string msg = frame_v2(
        "octra_circle_auth_v2",
        {op, circle_id, addr, subject});
    return ed25519_sign_detached(
        reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), sk);
}

inline std::string sign_register_request(const std::string& addr,
                                         const std::string& pk_blob,
                                         const uint8_t sk[64]) {
    std::string pk_hash = sha256_hex(pk_blob);
    std::string msg = "register_pvac|" + addr + "|" + pk_hash;
    return ed25519_sign_detached(
        reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), sk);
}

}