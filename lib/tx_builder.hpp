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
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <openssl/evp.h>
#include "json.hpp"

extern "C" {
#include "tweetnacl.h"
}

#include "../crypto_utils.hpp"

namespace octra {

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
    nlohmann::json j = ts;
    return j.dump();
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
            default: r += c;
        }
    }
    return r;
}

inline std::string canonical_json(const Transaction& tx) {
    std::string s = "{\"from\":\"" + json_escape(tx.from) + "\""
        ",\"to_\":\"" + json_escape(tx.to_) + "\""
        ",\"amount\":\"" + json_escape(tx.amount) + "\""
        ",\"nonce\":" + std::to_string(tx.nonce) +
        ",\"ou\":\"" + json_escape(tx.ou) + "\""
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
    std::string msg = canonical_json(tx);
    tx.signature = ed25519_sign_detached(
        reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), sk);
}

inline std::string tx_hash(const Transaction& tx) {
    std::string msg = canonical_json(tx);
    auto h = sha256(reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
    return hex_encode(h.data(), 32);
}

inline nlohmann::json build_tx_json(const Transaction& tx) {
    nlohmann::json j;
    j["from"] = tx.from;
    j["to_"] = tx.to_;
    j["amount"] = tx.amount;
    j["nonce"] = tx.nonce;
    j["ou"] = tx.ou;
    j["timestamp"] = tx.timestamp;
    j["signature"] = tx.signature;
    j["public_key"] = tx.public_key;
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

inline std::string sign_register_request(const std::string& addr,
                                         const std::string& pk_blob,
                                         const uint8_t sk[64]) {
    std::string pk_hash = sha256_hex(pk_blob);
    std::string msg = "register_pvac|" + addr + "|" + pk_hash;
    return ed25519_sign_detached(
        reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), sk);
}

} // namespace octra
