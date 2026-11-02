// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once

#include "json.hpp"
#include <string>

namespace octra {

inline std::string pvac_submit_state(bool ok, bool replied, int code,
    const nlohmann::json& reply, const std::string& hash, int http_status = 0) {
    if (ok && reply.is_object() && reply.contains("tx_hash") && reply["tx_hash"] == hash)
        return "pending";
    if (!ok && http_status == 413) return "unaccepted";
    if (!ok && replied) {
        for (const auto refusal : {100, 101, 102, 103, 104, 105, 108, 109, 111, 113, 114,
            115, 116, 118, -32600, -32602}) if (code == refusal) return "rejected";
        for (const auto retry : {107, 110, 117, -32005}) if (code == retry) return "unaccepted";
    }
    return "unknown";
}

inline std::string pvac_tx_terminal(const nlohmann::json& reply, const std::string& hash) {
    if (hash.empty() || !reply.is_object()
        || (!reply.contains("hash") && !reply.contains("tx_hash"))) return {};
    for (const auto* field : {"hash", "tx_hash"})
        if (reply.contains(field) && reply[field] != hash) return {};
    if (!reply.contains("status") || !reply["status"].is_string()) return {};
    const auto status = reply["status"].get<std::string>();
    return status == "confirmed" || status == "rejected" ? status : "";
}

inline bool pvac_nonce_used(int confirmed, int nonce, bool ok, bool replied, int code,
    const nlohmann::json& reply, const std::string& hash) {
    if (nonce <= 0 || confirmed < nonce) return false;
    if (!ok) return replied && code == 112;
    if (!reply.is_object() || (!reply.contains("hash") && !reply.contains("tx_hash"))) return false;
    for (const auto* field : {"hash", "tx_hash"})
        if (reply.contains(field) && reply[field] != hash) return false;
    return reply.contains("status") && reply["status"].is_string()
        && (reply["status"] == "dropped" || reply["status"] == "pending");
}

inline bool pvac_retry_lookup(bool ok, bool replied, int code,
    const nlohmann::json& reply, const std::string& hash) {
    if (hash.empty()) return false;
    if (!ok) return replied && code == 112;
    if (!reply.is_object() || (!reply.contains("hash") && !reply.contains("tx_hash"))) return false;
    for (const auto* field : {"hash", "tx_hash"})
        if (reply.contains(field) && reply[field] != hash) return false;
    return reply.contains("status") && reply["status"] == "dropped";
}

}