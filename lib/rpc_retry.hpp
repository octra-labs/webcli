// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once

#include "json.hpp"
#include "json_shape.hpp"
#include "rpc_io.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <functional>
#include <optional>
#include <string>

namespace octra {

enum class RpcFault { none, capacity, network, busy, deadline, state };

struct RpcStep {
    RpcFault fault = RpcFault::none;
    bool unsent = false;
    std::string status;
};

struct RpcSent {
    RpcBody reply;
    bool unsent = false;
    bool repeated = false;
};

struct RpcRetry {
    std::string method;
    int attempt = 0;
    std::string status;
    double wait = 0;
};

inline constexpr double rpc_retry_window = 25;
inline constexpr double rpc_retry_after_cap = 5;
inline constexpr double rpc_pause_spread = 0.2;
inline constexpr std::array<double, 5> rpc_pauses{0.25, 0.5, 1, 2, 4};
inline constexpr int rpc_state_changed_code = -32012;

inline bool rpc_write(const std::string& method) {
    static const std::array<const char*, 11> writes{"octra_submit", "octra_submitBatch", "staging_remove",
        "octra_registerPublicKey", "octra_registerPvacPubkey", "octra_privateTransfer",
        "octra_circleComputeSubmit", "contract_verify", "octra_programVerify",
        "contract_saveAbi", "octra_programSaveAbi"};
    return std::any_of(writes.begin(), writes.end(), [&](const char* name) { return method == name; });
}

inline nlohmann::json rpc_reply_error(const std::string& body) {
    JsonShape shape;
    if (body.empty() || body.size() > rpc_refusal_limit || !nlohmann::json::sax_parse(body, &shape)) return nullptr;
    const auto value = nlohmann::json::parse(body, nullptr, false);
    if (!value.is_object() || !value.contains("id")) return nullptr;
    const auto error = value.find("error");
    if (error == value.end() || !error->is_object()) return nullptr;
    return {{"id", value["id"]}, {"error", *error}};
}

inline bool rpc_state_changed(const std::string& body) {
    const auto reply = rpc_reply_error(body);
    if (reply.is_null() || reply.at("id").is_null()) return false;
    const auto& error = reply.at("error");
    const auto code = error.find("code");
    return code != error.end() && code->is_number_integer() && code->get<int64_t>() == rpc_state_changed_code;
}

inline bool rpc_capacity(const std::string& body) {
    const auto reply = rpc_reply_error(body);
    if (reply.is_null() || !reply.at("id").is_null()) return false;
    const auto& error = reply.at("error");
    const auto message = error.find("message");
    if (message == error.end() || !message->is_string()) return false;
    const auto text = message->get<std::string>();
    const std::string word = "capacity";
    return std::search(text.begin(), text.end(), word.begin(), word.end(),
        [](unsigned char left, unsigned char right) { return std::tolower(left) == right; }) != text.end();
}

inline bool rpc_gateway(int status) {
    return status == 408 || status == 425 || status == 502 || status == 504 || (status >= 520 && status <= 524);
}

inline RpcStep rpc_step(const RpcBody& reply) {
    switch (reply.link) {
    case RpcLink::local:
    case RpcLink::untrusted:
        return {RpcFault::none, true, ""};
    case RpcLink::unopened:
        return {RpcFault::network, true, "connect"};
    case RpcLink::broken:
        return {RpcFault::network, false, "reset"};
    case RpcLink::expired:
        return {RpcFault::network, false, "timeout"};
    case RpcLink::answered:
        break;
    }
    const bool capacity = rpc_capacity(reply.body);
    if (rpc_refusal(reply.status)) return {RpcFault::capacity, capacity && reply.status == 429, std::to_string(reply.status)};
    if (rpc_gateway(reply.status)) return {RpcFault::network, false, std::to_string(reply.status)};
    if (capacity) return {RpcFault::capacity, false, "capacity"};
    if (reply.status == 200 && rpc_state_changed(reply.body)) return {RpcFault::state, false, "state_changed"};
    return {};
}

inline bool rpc_repeat(const RpcStep& step, bool write) {
    return step.fault != RpcFault::none && (!write || step.unsent);
}

inline double rpc_pause(int attempt, std::optional<int> retry_after, double draw) {
    const auto step = static_cast<size_t>(std::clamp(attempt, 1, static_cast<int>(rpc_pauses.size())) - 1);
    const double base = retry_after ? std::min<double>(*retry_after, rpc_retry_after_cap) : rpc_pauses[step];
    return base * (1 + rpc_pause_spread * std::clamp(draw, 0.0, 1.0));
}

inline double rpc_window(int seconds) {
    return std::min<double>(rpc_retry_window, seconds);
}

inline std::string rpc_condition(RpcFault fault) {
    switch (fault) {
    case RpcFault::capacity:
        return "rpc capacity reached";
    case RpcFault::busy:
        return "wallet rpc slots busy";
    case RpcFault::deadline:
        return "request deadline reached";
    case RpcFault::state:
        return "committed state changed during read; retry";
    case RpcFault::network:
    case RpcFault::none:
        break;
    }
    return "network unreachable";
}

inline std::string rpc_cause(const std::string& text, const std::string& error) {
    return error.empty() ? text : text + ": " + error;
}

inline std::string rpc_retry_line(const RpcRetry& retry) {
    std::array<char, 32> wait{};
    std::snprintf(wait.data(), wait.size(), "%.2f", retry.wait);
    return "event = rpc_retry method = " + retry.method + " attempt = " + std::to_string(retry.attempt)
        + " status = " + retry.status + " wait = " + wait.data();
}

inline std::function<void(const RpcRetry&)>& rpc_retry_log() {
    static std::function<void(const RpcRetry&)> log;
    return log;
}

}