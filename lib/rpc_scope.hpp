// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once

#include "rpc_io.hpp"
#include <chrono>
#include <string>

namespace octra {

inline constexpr size_t rpc_timeout_limit_ms = 900000;
inline constexpr std::chrono::seconds rpc_reply_margin{2};

inline std::chrono::steady_clock::time_point& rpc_deadline() {
    thread_local auto deadline = std::chrono::steady_clock::time_point::max();
    return deadline;
}

inline std::chrono::steady_clock::time_point rpc_request_deadline(const std::string& timeout_ms,
    std::chrono::steady_clock::time_point now) {
    if (!rpc_length(timeout_ms, rpc_timeout_limit_ms)) return std::chrono::steady_clock::time_point::max();
    return now + std::chrono::milliseconds(std::stoi(timeout_ms)) - rpc_reply_margin;
}

inline int& rpc_once_depth() {
    thread_local int depth = 0;
    return depth;
}

class RpcOnce {
public:
    RpcOnce() { ++rpc_once_depth(); }
    RpcOnce(const RpcOnce&) = delete;
    RpcOnce& operator=(const RpcOnce&) = delete;
    ~RpcOnce() { --rpc_once_depth(); }
};

}