// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
// lambda0xE
// Arthur Edelstein
// Denis CMIX

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "endpoint_policy.hpp"
#include "json.hpp"

namespace octra::program_rpc {

inline constexpr size_t max_response_bytes = 8U * 1024U * 1024U;
inline constexpr size_t max_request_bytes = 5'065'536;
inline constexpr size_t max_json_items = 262'144;

struct Settings {
    size_t response_bytes = 64U * 1024U;
    int connect_seconds = 5;
    int read_seconds = 30;
};

struct Result {
    bool ok = false;
    bool remote_error = false;
    nlohmann::json value;
    int code = 0;
    std::string error;
    bool timed_out = false;
};

class Client {
    endpoint_policy::Parsed endpoint_;
    Settings settings_;
    bool ready_ = false;
    std::string error_;
    uint32_t next_id_ = 0;

public:
    Client(const std::string& url, Settings settings);

    bool ready() const;
    const std::string& error() const;
    const endpoint_policy::Parsed& endpoint() const;
    Result call(
        const std::string& method,
        const nlohmann::json& params = nlohmann::json::array());
};

bool same_origin(const Client& first, const Client& second);

}