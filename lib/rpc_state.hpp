// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once

#include <limits>
#include <algorithm>
#include <iterator>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include "json.hpp"

namespace octra {

struct RpcStateError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

struct WalletSessionError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

inline int rpc_nonce(const nlohmann::json& value) {
    if (!value.is_number_integer() ||
        (!value.is_number_unsigned() && value.get<int64_t>() < 0) ||
        value.get<uint64_t>() >= static_cast<uint64_t>(std::numeric_limits<int>::max()))
        throw RpcStateError("invalid or exhausted account nonce");
    return value.get<int>();
}

}