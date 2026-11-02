// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once

#include "json.hpp"
#include <algorithm>
#include <stdexcept>
#include <string>

namespace octra {

inline bool token_units(const std::string& text) {
    return !text.empty() && text.size() <= 512 && text.front() >= '1' && text.front() <= '9'
        && std::all_of(text.begin(), text.end(), [](char ch) { return ch >= '0' && ch <= '9'; });
}

inline std::string token_params(const std::string& recipient, const std::string& units) {
    if (!token_units(units)) throw std::invalid_argument("invalid token units");
    return "[" + nlohmann::json(recipient).dump() + "," + units + "]";
}

}