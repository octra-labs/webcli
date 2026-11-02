// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once

#include <string>
#include <regex>

namespace octra {

inline bool asset_mime_valid(const std::string& text) {
    if (text.empty() || text.size() > 256) return false;
    static const std::regex syntax(
        "^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+(;[ ]*[A-Za-z0-9_-]+=([A-Za-z0-9_.+-]+|\"[A-Za-z0-9_. +-]+\"))*$");
    return std::regex_match(text, syntax);
}

}