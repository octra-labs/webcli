// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once

#include <cstddef>
#include <string>

inline std::string sanitize_display(const std::string& s, std::size_t maxlen) {
    std::string out;
    for (char c : s) {
        if (out.size() >= maxlen) break;
        unsigned char u = static_cast<unsigned char>(c);
        bool ok = (u >= 'a' && u <= 'z') || (u >= 'A' && u <= 'Z') ||
                  (u >= '0' && u <= '9') || c == '.' || c == '_' || c == '-' || c == ' ';
        if (ok) out.push_back(c);
    }
    return out;
}