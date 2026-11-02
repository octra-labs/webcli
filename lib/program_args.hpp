// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once

#include "json_shape.hpp"
#include <string>

namespace octra {

inline bool program_args(const std::string& text) {
    if (text.size() > 1048576 || text.find('\0') != std::string::npos) return false;
    std::string shape;
    shape.reserve(text.size());
    bool quoted = false;
    bool escaped = false;
    for (size_t at = 0; at < text.size(); ++at) {
        const char ch = text[at];
        if (quoted) {
            shape += ch;
            if (escaped) escaped = false;
            else if (ch == '\\') escaped = true;
            else if (ch == '"') quoted = false;
        } else if (ch == '"') {
            quoted = true;
            shape += ch;
        } else if (ch == '-' || (ch >= '0' && ch <= '9')) {
            const size_t start = at;
            if (ch == '-') ++at;
            const size_t digits = at;
            while (at < text.size() && text[at] >= '0' && text[at] <= '9') ++at;
            if (at == digits || at - digits > 4096
                || (at - digits > 1 && text[digits] == '0')) return false;
            if (at < text.size() && (text[at] == '.' || text[at] == 'e' || text[at] == 'E')) return false;
            if (at == start) return false;
            shape += '0';
            --at;
        } else shape += ch;
    }
    const auto first = shape.find_first_not_of(" \t\r\n");
    JsonShape check;
    return first != std::string::npos && shape[first] == '['
        && nlohmann::json::sax_parse(shape, &check);
}

inline std::string program_params(const nlohmann::json& body) {
    std::string text = "[]";
    if (body.contains("params_raw")) {
        if (!body["params_raw"].is_string() || body.contains("params"))
            throw std::invalid_argument("params_raw must be a string without params");
        text = body["params_raw"].get<std::string>();
    } else if (body.contains("params")) text = body["params"].dump();
    if (!program_args(text))
        throw std::invalid_argument("invalid program parameters; use params_raw for large integers");
    return text;
}

inline std::string program_compact(const std::string& text) {
    if (!program_args(text)) throw std::invalid_argument("invalid program parameters");
    std::string output;
    output.reserve(text.size());
    for (size_t at = 0; at < text.size(); ++at) {
        const char ch = text[at];
        if (ch == '"') {
            const size_t start = at++;
            bool escaped = false;
            while (at < text.size()) {
                if (escaped) escaped = false;
                else if (text[at] == '\\') escaped = true;
                else if (text[at] == '"') break;
                ++at;
            }
            const auto quoted = nlohmann::json::parse(text.substr(start, at - start + 1)).dump();
            for (const char byte : quoted) {
                if (byte == '\x7f') output += "\\u007f";
                else output += byte;
            }
        } else if (ch == '-' || (ch >= '0' && ch <= '9')) {
            const size_t start = at;
            if (ch == '-') ++at;
            while (at < text.size() && text[at] >= '0' && text[at] <= '9') ++at;
            const auto integer = text.substr(start, at - start);
            output += integer == "-0" ? "0" : integer;
            --at;
        } else if (ch != ' ' && ch != '\t' && ch != '\n' && ch != '\r') output += ch;
    }
    return output;
}

}