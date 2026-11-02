// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once

#include "json.hpp"
#include "../sanitize.hpp"
#include "program_cli_plan.hpp"

namespace octra {

inline std::string compiler_version(const nlohmann::json& value) {
    if (!value.is_string()) return "";
    const auto& text = value.get_ref<const std::string&>();
    if (text.empty() || text.size() > 32 || text.find_first_not_of(' ') == std::string::npos) return "";
    for (const unsigned char ch : text) {
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
            || ch == '.' || ch == '+' || ch == '-' || ch == ' ')) return "";
    }
    return text;
}

inline std::string token_symbol(const std::string& text) {
    if (text.empty() || text.size() > 12) return "";
    std::string upper;
    for (const unsigned char ch : text) {
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9'))) return "";
        upper += ch >= 'a' && ch <= 'z' ? ch - 'a' + 'A' : ch;
    }
    return upper == "OCT" || upper == "0CT" ? "" : text;
}

inline std::string token_name(const std::string& text) {
    const auto name = sanitize_display(text, 32);
    std::string letters;
    for (const char ch : name) {
        if (ch >= 'a' && ch <= 'z') letters += ch - ('a' - 'A');
        else if ((ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')) letters += ch;
    }
    return letters == "OCT" || letters == "0CT" ? "" : name;
}

inline std::string decimal_text(const nlohmann::json& value, size_t digits) {
    const auto text = value.is_string() ? value.get<std::string>()
        : value.is_number_unsigned() || value.is_number_integer() ? value.dump() : "";
    if (text.empty() || text.size() > digits || (text.size() > 1 && text[0] == '0')) return "";
    for (const char ch : text) if (ch < '0' || ch > '9') return "";
    return text;
}

inline nlohmann::json token_rows(const nlohmann::json& rows) {
    auto result = nlohmann::json::array();
    if (!rows.is_array()) return result;
    for (const auto& row : rows) {
        if (!row.is_object() || !row.contains("address") || !row["address"].is_string()
            || !program_cli::valid_address(row["address"].get<std::string>())) continue;
        const auto decimals = decimal_text(row.value("decimals", nlohmann::json()), 3);
        const bool encrypted = row.value("balance_kind", nlohmann::json()) == "encrypted"
            && row.value("balance_is_encrypted", nlohmann::json()) == true;
        const auto balance = encrypted && row.contains("balance") && row["balance"].is_string()
            ? row["balance"].get<std::string>() : decimal_text(row.value("balance", nlohmann::json()), 512);
        if (decimals.empty() || std::stoul(decimals) > 255 || balance.empty()) continue;
        if (encrypted) {
            if (balance.size() > 96 * 1024 || balance.size() % 4 != 0) continue;
            const auto padding = balance.find('=');
            const auto payload = padding == std::string::npos ? balance.size() : padding;
            if (payload == 0 || balance.size() - payload > 2) continue;
            if (balance.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 0) < payload) continue;
            if (padding != std::string::npos && balance.find_first_not_of('=', padding) != std::string::npos) continue;
        }
        auto entry = row;
        entry["decimals"] = decimals;
        entry["balance"] = balance;
        entry["balance_kind"] = encrypted ? "encrypted" : "plain";
        entry["balance_is_encrypted"] = encrypted;
        entry["symbol"] = row.contains("symbol") && row["symbol"].is_string()
            ? token_symbol(row["symbol"]) : "";
        entry["name"] = row.contains("name") && row["name"].is_string()
            ? token_name(row["name"].get_ref<const std::string&>()) : "";
        result.push_back(std::move(entry));
    }
    return result;
}

inline nlohmann::json fee_quote(const nlohmann::json& source) {
    if (!source.is_object()) return nullptr;
    auto result = nlohmann::json::object();
    for (const auto* key : {"minimum", "recommended", "fast"}) {
        const auto text = decimal_text(source.value(key, nlohmann::json()), 8);
        if (text.empty() || text == "0" || std::stoull(text) > 10000000) return nullptr;
        result[key] = text;
    }
    if (std::stoull(result["recommended"].get<std::string>()) < std::stoull(result["minimum"].get<std::string>())
        || std::stoull(result["fast"].get<std::string>()) < std::stoull(result["recommended"].get<std::string>())) return nullptr;
    const auto base = decimal_text(source.value("base_fee", source["minimum"]), 8);
    if (base.empty() || base == "0" || std::stoull(base) > 10000000) return nullptr;
    result["base_fee"] = base;
    return result;
}

}