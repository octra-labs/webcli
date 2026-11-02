// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once

#include <set>
#include <string>
#include "json.hpp"

namespace octra {

inline nlohmann::json staging_status(const nlohmann::json& value,
    const std::string& address, const std::set<std::string>& own = {}) {
    using Json = nlohmann::json;
    const auto count = [](const Json& n) {
        return n.is_number_integer()
            && (n.is_number_unsigned() || n.get<int64_t>() >= 0)
            && n.get<uint64_t>() <= 9007199254740991ULL;
    };
    const Json unknown = {{"staging", nullptr}, {"staging_known", false}, {"staging_partial", false}};
    if (address.empty() || !value.is_object() || !value.contains("transactions")
        || !value["transactions"].is_array()) return unknown;
    const auto size = value["transactions"].size();
    if (value.contains("count")
        && (!count(value["count"]) || value["count"] != size)) return unknown;
    if (value.contains("truncated") && !value["truncated"].is_boolean()) return unknown;
    bool partial = false;
    if (!value.contains("total")) {
        if (!value.contains("truncated") || value["truncated"] != false) return unknown;
    } else {
        if (!count(value["total"]) || value["total"].get<uint64_t>() < size) return unknown;
        partial = value["total"].get<uint64_t>() > size;
        if (value.contains("truncated") && value["truncated"] != partial) return unknown;
    }
    std::set<std::string> hashes;
    for (const auto& tx : value["transactions"]) {
        if (!tx.is_object() || !tx.contains("from") || !tx["from"].is_string()
            || !tx.contains("hash") || !tx["hash"].is_string()
            || tx["hash"].get_ref<const std::string&>().empty()) return unknown;
        const auto& hash = tx["hash"].get_ref<const std::string&>();
        if (tx["from"] == address || own.count(hash)) hashes.insert(hash);
    }
    return {{"staging", partial && hashes.empty() ? Json(nullptr) : Json(hashes.size())},
        {"staging_known", !partial}, {"staging_partial", partial}};
}

}