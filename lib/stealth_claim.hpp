// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once

#include <charconv>
#include <limits>
#include <map>
#include <set>
#include <vector>
#include "rpc_state.hpp"

namespace octra {

inline uint64_t claim_id(const nlohmann::json& value) {
    uint64_t id = 0;
    bool valid = false;
    if (value.is_number_integer()) {
        valid = value.is_number_unsigned() || value.get<int64_t>() >= 0;
        if (valid) id = value.get<uint64_t>();
    } else if (value.is_string()) {
        const auto& raw = value.get_ref<const std::string&>();
        const auto parsed = std::from_chars(raw.data(), raw.data() + raw.size(), id);
        valid = parsed.ec == std::errc{} && parsed.ptr == raw.data() + raw.size();
    }
    if (!valid || id > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
        throw std::invalid_argument("output id must be a nonnegative integer");
    return id;
}

inline std::vector<uint64_t> claim_ids(const nlohmann::json& values) {
    if (!values.is_array() || values.empty() || values.size() > 64)
        throw std::invalid_argument("select between 1 and 64 output ids");
    std::set<uint64_t> seen;
    std::vector<uint64_t> ids;
    for (const auto& value : values) {
        const auto id = claim_id(value);
        if (!seen.insert(id).second) throw std::invalid_argument("duplicate output id");
        ids.push_back(id);
    }
    return ids;
}

inline nlohmann::json claim_outputs(const std::vector<uint64_t>& ids,
    const nlohmann::json& result) {
    if (!result.is_object() || !result.contains("complete") || result["complete"] != true ||
        !result.contains("outputs") || !result["outputs"].is_array() ||
        result["outputs"].size() != ids.size())
        throw RpcStateError("requested output set is incomplete");
    std::map<uint64_t, nlohmann::json> rows;
    for (const auto& row : result["outputs"]) {
        if (!row.is_object() || !row.contains("id"))
            throw RpcStateError("output id missing from RPC response");
        uint64_t id = 0;
        try { id = claim_id(row["id"]); }
        catch (const std::invalid_argument&) { throw RpcStateError("invalid output id from RPC"); }
        if (!rows.emplace(id, row).second) throw RpcStateError("duplicate output id from RPC");
    }
    auto outputs = nlohmann::json::array();
    for (const auto id : ids) {
        const auto row = rows.find(id);
        if (row == rows.end()) throw RpcStateError("RPC output ids do not match selection");
        outputs.push_back(row->second);
    }
    return outputs;
}

}