#pragma once

#include <cstdint>
#include <string>

#include "../rpc_client.hpp"

namespace octra {

struct StealthScanResult {
    bool ok = false;
    nlohmann::json outputs = nlohmann::json::array();
    std::string error;
    std::size_t pages = 0;
};

inline bool stealth_cursor(const nlohmann::json& value, int64_t& cursor) {
    try {
        if (value.is_number_integer()) {
            cursor = value.get<int64_t>();
            return cursor >= 0;
        }
        if (value.is_string()) {
            const std::string raw = value.get<std::string>();
            std::size_t used = 0;
            const long long parsed = std::stoll(raw, &used, 10);
            if (used != raw.size() || parsed < 0) return false;
            cursor = static_cast<int64_t>(parsed);
            return true;
        }
    } catch (...) {
        return false;
    }
    return false;
}

template <typename Client>
inline StealthScanResult fetch_stealth_outputs(Client& rpc,
                                               int from_epoch,
                                               int timeout_sec = 10) {
    constexpr int page_limit = 256;
    constexpr std::size_t output_limit = 65536;
    constexpr std::size_t page_count_limit = 1024;
    StealthScanResult scan;
    int64_t before_id = -1;

    for (std::size_t page_index = 0; page_index < page_count_limit; page_index++) {
        RpcResult page = rpc.get_stealth_outputs_page(
            from_epoch,
            before_id,
            page_limit,
            timeout_sec);
        if (!page.ok) {
            scan.error = page.error.empty() ? "stealth page request failed" : page.error;
            return scan;
        }
        if (!page.result.is_object()
            || !page.result.contains("outputs")
            || !page.result["outputs"].is_array()
            || !page.result.contains("has_more")
            || !page.result["has_more"].is_boolean()) {
            scan.error = "invalid stealth page response";
            return scan;
        }

        const nlohmann::json& outputs = page.result["outputs"];
        if (outputs.size() > page_limit
            || scan.outputs.size() > output_limit - outputs.size()) {
            scan.error = "stealth scan output limit exceeded";
            return scan;
        }
        for (const auto& output : outputs) scan.outputs.push_back(output);
        scan.pages = page_index + 1;

        if (!page.result["has_more"].get<bool>()) {
            scan.ok = true;
            return scan;
        }
        if (!page.result.contains("next_before_id")) {
            scan.error = "stealth page cursor missing";
            return scan;
        }

        int64_t next = -1;
        if (!stealth_cursor(page.result["next_before_id"], next)
            || (before_id >= 0 && next >= before_id)) {
            scan.error = "stealth page cursor invalid";
            return scan;
        }
        before_id = next;
    }

    scan.error = "stealth scan page limit exceeded";
    return scan;
}

}