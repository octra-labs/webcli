// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <cstdint>

namespace octra {

inline bool pvac_key_revision(uint64_t read, uint64_t current, uint64_t change, bool same) {
    return read == current || (read < current && current - read == 1 && current == change && same);
}

struct PvacKeyRead {
    std::string key;
    bool compatible = false;
    bool current = false;
    uint64_t revision = 0;
    std::chrono::steady_clock::time_point expires{};
};

class PvacKeyCache {
    using Clock = std::chrono::steady_clock;
    uint64_t generation_ = 0;
    std::string address_;
    std::string url_;
    std::shared_ptr<const PvacKeyRead> value_;

public:
    void clear() { value_.reset(); }

    std::shared_ptr<const PvacKeyRead> get(uint64_t generation, const std::string& address,
        const std::string& url, std::optional<bool> present = {}, Clock::time_point now = Clock::now()) const {
        if (!value_ || generation_ != generation || address_ != address || url_ != url
            || now >= value_->expires || (present && *present != !value_->key.empty())) return {};
        return value_;
    }

    void put(uint64_t generation, const std::string& address, const std::string& url,
        std::shared_ptr<PvacKeyRead> value, Clock::time_point now = Clock::now()) {
        generation_ = generation;
        address_ = address;
        url_ = url;
        value->expires = now + std::chrono::seconds(value->key.empty() ? 15 : 300);
        value_ = std::move(value);
    }
};

}