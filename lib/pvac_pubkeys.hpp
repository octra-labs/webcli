// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <utility>

namespace octra {

class PvacPubkeyCache {
    mutable std::mutex mutex_;
    uint64_t generation_ = 0;
    std::string address_;
    std::string digest_;
    std::shared_ptr<void> key_;

public:
    void clear() {
        const std::lock_guard<std::mutex> lock(mutex_);
        key_.reset();
        digest_.clear();
        address_.clear();
        generation_ = 0;
    }

    bool held() const {
        const std::lock_guard<std::mutex> lock(mutex_);
        return key_ != nullptr;
    }

    std::shared_ptr<void> get(uint64_t generation, const std::string& address, const std::string& digest) const {
        const std::lock_guard<std::mutex> lock(mutex_);
        if (!key_ || generation_ != generation || address_ != address || digest_ != digest) return {};
        return key_;
    }

    void put(uint64_t generation, const std::string& address, const std::string& digest, std::shared_ptr<void> key) {
        const std::lock_guard<std::mutex> lock(mutex_);
        generation_ = generation;
        address_ = address;
        digest_ = digest;
        key_ = std::move(key);
    }
};

}