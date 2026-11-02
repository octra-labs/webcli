// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once

#include <atomic>
#include <chrono>
#include <mutex>
#include <shared_mutex>
#include <thread>

namespace octra {

class WalletChange {
    std::atomic<unsigned>& pending_;
    std::unique_lock<std::shared_mutex> session_;
    std::unique_lock<std::shared_mutex> crypto_;
    bool waiting_ = false;
public:
    WalletChange(std::atomic<unsigned>& pending, std::shared_mutex& session,
        std::shared_mutex& crypto)
        : pending_(pending), session_(session, std::defer_lock), crypto_(crypto, std::defer_lock) {}
    ~WalletChange() { release(); }
    bool acquire() {
        if (waiting_) return session_.owns_lock() && crypto_.owns_lock();
        pending_.fetch_add(1);
        waiting_ = true;
        const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        do {
            if (session_.try_lock()) {
                if (crypto_.try_lock()) return true;
                session_.unlock();
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        } while (std::chrono::steady_clock::now() < end);
        release();
        return false;
    }
    void release() {
        if (crypto_.owns_lock()) crypto_.unlock();
        if (session_.owns_lock()) session_.unlock();
        if (waiting_) {
            waiting_ = false;
            pending_.fetch_sub(1);
        }
    }
};

}