// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <mutex>

namespace octra {

enum class RpcLane { user, poll };

inline constexpr std::size_t rpc_slots = 4;
inline constexpr std::size_t rpc_poll_slots = 2;
inline constexpr int rpc_gate_seconds = 60;

inline bool rpc_room(std::size_t busy, std::size_t polls, std::size_t users, RpcLane lane) {
    return busy < rpc_slots && (lane == RpcLane::user || (polls < rpc_poll_slots && users == 0));
}

inline RpcLane& rpc_lane() {
    thread_local RpcLane lane = RpcLane::poll;
    return lane;
}

class RpcGate {
    std::mutex mutex_;
    std::condition_variable changed_;
    std::size_t busy_ = 0;
    std::size_t polls_ = 0;
    std::size_t users_ = 0;

public:
    bool enter(RpcLane lane, std::chrono::steady_clock::time_point deadline) {
        const bool user = lane == RpcLane::user;
        std::unique_lock<std::mutex> lock(mutex_);
        users_ += user;
        const bool held = changed_.wait_until(lock, deadline,
            [&] { return rpc_room(busy_, polls_, users_, lane); });
        users_ -= user;
        busy_ += held;
        polls_ += held && !user;
        lock.unlock();
        changed_.notify_all();
        return held;
    }

    void leave(RpcLane lane) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            busy_ -= 1;
            polls_ -= lane == RpcLane::poll;
        }
        changed_.notify_all();
    }
};

inline RpcGate& rpc_gate() {
    static RpcGate gate;
    return gate;
}

class RpcSlot {
    RpcLane lane_;
    bool gated_;
    bool held_;

public:
    RpcSlot(RpcLane lane, bool gated, std::chrono::steady_clock::time_point deadline)
        : lane_(lane), gated_(gated), held_(!gated || rpc_gate().enter(lane, deadline)) {}
    RpcSlot(const RpcSlot&) = delete;
    RpcSlot& operator=(const RpcSlot&) = delete;
    ~RpcSlot() {
        if (gated_ && held_) rpc_gate().leave(lane_);
    }
    explicit operator bool() const { return held_; }
};

}