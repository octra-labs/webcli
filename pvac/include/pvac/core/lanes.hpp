// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <exception>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

namespace pvac {

inline constexpr size_t lane_cap = 256;

struct LaneBudget {
    std::atomic<size_t> limit;
    std::atomic<size_t> busy;
};

inline size_t lane_default() {
    const size_t cores = std::max<size_t>(1, std::thread::hardware_concurrency());
    return std::min<size_t>(4, cores);
}

inline LaneBudget& lane_budget() {
    static LaneBudget budget{{lane_default()}, {0}};
    return budget;
}

inline void set_lanes(size_t total) {
    if (total == 0 || total > lane_cap)
        throw std::invalid_argument("pvac: lane limit rejected");
    lane_budget().limit.store(total, std::memory_order_relaxed);
}

inline size_t lane_limit() {
    return lane_budget().limit.load(std::memory_order_relaxed);
}

class LaneClaim {
    std::atomic<size_t> held_{0};

public:
    explicit LaneClaim(size_t wanted) {
        auto& budget = lane_budget();
        size_t busy = budget.busy.fetch_add(1, std::memory_order_acq_rel) + 1;
        for (;;) {
            const size_t limit = budget.limit.load(std::memory_order_relaxed);
            const size_t take = std::min(wanted, limit > busy ? limit - busy : size_t{0});
            if (take == 0) return;
            if (budget.busy.compare_exchange_weak(busy, busy + take, std::memory_order_acq_rel)) {
                held_.store(take, std::memory_order_relaxed);
                return;
            }
        }
    }

    LaneClaim(const LaneClaim&) = delete;
    LaneClaim& operator=(const LaneClaim&) = delete;

    ~LaneClaim() {
        lane_budget().busy.fetch_sub(1 + held_.load(std::memory_order_acquire), std::memory_order_acq_rel);
    }

    size_t held() const { return held_.load(std::memory_order_acquire); }

    void drop(size_t count) {
        if (count == 0) return;
        held_.fetch_sub(count, std::memory_order_acq_rel);
        lane_budget().busy.fetch_sub(count, std::memory_order_acq_rel);
    }

    bool retire() {
        auto& budget = lane_budget();
        size_t busy = budget.busy.load(std::memory_order_acquire);
        while (busy > budget.limit.load(std::memory_order_relaxed)) {
            if (budget.busy.compare_exchange_weak(busy, busy - 1, std::memory_order_acq_rel)) {
                held_.fetch_sub(1, std::memory_order_acq_rel);
                return true;
            }
        }
        return false;
    }
};

template<class Task, class Launch>
inline std::vector<std::thread> lane_start(size_t wanted, const Task& task, Launch& launch) noexcept {
    std::vector<std::thread> started;
    try {
        started.reserve(wanted);
        while (started.size() < wanted) started.push_back(launch(task));
    } catch (...) {
        return started;
    }
    return started;
}

template<class Work, class Launch>
inline void lane_run(size_t count, size_t wanted, Work work, Launch launch) {
    if (count == 0) return;
    LaneClaim claim(std::min(wanted, count - 1));
    std::atomic<size_t> next{0};
    std::vector<std::exception_ptr> errors(count);
    const auto run = [&](size_t index) {
        try { work(index); }
        catch (...) { errors[index] = std::current_exception(); }
    };
    const auto helper = [&] {
        while (!claim.retire()) {
            const size_t index = next.fetch_add(1);
            if (index >= count) return;
            run(index);
        }
    };
    const size_t reserved = claim.held();
    auto helpers = lane_start(reserved, helper, launch);
    claim.drop(reserved - helpers.size());
    for (size_t index = next.fetch_add(1); index < count; index = next.fetch_add(1)) run(index);
    for (auto& thread : helpers) thread.join();
    for (const auto& error : errors)
        if (error) std::rethrow_exception(error);
}

template<class Work>
inline void lane_run(size_t count, size_t wanted, Work work) {
    lane_run(count, wanted, std::move(work), [](const auto& task) { return std::thread(task); });
}

template<class Work>
inline void lane_chunks(size_t count, size_t chunk, Work work) {
    if (chunk == 0) throw std::invalid_argument("pvac: lane chunk rejected");
    const size_t parts = count / chunk + (count % chunk != 0);
    lane_run(parts, parts > 1 ? parts - 1 : 0, [&](size_t part) {
        work(part * chunk, std::min(count, (part + 1) * chunk));
    });
}

}