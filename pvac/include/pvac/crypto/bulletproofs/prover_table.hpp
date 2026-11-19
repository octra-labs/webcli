// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once

#include <memory>
#include <mutex>
#include <stdexcept>
#include <vector>
#include "generators.hpp"
#include "prover_msm.hpp"

namespace pvac {
namespace bp {

struct ProverGenerators {
    std::vector<ProverPoint> g;
    std::vector<ProverPoint> h;
};

class ProverTable {
    std::mutex lock_;
    std::shared_ptr<const ProverGenerators> points_;

public:
    std::shared_ptr<const ProverGenerators> get(size_t n) {
        if (n == 0 || n > BP_MAX_VECTOR_SIZE)
            throw std::runtime_error("pvac: prover table size rejected");
        const std::lock_guard<std::mutex> guard(lock_);
        if (points_ && points_->g.size() >= n) return points_;
        const size_t old = points_ ? points_->g.size() : 0;
        auto next = std::make_shared<ProverGenerators>();
        next->g.reserve(n);
        next->h.reserve(n);
        if (points_) {
            next->g = points_->g;
            next->h = points_->h;
        }
        next->g.resize(n);
        next->h.resize(n);
        const auto encoded_g = generators().G_vec(n);
        const auto encoded_h = generators().H_vec(n);
        generator_run(old, n, [&](size_t first, size_t last) {
            for (size_t i = first; i < last; ++i) {
                next->g[i] = prover_point(encoded_g[i]);
                next->h[i] = prover_point(encoded_h[i]);
            }
        });
        points_ = std::move(next);
        return points_;
    }
};

inline ProverTable& prover_table() {
    static ProverTable table;
    return table;
}

inline const ProverPoint& prover_blind() {
    static const ProverPoint point = prover_point(pedersen_B_blinding());
    return point;
}

}
}