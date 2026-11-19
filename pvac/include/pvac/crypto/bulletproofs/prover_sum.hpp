// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once

#include <array>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>
#include "../../core/lanes.hpp"
#include "prover_msm.hpp"

namespace pvac {
namespace bp {

struct SumPart {
    const ProverPoint* points;
    const Scalar* scalars;
    size_t count;
};

using SumParts = std::vector<SumPart>;

inline constexpr size_t sum_lane_floor = 2048;
inline constexpr size_t public_cap = 8;

inline size_t sum_count(const SumParts& parts) {
    size_t count = 0;
    for (const auto& part : parts) {
        if (part.count != 0 && (!part.points || !part.scalars))
            throw std::invalid_argument("pvac: sum part is missing");
        if (part.count > std::numeric_limits<size_t>::max() - count)
            throw std::invalid_argument("pvac: sum count overflow");
        count += part.count;
    }
    return count;
}

inline size_t scalar_window(const Scalar& scalar, size_t bit, size_t width) {
    const size_t word = bit / 64;
    const size_t shift = bit % 64;
    const uint64_t low = scalar.v[word] >> shift;
    const uint64_t high = shift + width > 64 && word + 1 < 4 ? scalar.v[word + 1] << (64 - shift) : 0;
    return static_cast<size_t>((low | high) & ((uint64_t{1} << width) - 1));
}

inline ExtPoint window_total(const SumParts& parts, size_t bit, size_t width) {
    std::vector<ExtPoint> buckets((size_t{1} << width) - 1, ext_identity());
    for (const auto& part : parts) {
        for (size_t i = 0; i < part.count; ++i) {
            const size_t digit = scalar_window(part.scalars[i], bit, width);
            if (digit != 0) buckets[digit - 1] = prover_add(buckets[digit - 1], part.points[i]);
        }
    }
    auto running = ext_identity();
    auto total = ext_identity();
    for (size_t i = buckets.size(); i > 0; --i) {
        running = ext_add(running, buckets[i - 1]);
        total = ext_add(total, running);
    }
    return total;
}

inline ExtPoint window_join(const ExtPoint* totals, size_t windows, size_t width) {
    auto result = ext_identity();
    for (size_t window = windows; window > 0; --window) {
        for (size_t i = 0; i < width; ++i) result = ext_double(result);
        result = ext_add(result, totals[window - 1]);
    }
    return result;
}

inline std::vector<RistrettoPoint> prover_sums(const std::vector<SumParts>& sums) {
    struct Plan { size_t width, windows, first; };
    std::vector<Plan> plans;
    std::vector<size_t> owners;
    size_t points = 0;
    for (size_t sum = 0; sum < sums.size(); ++sum) {
        const size_t count = sum_count(sums[sum]);
        const size_t width = prover_window(count);
        const size_t windows = (256 + width - 1) / width;
        plans.push_back({width, windows, owners.size()});
        owners.insert(owners.end(), windows, sum);
        points += count;
    }
    std::vector<ExtPoint> totals(owners.size());
    const size_t wanted = points >= sum_lane_floor ? owners.size() : 0;
    lane_run(owners.size(), wanted, [&](size_t task) {
        const auto& plan = plans[owners[task]];
        totals[task] = window_total(sums[owners[task]], (task - plan.first) * plan.width, plan.width);
    });
    std::vector<RistrettoPoint> out;
    out.reserve(plans.size());
    for (const auto& plan : plans)
        out.push_back(rist_encode(window_join(totals.data() + plan.first, plan.windows, plan.width)));
    return out;
}

inline ExtPoint public_sum(const ProverPoint* points, const Scalar* scalars, size_t count, size_t stride) {
    if (count > public_cap)
        throw std::invalid_argument("pvac: public sum count rejected");
    std::array<std::array<ProverTerm, 8>, public_cap> tables;
    std::array<std::array<int8_t, 257>, public_cap> digits;
    for (size_t term = 0; term < count; ++term) {
        tables[term] = prover_terms(prover_add(ext_identity(), points[term * stride]));
        digits[term] = prover_digits(scalars[term * stride]);
    }
    auto result = ext_identity();
    for (size_t bit = 257; bit > 0; --bit) {
        result = ext_double(result);
        for (size_t term = 0; term < count; ++term) {
            const int digit = digits[term][bit - 1];
            if (digit != 0)
                result = prover_term_add(result, tables[term][(digit < 0 ? -digit : digit) / 2], digit < 0);
        }
    }
    return result;
}

inline void prover_affine(const ExtPoint* points, size_t count, ProverPoint* out) {
    if (count == 0) return;
    std::vector<Fe25519> prefix(count);
    auto product = fe_one();
    for (size_t i = 0; i < count; ++i) {
        prefix[i] = product;
        product = fe_mul(product, points[i].Z);
    }
    if (fe_is_zero(product))
        throw std::runtime_error("pvac: point z product is zero");
    auto inverse = fe_inv(product);
    const auto twice_d = ed_2d();
    for (size_t i = count; i > 0; --i) {
        const auto& point = points[i - 1];
        const auto scale = fe_mul(inverse, prefix[i - 1]);
        inverse = fe_mul(inverse, point.Z);
        const auto x = fe_mul(point.X, scale);
        const auto y = fe_mul(point.Y, scale);
        out[i - 1] = {fe_sub(y, x), fe_add(y, x), fe_mul(fe_mul(x, y), twice_d)};
    }
}

}
}