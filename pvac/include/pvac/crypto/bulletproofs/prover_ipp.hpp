// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once

#include <cstdint>
#include <stdexcept>
#include <utility>
#include <vector>
#include "transcript.hpp"
#include "generators.hpp"
#include "inner_product.hpp"
#include "prover_sum.hpp"

namespace pvac {
namespace bp {

inline constexpr size_t fold_groups = 8;
inline constexpr size_t fold_chunk = 4096;
inline constexpr size_t affine_chunk = 256;

struct FoldSide {
    const ProverPoint* points;
    std::vector<ProverPoint> owned;
    std::vector<Scalar> weights;
};

inline Scalar fold_scaled(const Scalar& value, const std::vector<Scalar>& weights, size_t index) {
    return weights.empty() ? value : sc_mul(value, weights[index], ScalarRule::Wide);
}

inline std::vector<Scalar> fold_terms(
    const std::vector<Scalar>& values, size_t value_first,
    const FoldSide& side, size_t groups, size_t n, size_t point_first
) {
    const size_t half = n / 2;
    std::vector<Scalar> terms(groups * half);
    lane_chunks(terms.size(), fold_chunk, [&](size_t first, size_t last) {
        for (size_t i = first; i < last; ++i) {
            const size_t group = i / half;
            const size_t j = i % half;
            terms[i] = fold_scaled(values[value_first + j], side.weights, group * n + point_first + j);
        }
    });
    return terms;
}

inline SumParts fold_parts(
    const FoldSide& side, const std::vector<Scalar>& terms,
    size_t groups, size_t n, size_t point_first
) {
    const size_t half = n / 2;
    SumParts parts;
    for (size_t group = 0; group < groups; ++group)
        parts.push_back({side.points + group * n + point_first, terms.data() + group * half, half});
    return parts;
}

inline std::vector<Scalar> fold_weights(
    const std::vector<Scalar>& weights, size_t count, size_t half,
    const Scalar& low, const Scalar& high
) {
    std::vector<Scalar> next(count);
    lane_chunks(count, fold_chunk, [&](size_t first, size_t last) {
        for (size_t i = first; i < last; ++i) {
            const auto& factor = (i / half) % 2 == 0 ? low : high;
            next[i] = weights.empty() ? factor : sc_mul(weights[i], factor, ScalarRule::Wide);
        }
    });
    return next;
}

inline void fold_settle(FoldSide& side, size_t groups, size_t n) {
    std::vector<ProverPoint> settled(n);
    lane_chunks(n, affine_chunk, [&](size_t first, size_t last) {
        std::vector<ExtPoint> sums(last - first);
        for (size_t j = first; j < last; ++j)
            sums[j - first] = public_sum(side.points + j, side.weights.data() + j, groups, n);
        prover_affine(sums.data(), sums.size(), settled.data() + first);
    });
    side.owned = std::move(settled);
    side.points = side.owned.data();
    side.weights.clear();
}

struct FoldState {
    std::vector<Scalar> a;
    std::vector<Scalar> b;
    FoldSide g;
    FoldSide h;
    size_t groups;
};

inline std::vector<RistrettoPoint> fold_sides(const FoldState& state, const ProverPoint& q, const ScalarOps& ops) {
    const size_t n = state.a.size();
    const size_t half = n / 2;
    Scalar c_L = sc_zero();
    Scalar c_R = sc_zero();
    for (size_t i = 0; i < half; i++) {
        c_L = sc_add(c_L, ops.mul(state.a[i], state.b[half + i]));
        c_R = sc_add(c_R, ops.mul(state.a[half + i], state.b[i]));
    }
    const auto left_g = fold_terms(state.a, 0, state.g, state.groups, n, half);
    const auto left_h = fold_terms(state.b, half, state.h, state.groups, n, 0);
    const auto right_g = fold_terms(state.a, half, state.g, state.groups, n, 0);
    const auto right_h = fold_terms(state.b, 0, state.h, state.groups, n, half);
    auto left = fold_parts(state.g, left_g, state.groups, n, half);
    const auto left_rest = fold_parts(state.h, left_h, state.groups, n, 0);
    left.insert(left.end(), left_rest.begin(), left_rest.end());
    left.push_back({&q, &c_L, 1});
    auto right = fold_parts(state.g, right_g, state.groups, n, 0);
    const auto right_rest = fold_parts(state.h, right_h, state.groups, n, half);
    right.insert(right.end(), right_rest.begin(), right_rest.end());
    right.push_back({&q, &c_R, 1});
    return prover_sums({left, right});
}

inline FoldState fold_round(FoldState&& state, const Scalar& u, const ScalarOps& ops) {
    const Scalar u_inv = ops.inv(u);
    const size_t n = state.a.size();
    const size_t half = n / 2;
    std::vector<Scalar> a(half);
    std::vector<Scalar> b(half);
    for (size_t i = 0; i < half; i++) {
        a[i] = sc_add(ops.mul(state.a[i], u), ops.mul(state.a[half + i], u_inv));
        b[i] = sc_add(ops.mul(state.b[i], u_inv), ops.mul(state.b[half + i], u));
    }
    state.g.weights = fold_weights(state.g.weights, state.groups * n, half, u_inv, u);
    state.h.weights = fold_weights(state.h.weights, state.groups * n, half, u, u_inv);
    state.a = std::move(a);
    state.b = std::move(b);
    state.groups *= 2;
    if (state.groups == fold_groups && half > 1) {
        fold_settle(state.g, state.groups, half);
        fold_settle(state.h, state.groups, half);
        state.groups = 1;
    }
    return std::move(state);
}

inline InnerProductProof ipp_fold(
    Transcript& transcript,
    const ProverPoint& q,
    std::vector<Scalar> a,
    std::vector<Scalar> b,
    const ProverPoint* g,
    const ProverPoint* h,
    const std::vector<Scalar>& h_scale = {}
) {
    const size_t n = a.size();
    if (n == 0 || (n & (n - 1)) != 0 || b.size() != n || !g || !h)
        throw std::invalid_argument("pvac: inner product shape rejected");
    if (!h_scale.empty() && h_scale.size() != n)
        throw std::runtime_error("pvac: generator scale count differs");
    const size_t lg = log2_size(n);
    InnerProductProof proof;
    proof.L.resize(lg);
    proof.R.resize(lg);
    FoldState state{std::move(a), std::move(b), {g, {}, {}}, {h, {}, h_scale}, 1};
    for (size_t k = 0; k < lg; ++k) {
        const auto sides = fold_sides(state, q, transcript.ops);
        proof.L[k] = sides[0];
        proof.R[k] = sides[1];
        transcript.append_point("L", proof.L[k]);
        transcript.append_point("R", proof.R[k]);
        const Scalar u = transcript.challenge_scalar("u");
        state = fold_round(std::move(state), u, transcript.ops);
    }
    proof.a = state.a[0];
    proof.b = state.b[0];
    return proof;
}

}
}