// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once

#include <array>
#include <cstdint>
#include <stdexcept>
#include <vector>
#include "generators.hpp"
#include "prover_msm.hpp"
#include "prover_sum.hpp"

namespace pvac {
namespace bp {

inline constexpr size_t comb_rows = 65;

using CombRow = std::array<ProverPoint, 8>;
using CombTable = std::array<CombRow, comb_rows>;

inline CombTable comb_table(const RistrettoPoint& base) {
    std::vector<ExtPoint> points;
    points.reserve(comb_rows * 8);
    auto row = rist_decode_or_throw(base);
    for (size_t i = 0; i < comb_rows; ++i) {
        auto multiple = row;
        for (size_t j = 0; j < 8; ++j) {
            points.push_back(multiple);
            multiple = ext_add(multiple, row);
        }
        for (size_t k = 0; k < 4; ++k) row = ext_double(row);
    }
    std::vector<ProverPoint> affine(points.size());
    prover_affine(points.data(), points.size(), affine.data());
    CombTable table;
    for (size_t i = 0; i < comb_rows; ++i)
        for (size_t j = 0; j < 8; ++j) table[i][j] = affine[i * 8 + j];
    return table;
}

inline std::array<int8_t, comb_rows> comb_digits(const Scalar& scalar) {
    std::array<int8_t, comb_rows> digits{};
    int carry = 0;
    for (size_t i = 0; i + 1 < comb_rows; ++i) {
        const int nibble = static_cast<int>((scalar.v[i / 16] >> (4 * (i % 16))) & 15) + carry;
        carry = (nibble + 8) >> 4;
        digits[i] = static_cast<int8_t>(nibble - (carry << 4));
    }
    digits[comb_rows - 1] = static_cast<int8_t>(carry);
    return digits;
}

inline uint64_t comb_opaque(uint64_t value) {
    asm("" : "+r"(value));
    return value;
}

inline Fe25519 comb_select(const Fe25519& kept, const Fe25519& offered, uint64_t mask) {
    Fe25519 out;
    for (size_t i = 0; i < 5; ++i) out.v[i] = kept.v[i] ^ (mask & (kept.v[i] ^ offered.v[i]));
    return out;
}

inline ProverPoint comb_pick(const CombRow& row, int8_t digit) {
    const uint32_t value = static_cast<uint32_t>(static_cast<int32_t>(digit));
    const uint32_t negative = value >> 31;
    const uint32_t magnitude = (value ^ (0u - negative)) + negative;
    ProverPoint picked{fe_one(), fe_one(), fe_zero()};
    for (uint32_t j = 0; j < 8; ++j) {
        const uint64_t hit = (((magnitude ^ (j + 1)) - 1) >> 31) & 1;
        const uint64_t mask = comb_opaque(0 - hit);
        picked.minus = comb_select(picked.minus, row[j].minus, mask);
        picked.plus = comb_select(picked.plus, row[j].plus, mask);
        picked.product = comb_select(picked.product, row[j].product, mask);
    }
    const uint64_t flip = comb_opaque(0 - static_cast<uint64_t>(negative));
    return {
        comb_select(picked.minus, picked.plus, flip),
        comb_select(picked.plus, picked.minus, flip),
        comb_select(picked.product, fe_neg(picked.product), flip)
    };
}

inline RistrettoPoint secret_commit(const Scalar& value, const Scalar& blinding) {
    static const CombTable value_table = comb_table(rist_G());
    static const CombTable blind_table = comb_table(rist_H());
    const auto value_digits = comb_digits(value);
    const auto blind_digits = comb_digits(blinding);
    auto sum = ext_identity();
    for (size_t i = 0; i < comb_rows; ++i) {
        sum = prover_add(sum, comb_pick(value_table[i], value_digits[i]));
        sum = prover_add(sum, comb_pick(blind_table[i], blind_digits[i]));
    }
    return rist_encode(sum);
}

}
}