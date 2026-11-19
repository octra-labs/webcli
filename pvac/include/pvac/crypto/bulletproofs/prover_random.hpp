// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <vector>
#include "../../core/random.hpp"
#include "../ristretto255.hpp"

namespace pvac {
namespace bp {

inline constexpr size_t random_block = 64;

inline void wipe_bytes(void* data, size_t size) {
    volatile uint8_t* const bytes = static_cast<volatile uint8_t*>(data);
    for (size_t i = 0; i < size; ++i) bytes[i] = 0;
}

inline Scalar random_scalar(const uint8_t* bytes, const ScalarOps& ops) {
    uint64_t words[8];
    for (size_t i = 0; i < 8; ++i) words[i] = load_le64(bytes + 8 * i);
    const auto scalar = ops.reduce(words);
    wipe_bytes(words, sizeof words);
    return scalar;
}

struct RandomBlock {
    std::array<uint8_t, random_block * 128> bytes;

    RandomBlock() = default;
    RandomBlock(const RandomBlock&) = delete;
    RandomBlock& operator=(const RandomBlock&) = delete;

    ~RandomBlock() { wipe_bytes(bytes.data(), bytes.size()); }
};

inline void random_pairs(std::vector<Scalar>& left, std::vector<Scalar>& right, const ScalarOps& ops) {
    if (left.size() != right.size())
        throw std::invalid_argument("pvac: random pair sizes differ");
    RandomBlock block;
    for (size_t first = 0; first < left.size(); first += random_block) {
        const size_t count = std::min(random_block, left.size() - first);
        csprng_bytes(block.bytes.data(), count * 128);
        for (size_t i = 0; i < count; ++i) {
            left[first + i] = random_scalar(block.bytes.data() + 128 * i, ops);
            right[first + i] = random_scalar(block.bytes.data() + 128 * i + 64, ops);
        }
    }
}

}
}