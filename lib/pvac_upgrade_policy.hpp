// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace octra::pvac_upgrade_policy {

inline constexpr int64_t min_fee_raw = 5000;
inline constexpr int64_t max_fee_raw = 10000000;
inline constexpr size_t private_spend_refresh_base_layers = 4;
inline constexpr size_t private_result_layers = 6;
inline constexpr size_t claim_delta_layers = 2;
inline constexpr const char* reset_phrase = "RESET ENCRYPTED BALANCE";

inline bool fee_allowed(int64_t value) {
    return value >= min_fee_raw && value <= max_fee_raw;
}

inline bool replay_matches(bool known, int64_t local, int64_t replay) {
    return known && local == replay;
}

inline bool refresh_before_private_spend(size_t base_layers) {
    return base_layers >= private_spend_refresh_base_layers;
}

inline size_t claim_capacity(size_t base_layers) {
    return base_layers >= private_result_layers ? 0
        : (private_result_layers - base_layers) / claim_delta_layers;
}

inline bool deposit_allowed(size_t base_layers) {
    return base_layers <= private_result_layers - claim_delta_layers;
}

inline bool reset_allowed(const std::string& value) {
    return value == reset_phrase;
}

}