#pragma once

#include <cstdint>
#include <string>

namespace octra::pvac_upgrade_policy {

inline constexpr int64_t min_fee_raw = 3000;
inline constexpr int64_t max_fee_raw = 10000000;
inline constexpr const char* reset_phrase = "RESET ENCRYPTED BALANCE";

inline bool fee_allowed(int64_t value) {
    return value >= min_fee_raw && value <= max_fee_raw;
}

inline bool replay_matches(bool known, int64_t local, int64_t replay) {
    return !known || local == replay;
}

inline bool reset_allowed(const std::string& value) {
    return value == reset_phrase;
}

}