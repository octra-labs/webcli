#pragma once

#include <cstddef>

namespace pvac {
namespace bp {

inline constexpr size_t R1CS_MAX_GATES = static_cast<size_t>(1) << 20;
inline constexpr size_t R1CS_MAX_COMMITTED = static_cast<size_t>(1) << 16;
inline constexpr size_t R1CS_MAX_CONSTRAINTS = 1'500'000;
inline constexpr size_t R1CS_MAX_TERMS = static_cast<size_t>(1) << 22;

}
}