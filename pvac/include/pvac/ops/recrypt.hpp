#pragma once

#include <cstdint>

#include "../core/types.hpp"
#include "../crypto/matrix.hpp"
#include "encrypt.hpp"
#include "arithmetic.hpp"

namespace pvac {

inline EvalKey make_evalkey(const PubKey& pk, const SecKey& sk, size_t pool_size, int depth_hint) {
    EvalKey ek;
    ek.zero_pool.reserve(pool_size);
    for (size_t i = 0; i < pool_size; ++i)
        ek.zero_pool.push_back(enc_zero_depth(pk, sk, depth_hint));
    ek.enc_one = enc_value(pk, sk, 1);
    return ek;
}

inline bool sigma_needs_balance(const PubKey& pk, const Cipher& C) {
    double d = sigma_density(pk, C);
    return d < 0.495 || d > 0.505;
}

inline Cipher ct_recrypt(const PubKey& pk, const EvalKey& ek, const Cipher& in) {
    if (ek.zero_pool.empty() || in.E.empty()) return in;

    Cipher result = in;

    for (int it = 0; it < 8 && sigma_needs_balance(pk, result); ++it) {
        size_t idx = csprng_u64() % ek.zero_pool.size();
        result = ct_add(pk, result, ek.zero_pool[idx]);
        ubk_apply(pk, result);
        guard_budget(pk, result, "recrypt");
    }

    compact_edges(pk, result);
    compact_layers(result);
    return result;
}

inline Cipher ct_recrypt_seeded(const PubKey& pk, const EvalKey& ek, const Cipher& in, const uint8_t seed[32]) {
    if (ek.zero_pool.empty() || in.E.empty()) return in;

    SeedableRng rng = make_seeded_rng(seed);
    Cipher result = in;

    for (int it = 0; it < 8 && sigma_needs_balance(pk, result); ++it) {
        size_t idx = rng.bounded(ek.zero_pool.size());
        result = ct_add(pk, result, ek.zero_pool[idx]);
        ubk_apply(pk, result);
        guard_budget(pk, result, "recrypt");
    }

    compact_edges(pk, result);
    compact_layers(result);
    return result;
}

}