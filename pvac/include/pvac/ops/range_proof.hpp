#pragma once

#include <cstdint>
#include <vector>
#include <array>
#include <thread>
#include <algorithm>

#include "../core/types.hpp"
#include "verify_zero.hpp"
#include "verify_zero_circuit.hpp"
#include "arithmetic.hpp"
#include "encrypt.hpp"
#include "commit.hpp"

namespace pvac {

static constexpr size_t RANGE_BITS = 64;

struct RangeProof {

    std::vector<Cipher> ct_bit;

    std::vector<ZeroProof> bit_proofs;

    ZeroProof lc_proof;
};

inline RangeProof make_range_proof(
    const PubKey& pk,
    const SecKey& sk,
    const Cipher& ct_value,
    uint64_t value
) {
    RangeProof rp;
    rp.ct_bit.resize(RANGE_BITS);
    rp.bit_proofs.resize(RANGE_BITS);

    unsigned hw = std::thread::hardware_concurrency();
    unsigned n_threads = (hw > 1) ? std::min(hw, (unsigned)RANGE_BITS) : 1;

    if (n_threads <= 1) {
        for (size_t i = 0; i < RANGE_BITS; ++i) {
            uint64_t b_i = (value >> i) & 1;
            rp.ct_bit[i] = enc_value(pk, sk, b_i);


            //!!
            auto ct_b_m1 = ct_sub_const(pk, rp.ct_bit[i], (uint64_t)1);
            uint8_t mul_seed[32];
            for (int k = 0; k < 32; ++k)
                mul_seed[k] = (uint8_t)((i * 37 + k * 13 + 0xA0) & 0xFF);
            auto ct_check = ct_mul_seeded(pk, rp.ct_bit[i], ct_b_m1, mul_seed);
            rp.bit_proofs[i] = make_zero_proof(pk, sk, ct_check);
        }
    } else {
        auto worker = [&](size_t from, size_t to) {
            for (size_t i = from; i < to; ++i) {
                uint64_t b_i = (value >> i) & 1;
                rp.ct_bit[i] = enc_value(pk, sk, b_i);
                auto ct_b_m1 = ct_sub_const(pk, rp.ct_bit[i], (uint64_t)1);
                uint8_t mul_seed[32];

                // !
                for (int k = 0; k < 32; ++k)
                    mul_seed[k] = (uint8_t)((i * 37 + k * 13 + 0xA0) & 0xFF);
                auto ct_check = ct_mul_seeded(pk, rp.ct_bit[i], ct_b_m1, mul_seed);
                rp.bit_proofs[i] = make_zero_proof(pk, sk, ct_check);
            }
        };

        std::vector<std::thread> threads;
        size_t chunk = (RANGE_BITS + n_threads - 1) / n_threads;
        for (unsigned t = 0; t < n_threads; ++t) {
            size_t from = t * chunk;
            size_t to = std::min(from + chunk, RANGE_BITS);
            if (from < to)
                threads.emplace_back(worker, from, to);
        }
        for (auto& th : threads)
            th.join();
    }

    Cipher ct_sum = rp.ct_bit[0];

    for (size_t i = 1; i < RANGE_BITS; ++i) {

        Fp power_of_two;
        if (i < 64) {
            power_of_two = fp_from_u64(1ULL << i);
        } else {

            power_of_two = fp_from_words(0, 1ULL << (i - 64));
        }

        auto scaled = ct_scale(pk, rp.ct_bit[i], power_of_two);
        ct_sum = ct_add(pk, ct_sum, scaled);
    }

    auto ct_lc_diff = ct_sub(pk, ct_sum, ct_value);

    rp.lc_proof = make_zero_proof(pk, sk, ct_lc_diff);

    return rp;
}

inline bool verify_range(
    const PubKey& pk,
    const Cipher& ct_value,
    const RangeProof& rp
) {

    if (rp.ct_bit.size() != RANGE_BITS) return false;
    if (rp.bit_proofs.size() != RANGE_BITS) return false;

    unsigned hw = std::thread::hardware_concurrency();


    // !
    unsigned n_threads = (hw > 1) ? std::min(hw, (unsigned)RANGE_BITS) : 1;
    std::vector<bool> results(RANGE_BITS, false);

    if (n_threads <= 1) {
        for (size_t i = 0; i < RANGE_BITS; ++i) {
            auto ct_b_m1 = ct_sub_const(pk, rp.ct_bit[i], (uint64_t)1);
            uint8_t mul_seed[32];
            for (int k = 0; k < 32; ++k)
                mul_seed[k] = (uint8_t)((i * 37 + k * 13 + 0xA0) & 0xFF);
            auto ct_check = ct_mul_seeded(pk, rp.ct_bit[i], ct_b_m1, mul_seed);
            if (!verify_zero(pk, ct_check, rp.bit_proofs[i]))
                return false;
        }
    } else {
        auto worker = [&](size_t from, size_t to) {
            for (size_t i = from; i < to; ++i) {
                auto ct_b_m1 = ct_sub_const(pk, rp.ct_bit[i], (uint64_t)1);
                uint8_t mul_seed[32];
                for (int k = 0; k < 32; ++k)
                    mul_seed[k] = (uint8_t)((i * 37 + k * 13 + 0xA0) & 0xFF);
                auto ct_check = ct_mul_seeded(pk, rp.ct_bit[i], ct_b_m1, mul_seed);
                results[i] = verify_zero(pk, ct_check, rp.bit_proofs[i]);
            }
        };

        std::vector<std::thread> threads;
        size_t chunk = (RANGE_BITS + n_threads - 1) / n_threads;
        for (unsigned t = 0; t < n_threads; ++t) {
            size_t from = t * chunk;
            size_t to = std::min(from + chunk, RANGE_BITS);
            if (from < to)
                threads.emplace_back(worker, from, to);
        }
        for (auto& th : threads)
            th.join();

        for (size_t i = 0; i < RANGE_BITS; ++i) {
            if (!results[i]) return false;
        }
    }

    Cipher ct_sum = rp.ct_bit[0];

    for (size_t i = 1; i < RANGE_BITS; ++i) {
        Fp power_of_two;

        if (i < 64) {
            power_of_two = fp_from_u64(1ULL << i);
        } else {
            power_of_two = fp_from_words(0, 1ULL << (i - 64));
        }

        auto scaled = ct_scale(pk, rp.ct_bit[i], power_of_two);
        ct_sum = ct_add(pk, ct_sum, scaled);
    }

    auto ct_lc_diff = ct_sub(pk, ct_sum, ct_value);

    if (!verify_zero(pk, ct_lc_diff, rp.lc_proof)) {
        return false;
    }

    return true;
}

struct AggregatedRangeProof {
    std::vector<Cipher> ct_bit;// 64 encrypted bits (needed by verifier)
    bp::R1CSProof proof; // single R1CS proof covering all 65 circuits
};

namespace detail {

struct BitPrepData {
    Cipher ct_check;
    std::vector<std::vector<Fp>> rinv;
    std::vector<std::vector<Fp>> A;
    std::vector<size_t> bases;
};

inline void prepare_bit(
    const PubKey& pk, const SecKey& sk,
    const Cipher& ct_bit_i, size_t i,
    BitPrepData& out
) {
    auto ct_b_m1 = ct_sub_const(pk, ct_bit_i, (uint64_t)1);
    uint8_t mul_seed[32];
    for (int k = 0; k < 32; ++k)
        mul_seed[k] = (uint8_t)((i * 37 + k * 13 + 0xA0) & 0xFF);
    out.ct_check = ct_mul_seeded(pk, ct_bit_i, ct_b_m1, mul_seed);

    size_t nL = out.ct_check.L.size();
    size_t S  = out.ct_check.slots;

    std::vector<std::vector<Fp>> cache(nL);
    std::vector<uint8_t> st(nL, 0);
    for (size_t lid = 0; lid < nL; lid++)
        layer_R_cached(pk, sk, out.ct_check, (uint32_t)lid, st, cache);

    out.rinv.resize(nL);
    for (size_t lid = 0; lid < nL; lid++) {
        out.rinv[lid].resize(S);
        for (size_t j = 0; j < S; j++)
            out.rinv[lid][j] = fp_inv(cache[lid][j]);
    }
    out.A = compute_layer_coeffs(pk, out.ct_check);
    out.bases = base_layer_indices(out.ct_check);
}

inline void prepare_lc(
    const PubKey& pk, const SecKey& sk,
    const Cipher& ct_lc_diff,
    BitPrepData& out
) {
    out.ct_check = ct_lc_diff;  // reuse field for the LC cipher

    size_t nL = ct_lc_diff.L.size();
    size_t S  = ct_lc_diff.slots;

    std::vector<std::vector<Fp>> cache(nL);
    std::vector<uint8_t> st(nL, 0);
    for (size_t lid = 0; lid < nL; lid++)
        layer_R_cached(pk, sk, ct_lc_diff, (uint32_t)lid, st, cache);

    out.rinv.resize(nL);
    for (size_t lid = 0; lid < nL; lid++) {
        out.rinv[lid].resize(S);
        for (size_t j = 0; j < S; j++)
            out.rinv[lid][j] = fp_inv(cache[lid][j]);
    }
    out.A = compute_layer_coeffs(pk, ct_lc_diff);
    out.bases = base_layer_indices(ct_lc_diff);
}

inline Cipher compute_lc_diff(
    const PubKey& pk,
    const std::vector<Cipher>& ct_bit,
    const Cipher& ct_value
) {
    Cipher ct_sum = ct_bit[0];
    for (size_t i = 1; i < RANGE_BITS; ++i) {
        Fp power_of_two;
        if (i < 64) power_of_two = fp_from_u64(1ULL << i);
        else        power_of_two = fp_from_words(0, 1ULL << (i - 64));
        ct_sum = ct_add(pk, ct_sum, ct_scale(pk, ct_bit[i], power_of_two));
    }
    return ct_sub(pk, ct_sum, ct_value);
}

inline void append_transcript_params(
    bp::Transcript& transcript,
    const std::vector<BitPrepData>& bit_data,
    const BitPrepData& lc_data
) {
    transcript.append_u64("RANGE_BITS", RANGE_BITS);
    for (size_t i = 0; i < RANGE_BITS; ++i) {
        transcript.append_u64("nL", bit_data[i].ct_check.L.size());
        transcript.append_u64("S", bit_data[i].ct_check.slots);
        transcript.append_u64("nB", bit_data[i].bases.size());
    }
    transcript.append_u64("nL", lc_data.ct_check.L.size());
    transcript.append_u64("S", lc_data.ct_check.slots);
    transcript.append_u64("nB", lc_data.bases.size());
}

}  // namespace detail

inline AggregatedRangeProof make_aggregated_range_proof(
    const PubKey& pk,
    const SecKey& sk,
    const Cipher& ct_value,
    uint64_t value
) {
    AggregatedRangeProof arp;
    arp.ct_bit.resize(RANGE_BITS);

    std::vector<detail::BitPrepData> bit_data(RANGE_BITS);

    unsigned hw = std::thread::hardware_concurrency();
    unsigned n_threads = (hw > 1) ? std::min(hw, (unsigned)RANGE_BITS) : 1;

    auto worker = [&](size_t from, size_t to) {
        for (size_t i = from; i < to; ++i) {
            uint64_t b_i = (value >> i) & 1;
            arp.ct_bit[i] = enc_value(pk, sk, b_i);
            detail::prepare_bit(pk, sk, arp.ct_bit[i], i, bit_data[i]);
        }
    };

    if (n_threads <= 1) {
        worker(0, RANGE_BITS);
    } else {
        std::vector<std::thread> threads;
        size_t chunk = (RANGE_BITS + n_threads - 1) / n_threads;
        for (unsigned t = 0; t < n_threads; ++t) {
            size_t from = t * chunk;
            size_t to = std::min(from + chunk, RANGE_BITS);
            if (from < to)
                threads.emplace_back(worker, from, to);
        }
        for (auto& th : threads)
            th.join();
    }

    auto ct_lc_diff = detail::compute_lc_diff(pk, arp.ct_bit, ct_value);
    detail::BitPrepData lc_data;
    detail::prepare_lc(pk, sk, ct_lc_diff, lc_data);

    bp::R1CSProver prover;
    for (size_t i = 0; i < RANGE_BITS; ++i) {
        detail::build_circuit(prover, bit_data[i].ct_check,
                              bit_data[i].A, bit_data[i].bases,
                              &bit_data[i].rinv, &sk);
    }
    detail::build_circuit(prover, lc_data.ct_check,
                          lc_data.A, lc_data.bases,
                          &lc_data.rinv, &sk);

    bp::Transcript transcript("pvac.range_proof.aggregated");
    detail::append_transcript_params(transcript, bit_data, lc_data);

    arp.proof = prover.prove(transcript);
    return arp;
}

inline bool verify_aggregated_range(
    const PubKey& pk,
    const Cipher& ct_value,
    const AggregatedRangeProof& arp
) {
    if (arp.ct_bit.size() != RANGE_BITS) return false;

    std::vector<detail::BitPrepData> vdata(RANGE_BITS);
    for (size_t i = 0; i < RANGE_BITS; ++i) {
        auto ct_b_m1 = ct_sub_const(pk, arp.ct_bit[i], (uint64_t)1);
        uint8_t mul_seed[32];
        for (int k = 0; k < 32; ++k)
            mul_seed[k] = (uint8_t)((i * 37 + k * 13 + 0xA0) & 0xFF);
        vdata[i].ct_check = ct_mul_seeded(pk, arp.ct_bit[i], ct_b_m1, mul_seed);
        vdata[i].A = compute_layer_coeffs(pk, vdata[i].ct_check);
        vdata[i].bases = base_layer_indices(vdata[i].ct_check);
    }

    auto ct_lc_diff = detail::compute_lc_diff(pk, arp.ct_bit, ct_value);
    detail::BitPrepData lc_data;
    lc_data.ct_check = ct_lc_diff;
    lc_data.A = compute_layer_coeffs(pk, ct_lc_diff);
    lc_data.bases = base_layer_indices(ct_lc_diff);

    bp::R1CSProver dummy;
    for (size_t i = 0; i < RANGE_BITS; ++i) {
        detail::build_circuit(dummy, vdata[i].ct_check,
                              vdata[i].A, vdata[i].bases,
                              nullptr, nullptr);
    }
    detail::build_circuit(dummy, lc_data.ct_check,
                          lc_data.A, lc_data.bases,
                          nullptr, nullptr);

    size_t expected_v = dummy.num_committed();
    if (arp.proof.V.size() != expected_v) return false;

    size_t v_offset = 0;
    for (size_t i = 0; i < RANGE_BITS; ++i) {
        auto& ct = vdata[i].ct_check;
        auto& bases = vdata[i].bases;
        size_t nB = bases.size();
        size_t S = ct.slots;
        for (size_t bi = 0; bi < nB; bi++) {
            size_t lid = bases[bi];
            if (ct.L[lid].PC.size() != S) return false;
            for (size_t j = 0; j < S; j++) {
                if (arp.proof.V[v_offset + bi * S + j] != ct.L[lid].PC[j])
                    return false;
            }
        }
        v_offset += nB * S;
    }
    {
        size_t nB = lc_data.bases.size();
        size_t S = ct_lc_diff.slots;
        for (size_t bi = 0; bi < nB; bi++) {
            size_t lid = lc_data.bases[bi];
            if (ct_lc_diff.L[lid].PC.size() != S) return false;
            for (size_t j = 0; j < S; j++) {
                if (arp.proof.V[v_offset + bi * S + j] != ct_lc_diff.L[lid].PC[j])
                    return false;
            }
        }
    }

    bp::ConstraintSystem cs;
    cs.num_gates = dummy.num_gates();
    cs.num_committed = dummy.num_committed();
    cs.constraints = dummy.get_constraints();

    bp::Transcript transcript("pvac.range_proof.aggregated");
    detail::append_transcript_params(transcript, vdata, lc_data);

    return bp::r1cs_verify(transcript, cs, arp.proof);
}

}
