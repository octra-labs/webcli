#include "pvac_c_api.h"

#include "include/pvac/pvac.hpp"
#include "include/pvac/crypto/legacy_profile.hpp"
#include "pvac_serialize.hpp"

#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <memory>
#include <new>

#define PK(h) (reinterpret_cast<pvac::PubKey*>(h))
#define SK(h) (reinterpret_cast<pvac::SecKey*>(h))
#define CT(h) (reinterpret_cast<pvac::Cipher*>(h))
#define PRM(h) (reinterpret_cast<pvac::Params*>(h))
#define ZP(h) (reinterpret_cast<pvac::ZeroProof*>(h))
#define RP(h) (reinterpret_cast<pvac::RangeProof*>(h))
#define ARP(h) (reinterpret_cast<pvac::AggregatedRangeProof*>(h))

static uint8_t* copy_bytes(const std::vector<uint8_t>& buf, size_t* len) noexcept {
    if (len)
        *len = 0;
    if (!len || buf.empty())
        return nullptr;
    auto* out = static_cast<uint8_t*>(std::malloc(buf.size()));
    if (!out)
        return nullptr;
    std::memcpy(out, buf.data(), buf.size());
    *len = buf.size();
    return out;
}

static bool fp_eq(const pvac::Fp& a, const pvac::Fp& b) {
    return a.lo == b.lo && a.hi == b.hi;
}

static bool fp_vec_eq(const std::vector<pvac::Fp>& a, const std::vector<pvac::Fp>& b) {
    if (a.size() != b.size())
        return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (!fp_eq(a[i], b[i]))
            return false;
    return true;
}

static bool bitvec_eq(const pvac::BitVec& a, const pvac::BitVec& b) {
    return a.nbits == b.nbits && a.w == b.w;
}

static bool bytes32_zero(const std::array<uint8_t, 32>& x) {
    return x == std::array<uint8_t, 32>{};
}

static bool params_eq(const pvac::Params& a, const pvac::Params& b) {
    return a.B == b.B &&
        a.m_bits == b.m_bits &&
        a.n_bits == b.n_bits &&
        a.h_col_wt == b.h_col_wt &&
        a.x_col_wt == b.x_col_wt &&
        a.err_wt == b.err_wt &&
        a.noise_entropy_bits == b.noise_entropy_bits &&
        a.tuple2_fraction == b.tuple2_fraction &&
        a.depth_slope_bits == b.depth_slope_bits &&
        a.edge_budget == b.edge_budget &&
        a.lpn_n == b.lpn_n &&
        a.lpn_t == b.lpn_t &&
        a.lpn_tau_num == b.lpn_tau_num &&
        a.lpn_tau_den == b.lpn_tau_den &&
        a.recrypt_lo == b.recrypt_lo &&
        a.recrypt_hi == b.recrypt_hi &&
        a.recrypt_rounds == b.recrypt_rounds;
}

static bool pubkey_is_key_bound_extension_impl(const pvac::PubKey& legacy, const pvac::PubKey& bound) {
    if (!params_eq(legacy.prm, bound.prm)) return false;
    if (legacy.canon_tag != bound.canon_tag) return false;
    if (legacy.H_digest != bound.H_digest) return false;
    if (!fp_eq(legacy.omega_B, bound.omega_B)) return false;
    if (!fp_vec_eq(legacy.powg_B, bound.powg_B)) return false;
    if (legacy.H.size() != bound.H.size()) return false;
    for (size_t i = 0; i < legacy.H.size(); ++i)
        if (!bitvec_eq(legacy.H[i], bound.H[i]))
            return false;
    if (legacy.ubk.perm != bound.ubk.perm) return false;
    if (legacy.ubk.inv != bound.ubk.inv) return false;
    if (bytes32_zero(bound.circuit_prf_key_commit)) return false;
    if (!bytes32_zero(legacy.circuit_prf_key_commit) &&
        legacy.circuit_prf_key_commit != bound.circuit_prf_key_commit)
        return false;
    return true;
}

extern "C" {

pvac_params pvac_default_params(void) {
    auto* p = new (std::nothrow) pvac::Params();
    return p;
}

void pvac_keygen_from_seed(pvac_params prm, const uint8_t seed[32],
                           pvac_pubkey* pk_out, pvac_seckey* sk_out) {
    auto* pk = new pvac::PubKey();
    auto* sk = new pvac::SecKey();
    pvac::set_debug_level(0);
    pvac::keygen_from_seed(*PRM(prm), *pk, *sk, seed);
    *pk_out = pk;
    *sk_out = sk;
}

pvac_cipher pvac_enc_value_seeded(pvac_pubkey pk, pvac_seckey sk,
                                  uint64_t val, const uint8_t seed[32]) {
    auto* ct = new pvac::Cipher();
    *ct = pvac::enc_value_seeded(*PK(pk), *SK(sk), val, seed);
    return ct;
}

pvac_cipher pvac_enc_zero_seeded(pvac_pubkey pk, pvac_seckey sk,
                                 const uint8_t seed[32]) {
    auto* ct = new pvac::Cipher();
    *ct = pvac::enc_zero_seeded(*PK(pk), *SK(sk), seed);
    return ct;
}

uint64_t pvac_dec_value(pvac_pubkey pk, pvac_seckey sk, pvac_cipher ct) {
    try {
        pvac::Fp r = pvac::dec_value(*PK(pk), *SK(sk), *CT(ct));
        return r.lo;
    } catch (...) {
        return 0;
    }
}

int pvac_dec_value_i64(pvac_pubkey pk, pvac_seckey sk, pvac_cipher ct,
                       int64_t* value_out) {
    if (!value_out)
        return 0;
    try {
        pvac::Fp value = pvac::dec_value(*PK(pk), *SK(sk), *CT(ct));
        return pvac::fp_to_i64(value, *value_out) ? 1 : 0;
    } catch (...) {
        return 0;
    }
}

int pvac_dec_value_legacy_i64(pvac_pubkey pk, pvac_seckey sk, pvac_cipher ct,
                              int64_t* value_out) {
    if (!value_out)
        return 0;
    try {
        pvac::Fp value = pvac::dec_value_legacy_mask(*PK(pk), *SK(sk), *CT(ct));
        return pvac::fp_to_i64(value, *value_out) ? 1 : 0;
    } catch (...) {
        return 0;
    }
}

void pvac_dec_value_fp(pvac_pubkey pk, pvac_seckey sk, pvac_cipher ct,
                       uint64_t* lo_out, uint64_t* hi_out) {
    if (!lo_out || !hi_out)
        return;
    try {
        pvac::Fp r = pvac::dec_value(*PK(pk), *SK(sk), *CT(ct));
        *lo_out = r.lo;
        *hi_out = r.hi;
    } catch (...) {
        *lo_out = 0;
        *hi_out = 0;
    }
}

pvac_cipher pvac_enc_value_fp_seeded(pvac_pubkey pk, pvac_seckey sk,
                                     uint64_t lo, uint64_t hi,
                                     const uint8_t seed[32]) {
    pvac::SeedableRng rng = pvac::make_seeded_rng(seed);
    pvac::Fp v;
    v.lo = lo;
    v.hi = hi;
    std::vector<pvac::Fp> vals = {v};
    std::vector<pvac::Fp> m = {rng.fp_nonzero()};
    auto* ct = new pvac::Cipher();
    *ct = pvac::combine_ciphers(*PK(pk),
        pvac::enc_fp_depth_seeded(*PK(pk), *SK(sk), pvac::field::Op::add(vals, m), 0, rng),
        pvac::enc_fp_depth_seeded(*PK(pk), *SK(sk), pvac::field::Op::neg(m), 0, rng));
    return ct;
}

pvac_cipher pvac_ct_add(pvac_pubkey pk, pvac_cipher a, pvac_cipher b) {
    auto* ct = new pvac::Cipher();
    *ct = pvac::ct_add(*PK(pk), *CT(a), *CT(b));
    return ct;
}

pvac_cipher pvac_ct_sub(pvac_pubkey pk, pvac_cipher a, pvac_cipher b) {
    auto* ct = new pvac::Cipher();
    *ct = pvac::ct_sub(*PK(pk), *CT(a), *CT(b));
    return ct;
}

pvac_cipher pvac_ct_mul_seeded(pvac_pubkey pk, pvac_cipher a, pvac_cipher b, const uint8_t seed[32]) {
    auto* ct = new pvac::Cipher();
    *ct = pvac::ct_mul_seeded(*PK(pk), *CT(a), *CT(b), seed);
    return ct;
}

pvac_cipher pvac_ct_scale(pvac_pubkey pk, pvac_cipher ct, int64_t scalar) {
    auto* out = new pvac::Cipher();
    *out = pvac::ct_scale(*PK(pk), *CT(ct), pvac::fp_from_u64(static_cast<uint64_t>(scalar)));
    return out;
}

pvac_cipher pvac_ct_add_const(pvac_pubkey pk, pvac_cipher ct, uint64_t k_lo, uint64_t k_hi) {
    auto* out = new pvac::Cipher();
    pvac::Fp k;
    k.lo = k_lo;
    k.hi = k_hi;
    *out = *CT(ct);
    for (size_t j = 0; j < out->c0.size(); ++j)
        out->c0[j] = pvac::fp_add(out->c0[j], k);
    return out;
}

pvac_cipher pvac_ct_sub_const(pvac_pubkey pk, pvac_cipher ct, uint64_t k) {
    auto* out = new pvac::Cipher();
    *out = *CT(ct);
    pvac::Fp neg_k = pvac::fp_neg(pvac::fp_from_u64(k));
    for (size_t j = 0; j < out->c0.size(); ++j)
        out->c0[j] = pvac::fp_add(out->c0[j], neg_k);
    return out;
}

pvac_cipher pvac_ct_div_const(pvac_pubkey pk, pvac_cipher ct, uint64_t k_lo, uint64_t k_hi) {
    auto* out = new pvac::Cipher();
    pvac::Fp k;
    k.lo = k_lo;
    k.hi = k_hi;
    *out = pvac::ct_scale(*PK(pk), *CT(ct), pvac::fp_inv(k));
    return out;
}

pvac_cipher pvac_ct_square_seeded(pvac_pubkey pk, pvac_cipher ct, const uint8_t seed[32]) {
    auto* out = new pvac::Cipher();
    *out = pvac::ct_square_seeded(*PK(pk), *CT(ct), seed);
    return out;
}

void pvac_commit_ct(pvac_pubkey pk, pvac_cipher ct, uint8_t out[32]) {
    if (!out)
        return;
    auto h = pvac::commit_ct(*PK(pk), *CT(ct));
    std::memcpy(out, h.data(), 32);
}

int pvac_commit_ct_v2(pvac_pubkey pk, pvac_cipher ct, uint8_t *out, size_t out_cap, size_t *out_len) {
    if (out_len) *out_len = 32;
    if (!out || out_cap < 32) return -1;
    try {
        auto h = pvac::commit_ct(*PK(pk), *CT(ct));
        std::memcpy(out, h.data(), 32);
        return 0;
    } catch (...) {
        return -2;
    }
}

int pvac_cipher_has_key_bound_material(pvac_cipher ct) {
    try {
        if (!ct)
            return 0;
        const auto& c = *CT(ct);
        if (c.slots == 0 || c.L.empty())
            return 0;
        if (!pvac::is_valid_cipher_shape(c))
            return 0;
        bool has_base = false;
        for (const auto& layer : c.L) {
            if (layer.rule == pvac::RRule::BASE) {
                has_base = true;
                if (layer.R_PC.size() != c.slots || layer.PC.size() != c.slots)
                    return 0;
            }
        }
        return has_base ? 1 : 0;
    } catch (...) {
        return 0;
    }
}

int pvac_cipher_has_canonical_r_com(pvac_pubkey pk, pvac_cipher ct) {
    try {
        if (!pk || !ct)
            return 0;
        const auto& p = *PK(pk);
        const auto& c = *CT(ct);
        if (c.slots == 0 || c.L.empty())
            return 0;
        if (!pvac::is_valid_cipher_shape(c))
            return 0;
        std::vector<pvac::Fp> slots(c.slots, pvac::fp_from_u64(0));
        bool has_base = false;
        for (const auto& layer : c.L) {
            if (layer.rule != pvac::RRule::BASE)
                continue;
            has_base = true;
            auto expected = pvac::compute_R_com_base(
                p.canon_tag,
                layer.seed.ztag,
                layer.seed.nonce.lo,
                layer.seed.nonce.hi,
                slots);
            if (layer.R_com != expected)
                return 0;
        }
        return has_base ? 1 : 0;
    } catch (...) {
        return 0;
    }
}

size_t pvac_cipher_base_layer_count(pvac_cipher ct) {
    try {
        if (!ct)
            return 0;
        const auto& c = *CT(ct);
        if (!pvac::is_valid_cipher_shape(c))
            return 0;
        size_t count = 0;
        for (const auto& layer : c.L) {
            if (layer.rule == pvac::RRule::BASE)
                ++count;
        }
        return count;
    } catch (...) {
        return 0;
    }
}

int pvac_cipher_inspect_public(pvac_cipher ct,
                               pvac_cipher_shape_view* shape,
                               pvac_cipher_layer_view* layers,
                               size_t layer_cap,
                               pvac_cipher_edge_view* edges,
                               size_t edge_cap,
                               size_t sigma_sample_cap) {
    try {
        if (!ct || !shape)
            return -1;
        const auto& c = *CT(ct);
        if (!pvac::is_valid_cipher_shape(c))
            return -2;
        if (c.slots > 65536 || c.c0.size() > 65536 ||
            c.L.size() > 4096 || c.E.size() > 1200000)
            return -3;

        *shape = {};
        shape->slots = c.slots;
        shape->layer_count = c.L.size();
        shape->edge_count = c.E.size();
        shape->c0_count = c.c0.size();

        if (!layers && layer_cap == 0 && !edges && edge_cap == 0 &&
            sigma_sample_cap == 0)
            return 0;
        if (c.L.size() > layer_cap || (!c.L.empty() && !layers))
            return -4;
        if (edge_cap > 0 && !edges)
            return -5;
        for (size_t i = 0; i < c.L.size(); ++i) {
            const auto& layer = c.L[i];
            layers[i] = {};
            layers[i].rule = static_cast<uint8_t>(layer.rule);
            layers[i].parent_a = layer.rule == pvac::RRule::PROD ? layer.pa : UINT32_MAX;
            layers[i].parent_b = layer.rule == pvac::RRule::PROD ? layer.pb : UINT32_MAX;
            layers[i].r_pc_count = layer.R_PC.size();
            layers[i].pc_count = layer.PC.size();
            layers[i].has_r_com = bytes32_zero(layer.R_com) ? 0 : 1;
        }

        const size_t sigma_cap = std::min(sigma_sample_cap, static_cast<size_t>(4096));
        const size_t sigma_stride = sigma_cap == 0 || c.E.empty()
            ? 0
            : std::max(static_cast<size_t>(1), (c.E.size() + sigma_cap - 1) / sigma_cap);
        const size_t visual_stride = edge_cap == 0 || c.E.empty()
            ? 0
            : std::max(static_cast<size_t>(1), (c.E.size() + edge_cap - 1) / edge_cap);
        size_t visual_count = 0;

        for (size_t i = 0; i < c.E.size(); ++i) {
            const auto& edge = c.E[i];
            const uint64_t tail_bits = edge.s.nbits % 64;
            if (tail_bits != 0 && !edge.s.w.empty() &&
                (edge.s.w.back() >> tail_bits) != 0)
                return -2;
            auto& layer = layers[edge.layer_id];
            ++layer.edge_count;

            if (sigma_stride != 0 && i % sigma_stride == 0 &&
                shape->sampled_edge_count < sigma_cap) {
                const uint64_t bits = static_cast<uint64_t>(edge.s.nbits);
                const uint64_t ones = static_cast<uint64_t>(edge.s.popcnt());
                if (ones > bits)
                    return -2;
                ++shape->sampled_edge_count;
                shape->sampled_sigma_bits += bits;
                shape->sampled_sigma_ones += ones;
                ++layer.sampled_edge_count;
                layer.sampled_sigma_bits += bits;
                layer.sampled_sigma_ones += ones;
            }

            if (visual_stride != 0 && i % visual_stride == 0 &&
                visual_count < edge_cap) {
                edges[visual_count] = {};
                edges[visual_count].layer_id = edge.layer_id;
                edges[visual_count].idx = edge.idx;
                edges[visual_count].channel = edge.ch;
                edges[visual_count].weight_slots = edge.w.size();
                edges[visual_count].sigma_bits = static_cast<uint64_t>(edge.s.nbits);
                edges[visual_count].sigma_ones = static_cast<uint64_t>(edge.s.popcnt());
                if (edges[visual_count].sigma_ones > edges[visual_count].sigma_bits)
                    return -2;
                ++visual_count;
            }
        }

        shape->sigma_exact = shape->sampled_edge_count == c.E.size() ? 1 : 0;
        return static_cast<int>(visual_count);
    } catch (...) {
        return -6;
    }
}

int pvac_pubkey_is_key_bound_extension(pvac_pubkey legacy, pvac_pubkey bound) {
    try {
        if (!legacy || !bound)
            return 0;
        return pubkey_is_key_bound_extension_impl(*PK(legacy), *PK(bound)) ? 1 : 0;
    } catch (...) {
        return 0;
    }
}

int pvac_pubkey_is_legacy_v1_profile(pvac_pubkey legacy, pvac_pubkey current) {
    try {
        if (!legacy || !current)
            return 0;
        return pvac::legacy_v1_pubkey_matches(*PK(legacy), *PK(current)) ? 1 : 0;
    } catch (...) {
        return 0;
    }
}

int pvac_pubkey_is_proof_profile(pvac_pubkey a, pvac_pubkey b) {
    try {
        if (!a || !b)
            return 0;
        return pvac::proof_profile_matches(*PK(a), *PK(b)) ? 1 : 0;
    } catch (...) {
        return 0;
    }
}

int pvac_pubkey_matches_secret_profile(
    pvac_pubkey candidate,
    pvac_pubkey current,
    pvac_seckey sk
) {
    try {
        if (!candidate || !current || !sk)
            return 0;
        return pvac::secret_profile_matches(
            *PK(candidate),
            *PK(current),
            *SK(sk)) ? 1 : 0;
    } catch (...) {
        return 0;
    }
}

pvac_zero_proof pvac_make_zero_proof(pvac_pubkey pk, pvac_seckey sk, pvac_cipher ct) {
    auto* zp = new pvac::ZeroProof();
    *zp = pvac::make_zero_proof(*PK(pk), *SK(sk), *CT(ct));
    return zp;
}

int pvac_verify_zero(pvac_pubkey pk, pvac_cipher ct, pvac_zero_proof proof) {
    try {
        return pvac::verify_zero(*PK(pk), *CT(ct), *ZP(proof)) ? 1 : 0;
    } catch (...) {
        return 0;
    }
}

pvac_zero_proof pvac_make_zero_proof_bound(pvac_pubkey pk, pvac_seckey sk, pvac_cipher ct,
                                            uint64_t amount, const uint8_t blinding[32]) {
    pvac::Scalar blind = pvac::sc_reduce256(blinding);
    auto* zp = new pvac::ZeroProof();
    *zp = pvac::make_zero_proof_bound(*PK(pk), *SK(sk), *CT(ct), amount, blind);
    return zp;
}

int pvac_verify_zero_bound(pvac_pubkey pk, pvac_cipher ct, pvac_zero_proof proof,
                            const uint8_t amount_commitment[32]) {
    pvac::RistrettoPoint commit;
    std::memcpy(commit.data(), amount_commitment, 32);
    try {
        pvac::ExtPoint decoded_commit;
        if (!pvac::rist_decode(decoded_commit, commit))
            return 0;
        return pvac::verify_zero_bound(*PK(pk), *CT(ct), *ZP(proof), commit) ? 1 : 0;
    } catch (...) {
        return 0;
    }
}

pvac_zero_proof pvac_make_zero_proof_bound_key_switch(
    pvac_pubkey pk,
    pvac_seckey sk,
    pvac_cipher ct,
    uint64_t amount,
    const uint8_t blinding[32]
) {
    if (!pk || !sk || !ct || !blinding)
        return nullptr;
    try {
        pvac::Scalar blind = pvac::sc_reduce256(blinding);
        auto proof = std::make_unique<pvac::ZeroProof>(
            pvac::make_zero_proof_bound_key_switch(
                *PK(pk),
                *SK(sk),
                *CT(ct),
                amount,
                blind));
        return proof.release();
    } catch (...) {
        return nullptr;
    }
}

int pvac_verify_zero_bound_key_switch(
    pvac_pubkey pk,
    pvac_cipher ct,
    pvac_zero_proof proof,
    const uint8_t amount_commitment[32]
) {
    if (!pk || !ct || !proof || !amount_commitment)
        return 0;
    pvac::RistrettoPoint commit;
    std::memcpy(commit.data(), amount_commitment, 32);
    try {
        pvac::ExtPoint decoded_commit;
        if (!pvac::rist_decode(decoded_commit, commit))
            return 0;
        return pvac::verify_zero_bound_key_switch(
            *PK(pk),
            *CT(ct),
            *ZP(proof),
            commit) ? 1 : 0;
    } catch (...) {
        return 0;
    }
}

pvac_zero_proof pvac_make_bound_range_proof(pvac_pubkey pk, pvac_seckey sk, pvac_cipher ct,
                                            uint64_t amount, const uint8_t blinding[32]) {
    pvac::Scalar blind = pvac::sc_reduce256(blinding);
    auto* zp = new pvac::ZeroProof();
    *zp = pvac::make_zero_proof_bound_range(*PK(pk), *SK(sk), *CT(ct), amount, blind);
    return zp;
}

int pvac_verify_bound_range_commitment(
    pvac_pubkey pk,
    pvac_cipher ct,
    pvac_zero_proof proof,
    const uint8_t amount_commitment[32]) {
    if (!pk || !ct || !proof || !amount_commitment)
        return 0;
    pvac::RistrettoPoint commitment;
    std::memcpy(commitment.data(), amount_commitment, 32);
    try {
        pvac::ExtPoint decoded;
        if (!pvac::rist_decode(decoded, commitment))
            return 0;
        return pvac::verify_zero_bound_range(
            *PK(pk),
            *CT(ct),
            *ZP(proof),
            commitment) ? 1 : 0;
    } catch (...) {
        return 0;
    }
}

void pvac_pedersen_commit(uint64_t amount, const uint8_t blinding[32], uint8_t out[32]) {
    if (!out)
        return;
    pvac::Scalar val = pvac::bp::sc_from_u64(amount);
    pvac::Scalar blind = pvac::sc_reduce256(blinding);
    pvac::RistrettoPoint pt = pvac::pedersen_commit(val, blind);
    std::memcpy(out, pt.data(), 32);
}

int pvac_pedersen_commit_v2(uint64_t amount, const uint8_t blinding[32],
                            uint8_t *out, size_t out_cap, size_t *out_len) {
    if (out_len) *out_len = 32;
    if (!out || out_cap < 32) return -1;
    try {
        pvac::Scalar val = pvac::bp::sc_from_u64(amount);
        pvac::Scalar blind = pvac::sc_reduce256(blinding);
        pvac::RistrettoPoint pt = pvac::pedersen_commit(val, blind);
        std::memcpy(out, pt.data(), 32);
        return 0;
    } catch (...) {
        return -2;
    }
}

int pvac_blinding_add(const uint8_t a[32], const uint8_t b[32], uint8_t out[32]) {
    if (!a || !b || !out)
        return -1;
    pvac::Scalar sa = pvac::sc_reduce256(a);
    pvac::Scalar sb = pvac::sc_reduce256(b);
    pvac::Scalar sr = pvac::sc_add(sa, sb);
    pvac::sc_tobytes(out, sr);
    return 0;
}

int pvac_blinding_sub(const uint8_t a[32], const uint8_t b[32], uint8_t out[32]) {
    if (!a || !b || !out)
        return -1;
    pvac::Scalar sa = pvac::sc_reduce256(a);
    pvac::Scalar sb = pvac::sc_reduce256(b);
    pvac::Scalar sr = pvac::sc_sub(sa, sb);
    pvac::sc_tobytes(out, sr);
    return 0;
}

pvac_range_proof pvac_make_range_proof(pvac_pubkey pk, pvac_seckey sk,
                                       pvac_cipher ct, uint64_t value) {
    auto* rp = new pvac::RangeProof();
    *rp = pvac::make_range_proof(*PK(pk), *SK(sk), *CT(ct), value);
    return rp;
}

int pvac_verify_range(pvac_pubkey pk, pvac_cipher ct, pvac_range_proof proof) {
    try {
        return pvac::verify_range(*PK(pk), *CT(ct), *RP(proof)) ? 1 : 0;
    } catch (...) {
        return 0;
    }
}

uint8_t* pvac_serialize_cipher(pvac_cipher ct, size_t* len) {
    try {
        return copy_bytes(pvac_ser::serialize_cipher(*CT(ct)), len);
    } catch (...) {
        if (len)
            *len = 0;
        return nullptr;
    }
}

uint8_t* pvac_serialize_cipher_public(pvac_cipher ct, size_t* len) {
    try {
        return copy_bytes(pvac_ser::serialize_cipher_public(*CT(ct)), len);
    } catch (...) {
        if (len)
            *len = 0;
        return nullptr;
    }
}

pvac_cipher pvac_deserialize_cipher(const uint8_t* data, size_t len) {
    try {
        auto* ct = new pvac::Cipher();
        *ct = pvac_ser::deserialize_cipher(data, len);
        return ct;
    } catch (const std::exception& e) {
        fprintf(stderr, "[pvac_c_api] deserialize_cipher failed: %s\n", e.what());
        return nullptr;
    } catch (...) {
        fprintf(stderr, "[pvac_c_api] deserialize_cipher failed: unknown\n");
        return nullptr;
    }
}

uint8_t* pvac_serialize_pubkey(pvac_pubkey pk, size_t* len) {
    try {
        return copy_bytes(pvac_ser::serialize_pubkey(*PK(pk)), len);
    } catch (...) {
        if (len)
            *len = 0;
        return nullptr;
    }
}

pvac_pubkey pvac_deserialize_pubkey(const uint8_t* data, size_t len) {
    try {
        auto* pk = new pvac::PubKey();
        *pk = pvac_ser::deserialize_pubkey(data, len);
        return pk;
    } catch (const std::exception& e) {
        fprintf(stderr, "[pvac_c_api] deserialize_pubkey failed: %s\n", e.what());
        return nullptr;
    } catch (...) {
        fprintf(stderr, "[pvac_c_api] deserialize_pubkey failed: unknown\n");
        return nullptr;
    }
}

uint8_t* pvac_serialize_seckey(pvac_seckey sk, size_t* len) {
    try {
        return copy_bytes(pvac_ser::serialize_seckey(*SK(sk)), len);
    } catch (...) {
        if (len)
            *len = 0;
        return nullptr;
    }
}

pvac_seckey pvac_deserialize_seckey(const uint8_t* data, size_t len) {
    try {
        auto* sk = new pvac::SecKey();
        *sk = pvac_ser::deserialize_seckey(data, len);
        return sk;
    } catch (const std::exception& e) {
        fprintf(stderr, "[pvac_c_api] deserialize_seckey failed: %s\n", e.what());
        return nullptr;
    } catch (...) {
        fprintf(stderr, "[pvac_c_api] deserialize_seckey failed: unknown\n");
        return nullptr;
    }
}

uint8_t* pvac_serialize_zero_proof(pvac_zero_proof zp, size_t* len) {
    try {
        pvac_ser::Writer w;
        pvac_ser::write_zero_proof_raw(w, *ZP(zp));
        return copy_bytes(w.buf, len);
    } catch (...) {
        if (len)
            *len = 0;
        return nullptr;
    }
}

uint8_t* pvac_serialize_bound_range_proof(pvac_zero_proof zp, size_t* len) {
    try {
        return copy_bytes(pvac_ser::serialize_bound_range_proof(*ZP(zp)), len);
    } catch (...) {
        if (len)
            *len = 0;
        return nullptr;
    }
}

pvac_zero_proof pvac_deserialize_zero_proof(const uint8_t* data, size_t len) {
    try {
        pvac_ser::Reader r(data, len);
        auto* zp = new pvac::ZeroProof();
        *zp = pvac_ser::read_zero_proof_raw(r);
        if (r.failed) {
            delete zp;
            fprintf(stderr, "[pvac_c_api] deserialize_zero_proof failed: %s\n", r.error);
            return nullptr;
        }
        return zp;
    } catch (const std::exception& e) {
        fprintf(stderr, "[pvac_c_api] deserialize_zero_proof failed: %s\n", e.what());
        return nullptr;
    } catch (...) {
        fprintf(stderr, "[pvac_c_api] deserialize_zero_proof failed: unknown\n");
        return nullptr;
    }
}

uint8_t* pvac_serialize_range_proof(pvac_range_proof rp, size_t* len) {
    try {
        return copy_bytes(pvac_ser::serialize_range_proof(*RP(rp)), len);
    } catch (...) {
        if (len)
            *len = 0;
        return nullptr;
    }
}

pvac_range_proof pvac_deserialize_range_proof(const uint8_t* data, size_t len) {
    try {
        auto* rp = new pvac::RangeProof();
        *rp = pvac_ser::deserialize_range_proof(data, len);
        return rp;
    } catch (const std::exception& e) {
        fprintf(stderr, "[pvac_c_api] deserialize_range_proof failed: %s\n", e.what());
        return nullptr;
    } catch (...) {
        fprintf(stderr, "[pvac_c_api] deserialize_range_proof failed: unknown\n");
        return nullptr;
    }
}

pvac_agg_range_proof pvac_make_aggregated_range_proof(pvac_pubkey pk, pvac_seckey sk,
                                                       pvac_cipher ct, uint64_t value) {
    auto* arp = new pvac::AggregatedRangeProof();
    *arp = pvac::make_aggregated_range_proof(*PK(pk), *SK(sk), *CT(ct), value);
    return arp;
}

int pvac_verify_aggregated_range(pvac_pubkey pk, pvac_cipher ct, pvac_agg_range_proof proof) {
    try {
        return pvac::verify_aggregated_range(*PK(pk), *CT(ct), *ARP(proof)) ? 1 : 0;
    } catch (...) {
        return 0;
    }
}

uint8_t* pvac_serialize_agg_range_proof(pvac_agg_range_proof arp, size_t* len) {
    try {
        return copy_bytes(pvac_ser::serialize_agg_range_proof(*ARP(arp)), len);
    } catch (...) {
        if (len)
            *len = 0;
        return nullptr;
    }
}

pvac_agg_range_proof pvac_deserialize_agg_range_proof(const uint8_t* data, size_t len) {
    try {
        auto* arp = new pvac::AggregatedRangeProof();
        *arp = pvac_ser::deserialize_agg_range_proof(data, len);
        return arp;
    } catch (const std::exception& e) {
        fprintf(stderr, "[pvac_c_api] deserialize_agg_range_proof failed: %s\n", e.what());
        return nullptr;
    }
}

void pvac_free_agg_range_proof(pvac_agg_range_proof p) { delete ARP(p); }

void pvac_aes_kat(uint8_t out[16]) {
    pvac::Sha256 h;
    h.init();
    const char* label = "pvac.aes.kat.key";
    h.update(label, strlen(label));
    uint8_t key[32];
    h.finish(key);

    pvac::AesCtr256 prg;
    prg.init(key, 0);
    alignas(16) uint64_t buf[2];
    buf[0] = prg.next_u64();
    buf[1] = prg.next_u64();
    memcpy(out, buf, 16);
}

void pvac_free_params(pvac_params p) { delete PRM(p); }
void pvac_free_pubkey(pvac_pubkey p) { delete PK(p); }
void pvac_free_seckey(pvac_seckey p) { delete SK(p); }
void pvac_free_cipher(pvac_cipher p) { delete CT(p); }
void pvac_free_zero_proof(pvac_zero_proof p) { delete ZP(p); }
void pvac_free_range_proof(pvac_range_proof p) { delete RP(p); }
void pvac_free_bytes(uint8_t* buf) { std::free(buf); }

}