#include "pvac_c_api.h"

#include "include/pvac/pvac.hpp"
#include "pvac_serialize.hpp"

#include <cstring>
#include <cstdlib>
#include <new>

#define PK(h) (reinterpret_cast<pvac::PubKey*>(h))
#define SK(h) (reinterpret_cast<pvac::SecKey*>(h))
#define CT(h) (reinterpret_cast<pvac::Cipher*>(h))
#define PRM(h) (reinterpret_cast<pvac::Params*>(h))
#define ZP(h) (reinterpret_cast<pvac::ZeroProof*>(h))
#define RP(h) (reinterpret_cast<pvac::RangeProof*>(h))
#define ARP(h) (reinterpret_cast<pvac::AggregatedRangeProof*>(h))

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
    pvac::Fp r = pvac::dec_value(*PK(pk), *SK(sk), *CT(ct));
    return r.lo;
}

void pvac_dec_value_fp(pvac_pubkey pk, pvac_seckey sk, pvac_cipher ct,
                       uint64_t* lo_out, uint64_t* hi_out) {
    pvac::Fp r = pvac::dec_value(*PK(pk), *SK(sk), *CT(ct));
    *lo_out = r.lo;
    *hi_out = r.hi;
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
    auto h = pvac::commit_ct(*PK(pk), *CT(ct));
    std::memcpy(out, h.data(), 32);
}

pvac_zero_proof pvac_make_zero_proof(pvac_pubkey pk, pvac_seckey sk, pvac_cipher ct) {
    auto* zp = new pvac::ZeroProof();
    *zp = pvac::make_zero_proof(*PK(pk), *SK(sk), *CT(ct));
    return zp;
}

int pvac_verify_zero(pvac_pubkey pk, pvac_cipher ct, pvac_zero_proof proof) {
    return pvac::verify_zero(*PK(pk), *CT(ct), *ZP(proof)) ? 1 : 0;
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
    return pvac::verify_zero_bound(*PK(pk), *CT(ct), *ZP(proof), commit) ? 1 : 0;
}

void pvac_pedersen_commit(uint64_t amount, const uint8_t blinding[32], uint8_t out[32]) {
    pvac::Scalar val = pvac::bp::sc_from_u64(amount);
    pvac::Scalar blind = pvac::sc_reduce256(blinding);
    pvac::RistrettoPoint pt = pvac::pedersen_commit(val, blind);
    std::memcpy(out, pt.data(), 32);
}

pvac_range_proof pvac_make_range_proof(pvac_pubkey pk, pvac_seckey sk,
                                       pvac_cipher ct, uint64_t value) {
    auto* rp = new pvac::RangeProof();
    *rp = pvac::make_range_proof(*PK(pk), *SK(sk), *CT(ct), value);
    return rp;
}

int pvac_verify_range(pvac_pubkey pk, pvac_cipher ct, pvac_range_proof proof) {
    return pvac::verify_range(*PK(pk), *CT(ct), *RP(proof)) ? 1 : 0;
}

uint8_t* pvac_serialize_cipher(pvac_cipher ct, size_t* len) {
    auto buf = pvac_ser::serialize_cipher(*CT(ct));
    *len = buf.size();
    auto* out = (uint8_t*)std::malloc(buf.size());
    std::memcpy(out, buf.data(), buf.size());
    return out;
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
    auto buf = pvac_ser::serialize_pubkey(*PK(pk));
    *len = buf.size();
    auto* out = (uint8_t*)std::malloc(buf.size());
    std::memcpy(out, buf.data(), buf.size());
    return out;
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
    auto buf = pvac_ser::serialize_seckey(*SK(sk));
    *len = buf.size();
    auto* out = (uint8_t*)std::malloc(buf.size());
    std::memcpy(out, buf.data(), buf.size());
    return out;
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

    pvac_ser::Writer w;
    pvac_ser::write_zero_proof_raw(w, *ZP(zp));
    *len = w.buf.size();
    auto* out = (uint8_t*)std::malloc(w.buf.size());
    std::memcpy(out, w.buf.data(), w.buf.size());
    return out;
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
    auto buf = pvac_ser::serialize_range_proof(*RP(rp));
    *len = buf.size();
    auto* out = (uint8_t*)std::malloc(buf.size());
    std::memcpy(out, buf.data(), buf.size());
    return out;
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

// ═══ Aggregated Range Proof ═══

pvac_agg_range_proof pvac_make_aggregated_range_proof(pvac_pubkey pk, pvac_seckey sk,
                                                       pvac_cipher ct, uint64_t value) {
    auto* arp = new pvac::AggregatedRangeProof();
    *arp = pvac::make_aggregated_range_proof(*PK(pk), *SK(sk), *CT(ct), value);
    return arp;
}

int pvac_verify_aggregated_range(pvac_pubkey pk, pvac_cipher ct, pvac_agg_range_proof proof) {
    return pvac::verify_aggregated_range(*PK(pk), *CT(ct), *ARP(proof)) ? 1 : 0;
}

uint8_t* pvac_serialize_agg_range_proof(pvac_agg_range_proof arp, size_t* len) {
    auto buf = pvac_ser::serialize_agg_range_proof(*ARP(arp));
    *len = buf.size();
    auto* out = (uint8_t*)std::malloc(buf.size());
    std::memcpy(out, buf.data(), buf.size());
    return out;
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

int pvac_verify_range_any(pvac_pubkey pk, pvac_cipher ct,
                           const uint8_t* proof_data, size_t proof_len) {
    try {
        auto rpa = pvac_ser::deserialize_range_proof_any(proof_data, proof_len);
        if (rpa.format == pvac_ser::RP_OLD)
            return pvac::verify_range(*PK(pk), *CT(ct), rpa.old_proof) ? 1 : 0;
        else
            return pvac::verify_aggregated_range(*PK(pk), *CT(ct), rpa.agg_proof) ? 1 : 0;
    } catch (const std::exception& e) {
        fprintf(stderr, "[pvac_c_api] verify_range_any failed: %s\n", e.what());
        return 0;
    }
}

void pvac_free_agg_range_proof(pvac_agg_range_proof p) { delete ARP(p); }

void pvac_free_params(pvac_params p) { delete PRM(p); }
void pvac_free_pubkey(pvac_pubkey p) { delete PK(p); }
void pvac_free_seckey(pvac_seckey p) { delete SK(p); }
void pvac_free_cipher(pvac_cipher p) { delete CT(p); }
void pvac_free_zero_proof(pvac_zero_proof p) { delete ZP(p); }
void pvac_free_range_proof(pvac_range_proof p) { delete RP(p); }
void pvac_free_bytes(uint8_t* buf) { std::free(buf); }

}
