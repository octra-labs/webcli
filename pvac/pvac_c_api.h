#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void* pvac_params;
typedef void* pvac_pubkey;
typedef void* pvac_seckey;
typedef void* pvac_cipher;
typedef void* pvac_zero_proof;
typedef void* pvac_range_proof;

typedef struct {
    size_t slots;
    size_t layer_count;
    size_t edge_count;
    size_t c0_count;
    size_t sampled_edge_count;
    uint64_t sampled_sigma_ones;
    uint64_t sampled_sigma_bits;
    int sigma_exact;
} pvac_cipher_shape_view;

typedef struct {
    uint8_t rule;
    uint32_t parent_a;
    uint32_t parent_b;
    size_t edge_count;
    size_t r_pc_count;
    size_t pc_count;
    size_t sampled_edge_count;
    uint64_t sampled_sigma_ones;
    uint64_t sampled_sigma_bits;
    int has_r_com;
} pvac_cipher_layer_view;

typedef struct {
    uint32_t layer_id;
    uint16_t idx;
    uint8_t channel;
    size_t weight_slots;
    uint64_t sigma_bits;
    uint64_t sigma_ones;
} pvac_cipher_edge_view;

pvac_params pvac_default_params(void);
void pvac_keygen_from_seed(pvac_params prm, const uint8_t seed[32],
                           pvac_pubkey* pk_out, pvac_seckey* sk_out);
pvac_cipher pvac_enc_value_seeded(pvac_pubkey pk, pvac_seckey sk,
                                  uint64_t val, const uint8_t seed[32]);
pvac_cipher pvac_enc_zero_seeded(pvac_pubkey pk, pvac_seckey sk,
                                 const uint8_t seed[32]);
uint64_t pvac_dec_value(pvac_pubkey pk, pvac_seckey sk, pvac_cipher ct);
int pvac_dec_value_i64(pvac_pubkey pk, pvac_seckey sk, pvac_cipher ct,
                       int64_t* value_out);
int pvac_dec_value_legacy_i64(pvac_pubkey pk, pvac_seckey sk, pvac_cipher ct,
                              int64_t* value_out);
void pvac_dec_value_fp(pvac_pubkey pk, pvac_seckey sk, pvac_cipher ct,
                       uint64_t* lo_out, uint64_t* hi_out);
pvac_cipher pvac_enc_value_fp_seeded(pvac_pubkey pk, pvac_seckey sk,
                                     uint64_t lo, uint64_t hi,
                                     const uint8_t seed[32]);
pvac_cipher pvac_ct_add(pvac_pubkey pk, pvac_cipher a, pvac_cipher b);
pvac_cipher pvac_ct_sub(pvac_pubkey pk, pvac_cipher a, pvac_cipher b);
pvac_cipher pvac_ct_mul_seeded(pvac_pubkey pk, pvac_cipher a, pvac_cipher b, const uint8_t seed[32]);
pvac_cipher pvac_ct_scale(pvac_pubkey pk, pvac_cipher ct, int64_t scalar);
pvac_cipher pvac_ct_add_const(pvac_pubkey pk, pvac_cipher ct, uint64_t k_lo, uint64_t k_hi);
pvac_cipher pvac_ct_sub_const(pvac_pubkey pk, pvac_cipher ct, uint64_t k);
pvac_cipher pvac_ct_div_const(pvac_pubkey pk, pvac_cipher ct, uint64_t k_lo, uint64_t k_hi);
pvac_cipher pvac_ct_square_seeded(pvac_pubkey pk, pvac_cipher ct, const uint8_t seed[32]);
void pvac_commit_ct(pvac_pubkey pk, pvac_cipher ct, uint8_t out[32]);
int pvac_commit_ct_v2(pvac_pubkey pk, pvac_cipher ct, uint8_t *out, size_t out_cap, size_t *out_len);
int pvac_cipher_has_key_bound_material(pvac_cipher ct);
int pvac_cipher_has_canonical_r_com(pvac_pubkey pk, pvac_cipher ct);
size_t pvac_cipher_base_layer_count(pvac_cipher ct);
int pvac_cipher_inspect_public(pvac_cipher ct,
                               pvac_cipher_shape_view* shape,
                               pvac_cipher_layer_view* layers,
                               size_t layer_cap,
                               pvac_cipher_edge_view* edges,
                               size_t edge_cap,
                               size_t sigma_sample_cap);
int pvac_pubkey_is_key_bound_extension(pvac_pubkey legacy, pvac_pubkey bound);
int pvac_pubkey_is_legacy_v1_profile(pvac_pubkey legacy, pvac_pubkey current);
int pvac_pubkey_is_proof_profile(pvac_pubkey a, pvac_pubkey b);

pvac_zero_proof pvac_make_zero_proof(pvac_pubkey pk, pvac_seckey sk, pvac_cipher ct);
int pvac_verify_zero(pvac_pubkey pk, pvac_cipher ct, pvac_zero_proof proof);

pvac_zero_proof pvac_make_zero_proof_bound(pvac_pubkey pk, pvac_seckey sk, pvac_cipher ct,
                                            uint64_t amount, const uint8_t blinding[32]);
int pvac_verify_zero_bound(pvac_pubkey pk, pvac_cipher ct, pvac_zero_proof proof,
                            const uint8_t amount_commitment[32]);
pvac_zero_proof pvac_make_bound_range_proof(pvac_pubkey pk, pvac_seckey sk, pvac_cipher ct,
                                            uint64_t amount, const uint8_t blinding[32]);
int pvac_verify_bound_range(pvac_pubkey pk, pvac_cipher ct, pvac_zero_proof proof);

void pvac_pedersen_commit(uint64_t amount, const uint8_t blinding[32], uint8_t out[32]);
int pvac_pedersen_commit_v2(uint64_t amount, const uint8_t blinding[32],
                            uint8_t *out, size_t out_cap, size_t *out_len);
int pvac_blinding_add(const uint8_t a[32], const uint8_t b[32], uint8_t out[32]);
int pvac_blinding_sub(const uint8_t a[32], const uint8_t b[32], uint8_t out[32]);

pvac_range_proof pvac_make_range_proof(pvac_pubkey pk, pvac_seckey sk,
                                       pvac_cipher ct, uint64_t value);
int pvac_verify_range(pvac_pubkey pk, pvac_cipher ct, pvac_range_proof proof);

typedef void* pvac_agg_range_proof;
pvac_agg_range_proof pvac_make_aggregated_range_proof(pvac_pubkey pk, pvac_seckey sk,
                                                       pvac_cipher ct, uint64_t value);
int pvac_verify_aggregated_range(pvac_pubkey pk, pvac_cipher ct, pvac_agg_range_proof proof);
uint8_t* pvac_serialize_agg_range_proof(pvac_agg_range_proof arp, size_t* len);
pvac_agg_range_proof pvac_deserialize_agg_range_proof(const uint8_t* data, size_t len);
void pvac_free_agg_range_proof(pvac_agg_range_proof p);
int pvac_verify_range_any(pvac_pubkey pk, pvac_cipher ct,
                           const uint8_t* proof_data, size_t proof_len);

uint8_t* pvac_serialize_cipher(pvac_cipher ct, size_t* len);
uint8_t* pvac_serialize_cipher_public(pvac_cipher ct, size_t* len);
pvac_cipher pvac_deserialize_cipher(const uint8_t* data, size_t len);
uint8_t* pvac_serialize_pubkey(pvac_pubkey pk, size_t* len);
pvac_pubkey pvac_deserialize_pubkey(const uint8_t* data, size_t len);
uint8_t* pvac_serialize_seckey(pvac_seckey sk, size_t* len);
pvac_seckey pvac_deserialize_seckey(const uint8_t* data, size_t len);
uint8_t* pvac_serialize_zero_proof(pvac_zero_proof zp, size_t* len);
uint8_t* pvac_serialize_bound_range_proof(pvac_zero_proof zp, size_t* len);
pvac_zero_proof pvac_deserialize_zero_proof(const uint8_t* data, size_t len);
uint8_t* pvac_serialize_range_proof(pvac_range_proof rp, size_t* len);
pvac_range_proof pvac_deserialize_range_proof(const uint8_t* data, size_t len);

void pvac_free_params(pvac_params p);
void pvac_free_pubkey(pvac_pubkey p);
void pvac_free_seckey(pvac_seckey p);
void pvac_free_cipher(pvac_cipher p);
void pvac_free_zero_proof(pvac_zero_proof p);
void pvac_free_range_proof(pvac_range_proof p);
void pvac_free_bytes(uint8_t* buf);

void pvac_aes_kat(uint8_t out[16]);

#ifdef __cplusplus
}

#endif