#pragma once

#include <atomic>
#include <cstddef>
#include <string>

#include "../pvac/pvac_c_api.h"

namespace octra {
namespace circle_verifier_policy {

constexpr size_t max_ciphertext_encoded_bytes = 96 * 1024;
constexpr size_t max_proof_encoded_bytes = 64 * 1024;
constexpr size_t max_commitment_encoded_bytes = 64;
constexpr size_t max_base_layers = 2;
constexpr size_t max_layers = 8;
constexpr size_t max_edges = 512;

inline bool ciphertext_size_allowed(const std::string& ciphertext) {
    return !ciphertext.empty()
        && ciphertext.size() <= max_ciphertext_encoded_bytes;
}

inline bool proof_size_allowed(const std::string& proof) {
    return !proof.empty()
        && proof.size() <= max_proof_encoded_bytes;
}

inline bool commitment_size_allowed(const std::string& commitment) {
    return !commitment.empty()
        && commitment.size() <= max_commitment_encoded_bytes;
}

inline bool encoded_size_allowed(const std::string& ciphertext,
                                 const std::string& proof) {
    return ciphertext_size_allowed(ciphertext) && proof_size_allowed(proof);
}

inline bool cipher_shape_allowed(pvac_cipher cipher) {
    pvac_cipher_shape_view shape{};
    const int inspected =
        pvac_cipher_inspect_public(cipher, &shape, nullptr, 0, nullptr, 0, 0);
    const size_t base_layers = pvac_cipher_base_layer_count(cipher);
    return inspected == 0
        && shape.slots == 1
        && shape.c0_count == 1
        && shape.layer_count > 0
        && shape.layer_count <= max_layers
        && shape.edge_count <= max_edges
        && base_layers > 0
        && base_layers <= max_base_layers;
}

class Lane {
    std::atomic<bool> busy_{false};

public:
    class Lease {
        std::atomic<bool>* busy_ = nullptr;

    public:
        Lease() = default;
        explicit Lease(std::atomic<bool>* busy) : busy_(busy) {}
        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;

        Lease(Lease&& other) noexcept : busy_(other.busy_) {
            other.busy_ = nullptr;
        }

        Lease& operator=(Lease&& other) noexcept {
            if (this == &other) return *this;
            if (busy_) busy_->store(false, std::memory_order_release);
            busy_ = other.busy_;
            other.busy_ = nullptr;
            return *this;
        }

        ~Lease() {
            if (busy_) busy_->store(false, std::memory_order_release);
        }

        explicit operator bool() const {
            return busy_ != nullptr;
        }
    };

    Lease try_acquire() {
        bool expected = false;
        if (!busy_.compare_exchange_strong(
                expected,
                true,
                std::memory_order_acq_rel,
                std::memory_order_relaxed)) {
            return Lease();
        }
        return Lease(&busy_);
    }
};

}
}