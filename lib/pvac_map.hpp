#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "../crypto_utils.hpp"

extern "C" {
#include "pvac_c_api.h"
}

namespace octra {

struct CipherLayerMap {
    size_t id = 0;
    uint8_t rule = 0;
    uint32_t parent_a = UINT32_MAX;
    uint32_t parent_b = UINT32_MAX;
    size_t depth = 0;
    size_t edge_count = 0;
    size_t r_pc_count = 0;
    size_t pc_count = 0;
    size_t sigma_samples = 0;
    uint64_t sigma_ones = 0;
    uint64_t sigma_bits = 0;
    bool sigma_exact = false;
    bool has_r_com = false;
};

struct CipherEdgeMap {
    uint32_t layer_id = 0;
    uint16_t idx = 0;
    uint8_t channel = 0;
    size_t weight_slots = 0;
    uint64_t sigma_ones = 0;
    uint64_t sigma_bits = 0;
};

struct CipherMap {
    size_t wire_bytes = 0;
    std::string wire_hash;
    size_t slots = 0;
    size_t c0_count = 0;
    size_t edge_count = 0;
    size_t base_layers = 0;
    size_t prod_layers = 0;
    size_t max_depth = 0;
    size_t sigma_samples = 0;
    uint64_t sigma_ones = 0;
    uint64_t sigma_bits = 0;
    bool sigma_exact = false;
    std::vector<CipherLayerMap> layers;
    std::vector<CipherEdgeMap> edges;
};

namespace PvacMap {

inline constexpr size_t max_wire_bytes = 48u * 1024u * 1024u;
inline constexpr size_t max_edge_samples = 192;
inline constexpr size_t max_sigma_samples = 4096;
inline constexpr const char* prefix = "hfhe_v1|";
using CipherPtr = std::unique_ptr<void, decltype(&pvac_free_cipher)>;

inline int b64_value(uint8_t ch) {
    if (ch >= 'A' && ch <= 'Z') return ch - 'A';
    if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
    if (ch >= '0' && ch <= '9') return ch - '0' + 52;
    if (ch == '+') return 62;
    if (ch == '/') return 63;
    return -1;
}

inline bool decode_b64(const std::string& input, std::vector<uint8_t>& out) {
    out.clear();
    if (input.empty() || input.size() % 4 != 0)
        return false;
    if (input.size() > max_wire_bytes * 4 / 3 + 4)
        return false;
    out.reserve(input.size() / 4 * 3);
    for (size_t i = 0; i < input.size(); i += 4) {
        const bool last = i + 4 == input.size();
        const int a = b64_value(static_cast<uint8_t>(input[i]));
        const int b = b64_value(static_cast<uint8_t>(input[i + 1]));
        if (a < 0 || b < 0)
            return false;
        out.push_back(static_cast<uint8_t>((a << 2) | (b >> 4)));
        if (input[i + 2] == '=') {
            if (!last || input[i + 3] != '=' || (b & 15) != 0)
                return false;
            continue;
        }
        const int c = b64_value(static_cast<uint8_t>(input[i + 2]));
        if (c < 0)
            return false;
        out.push_back(static_cast<uint8_t>((b << 4) | (c >> 2)));
        if (input[i + 3] == '=') {
            if (!last || (c & 3) != 0)
                return false;
            continue;
        }
        const int d = b64_value(static_cast<uint8_t>(input[i + 3]));
        if (d < 0)
            return false;
        out.push_back(static_cast<uint8_t>((c << 6) | d));
    }
    return out.size() <= max_wire_bytes;
}

inline bool read(const std::string& cipher_str,
                 CipherMap& out,
                 std::string& error) {
    out = {};
    error.clear();
    if (cipher_str.rfind(prefix, 0) != 0) {
        error = "ciphertext format is not supported";
        return false;
    }

    std::vector<uint8_t> wire;
    if (!decode_b64(cipher_str.substr(std::strlen(prefix)), wire)) {
        error = "ciphertext encoding is invalid or too large";
        return false;
    }
    CipherPtr cipher(
        pvac_deserialize_cipher(wire.data(), wire.size()),
        &pvac_free_cipher);
    if (!cipher) {
        error = "ciphertext structure is invalid";
        return false;
    }

    pvac_cipher_shape_view shape{};
    int rc = pvac_cipher_inspect_public(
        cipher.get(), &shape, nullptr, 0, nullptr, 0, 0);
    if (rc != 0) {
        error = "ciphertext structure exceeds inspection limits";
        return false;
    }

    std::vector<pvac_cipher_layer_view> layers(shape.layer_count);
    std::vector<pvac_cipher_edge_view> edges(max_edge_samples);
    rc = pvac_cipher_inspect_public(
        cipher.get(),
        &shape,
        layers.data(),
        layers.size(),
        edges.data(),
        edges.size(),
        max_sigma_samples);
    if (rc < 0) {
        error = "ciphertext structure inspection failed";
        return false;
    }

    out.wire_bytes = wire.size();
    out.wire_hash = sha256_hex(std::string(
        reinterpret_cast<const char*>(wire.data()),
        wire.size()));
    out.slots = shape.slots;
    out.c0_count = shape.c0_count;
    out.edge_count = shape.edge_count;
    out.sigma_samples = shape.sampled_edge_count;
    out.sigma_ones = shape.sampled_sigma_ones;
    out.sigma_bits = shape.sampled_sigma_bits;
    out.sigma_exact = shape.sigma_exact != 0;
    out.layers.reserve(layers.size());

    for (size_t i = 0; i < layers.size(); ++i) {
        const auto& raw = layers[i];
        CipherLayerMap layer;
        layer.id = i;
        layer.rule = raw.rule;
        layer.parent_a = raw.parent_a;
        layer.parent_b = raw.parent_b;
        layer.edge_count = raw.edge_count;
        layer.r_pc_count = raw.r_pc_count;
        layer.pc_count = raw.pc_count;
        layer.sigma_samples = raw.sampled_edge_count;
        layer.sigma_ones = raw.sampled_sigma_ones;
        layer.sigma_bits = raw.sampled_sigma_bits;
        layer.sigma_exact = raw.sampled_edge_count == raw.edge_count;
        layer.has_r_com = raw.has_r_com != 0;
        if (raw.rule == static_cast<uint8_t>(0)) {
            ++out.base_layers;
        } else {
            ++out.prod_layers;
            layer.depth = 1 + std::max(
                out.layers[raw.parent_a].depth,
                out.layers[raw.parent_b].depth);
        }
        out.max_depth = std::max(out.max_depth, layer.depth);
        out.layers.push_back(layer);
    }

    out.edges.reserve(static_cast<size_t>(rc));
    for (int i = 0; i < rc; ++i) {
        const auto& raw = edges[static_cast<size_t>(i)];
        CipherEdgeMap edge;
        edge.layer_id = raw.layer_id;
        edge.idx = raw.idx;
        edge.channel = raw.channel;
        edge.weight_slots = raw.weight_slots;
        edge.sigma_ones = raw.sigma_ones;
        edge.sigma_bits = raw.sigma_bits;
        out.edges.push_back(edge);
    }
    return true;
}

}

}