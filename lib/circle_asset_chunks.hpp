#pragma once

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

#include "../crypto_utils.hpp"
#include "../rpc_client.hpp"

namespace octra {

inline constexpr const char* circle_chunk_format = "octra.circle.asset.chunks.v1";
inline constexpr const char* circle_chunk_manifest_type = "application/vnd.octra.circle.chunks+json";
inline constexpr const char* circle_chunk_type = "application/octet-stream";
inline constexpr std::size_t circle_chunk_max_raw = 33554432;
inline constexpr std::size_t circle_chunk_raw = 2097152;
inline constexpr std::size_t circle_chunk_count_max = 32;

inline bool circle_chunk_hash(const std::string& value) {
    if (value.size() != 64) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return std::isdigit(c) || (c >= 'a' && c <= 'f');
    });
}

inline bool circle_chunk_content_type(const std::string& value) {
    return !value.empty() && value.size() <= 256 &&
        std::all_of(value.begin(), value.end(), [](unsigned char c) {
            return c >= 0x20 && c <= 0x7e;
        });
}

inline std::string circle_chunk_index(std::size_t value) {
    std::string index = std::to_string(value);
    index.insert(0, 4 - index.size(), '0');
    return index;
}

inline bool circle_chunk_size(const nlohmann::json& value, std::size_t& out) {
    if (!value.is_string()) return false;
    const std::string raw = value.get<std::string>();
    if (raw.empty() || !std::all_of(raw.begin(), raw.end(), [](unsigned char c) {
        return std::isdigit(c);
    })) return false;
    try {
        const unsigned long long parsed = std::stoull(raw);
        if (parsed > std::numeric_limits<std::size_t>::max()) return false;
        out = static_cast<std::size_t>(parsed);
        return true;
    } catch (...) {
        return false;
    }
}

inline bool circle_chunk_body(const std::string& encoded, std::vector<uint8_t>& raw) {
    raw = base64_decode(encoded);
    return base64_encode(raw.data(), raw.size()) == encoded;
}

inline std::string circle_chunk_digest(const std::vector<uint8_t>& raw) {
    const auto digest = sha256(raw.data(), raw.size());
    return hex_encode(digest.data(), digest.size());
}

template <typename Fetch>
inline RpcResult resolve_circle_asset_with(Fetch fetch, const std::string& path) {
    RpcResult root = fetch(path);
    if (!root.ok || root.result.value("content_type", "") != circle_chunk_manifest_type) {
        return root;
    }
    const std::string encoded = root.result.value("body_b64", "");
    if (encoded.empty() || encoded.size() > 131072) {
        return {false, {}, "invalid circle chunk manifest body"};
    }
    std::vector<uint8_t> manifest_raw;
    if (!circle_chunk_body(encoded, manifest_raw)) {
        return {false, {}, "invalid circle chunk manifest encoding"};
    }
    nlohmann::json manifest;
    try {
        manifest = nlohmann::json::parse(manifest_raw.begin(), manifest_raw.end());
    } catch (...) {
        return {false, {}, "invalid circle chunk manifest json"};
    }
    if (!manifest.is_object() || manifest.value("format", "") != circle_chunk_format) {
        return {false, {}, "invalid circle chunk manifest format"};
    }
    const std::string content_type = manifest.value("content_type", "");
    const std::string encoding = manifest.value("encoding", "");
    const std::string digest = manifest.value("sha256", "");
    std::size_t total = 0;
    if (!circle_chunk_content_type(content_type) || encoding != "identity" ||
        !circle_chunk_hash(digest) || !manifest.contains("size_bytes") ||
        !circle_chunk_size(manifest["size_bytes"], total) || total > circle_chunk_max_raw) {
        return {false, {}, "invalid circle chunk manifest fields"};
    }
    if (!manifest.contains("chunks") || !manifest["chunks"].is_array() ||
        manifest["chunks"].empty() || manifest["chunks"].size() > circle_chunk_count_max) {
        return {false, {}, "invalid circle chunk manifest list"};
    }
    const std::string prefix = "/.octra/chunks/" + digest + "/";
    std::vector<uint8_t> body;
    body.reserve(total);
    std::size_t index = 0;
    for (const auto& item : manifest["chunks"]) {
        if (!item.is_object()) return {false, {}, "invalid circle chunk entry"};
        const std::string chunk_path = item.value("path", "");
        const std::string chunk_hash = item.value("sha256", "");
        std::size_t chunk_size = 0;
        if (chunk_path != prefix + circle_chunk_index(index) || !circle_chunk_hash(chunk_hash) ||
            !item.contains("size_bytes") || !circle_chunk_size(item["size_bytes"], chunk_size) ||
            chunk_size == 0 || chunk_size > circle_chunk_raw || chunk_size > total - body.size()) {
            return {false, {}, "invalid circle chunk entry fields"};
        }
        RpcResult part = fetch(chunk_path);
        if (!part.ok || part.result.value("content_type", "") != circle_chunk_type) {
            return {false, {}, "circle chunk unavailable"};
        }
        std::vector<uint8_t> chunk;
        if (!circle_chunk_body(part.result.value("body_b64", ""), chunk) ||
            chunk.size() != chunk_size || circle_chunk_digest(chunk) != chunk_hash) {
            return {false, {}, "circle chunk verification failed"};
        }
        body.insert(body.end(), chunk.begin(), chunk.end());
        ++index;
    }
    if (body.size() != total || circle_chunk_digest(body) != digest) {
        return {false, {}, "circle asset verification failed"};
    }
    root.result["content_type"] = content_type;
    root.result["encoding"] = encoding;
    root.result["size_bytes"] = std::to_string(body.size());
    root.result["blob_hash"] = digest;
    root.result["body_b64"] = base64_encode(body.data(), body.size());
    root.result["chunked"] = true;
    root.result["chunks"] = manifest["chunks"].size();
    return root;
}

inline RpcResult resolve_circle_asset(RpcClient& rpc,
                                      const std::string& circle_id,
                                      const std::string& path) {
    return resolve_circle_asset_with(
        [&](const std::string& item_path) {
            return rpc.circle_asset(circle_id, item_path);
        },
        path);
}

}