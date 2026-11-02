// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
// lambda0xE
// Arthur Edelstein
// Denis CMIX

#pragma once
#include "program_args.hpp"

#include <cstddef>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "json.hpp"

namespace octra::program_cli::detail {

inline constexpr size_t max_source_files = 32;
inline constexpr size_t max_source_path_bytes = 256;
inline constexpr size_t max_source_bytes = 65'536;
inline constexpr size_t max_sources_bytes = 262'144;
inline constexpr size_t max_project_bytes = 524'288;
inline constexpr size_t max_params_bytes = 65'536;
inline constexpr size_t max_path_bytes = 4'096;
inline constexpr size_t max_directory_entries = 1'024;
inline constexpr size_t max_envelope_bytes = 2'097'152;
inline constexpr size_t max_certificate_bytes = 1'048'576;
inline constexpr size_t max_package_bytes = 2'360'000;
inline constexpr size_t max_envelope_b64_bytes = ((max_envelope_bytes + 2) / 3) * 4;
inline constexpr size_t max_package_b64_bytes = ((max_package_bytes + 2) / 3) * 4;
inline constexpr size_t max_version_bytes = 128;
inline constexpr size_t max_params_json_items = 4'096;
inline constexpr size_t max_project_json_items = 16'384;
inline constexpr size_t max_certificate_json_items = 65'536;

inline bool ascii_alnum(unsigned char c) {
    return (c >= 'a' && c <= 'z')
        || (c >= 'A' && c <= 'Z')
        || (c >= '0' && c <= '9');
}

inline bool json_depth_ok(std::string_view raw, size_t maximum) {
    size_t depth = 0;
    bool quoted = false;
    bool escaped = false;
    for (char value : raw) {
        const auto c = static_cast<unsigned char>(value);
        if (quoted) {
            if (escaped) escaped = false;
            else if (c == '\\') escaped = true;
            else if (c == '"') quoted = false;
            continue;
        }
        if (c == '"') quoted = true;
        else if (c == '{' || c == '[') {
            if (++depth > maximum) return false;
        } else if ((c == '}' || c == ']') && depth > 0) {
            --depth;
        }
    }
    return true;
}

enum class JsonRoot {
    any,
    array,
    object,
    scalar
};

class JsonShape final : public nlohmann::json_sax<nlohmann::json> {
    struct Frame {
        bool object = false;
        std::set<std::string> keys;
    };

    size_t max_depth_;
    size_t max_items_;
    size_t items_ = 0;
    std::vector<Frame> frames_;
    JsonRoot root_ = JsonRoot::any;
    bool root_seen_ = false;

    bool item() {
        if (items_ >= max_items_) return false;
        ++items_;
        return true;
    }

    bool root(JsonRoot kind) {
        if (!frames_.empty()) return true;
        if (root_seen_) return false;
        root_seen_ = true;
        root_ = kind;
        return true;
    }

    bool scalar_item() {
        return item() && root(JsonRoot::scalar);
    }

public:
    JsonShape(size_t max_depth, size_t max_items)
        : max_depth_(max_depth), max_items_(max_items) {}

    bool null() override {
        return scalar_item();
    }

    bool boolean(bool) override {
        return scalar_item();
    }

    bool number_integer(number_integer_t) override {
        return scalar_item();
    }

    bool number_unsigned(number_unsigned_t) override {
        return scalar_item();
    }

    bool number_float(number_float_t, const string_t&) override {
        return scalar_item();
    }

    bool string(string_t&) override {
        return scalar_item();
    }

    bool binary(binary_t&) override {
        return scalar_item();
    }

    bool start_object(std::size_t) override {
        if (!item()
            || !root(JsonRoot::object)
            || frames_.size() >= max_depth_) return false;
        frames_.push_back({true, {}});
        return true;
    }

    bool key(string_t& value) override {
        if (frames_.empty()
            || !frames_.back().object
            || !item()) return false;
        return frames_.back().keys.insert(value).second;
    }

    bool end_object() override {
        if (frames_.empty() || !frames_.back().object) return false;
        frames_.pop_back();
        return true;
    }

    bool start_array(std::size_t) override {
        if (!item()
            || !root(JsonRoot::array)
            || frames_.size() >= max_depth_) return false;
        frames_.push_back({false, {}});
        return true;
    }

    bool end_array() override {
        if (frames_.empty() || frames_.back().object) return false;
        frames_.pop_back();
        return true;
    }

    bool parse_error(
        std::size_t,
        const std::string&,
        const nlohmann::detail::exception&) override {
        return false;
    }

    bool complete(JsonRoot expected) const {
        return root_seen_
            && frames_.empty()
            && (expected == JsonRoot::any || expected == root_);
    }
};

inline bool json_shape_ok(
    std::string_view raw,
    size_t max_depth,
    size_t max_items,
    JsonRoot root) {
    JsonShape shape(max_depth, max_items);
    return nlohmann::json::sax_parse(raw.begin(), raw.end(), &shape)
        && shape.complete(root);
}

inline bool params_json_ok(const std::string& raw, std::string& error) {
    if (raw.size() > max_params_bytes) {
        error = "Program parameters exceed limit";
        return false;
    }
    if (!octra::program_args(raw) || !json_shape_ok(
            raw,
            32,
            max_params_json_items,
            JsonRoot::array)) {
        error = "Program parameters are invalid JSON";
        return false;
    }
    return true;
}

}