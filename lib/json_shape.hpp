// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once

#include "json.hpp"
#include <unordered_set>
#include <vector>

namespace octra {

class JsonShape : public nlohmann::json_sax<nlohmann::json> {
    struct Frame {
        bool object;
        std::unordered_set<std::string> keys;
    };
    size_t limit_;
    size_t items_ = 0;
    std::vector<Frame> frames_;

    bool item() { return items_++ < limit_; }
    bool start(bool object) {
        if (!item() || frames_.size() >= 64) return false;
        frames_.push_back({object, {}});
        return true;
    }
    bool end(bool object) {
        if (frames_.empty() || frames_.back().object != object) return false;
        frames_.pop_back();
        return true;
    }

public:
    explicit JsonShape(size_t limit = 1000000) : limit_(limit) {}
    bool null() override { return item(); }
    bool boolean(bool) override { return item(); }
    bool number_integer(number_integer_t) override { return item(); }
    bool number_unsigned(number_unsigned_t) override { return item(); }
    bool number_float(number_float_t, const string_t&) override { return item(); }
    bool string(string_t&) override { return item(); }
    bool binary(binary_t&) override { return item(); }
    bool start_object(size_t) override { return start(true); }
    bool start_array(size_t) override { return start(false); }
    bool end_object() override { return end(true); }
    bool end_array() override { return end(false); }
    bool key(string_t& value) override {
        return !frames_.empty() && frames_.back().object && item()
            && frames_.back().keys.insert(value).second;
    }
    bool parse_error(size_t, const std::string&, const nlohmann::detail::exception&) override {
        return false;
    }
};

}