// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once
#include <array>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include "json.hpp"
#include "../crypto_utils.hpp"
#include "tx_builder.hpp"

namespace octra {

struct ResourceComputeIntent {
    uint64_t unit_price = 0;
    uint64_t fee_cap = 0;
    std::string chain_id;
    std::string circle_id;
    uint64_t model_epoch = 0;
    std::string model_state_root;
    std::string graph_root;
    std::string model_root;
    std::string program_root;
    std::string executor_root;
    std::string caller;
    std::array<uint8_t, 32> caller_public_key{};
    std::string session_id;
    uint64_t sequence = 0;
    uint64_t valid_until = 0;
    uint32_t fuel_limit = 0;
    uint32_t guest_bytes = 0;
    uint32_t memory_bytes = 0;
    std::string method_name;
    std::string params_json;
    uint32_t max_output_bytes = 0;
};

inline bool compute_hash32(const std::string& value) {
    if (value.size() != 64) return false;
    for (unsigned char c : value) {
        if ((c < '0' || c > '9') && (c < 'a' || c > 'f')) return false;
    }
    return true;
}

inline void compute_put_u32(std::string& output, uint32_t value) {
    output.push_back(static_cast<char>((value >> 24) & 0xff));
    output.push_back(static_cast<char>((value >> 16) & 0xff));
    output.push_back(static_cast<char>((value >> 8) & 0xff));
    output.push_back(static_cast<char>(value & 0xff));
}

inline void compute_put_u64(std::string& output, uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        output.push_back(static_cast<char>((value >> shift) & 0xff));
    }
}

inline void compute_put_string(std::string& output, const std::string& value) {
    if (value.size() > std::numeric_limits<uint32_t>::max()) {
        throw std::invalid_argument("resource compute string exceeds encoding limit");
    }
    compute_put_u32(output, static_cast<uint32_t>(value.size()));
    output.append(value);
}

inline void compute_put_hash32(std::string& output, const std::string& value) {
    if (!compute_hash32(value)) {
        throw std::invalid_argument("resource compute hash refused");
    }
    const auto raw = hex_decode(value);
    output.append(reinterpret_cast<const char*>(raw.data()), raw.size());
}

inline std::array<uint8_t, 32> compute_domain_hash(
        const std::string& domain,
        const std::string& payload) {
    std::string encoded;
    encoded.reserve(domain.size() + 1 + payload.size());
    encoded.append(domain);
    encoded.push_back('\0');
    encoded.append(payload);
    return sha256(reinterpret_cast<const uint8_t*>(encoded.data()), encoded.size());
}

inline std::array<uint8_t, 32> resource_compute_input_hash(
        const std::string& method_name,
        const std::string& params_json) {
    std::string encoded;
    compute_put_string(encoded, method_name);
    compute_put_string(encoded, params_json);
    return compute_domain_hash("octra:resource_compute_input", encoded);
}

inline std::array<uint8_t, 32> resource_compute_intent_hash(
        const ResourceComputeIntent& intent) {
    if (intent.unit_price == 0 || intent.fee_cap == 0
        || intent.fee_cap > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())
        || intent.fuel_limit == 0 || intent.unit_price > intent.fee_cap / intent.fuel_limit) {
        throw std::invalid_argument("resource compute fee limit refused");
    }
    if (intent.memory_bytes == 0 || intent.memory_bytes > 2147483648U) {
        throw std::invalid_argument("resource compute memory refused");
    }
    if (intent.guest_bytes < 65536U || intent.guest_bytes > 67108864U
        || intent.guest_bytes % 65536U != 0) {
        throw std::invalid_argument("resource compute pages refused");
    }
    if (intent.fuel_limit == 0 || intent.fuel_limit > 2000000000U) {
        throw std::invalid_argument("resource compute fuel refused");
    }
    if (intent.valid_until < intent.model_epoch
        || intent.valid_until > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
        throw std::invalid_argument("resource compute expiry refused");
    }
    if (intent.chain_id.empty() || intent.chain_id.size() > 128) {
        throw std::invalid_argument("resource compute chain id refused");
    }
    if (intent.circle_id.empty() || intent.circle_id.size() > 128) {
        throw std::invalid_argument("resource compute circle id refused");
    }
    if (intent.caller.empty() || intent.caller.size() > 128) {
        throw std::invalid_argument("resource compute caller refused");
    }
    if (intent.method_name.empty() || intent.method_name.size() > 64) {
        throw std::invalid_argument("resource compute method refused");
    }
    if (intent.params_json.size() > 65536) {
        throw std::invalid_argument("resource compute parameters exceed limit");
    }
    const size_t input_bytes = intent.method_name.size() + intent.params_json.size();
    if (input_bytes > std::numeric_limits<uint32_t>::max()) {
        throw std::invalid_argument("resource compute input exceeds encoding limit");
    }
    if (intent.max_output_bytes == 0 || intent.max_output_bytes > 262144) {
        throw std::invalid_argument("resource compute output limit refused");
    }
    const auto input_hash = resource_compute_input_hash(
        intent.method_name,
        intent.params_json);
    std::string encoded;
    compute_put_string(encoded, intent.chain_id);
    compute_put_string(encoded, intent.circle_id);
    compute_put_u64(encoded, intent.model_epoch);
    compute_put_hash32(encoded, intent.model_state_root);
    compute_put_hash32(encoded, intent.graph_root);
    compute_put_hash32(encoded, intent.model_root);
    compute_put_hash32(encoded, intent.program_root);
    compute_put_hash32(encoded, intent.executor_root);
    compute_put_string(encoded, intent.caller);
    encoded.append(
        reinterpret_cast<const char*>(intent.caller_public_key.data()),
        intent.caller_public_key.size());
    compute_put_hash32(encoded, intent.session_id);
    compute_put_u64(encoded, intent.sequence);
    encoded.append(reinterpret_cast<const char*>(input_hash.data()), input_hash.size());
    compute_put_u32(encoded, static_cast<uint32_t>(input_bytes));
    compute_put_u32(encoded, intent.max_output_bytes);
    const auto body = compute_domain_hash("octra:resource_compute_intent", encoded);
    std::string scoped(reinterpret_cast<const char*>(body.data()), body.size());
    compute_put_u64(scoped, intent.valid_until);
    const auto timed = compute_domain_hash("octra:compute_intent_expiry", scoped);
    scoped.assign(reinterpret_cast<const char*>(timed.data()), timed.size());
    compute_put_u32(scoped, intent.fuel_limit);
    const auto metered = compute_domain_hash("octra:compute_intent_fuel", scoped);
    scoped.assign(reinterpret_cast<const char*>(metered.data()), metered.size());
    compute_put_u32(scoped, intent.guest_bytes);
    const auto paged = compute_domain_hash("octra:compute_intent_guest", scoped);
    scoped.assign(reinterpret_cast<const char*>(paged.data()), paged.size());
    compute_put_u32(scoped, intent.memory_bytes);
    const auto memory = compute_domain_hash("octra:compute_intent_memory", scoped);
    scoped.assign(reinterpret_cast<const char*>(memory.data()), memory.size());
    compute_put_u64(scoped, intent.unit_price);
    compute_put_u64(scoped, intent.fee_cap);
    return compute_domain_hash("octra:compute_intent_fee", scoped);
}

inline nlohmann::json signed_resource_compute_params(
        const ResourceComputeIntent& intent,
        const std::string& caller_public_key_b64,
        const uint8_t secret_key[64]) {
    const auto digest = resource_compute_intent_hash(intent);
    nlohmann::json result;
    result["caller"] = intent.caller;
    result["valid_until"] = std::to_string(intent.valid_until);
    result["fuel_limit"] = intent.fuel_limit;
    result["guest_bytes"] = intent.guest_bytes;
    result["memory_bytes"] = intent.memory_bytes;
    result["unit_price"] = std::to_string(intent.unit_price);
    result["fee_cap"] = std::to_string(intent.fee_cap);
    result["caller_public_key"] = caller_public_key_b64;
    result["caller_signature"] = ed25519_sign_detached(
        digest.data(), digest.size(), secret_key);
    result["circle_id"] = intent.circle_id;
    result["executor_root"] = intent.executor_root;
    result["graph_root"] = intent.graph_root;
    result["max_output_bytes"] = intent.max_output_bytes;
    result["method_name"] = intent.method_name;
    result["model_epoch"] = std::to_string(intent.model_epoch);
    result["model_root"] = intent.model_root;
    result["model_state_root"] = intent.model_state_root;
    result["params_json"] = intent.params_json;
    result["program_root"] = intent.program_root;
    result["sequence"] = std::to_string(intent.sequence);
    result["session_id"] = intent.session_id;
    return result;
}

struct ComputeRead {
    std::string chain_id;
    std::string node_id;
    std::string caller;
    std::array<uint8_t, 32> public_key{};
    std::string job_id;
    uint64_t epoch_id = 0;
    uint64_t expires_epoch = 0;
};

inline std::array<uint8_t, 32> compute_read_hash(const ComputeRead& read) {
    if (read.chain_id.empty() || read.chain_id.size() > 128
        || read.node_id.empty() || read.node_id.size() > 128
        || read.caller != derive_address_from_pubkey(read.public_key.data())
        || read.epoch_id > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())
        || read.expires_epoch > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())
        || read.expires_epoch < read.epoch_id
        || read.expires_epoch - read.epoch_id > 16) {
        throw std::invalid_argument("compute read scope refused");
    }
    std::string encoded;
    compute_put_string(encoded, read.chain_id);
    compute_put_string(encoded, read.node_id);
    compute_put_string(encoded, read.caller);
    encoded.append(reinterpret_cast<const char*>(read.public_key.data()), read.public_key.size());
    compute_put_hash32(encoded, read.job_id);
    compute_put_u64(encoded, read.epoch_id);
    compute_put_u64(encoded, read.expires_epoch);
    return compute_domain_hash("octra:compute_read", encoded);
}

inline nlohmann::json signed_compute_read(const ComputeRead& read, const uint8_t secret_key[64]) {
    const auto digest = compute_read_hash(read);
    return {
        {"chain_id", read.chain_id},
        {"node_id", read.node_id},
        {"caller", read.caller},
        {"caller_public_key", base64_encode(read.public_key.data(), read.public_key.size())},
        {"caller_signature", ed25519_sign_detached(digest.data(), digest.size(), secret_key)},
        {"job_id", read.job_id},
        {"epoch_id", std::to_string(read.epoch_id)},
        {"expires_epoch", std::to_string(read.expires_epoch)}
    };
}

class ResourceComputeWeight {
public:
    ResourceComputeWeight(uint64_t value = 0) {
        do {
            limbs_.push_back(static_cast<uint32_t>(value % radix));
            value /= radix;
        } while (value != 0);
    }

    static ResourceComputeWeight decimal(const std::string& text) {
        if (text.empty() || (text.size() > 1 && text.front() == '0')) {
            throw std::invalid_argument("resource compute weight differs");
        }
        ResourceComputeWeight value;
        value.limbs_.assign(1, 0);
        for (unsigned char byte : text) {
            if (byte < '0' || byte > '9') {
                throw std::invalid_argument("resource compute weight differs");
            }
            value.multiply(10);
            value.add(static_cast<uint32_t>(byte - '0'));
        }
        value.normalize();
        return value;
    }

    std::string decimal() const {
        std::ostringstream output;
        output << limbs_.back();
        for (size_t index = limbs_.size() - 1; index > 0; --index) {
            output << std::setw(9) << std::setfill('0') << limbs_[index - 1];
        }
        return output.str();
    }

    ResourceComputeWeight& operator+=(const ResourceComputeWeight& other) {
        const size_t count = std::max(limbs_.size(), other.limbs_.size());
        limbs_.resize(count, 0);
        uint64_t carry = 0;
        for (size_t index = 0; index < count; ++index) {
            const uint64_t right = index < other.limbs_.size() ? other.limbs_[index] : 0;
            const uint64_t sum = static_cast<uint64_t>(limbs_[index]) + right + carry;
            limbs_[index] = static_cast<uint32_t>(sum % radix);
            carry = sum / radix;
        }
        if (carry != 0) limbs_.push_back(static_cast<uint32_t>(carry));
        return *this;
    }

    friend ResourceComputeWeight operator+(
            ResourceComputeWeight left,
            const ResourceComputeWeight& right) {
        left += right;
        return left;
    }

    friend ResourceComputeWeight operator*(ResourceComputeWeight value, uint32_t factor) {
        value.multiply(factor);
        return value;
    }

    friend ResourceComputeWeight operator/(ResourceComputeWeight value, uint32_t divisor) {
        value.divide(divisor);
        return value;
    }

    friend bool operator==(const ResourceComputeWeight& left, const ResourceComputeWeight& right) {
        return left.limbs_ == right.limbs_;
    }

    friend bool operator!=(const ResourceComputeWeight& left, const ResourceComputeWeight& right) {
        return !(left == right);
    }

    friend bool operator<(const ResourceComputeWeight& left, const ResourceComputeWeight& right) {
        if (left.limbs_.size() != right.limbs_.size()) {
            return left.limbs_.size() < right.limbs_.size();
        }
        for (size_t index = left.limbs_.size(); index > 0; --index) {
            if (left.limbs_[index - 1] != right.limbs_[index - 1]) {
                return left.limbs_[index - 1] < right.limbs_[index - 1];
            }
        }
        return false;
    }

    friend bool operator>(const ResourceComputeWeight& left, const ResourceComputeWeight& right) {
        return right < left;
    }

    friend bool operator<=(const ResourceComputeWeight& left, const ResourceComputeWeight& right) {
        return !(right < left);
    }

    friend bool operator>=(const ResourceComputeWeight& left, const ResourceComputeWeight& right) {
        return !(left < right);
    }

private:
    static constexpr uint64_t radix = 1000000000ULL;
    std::vector<uint32_t> limbs_;

    void normalize() {
        while (limbs_.size() > 1 && limbs_.back() == 0) limbs_.pop_back();
    }

    void multiply(uint32_t factor) {
        uint64_t carry = 0;
        for (uint32_t& limb : limbs_) {
            const uint64_t product = static_cast<uint64_t>(limb) * factor + carry;
            limb = static_cast<uint32_t>(product % radix);
            carry = product / radix;
        }
        if (carry != 0) limbs_.push_back(static_cast<uint32_t>(carry));
        normalize();
    }

    void add(uint32_t value) {
        uint64_t carry = value;
        size_t index = 0;
        while (carry != 0) {
            if (index == limbs_.size()) limbs_.push_back(0);
            const uint64_t sum = static_cast<uint64_t>(limbs_[index]) + carry;
            limbs_[index] = static_cast<uint32_t>(sum % radix);
            carry = sum / radix;
            ++index;
        }
    }

    void divide(uint32_t divisor) {
        if (divisor == 0) throw std::invalid_argument("resource compute weight divisor is zero");
        uint64_t remainder = 0;
        for (size_t index = limbs_.size(); index > 0; --index) {
            const uint64_t value = remainder * radix + limbs_[index - 1];
            limbs_[index - 1] = static_cast<uint32_t>(value / divisor);
            remainder = value % divisor;
        }
        normalize();
    }
};

inline std::string compute_hash_hex(const std::array<uint8_t, 32>& value) {
    return hex_encode(value.data(), value.size());
}

inline bool compute_exact_fields(
        const nlohmann::json& value,
        const std::set<std::string>& expected) {
    if (!value.is_object()) return false;
    std::set<std::string> actual;
    for (auto it = value.begin(); it != value.end(); ++it) {
        actual.insert(it.key());
    }
    return actual == expected;
}

inline uint64_t compute_decimal_u64(
        const nlohmann::json& value,
        const std::string& name) {
    if (!value.is_string()) {
        throw std::invalid_argument(name + " must be a decimal string");
    }
    const std::string text = value.get<std::string>();
    if (text.empty() || (text.size() > 1 && text.front() == '0')) {
        throw std::invalid_argument(name + " differs");
    }
    uint64_t result = 0;
    for (unsigned char byte : text) {
        if (byte < '0' || byte > '9') {
            throw std::invalid_argument(name + " differs");
        }
        const uint64_t digit = static_cast<uint64_t>(byte - '0');
        if (result > (std::numeric_limits<uint64_t>::max() - digit) / 10) {
            throw std::invalid_argument(name + " exceeds uint64");
        }
        result = result * 10 + digit;
    }
    return result;
}

inline uint32_t compute_json_u32(
        const nlohmann::json& value,
        const std::string& name) {
    if (!value.is_number_unsigned() && !value.is_number_integer()) {
        throw std::invalid_argument(name + " must be an integer");
    }
    const int64_t signed_value = value.get<int64_t>();
    if (signed_value < 0
        || static_cast<uint64_t>(signed_value) > std::numeric_limits<uint32_t>::max()) {
        throw std::invalid_argument(name + " exceeds uint32");
    }
    return static_cast<uint32_t>(signed_value);
}

inline ResourceComputeWeight compute_decimal_weight(
        const nlohmann::json& value,
        const std::string& name) {
    if (!value.is_string()) {
        throw std::invalid_argument(name + " must be a decimal string");
    }
    const std::string text = value.get<std::string>();
    if (text.empty() || (text.size() > 1 && text.front() == '0')) {
        throw std::invalid_argument(name + " differs");
    }
    try {
        return ResourceComputeWeight::decimal(text);
    } catch (...) {
        throw std::invalid_argument(name + " differs");
    }
}

inline std::string compute_weight_string(const ResourceComputeWeight& value) {
    return value.decimal();
}

inline std::array<uint8_t, 32> resource_compute_request_hash(
        const nlohmann::json& request) {
    std::set<std::string> fields = {
        "caller", "chain_id", "circle_id", "epoch_id", "executor_root",
        "expires_epoch", "graph_root", "input_bytes", "input_hash",
        "max_output_bytes", "model_epoch", "model_root", "model_state_root",
        "program_root", "selection_root", "sequence", "session_id",
        "state_root", "validator_set_root"
    };
    if (request.contains("fuel_limit")) fields.insert("fuel_limit");
    if (request.contains("guest_bytes")) fields.insert("guest_bytes");
    if (request.contains("memory_bytes")) fields.insert("memory_bytes");
    if (request.contains("unit_price")) fields.insert("unit_price");
    if (request.contains("fee_cap")) fields.insert("fee_cap");
    if (request.contains("unit_price") != request.contains("fee_cap")
        || (request.contains("unit_price") && !request.contains("memory_bytes"))) {
        throw std::invalid_argument("resource compute fee fields differ");
    }
    if (request.contains("memory_bytes") && !request.contains("guest_bytes")) {
        throw std::invalid_argument("resource compute pages required");
    }
    if (request.contains("guest_bytes") && !request.contains("fuel_limit")) {
        throw std::invalid_argument("resource compute fuel required");
    }
    if (!compute_exact_fields(request, fields)) {
        throw std::invalid_argument("resource compute request fields differ");
    }
    const std::array<std::string, 4> strings = {
        "chain_id", "circle_id", "caller", "model_root"
    };
    for (const auto& name : strings) {
        if (!request[name].is_string()) {
            throw std::invalid_argument("resource compute request string differs");
        }
    }
    const uint64_t epoch_id = compute_decimal_u64(request["epoch_id"], "epoch id");
    const uint64_t expires_epoch = compute_decimal_u64(request["expires_epoch"], "expires epoch");
    const uint64_t model_epoch = compute_decimal_u64(request["model_epoch"], "model epoch");
    const uint64_t sequence = compute_decimal_u64(request["sequence"], "sequence");
    const uint32_t input_bytes = compute_json_u32(request["input_bytes"], "input bytes");
    const uint32_t max_output_bytes = compute_json_u32(request["max_output_bytes"], "output bytes");
    if (expires_epoch < epoch_id || model_epoch > epoch_id
        || input_bytes == 0 || max_output_bytes == 0 || max_output_bytes > 1048576) {
        throw std::invalid_argument("resource compute request interval differs");
    }
    std::string encoded;
    compute_put_string(encoded, request["chain_id"].get<std::string>());
    compute_put_u64(encoded, epoch_id);
    compute_put_u64(encoded, expires_epoch);
    compute_put_hash32(encoded, request["validator_set_root"].get<std::string>());
    compute_put_hash32(encoded, request["selection_root"].get<std::string>());
    compute_put_string(encoded, request["circle_id"].get<std::string>());
    compute_put_hash32(encoded, request["state_root"].get<std::string>());
    compute_put_u64(encoded, model_epoch);
    compute_put_hash32(encoded, request["model_state_root"].get<std::string>());
    compute_put_hash32(encoded, request["graph_root"].get<std::string>());
    compute_put_hash32(encoded, request["model_root"].get<std::string>());
    compute_put_hash32(encoded, request["program_root"].get<std::string>());
    compute_put_hash32(encoded, request["executor_root"].get<std::string>());
    compute_put_string(encoded, request["caller"].get<std::string>());
    compute_put_hash32(encoded, request["session_id"].get<std::string>());
    compute_put_u64(encoded, sequence);
    compute_put_hash32(encoded, request["input_hash"].get<std::string>());
    compute_put_u32(encoded, input_bytes);
    compute_put_u32(encoded, max_output_bytes);
    const auto body = compute_domain_hash("octra:resource_compute_request", encoded);
    if (!request.contains("fuel_limit")) return body;
    const auto fuel = compute_json_u32(request["fuel_limit"], "fuel limit");
    if (fuel == 0 || fuel > 2000000000U) {
        throw std::invalid_argument("resource compute fuel refused");
    }
    encoded.assign(reinterpret_cast<const char*>(body.data()), body.size());
    compute_put_u32(encoded, fuel);
    const auto metered = compute_domain_hash("octra:compute_request_fuel", encoded);
    if (!request.contains("guest_bytes")) return metered;
    const auto bytes = compute_json_u32(request["guest_bytes"], "guest bytes");
    if (bytes < 65536U || bytes > 67108864U || bytes % 65536U != 0) {
        throw std::invalid_argument("resource compute pages refused");
    }
    encoded.assign(reinterpret_cast<const char*>(metered.data()), metered.size());
    compute_put_u32(encoded, bytes);
    const auto paged = compute_domain_hash("octra:compute_request_guest", encoded);
    if (!request.contains("memory_bytes")) return paged;
    const auto memory = compute_json_u32(request["memory_bytes"], "memory bytes");
    if (memory == 0 || memory > 2147483648U) {
        throw std::invalid_argument("resource compute memory refused");
    }
    encoded.assign(reinterpret_cast<const char*>(paged.data()), paged.size());
    compute_put_u32(encoded, memory);
    const auto scoped = compute_domain_hash("octra:compute_request_memory", encoded);
    if (!request.contains("unit_price")) return scoped;
    const auto price = compute_decimal_u64(request["unit_price"], "unit price");
    const auto cap = compute_decimal_u64(request["fee_cap"], "fee cap");
    if (price == 0 || cap == 0 || cap > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())
        || price > cap / fuel) {
        throw std::invalid_argument("resource compute fee limit refused");
    }
    encoded.assign(reinterpret_cast<const char*>(scoped.data()), scoped.size());
    compute_put_u64(encoded, price);
    compute_put_u64(encoded, cap);
    return compute_domain_hash("octra:compute_request_fee", encoded);
}

inline std::array<uint8_t, 32> resource_compute_vote_hash(
        const nlohmann::json& vote) {
    const std::set<std::string> fields = {
        "node_id", "operations", "output_bytes", "output_hash", "request_id",
        "signature", "steps", "trace_root"
    };
    if (!compute_exact_fields(vote, fields)
        || !vote["node_id"].is_string()
        || !vote["signature"].is_string()) {
        throw std::invalid_argument("resource compute vote fields differ");
    }
    const uint32_t output_bytes = compute_json_u32(vote["output_bytes"], "vote output bytes");
    const uint64_t steps = compute_decimal_u64(vote["steps"], "vote steps");
    const uint64_t operations = compute_decimal_u64(vote["operations"], "vote operations");
    if (output_bytes == 0 || steps == 0 || operations == 0) {
        throw std::invalid_argument("resource compute vote counters differ");
    }
    std::string encoded;
    compute_put_hash32(encoded, vote["request_id"].get<std::string>());
    compute_put_string(encoded, vote["node_id"].get<std::string>());
    compute_put_hash32(encoded, vote["output_hash"].get<std::string>());
    compute_put_hash32(encoded, vote["trace_root"].get<std::string>());
    compute_put_u32(encoded, output_bytes);
    compute_put_u64(encoded, steps);
    compute_put_u64(encoded, operations);
    return compute_domain_hash("octra:resource_compute_vote", encoded);
}

inline std::array<uint8_t, 32> resource_compute_vote_id(
        const nlohmann::json& vote) {
    const auto vote_hash = resource_compute_vote_hash(vote);
    const auto signature = base64_decode(vote["signature"].get<std::string>());
    if (signature.size() != 64) {
        throw std::invalid_argument("resource compute vote signature size differs");
    }
    std::string encoded(
        reinterpret_cast<const char*>(vote_hash.data()),
        vote_hash.size());
    encoded.append(reinterpret_cast<const char*>(signature.data()), signature.size());
    return compute_domain_hash("octra:resource_compute_vote_id", encoded);
}

inline bool resource_compute_verify_ed25519(
        const std::array<uint8_t, 32>& digest,
        const std::string& signature_b64,
        const std::string& public_key_b64) {
    const auto signature = base64_decode(signature_b64);
    const auto public_key = base64_decode(public_key_b64);
    if (signature.size() != 64 || public_key.size() != 32
        || !ed25519_public_key_safe(public_key.data())) {
        return false;
    }
    std::array<unsigned char, 96> signed_message{};
    std::memcpy(signed_message.data(), signature.data(), signature.size());
    std::memcpy(signed_message.data() + signature.size(), digest.data(), digest.size());
    std::array<unsigned char, 96> opened{};
    unsigned long long opened_length = 0;
    return crypto_sign_open(
        opened.data(),
        &opened_length,
        signed_message.data(),
        signed_message.size(),
        public_key.data()) == 0
        && opened_length == digest.size();
}

inline std::array<uint8_t, 32> resource_compute_selection_hash(
        const nlohmann::json& selection) {
    const std::set<std::string> fields = {
        "challenge", "members", "root", "target_epoch"
    };
    const std::set<std::string> member_fields = {
        "evidence_root", "executor_root", "graph_root", "model_root",
        "node_id", "program_root", "score"
    };
    if (!compute_exact_fields(selection, fields)
        || !selection["members"].is_array()
        || selection["members"].empty()
        || selection["members"].size() > 64) {
        throw std::invalid_argument("resource compute selection fields differ");
    }
    std::string encoded;
    compute_put_u64(
        encoded,
        compute_decimal_u64(selection["target_epoch"], "selection epoch"));
    compute_put_hash32(encoded, selection["challenge"].get<std::string>());
    compute_put_u32(encoded, static_cast<uint32_t>(selection["members"].size()));
    for (const auto& member : selection["members"]) {
        if (!compute_exact_fields(member, member_fields)
            || !member["node_id"].is_string()) {
            throw std::invalid_argument("resource compute member fields differ");
        }
        compute_put_string(encoded, member["node_id"].get<std::string>());
        compute_put_hash32(encoded, member["graph_root"].get<std::string>());
        compute_put_hash32(encoded, member["model_root"].get<std::string>());
        compute_put_hash32(encoded, member["program_root"].get<std::string>());
        compute_put_hash32(encoded, member["executor_root"].get<std::string>());
        compute_put_hash32(encoded, member["evidence_root"].get<std::string>());
        compute_put_hash32(encoded, member["score"].get<std::string>());
    }
    return compute_domain_hash("octra:resource_compute_selection", encoded);
}

struct ResourceComputeValidator {
    std::string address;
    std::string public_key_b64;
    ResourceComputeWeight weight;
};

inline std::map<std::string, ResourceComputeValidator>
resource_compute_validator_map(const nlohmann::json& proof) {
    if (!proof.is_object()
        || !proof.contains("validators")
        || !proof["validators"].is_array()
        || proof["validators"].empty()
        || proof["validators"].size() > 256) {
        throw std::invalid_argument("validator set proof differs");
    }
    const bool weighted = proof.value("weighted", false);
    std::map<std::string, ResourceComputeValidator> validators;
    std::set<std::string> public_keys;
    for (const auto& row : proof["validators"]) {
        const std::set<std::string> expected = weighted
            ? std::set<std::string>{"address", "pubkey", "weight"}
            : std::set<std::string>{"address", "pubkey"};
        if (!compute_exact_fields(row, expected)
            || !row["address"].is_string()
            || !row["pubkey"].is_string()) {
            throw std::invalid_argument("validator set row differs");
        }
        const std::string address = row["address"].get<std::string>();
        const std::string public_key_b64 = row["pubkey"].get<std::string>();
        const auto public_key = base64_decode(public_key_b64);
        const ResourceComputeWeight weight = weighted
            ? compute_decimal_weight(row["weight"], "validator weight")
            : ResourceComputeWeight(1);
        if (address.empty() || public_key.size() != 32 || weight <= 0
            || derive_address_from_pubkey(public_key.data()) != address
            || !validators.emplace(
                    address,
                    ResourceComputeValidator{address, public_key_b64, weight}).second
            || !public_keys.insert(public_key_b64).second) {
            throw std::invalid_argument("validator set identity differs");
        }
    }
    return validators;
}

inline std::array<uint8_t, 32> resource_compute_validator_set_hash(
        const nlohmann::json& proof,
        const std::map<std::string, ResourceComputeValidator>& validators) {
    const bool weighted = proof.value("weighted", false);
    const uint32_t n = compute_json_u32(proof.at("n"), "validator count");
    const uint32_t f = compute_json_u32(proof.at("f"), "fault count");
    const uint32_t quorum = compute_json_u32(proof.at("quorum"), "validator quorum");
    const uint32_t expected_f = n == 0 ? 0 : (n - 1) / 3;
    const uint32_t expected_quorum = n == 0 ? 0 : (n < 4 ? n : n - expected_f);
    if (n != validators.size() || f != expected_f || quorum != expected_quorum) {
        throw std::invalid_argument("validator set arithmetic differs");
    }
    ResourceComputeWeight total = 0;
    for (const auto& entry : validators) total += entry.second.weight;
    const ResourceComputeWeight quorum_weight = (total * 2) / 3 + 1;
    if (weighted
        && (compute_decimal_weight(proof.at("total_weight"), "total weight") != total
            || compute_decimal_weight(proof.at("quorum_weight"), "quorum weight") != quorum_weight)) {
        throw std::invalid_argument("validator weight arithmetic differs");
    }
    std::string encoded;
    compute_put_u32(encoded, n);
    compute_put_u32(encoded, f);
    compute_put_u32(encoded, quorum);
    if (weighted) {
        compute_put_string(encoded, compute_weight_string(total));
        compute_put_string(encoded, compute_weight_string(quorum_weight));
    }
    compute_put_u32(encoded, static_cast<uint32_t>(validators.size()));
    for (const auto& entry : validators) {
        const auto public_key = base64_decode(entry.second.public_key_b64);
        compute_put_string(encoded, entry.first);
        encoded.append(
            reinterpret_cast<const char*>(public_key.data()),
            public_key.size());
        if (weighted) compute_put_string(encoded, compute_weight_string(entry.second.weight));
    }
    if (proof.contains("authors") && !proof["authors"].is_null()) {
        const auto& authors = proof["authors"];
        if (!weighted || !compute_exact_fields(authors, {"height", "validators"})) {
            throw std::invalid_argument("author proof context differs");
        }
        const uint64_t height = compute_decimal_u64(authors.at("height"), "author height");
        if (height > static_cast<uint64_t>(INT64_MAX)) {
            throw std::invalid_argument("author height exceeds limit");
        }
        const auto entries = resource_compute_validator_map(
            {{"weighted", true}, {"validators", authors.at("validators")}});
        compute_put_string(encoded, "octra:relief_authors");
        compute_put_u64(encoded, height);
        compute_put_u32(encoded, static_cast<uint32_t>(entries.size()));
        for (const auto& entry : entries) {
            const auto public_key = base64_decode(entry.second.public_key_b64);
            if (validators.count(entry.first) != 0
                || std::any_of(validators.begin(), validators.end(), [&](const auto& voter) {
                    return base64_decode(voter.second.public_key_b64) == public_key;
                })) {
                throw std::invalid_argument("author overlaps validator set");
            }
            compute_put_string(encoded, entry.first);
            compute_put_string(encoded, std::string(
                reinterpret_cast<const char*>(public_key.data()), public_key.size()));
            compute_put_string(encoded, compute_weight_string(entry.second.weight));
        }
    }
    return compute_domain_hash(
        weighted ? "octra:consensus_validator_set:v2" : "octra:consensus_validator_set:v1",
        encoded);
}

inline std::array<uint8_t, 32> resource_compute_certificate_hash(
        const nlohmann::json& certificate) {
    std::string encoded;
    compute_put_hash32(encoded, certificate["request_id"].get<std::string>());
    compute_put_hash32(encoded, certificate["output_hash"].get<std::string>());
    compute_put_hash32(encoded, certificate["trace_root"].get<std::string>());
    compute_put_u32(
        encoded,
        compute_json_u32(certificate["output_bytes"], "certificate output bytes"));
    compute_put_u64(
        encoded,
        compute_decimal_u64(certificate["steps"], "certificate steps"));
    compute_put_u64(
        encoded,
        compute_decimal_u64(certificate["operations"], "certificate operations"));
    compute_put_string(
        encoded,
        compute_weight_string(
            compute_decimal_weight(certificate["signed_weight"], "signed weight")));
    compute_put_u32(encoded, static_cast<uint32_t>(certificate["signers"].size()));
    for (const auto& signer : certificate["signers"]) {
        compute_put_string(encoded, signer["node_id"].get<std::string>());
        compute_put_string(
            encoded,
            compute_weight_string(
                compute_decimal_weight(signer["weight"], "signer weight")));
        compute_put_hash32(encoded, signer["vote_id"].get<std::string>());
    }
    return compute_domain_hash("octra:resource_compute_certificate", encoded);
}

inline void verify_resource_compute_finished_or_throw(
        const nlohmann::json& response,
        const nlohmann::json& proof,
        const ResourceComputeIntent& intent) {
    if (!response.is_object()
        || response.value("status", "") != "finished"
        || !response.contains("request")
        || !response.contains("selection")
        || !response.contains("certificate")
        || !response.contains("output_json")
        || !response["output_json"].is_string()) {
        throw std::invalid_argument("resource compute response differs");
    }
    const auto validators = resource_compute_validator_map(proof);
    const auto validator_set_hash = resource_compute_validator_set_hash(proof, validators);
    if (!proof.contains("validator_set_hash")
        || proof["validator_set_hash"] != compute_hash_hex(validator_set_hash)
        || !proof.contains("chain_id")
        || proof["chain_id"] != intent.chain_id) {
        throw std::invalid_argument("validator set root differs");
    }
    const auto& request = response["request"];
    const auto request_hash = resource_compute_request_hash(request);
    const std::string request_id = compute_hash_hex(request_hash);
    const auto input_hash = resource_compute_input_hash(intent.method_name, intent.params_json);
    const size_t input_bytes = intent.method_name.size() + intent.params_json.size();
    if (request["chain_id"] != intent.chain_id
        || request["circle_id"] != intent.circle_id
        || compute_decimal_u64(request["model_epoch"], "model epoch") != intent.model_epoch
        || request["model_state_root"] != intent.model_state_root
        || request["graph_root"] != intent.graph_root
        || request["model_root"] != intent.model_root
        || request["program_root"] != intent.program_root
        || request["executor_root"] != intent.executor_root
        || request["caller"] != intent.caller
        || request["session_id"] != intent.session_id
        || !request.contains("fuel_limit")
        || compute_json_u32(request["fuel_limit"], "fuel limit") != intent.fuel_limit
        || !request.contains("guest_bytes")
        || compute_json_u32(request["guest_bytes"], "guest bytes") != intent.guest_bytes
        || !request.contains("memory_bytes")
        || compute_json_u32(request["memory_bytes"], "memory bytes") != intent.memory_bytes
        || !request.contains("unit_price") || !request.contains("fee_cap")
        || compute_decimal_u64(request["unit_price"], "unit price") != intent.unit_price
        || compute_decimal_u64(request["fee_cap"], "fee cap") != intent.fee_cap
        || compute_decimal_u64(request["expires_epoch"], "expires epoch") > intent.valid_until
        || compute_decimal_u64(request["sequence"], "sequence") != intent.sequence
        || request["input_hash"] != compute_hash_hex(input_hash)
        || compute_json_u32(request["input_bytes"], "input bytes") != input_bytes
        || compute_json_u32(request["max_output_bytes"], "output bytes") != intent.max_output_bytes
        || request["validator_set_root"] != compute_hash_hex(validator_set_hash)) {
        throw std::invalid_argument("resource compute request binding differs");
    }
    const auto& selection = response["selection"];
    const auto selection_hash = resource_compute_selection_hash(selection);
    if (selection["root"] != compute_hash_hex(selection_hash)
        || request["selection_root"] != selection["root"]
        || compute_decimal_u64(selection["target_epoch"], "selection epoch")
            != compute_decimal_u64(request["epoch_id"], "request epoch")) {
        throw std::invalid_argument("resource compute selection root differs");
    }
    std::set<std::string> selected;
    ResourceComputeWeight selected_weight = 0;
    for (const auto& member : selection["members"]) {
        const std::string node_id = member["node_id"].get<std::string>();
        const auto validator = validators.find(node_id);
        if (validator == validators.end() || !selected.insert(node_id).second
            || member["graph_root"] != intent.graph_root
            || member["model_root"] != intent.model_root
            || member["program_root"] != intent.program_root
            || member["executor_root"] != intent.executor_root) {
            throw std::invalid_argument("resource compute selected member differs");
        }
        selected_weight += validator->second.weight;
    }
    const size_t signer_floor = selected.size() - ((selected.size() - 1) / 3);
    const ResourceComputeWeight weight_floor = (selected_weight * 2) / 3 + 1;
    const auto& certificate = response["certificate"];
    const std::set<std::string> certificate_fields = {
        "operations", "output_bytes", "output_hash", "request_id", "root",
        "signed_weight", "signer_count", "signers", "steps", "trace_root", "votes"
    };
    if (!compute_exact_fields(certificate, certificate_fields)
        || !certificate["signers"].is_array()
        || !certificate["votes"].is_array()
        || certificate["signers"].size() != certificate["votes"].size()
        || certificate["signers"].size() < signer_floor
        || compute_json_u32(certificate["signer_count"], "signer count")
            != certificate["signers"].size()
        || certificate["request_id"] != request_id) {
        throw std::invalid_argument("resource compute certificate fields differ");
    }
    const std::string output_json = response["output_json"].get<std::string>();
    const auto output_hash = compute_domain_hash("octra:resource_compute_output", output_json);
    const uint32_t certificate_output_bytes =
        compute_json_u32(certificate["output_bytes"], "certificate output bytes");
    const uint64_t fuel_used = compute_decimal_u64(certificate["steps"], "certificate steps");
    if (fuel_used == 0 || fuel_used > intent.fuel_limit) {
        throw std::invalid_argument("resource compute fuel exceeds signed limit");
    }
    if (certificate_output_bytes != output_json.size()
        || certificate_output_bytes > intent.max_output_bytes
        || certificate["output_hash"] != compute_hash_hex(output_hash)) {
        throw std::invalid_argument("resource compute output binding differs");
    }
    std::set<std::string> voters;
    std::map<std::string, std::string> vote_ids;
    ResourceComputeWeight signed_weight = 0;
    std::string previous_node;
    for (const auto& vote : certificate["votes"]) {
        const std::string node_id = vote["node_id"].get<std::string>();
        const auto validator = validators.find(node_id);
        if (validator == validators.end()
            || selected.count(node_id) != 1
            || !voters.insert(node_id).second
            || (!previous_node.empty() && node_id <= previous_node)
            || vote["request_id"] != request_id
            || vote["output_hash"] != certificate["output_hash"]
            || vote["trace_root"] != certificate["trace_root"]
            || compute_json_u32(vote["output_bytes"], "vote output bytes") != certificate_output_bytes
            || vote["steps"] != certificate["steps"]
            || vote["operations"] != certificate["operations"]) {
            throw std::invalid_argument("resource compute vote binding differs");
        }
        const auto vote_hash = resource_compute_vote_hash(vote);
        if (!resource_compute_verify_ed25519(
                vote_hash,
                vote["signature"].get<std::string>(),
                validator->second.public_key_b64)) {
            throw std::invalid_argument("resource compute vote signature refused");
        }
        previous_node = node_id;
        signed_weight += validator->second.weight;
        vote_ids.emplace(node_id, compute_hash_hex(resource_compute_vote_id(vote)));
    }
    if (signed_weight < weight_floor
        || compute_decimal_weight(certificate["signed_weight"], "signed weight") != signed_weight) {
        throw std::invalid_argument("resource compute certificate weight differs");
    }
    previous_node.clear();
    for (const auto& signer : certificate["signers"]) {
        const std::set<std::string> signer_fields = {"node_id", "vote_id", "weight"};
        if (!compute_exact_fields(signer, signer_fields)
            || !signer["node_id"].is_string()) {
            throw std::invalid_argument("resource compute signer fields differ");
        }
        const std::string node_id = signer["node_id"].get<std::string>();
        const auto validator = validators.find(node_id);
        const auto vote_id = vote_ids.find(node_id);
        if (validator == validators.end()
            || vote_id == vote_ids.end()
            || (!previous_node.empty() && node_id <= previous_node)
            || signer["vote_id"] != vote_id->second
            || compute_decimal_weight(signer["weight"], "signer weight")
                != validator->second.weight) {
            throw std::invalid_argument("resource compute signer binding differs");
        }
        previous_node = node_id;
    }
    const auto certificate_hash = resource_compute_certificate_hash(certificate);
    if (certificate["root"] != compute_hash_hex(certificate_hash)) {
        throw std::invalid_argument("resource compute certificate root differs");
    }
    const uint64_t maximum = intent.unit_price * intent.fuel_limit;
    const uint64_t used = intent.unit_price * fuel_used;
    if (!response.contains("quote")
        || !compute_exact_fields(response["quote"], {"used", "unused"})
        || compute_decimal_u64(response["quote"]["used"], "quote used") != used
        || compute_decimal_u64(response["quote"]["unused"], "quote unused") != maximum - used) {
        throw std::invalid_argument("resource compute quote differs");
    }
}

inline bool verify_resource_compute_finished(
        const nlohmann::json& response,
        const nlohmann::json& proof,
        const ResourceComputeIntent& intent,
        std::string& error) {
    try {
        verify_resource_compute_finished_or_throw(response, proof, intent);
        error.clear();
        return true;
    } catch (const std::exception& exception) {
        error = exception.what();
        return false;
    }
}

}