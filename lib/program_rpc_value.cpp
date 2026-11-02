// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
// lambda0xE
// Arthur Edelstein
// Denis CMIX

#include "program_rpc_value.hpp"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <limits>

#include "../crypto_utils.hpp"
#include "program_cli_detail.hpp"
#include "program_cli_plan.hpp"
#include "tx_builder.hpp"

namespace octra::program_cli {

namespace {

bool decimal_text(const std::string& value, bool positive) {
    if (value.empty() || value.size() > 64) return false;
    if (value.size() > 1 && value.front() == '0') return false;
    if (!std::all_of(value.begin(), value.end(), [](unsigned char c) {
            return c >= '0' && c <= '9';
        })) return false;
    return !positive || value != "0";
}

bool decimal_u64(const std::string& value, uint64_t& out) {
    if (!decimal_text(value, false)) return false;
    const auto parsed = std::from_chars(
        value.data(),
        value.data() + value.size(),
        out);
    return parsed.ec == std::errc()
        && parsed.ptr == value.data() + value.size();
}

bool json_int(const nlohmann::json& value, int& out) {
    if (!value.is_number_integer()) return false;
    if (value.is_number_unsigned()) {
        const uint64_t number = value.get<uint64_t>();
        if (number > static_cast<uint64_t>(std::numeric_limits<int>::max()))
            return false;
        out = static_cast<int>(number);
        return true;
    }
    const int64_t number = value.get<int64_t>();
    if (number < 0 || number > std::numeric_limits<int>::max()) return false;
    out = static_cast<int>(number);
    return true;
}

bool hash_text(const std::string& value) {
    return value.size() == 64
        && std::all_of(value.begin(), value.end(), [](unsigned char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        });
}

bool base64_text(const std::string& value) {
    if (value.empty() || value.size() % 4 != 0) return false;
    size_t padding = 0;
    if (value.back() == '=') ++padding;
    if (value.size() > 1 && value[value.size() - 2] == '=') ++padding;
    for (size_t index = 0; index < value.size(); ++index) {
        const unsigned char c = static_cast<unsigned char>(value[index]);
        const bool data = detail::ascii_alnum(c) || c == '+' || c == '/';
        const bool pad = c == '=' && index >= value.size() - padding;
        if (!data && !pad) return false;
    }
    return true;
}

std::optional<uint64_t> base_fee(size_t package_bytes) {
    if (package_bytes > detail::max_package_b64_bytes) return std::nullopt;
    const uint64_t groups = (static_cast<uint64_t>(package_bytes) + 1'023) / 1'024;
    if (groups > (std::numeric_limits<uint64_t>::max() - 200'000) / 1'000)
        return std::nullopt;
    return 200'000 + groups * 1'000;
}

bool fee_choice(uint64_t value, uint64_t base) {
    return value == base
        || (base <= std::numeric_limits<uint64_t>::max() / 2
            && value == base * 2)
        || (base <= std::numeric_limits<uint64_t>::max() / 5
            && value == base * 5);
}

}

std::optional<AccountValue> account_value(
    const nlohmann::json& value,
    const std::string& address) {
    if (!valid_address(address)
        || !value.is_object()
        || !value.contains("address")
        || !value["address"].is_string()
        || value["address"] != address
        || !value.contains("balance_raw")
        || !value["balance_raw"].is_string()
        || !value.contains("nonce")
        || !value.contains("pending_nonce")) return std::nullopt;
    const auto& balance = value["balance_raw"].get_ref<const std::string&>();
    int confirmed = 0;
    int pending = 0;
    if (!decimal_text(balance, false)
        || !json_int(value["nonce"], confirmed)
        || !json_int(value["pending_nonce"], pending)
        || pending < confirmed
        || pending == std::numeric_limits<int>::max()) return std::nullopt;
    return AccountValue{balance, confirmed, pending, pending + 1};
}

std::optional<std::string> fee_value(
    const nlohmann::json& value,
    size_t package_bytes) {
    if (!value.is_object()
        || !value.contains("minimum")
        || !value["minimum"].is_string()) return std::nullopt;
    const auto base = base_fee(package_bytes);
    const auto& fee = value["minimum"].get_ref<const std::string&>();
    uint64_t number = 0;
    if (!base
        || !decimal_u64(fee, number)
        || !fee_choice(number, *base)) return std::nullopt;
    return fee;
}

std::optional<std::string> address_value(
    const nlohmann::json& value,
    const std::string& deployer,
    int nonce) {
    if (!valid_address(deployer)
        || nonce <= 0
        || !value.is_object()
        || !value.contains("address")
        || !value["address"].is_string()
        || !value.contains("deployer")
        || !value["deployer"].is_string()
        || value["deployer"] != deployer
        || !value.contains("nonce")) return std::nullopt;
    int returned_nonce = 0;
    const auto& address = value["address"].get_ref<const std::string&>();
    if (!valid_address(address)
        || !json_int(value["nonce"], returned_nonce)
        || returned_nonce != nonce) return std::nullopt;
    return address;
}

std::optional<std::string> submit_value(
    const nlohmann::json& value,
    const std::string& expected_hash,
    int nonce,
    size_t package_bytes) {
    if (!hash_text(expected_hash)
        || nonce <= 0
        || !value.is_object()
        || !value.contains("status")
        || !value["status"].is_string()
        || value["status"] != "accepted"
        || !value.contains("tx_hash")
        || !value["tx_hash"].is_string()
        || !value.contains("nonce")
        || !value.contains("ou_cost")
        || !value["ou_cost"].is_string()) return std::nullopt;
    int returned_nonce = 0;
    uint64_t cost = 0;
    const auto base = base_fee(package_bytes);
    const auto& hash = value["tx_hash"].get_ref<const std::string&>();
    const auto& ou_cost = value["ou_cost"].get_ref<const std::string&>();
    if (!base
        || !hash_text(hash)
        || hash != expected_hash
        || !json_int(value["nonce"], returned_nonce)
        || returned_nonce != nonce
        || !decimal_u64(ou_cost, cost)
        || cost != *base) return std::nullopt;
    return hash;
}

std::optional<ReceiptValue> receipt_value(
    const nlohmann::json& value,
    const std::string& address) {
    if (!valid_address(address)
        || !value.is_object()
        || !value.contains("contract")
        || !value["contract"].is_string()
        || value["contract"] != address
        || !value.contains("method")
        || !value["method"].is_string()
        || value["method"] != "constructor"
        || !value.contains("success")
        || !value["success"].is_boolean()
        || !value.contains("effort")
        || !value.contains("events")
        || !value["events"].is_array()
        || !value.contains("error")
        || !(value["error"].is_null() || value["error"].is_string())
        || !value.contains("epoch")
        || !value.contains("ts")
        || !value["ts"].is_number()) return std::nullopt;
    if (value.contains("program")
        && (!value["program"].is_string() || value["program"] != address))
        return std::nullopt;
    if (value["error"].is_string()
        && value["error"].get_ref<const std::string&>().size() > 4'096)
        return std::nullopt;
    int effort = 0;
    int epoch = 0;
    if (!json_int(value["effort"], effort)
        || !json_int(value["epoch"], epoch)) return std::nullopt;
    double timestamp = 0.0;
    try {
        timestamp = value["ts"].get<double>();
    } catch (...) {
        return std::nullopt;
    }
    if (!std::isfinite(timestamp) || timestamp < 0.0) return std::nullopt;
    return ReceiptValue{value["success"].get<bool>(), effort, epoch};
}

std::optional<std::string> verify_value(const nlohmann::json& value) {
    if (!value.is_object()
        || !value.contains("verified")
        || !value["verified"].is_boolean()
        || !value["verified"].get<bool>()
        || !value.contains("code_hash")
        || !value["code_hash"].is_string()) return std::nullopt;
    const auto& hash = value["code_hash"].get_ref<const std::string&>();
    if (!hash_text(hash)) return std::nullopt;
    return hash;
}

std::optional<std::string> envelope_hash(const std::string& envelope_b64) {
    if (envelope_b64.empty()
        || envelope_b64.size() > detail::max_envelope_b64_bytes
        || !base64_text(envelope_b64)) return std::nullopt;
    const auto raw = octra::base64_decode(envelope_b64);
    if (raw.empty()
        || raw.size() > detail::max_envelope_bytes
        || octra::base64_encode(raw.data(), raw.size()) != envelope_b64)
        return std::nullopt;
    const auto digest = octra::sha256(raw.data(), raw.size());
    return octra::hex_encode(digest.data(), digest.size());
}

std::optional<std::string> transaction_hash(
    const octra::Transaction& transaction) {
    if (!std::isfinite(transaction.timestamp)) return std::nullopt;
    try {
        return octra::tx_hash(transaction);
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<std::string> program_address_from_envelope(
    const std::string& envelope_b64,
    const std::string& deployer,
    int nonce) {
    if (!valid_address(deployer)
        || nonce <= 0
        || envelope_b64.empty()
        || envelope_b64.size() > detail::max_envelope_b64_bytes
        || !base64_text(envelope_b64)) return std::nullopt;
    const auto raw = octra::base64_decode(envelope_b64);
    if (raw.empty()
        || raw.size() > detail::max_envelope_bytes
        || octra::base64_encode(raw.data(), raw.size()) != envelope_b64)
        return std::nullopt;
    std::string input(
        reinterpret_cast<const char*>(raw.data()),
        raw.size());
    input += ":" + deployer + ":" + std::to_string(nonce);
    auto digest = octra::sha256(
        reinterpret_cast<const uint8_t*>(input.data()),
        input.size());
    std::string encoded = octra::base58_encode(digest.data(), digest.size());
    for (int suffix = 0; encoded.size() < 44 && suffix < 8; ++suffix) {
        const std::string extended = input + std::to_string(suffix);
        digest = octra::sha256(
            reinterpret_cast<const uint8_t*>(extended.data()),
            extended.size());
        encoded += octra::base58_encode(digest.data(), digest.size());
    }
    if (encoded.size() < 44) return std::nullopt;
    return "oct" + encoded.substr(0, 44);
}

bool decimal_at_least(
    const std::string& amount,
    const std::string& minimum) {
    if (!decimal_text(amount, false) || !decimal_text(minimum, false))
        return false;
    if (amount.size() != minimum.size()) return amount.size() > minimum.size();
    return amount >= minimum;
}

}