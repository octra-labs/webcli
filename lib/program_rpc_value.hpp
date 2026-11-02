// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
// lambda0xE
// Arthur Edelstein
// Denis CMIX

#pragma once

#include <cstddef>
#include <optional>
#include <string>

#include "json.hpp"

namespace octra {

struct Transaction;

}

namespace octra::program_cli {

struct AccountValue {
    std::string balance;
    int confirmed_nonce = 0;
    int pending_nonce = 0;
    int next_nonce = 0;
};

struct ReceiptValue {
    bool success = false;
    int effort = 0;
    int epoch = 0;
};

std::optional<AccountValue> account_value(
    const nlohmann::json& value,
    const std::string& address);
std::optional<std::string> fee_value(
    const nlohmann::json& value,
    size_t package_bytes);
std::optional<std::string> address_value(
    const nlohmann::json& value,
    const std::string& deployer,
    int nonce);
std::optional<std::string> submit_value(
    const nlohmann::json& value,
    const std::string& expected_hash,
    int nonce,
    size_t package_bytes);
std::optional<ReceiptValue> receipt_value(
    const nlohmann::json& value,
    const std::string& address);
std::optional<std::string> verify_value(const nlohmann::json& value);
std::optional<std::string> envelope_hash(const std::string& envelope_b64);
std::optional<std::string> transaction_hash(const octra::Transaction& transaction);
std::optional<std::string> program_address_from_envelope(
    const std::string& envelope_b64,
    const std::string& deployer,
    int nonce);
bool decimal_at_least(
    const std::string& amount,
    const std::string& minimum);

}