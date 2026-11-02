// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
// lambda0xE
// Arthur Edelstein
// Denis CMIX

#include "program_cli_runtime.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <sstream>
#include <utility>
#include <vector>

#include "../crypto_utils.hpp"
#include "program_cli_detail.hpp"
#include "program_rpc_value.hpp"
#include "tx_builder.hpp"

namespace octra::program_cli {

namespace {

inline constexpr int retry_calls = 3;
inline constexpr int receipt_calls = 13;

class SignerUse final {
    ProgramSigner& signer_;
    bool active_ = true;

public:
    explicit SignerUse(ProgramSigner& signer) : signer_(signer) {}

    ~SignerUse() {
        clear();
    }

    SignerUse(const SignerUse&) = delete;
    SignerUse& operator=(const SignerUse&) = delete;

    void clear() noexcept {
        if (!active_) return;
        signer_.clear();
        active_ = false;
    }
};

enum class RetryMode {
    compiler,
    read,
    verify
};

bool retry_code(RetryMode mode, int code) {
    if (code == -32'005) return true;
    return mode == RetryMode::read && code == -32'012;
}

RpcReply call_once(
    ProgramRpc& rpc,
    const std::string& method,
    const nlohmann::json& params) {
    try {
        return rpc.call(method, params);
    } catch (...) {
        return {};
    }
}

RpcReply call_retry(
    ProgramRpc& rpc,
    RunTimer& timer,
    const std::string& method,
    const nlohmann::json& params,
    RetryMode mode) {
    for (int call = 0; call < retry_calls; ++call) {
        auto reply = call_once(rpc, method, params);
        if (reply.ok
            || reply.timed_out
            || !reply.remote_error
            || !retry_code(mode, reply.code)
            || call + 1 == retry_calls) return reply;
        timer.pause(call == 0
            ? std::chrono::milliseconds(500)
            : std::chrono::milliseconds(1'500));
    }
    return {};
}

bool source_set_ok(const SourceBundle& sources) {
    if (sources.files.empty() || sources.files.size() > detail::max_source_files)
        return false;
    size_t total = 0;
    std::string previous;
    bool main_seen = false;
    for (const auto& file : sources.files) {
        if (!valid_source_path(file.path)
            || file.body.size() > detail::max_source_bytes
            || (!previous.empty() && previous >= file.path)
            || file.path.size() > detail::max_sources_bytes - total)
            return false;
        previous = file.path;
        total += file.path.size();
        if (file.body.size() > detail::max_sources_bytes - total) return false;
        total += file.body.size();
        if (file.path == "main.aml") {
            if (main_seen || file.body != sources.main_source) return false;
            main_seen = true;
        }
    }
    return main_seen;
}

bool checked_params(const std::string& input, std::string& output) {
    std::string error;
    if (!detail::params_json_ok(input, error)) return false;
    output = input;
    return true;
}

bool base64_value(
    const std::string& value,
    size_t text_size,
    size_t raw_size) {
    if (value.size() != text_size || value.size() % 4 != 0) return false;
    size_t padding = 0;
    if (!value.empty() && value.back() == '=') ++padding;
    if (value.size() > 1 && value[value.size() - 2] == '=') ++padding;
    for (size_t index = 0; index < value.size(); ++index) {
        const unsigned char c = static_cast<unsigned char>(value[index]);
        const bool data = detail::ascii_alnum(c) || c == '+' || c == '/';
        const bool pad = c == '=' && index >= value.size() - padding;
        if (!data && !pad) return false;
    }
    const auto raw = octra::base64_decode(value);
    return raw.size() == raw_size
        && octra::base64_encode(raw.data(), raw.size()) == value;
}

bool sign_fields_ok(
    const octra::Transaction& transaction,
    const std::string& deployer,
    const std::string& address,
    const std::string& fee,
    const std::string& package,
    const std::string& params,
    const std::string& public_key,
    int nonce,
    double timestamp) {
    return transaction.from == deployer
        && transaction.to_ == address
        && transaction.amount == "0"
        && transaction.nonce == nonce
        && transaction.ou == fee
        && transaction.timestamp == timestamp
        && transaction.op_type == "program_deploy"
        && transaction.encrypted_data == package
        && transaction.message == params
        && transaction.public_key == public_key
        && base64_value(transaction.signature, 88, 64);
}

nlohmann::json compile_params(const SourceBundle& sources) {
    nlohmann::json request;
    request["files"] = compile_files_json(sources);
    request["main"] = "main.aml";
    request["program"] = true;
    return nlohmann::json::array({std::move(request)});
}

nlohmann::json verify_params(
    const std::string& address,
    const SourceBundle& sources) {
    return nlohmann::json::array({
        address,
        sources.main_source,
        verify_files_json(sources)
    });
}

void rpc_failure(
    RunResult& result,
    const RpcReply& reply,
    const std::string& error) {
    result.error = error;
    if (!reply.remote_error || reply.timed_out) return;
    result.has_rpc_code = true;
    result.rpc_code = reply.code;
}

RunResult base_result(const std::string& action) {
    RunResult result;
    result.action = action;
    result.state = "failed";
    return result;
}

std::string report_field(const std::string& value, size_t maximum) {
    std::string out;
    out.reserve(std::min(value.size(), maximum));
    for (unsigned char c : value) {
        if (out.size() == maximum) break;
        out.push_back(c >= 0x20 && c <= 0x7e ? static_cast<char>(c) : '?');
    }
    return out;
}

std::optional<std::string> publish_source(
    ProgramRpc& primary,
    RunTimer& timer,
    const std::string& address,
    const SourceBundle& sources,
    RunResult& result) {
    const auto reply = call_retry(
        primary,
        timer,
        "octra_programVerify",
        verify_params(address, sources),
        RetryMode::verify);
    if (!reply.ok) {
        rpc_failure(result, reply, "Program verification request failed");
        return std::nullopt;
    }
    const auto hash = verify_value(reply.value);
    if (!hash) result.error = "Program verification response is invalid";
    return hash;
}

}

RunResult run_deploy(
    ProgramRpc& primary,
    ProgramRpc* check,
    ProgramSigner& signer,
    RunTimer& timer,
    const SourceBundle& sources,
    const std::string& params_json) {
    auto result = base_result("deploy");
    SignerUse signer_use(signer);
    try {
        const auto& signer_address = signer.address();
        const auto& signer_public_key = signer.public_key_b64();
        std::string params;
        if (!valid_address(signer_address)
            || !base64_value(signer_public_key, 44, 32)
            || !source_set_ok(sources)
            || !checked_params(params_json, params)) {
            result.error = "Program deploy input is invalid";
            return result;
        }
        const std::string deployer = signer_address;
        const std::string public_key = signer_public_key;
        if (!primary.loopback()
            && (check == nullptr
                || check == &primary
                || primary.same_origin(*check))) {
            result.error = "Remote Program deploy requires a separate compiler endpoint";
            return result;
        }
        if (check != nullptr
            && (check == &primary || primary.same_origin(*check))) {
            result.error = "Program compiler endpoints must differ";
            return result;
        }

        const auto compiler_params = compile_params(sources);
        const auto primary_reply = call_retry(
            primary,
            timer,
            "octra_compileAmlMulti",
            compiler_params,
            RetryMode::compiler);
        if (!primary_reply.ok) {
            rpc_failure(result, primary_reply, "Program compiler request failed");
            return result;
        }
        const auto primary_artifact = inspect_compile_package(
            primary_reply.value,
            sources);
        if (!primary_artifact.ok) {
            result.error = "Program compiler response is invalid";
            return result;
        }
        if (check != nullptr) {
            const auto check_reply = call_retry(
                *check,
                timer,
                "octra_compileAmlMulti",
                compiler_params,
                RetryMode::compiler);
            if (!check_reply.ok) {
                rpc_failure(result, check_reply, "Program compiler check failed");
                return result;
            }
            const auto check_artifact = inspect_compile_package(
                check_reply.value,
                sources);
            if (!check_artifact.ok) {
                result.error = "Program compiler check response is invalid";
                return result;
            }
            if (primary_artifact.artifact.envelope_b64
                    != check_artifact.artifact.envelope_b64
                || primary_artifact.artifact.package_b64
                    != check_artifact.artifact.package_b64) {
                result.error = "Program compiler results differ";
                return result;
            }
        }

        const auto expected_hash = envelope_hash(
            primary_artifact.artifact.envelope_b64);
        if (!expected_hash) {
            result.error = "Program compiler response is invalid";
            return result;
        }
        const auto account_reply = call_retry(
            primary,
            timer,
            "octra_balance",
            nlohmann::json::array({deployer}),
            RetryMode::read);
        if (!account_reply.ok) {
            rpc_failure(result, account_reply, "Program account request failed");
            return result;
        }
        const auto account = account_value(account_reply.value, deployer);
        if (!account) {
            result.error = "Program account response is invalid";
            return result;
        }
        result.nonce = account->next_nonce;
        const auto expected_address = program_address_from_envelope(
            primary_artifact.artifact.envelope_b64,
            deployer,
            account->next_nonce);
        if (!expected_address) {
            result.error = "Program address calculation failed";
            return result;
        }

        const size_t package_bytes = primary_artifact.artifact.package_b64.size();
        const auto fee_reply = call_retry(
            primary,
            timer,
            "octra_recommendedFee",
            nlohmann::json::array({
                "program_deploy",
                {{"encrypted_data_len", package_bytes}}
            }),
            RetryMode::read);
        if (!fee_reply.ok) {
            rpc_failure(result, fee_reply, "Program fee request failed");
            return result;
        }
        const auto fee = fee_value(fee_reply.value, package_bytes);
        if (!fee) {
            result.error = "Program fee response is invalid";
            return result;
        }
        if (!decimal_at_least(account->balance, *fee)) {
            result.error = "Program account balance is insufficient";
            return result;
        }

        const auto address_reply = call_retry(
            primary,
            timer,
            "octra_computeProgramAddress",
            nlohmann::json::array({
                primary_artifact.artifact.envelope_b64,
                deployer,
                account->next_nonce
            }),
            RetryMode::read);
        if (!address_reply.ok) {
            rpc_failure(result, address_reply, "Program address request failed");
            return result;
        }
        const auto address = address_value(
            address_reply.value,
            deployer,
            account->next_nonce);
        if (!address || *address != *expected_address) {
            result.error = "Program address response is invalid";
            return result;
        }
        result.address = *address;

        const double clock_value = timer.now();
        if (!std::isfinite(clock_value) || clock_value <= 0.0) {
            result.error = "Program transaction time is invalid";
            return result;
        }
        const double timestamp = std::floor(clock_value);
        if (timestamp <= 0.0) {
            result.error = "Program transaction time is invalid";
            return result;
        }
        octra::Transaction transaction;
        transaction.from = deployer;
        transaction.to_ = *address;
        transaction.amount = "0";
        transaction.nonce = account->next_nonce;
        transaction.ou = *fee;
        transaction.timestamp = timestamp;
        transaction.op_type = "program_deploy";
        transaction.encrypted_data = primary_artifact.artifact.package_b64;
        transaction.message = params;
        transaction.public_key = public_key;
        if (!signer.sign(transaction)
            || !sign_fields_ok(
                transaction,
                deployer,
                *address,
                *fee,
                primary_artifact.artifact.package_b64,
                params,
                public_key,
                account->next_nonce,
                timestamp)) {
            result.error = "Program transaction signing failed";
            return result;
        }
        const auto expected_tx_hash = transaction_hash(transaction);
        if (!expected_tx_hash) {
            result.error = "Program transaction hashing failed";
            return result;
        }
        signer_use.clear();

        nlohmann::json transaction_json;
        try {
            transaction_json = octra::build_tx_json(transaction);
        } catch (...) {
            result.error = "Program transaction encoding failed";
            return result;
        }
        const auto submit_reply = call_once(
            primary,
            "octra_submit",
            nlohmann::json::array({std::move(transaction_json)}));
        if (!submit_reply.ok) {
            result.state = submit_reply.remote_error && !submit_reply.timed_out
                ? "failed"
                : "submit_unknown";
            if (result.state == "submit_unknown")
                result.tx_hash = *expected_tx_hash;
            rpc_failure(result, submit_reply, "Program submit request failed");
            return result;
        }
        const auto tx_hash = submit_value(
            submit_reply.value,
            *expected_tx_hash,
            account->next_nonce,
            package_bytes);
        if (!tx_hash) {
            result.state = "submit_unknown";
            result.tx_hash = *expected_tx_hash;
            result.error = "Program submit response is invalid";
            return result;
        }
        result.submitted = true;
        result.state = "submitted";
        result.tx_hash = *tx_hash;

        std::optional<ReceiptValue> receipt;
        for (int call = 0; call < receipt_calls; ++call) {
            const auto receipt_reply = call_once(
                primary,
                "octra_programReceipt",
                nlohmann::json::array({*tx_hash}));
            if (receipt_reply.ok) {
                receipt = receipt_value(receipt_reply.value, *address);
                if (!receipt) result.error = "Program receipt response is invalid";
                break;
            }
            const bool waiting = receipt_reply.remote_error
                && !receipt_reply.timed_out
                && (receipt_reply.code == 112
                    || receipt_reply.code == -32'005
                    || receipt_reply.code == -32'012);
            if (!waiting) {
                rpc_failure(result, receipt_reply, "Program receipt request failed");
                break;
            }
            if (call + 1 < receipt_calls)
                timer.pause(std::chrono::milliseconds(5'000));
        }
        if (!receipt) {
            if (result.error.empty()) result.error = "Program receipt is not available";
            return result;
        }
        result.confirmed = true;
        if (!receipt->success) {
            result.state = "execution_failed";
            result.error = "Program constructor failed";
            return result;
        }
        result.state = "deployed";

        const auto code_hash = publish_source(
            primary,
            timer,
            *address,
            sources,
            result);
        if (!code_hash) return result;
        if (*code_hash != *expected_hash) {
            result.error = "Program verification hash differs";
            return result;
        }
        result.code_hash = *code_hash;
        result.verified = true;
        result.ok = true;
        result.state = "verified";
        return result;
    } catch (...) {
        result.error = "Program deploy failed";
        return result;
    }
}

RunResult run_verify(
    ProgramRpc& primary,
    RunTimer& timer,
    const std::string& address,
    const SourceBundle& sources) {
    auto result = base_result("verify");
    try {
        if (!valid_address(address) || !source_set_ok(sources)) {
            result.error = "Program verification input is invalid";
            return result;
        }
        result.address = address;
        const auto code_hash = publish_source(
            primary,
            timer,
            address,
            sources,
            result);
        if (!code_hash) return result;
        result.code_hash = *code_hash;
        result.verified = true;
        result.ok = true;
        result.state = "verified";
        return result;
    } catch (...) {
        result.error = "Program verification failed";
        return result;
    }
}

nlohmann::json run_json(const RunResult& result) {
    nlohmann::json value;
    value["action"] = report_field(result.action, 32);
    value["status"] = result.ok ? "ok" : "error";
    value["state"] = report_field(result.state, 32);
    value["submitted"] = result.submitted;
    value["confirmed"] = result.confirmed;
    value["verified"] = result.verified;
    if (result.nonce > 0) value["nonce"] = result.nonce;
    if (!result.address.empty()) value["address"] = report_field(result.address, 47);
    if (!result.tx_hash.empty()) value["tx_hash"] = report_field(result.tx_hash, 64);
    if (!result.code_hash.empty()) value["code_hash"] = report_field(result.code_hash, 64);
    if (result.has_rpc_code) value["rpc_code"] = result.rpc_code;
    if (!result.error.empty()) value["error"] = report_field(result.error, 256);
    return value;
}

std::string run_text(const RunResult& result) {
    std::ostringstream out;
    out << "action = " << report_field(result.action, 32)
        << " status = " << (result.ok ? "ok" : "error")
        << " state = " << report_field(result.state, 32)
        << " submitted = " << (result.submitted ? "true" : "false")
        << " confirmed = " << (result.confirmed ? "true" : "false")
        << " verified = " << (result.verified ? "true" : "false");
    if (result.nonce > 0) out << " nonce = " << result.nonce;
    if (!result.address.empty())
        out << " address = " << report_field(result.address, 47);
    if (!result.tx_hash.empty())
        out << " tx_hash = " << report_field(result.tx_hash, 64);
    if (!result.code_hash.empty())
        out << " code_hash = " << report_field(result.code_hash, 64);
    if (result.has_rpc_code) out << " rpc_code = " << result.rpc_code;
    if (!result.error.empty())
        out << " error = " << report_field(result.error, 256);
    return out.str();
}

}