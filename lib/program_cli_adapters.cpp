// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
// lambda0xE
// Arthur Edelstein
// Denis CMIX

#include "program_cli_adapters.hpp"

#include <chrono>
#include <thread>
#include <utility>

#include "endpoint_policy.hpp"
#include "tx_builder.hpp"

namespace octra::program_cli {

NodeRpc::NodeRpc(const std::string& url)
    : compile_client_(url, {program_rpc::max_response_bytes, 5, 30}),
      verify_client_(url, {4U * 1024U * 1024U, 5, 30}),
      read_client_(url, {256U * 1024U, 5, 30}) {}

bool NodeRpc::ready() const noexcept {
    return compile_client_.ready()
        && verify_client_.ready()
        && read_client_.ready();
}

const std::string& NodeRpc::error() const noexcept {
    if (!compile_client_.ready()) return compile_client_.error();
    if (!verify_client_.ready()) return verify_client_.error();
    return read_client_.error();
}

RpcReply NodeRpc::call(
    const std::string& method,
    const nlohmann::json& params) {
    program_rpc::Client* client = &read_client_;
    if (method == "octra_compileAmlMulti") client = &compile_client_;
    else if (method == "octra_programVerify") client = &verify_client_;
    auto reply = client->call(method, params);
    return {
        reply.ok,
        reply.remote_error,
        std::move(reply.value),
        reply.code,
        reply.timed_out
    };
}

bool NodeRpc::loopback() const noexcept {
    return ready()
        && endpoint_policy::loopback(read_client_.endpoint().host);
}

bool NodeRpc::same_origin(const ProgramRpc& other) const noexcept {
    const auto* node = dynamic_cast<const NodeRpc*>(&other);
    return node != nullptr
        && program_rpc::same_origin(read_client_, node->read_client_);
}

WalletSigner::WalletSigner(ProgramWallet& wallet) noexcept : wallet_(wallet) {}

const std::string& WalletSigner::address() const noexcept {
    return wallet_.address();
}

const std::string& WalletSigner::public_key_b64() const noexcept {
    return wallet_.public_key_b64();
}

bool WalletSigner::sign(octra::Transaction& transaction) noexcept {
    try {
        octra::sign_transaction(transaction, wallet_.secret_key());
        return true;
    } catch (...) {
        return false;
    }
}

void WalletSigner::clear() noexcept {
    wallet_.clear();
}

double SystemRunTimer::now() const noexcept {
    const auto elapsed = std::chrono::system_clock::now().time_since_epoch();
    return std::chrono::duration<double>(elapsed).count();
}

void SystemRunTimer::pause(std::chrono::milliseconds duration) noexcept {
    std::this_thread::sleep_for(duration);
}

}