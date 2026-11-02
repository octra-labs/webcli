// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
// lambda0xE
// Arthur Edelstein
// Denis CMIX

#include "program_cli_app.hpp"

#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>

#include "program_cli_adapters.hpp"
#include "program_cli_detail.hpp"
#include "program_cli_runtime.hpp"
#include "program_terminal.hpp"
#include "program_wallet.hpp"

namespace octra::program_cli {

namespace {

std::string action_name(Command command) {
    return command == Command::deploy ? "deploy" : "verify";
}

int emit(const Options& options, const RunResult& result) {
    if (options.json_output) std::cout << run_json(result).dump() << '\n';
    else std::cout << run_text(result) << '\n';
    return result.ok ? 0 : 1;
}

int fail(const Options& options, const std::string& error) {
    RunResult result;
    result.action = action_name(options.command);
    result.state = "failed";
    result.error = error;
    return emit(options, result);
}

std::string environment_rpc() {
    const char* value = std::getenv("OCTRA_RPC_URL");
    if (value == nullptr) return "";
    size_t size = 0;
    while (size <= detail::max_path_bytes && value[size] != '\0') ++size;
    if (size == 0 || size > detail::max_path_bytes) return "";
    return std::string(value, size);
}

std::string verify_rpc(const Options& options) {
    if (!options.rpc_url.empty()) return options.rpc_url;
    const std::string environment = environment_rpc();
    return environment.empty() ? "https://devnet.octrascan.io/rpc" : environment;
}

int run_verify_command(
    const Options& options,
    const SourceBundle& sources) {
    NodeRpc primary(verify_rpc(options));
    if (!primary.ready()) return fail(options, primary.error());
    SystemRunTimer timer;
    return emit(
        options,
        run_verify(primary, timer, options.address, sources));
}

int run_deploy_command(
    const Options& options,
    const SourceBundle& sources) {
    std::string params_error;
    const std::string params = deploy_params(options, params_error);
    if (!params_error.empty()) return fail(options, params_error);

    auto pin = read_terminal_pin();
    if (!pin.ok) {
        const bool interrupted = pin.interrupted;
        const int status = fail(options, pin.error);
        return interrupted ? 130 : status;
    }
    auto wallet_read = read_program_wallet(options.wallet_path, pin.pin);
    pin.pin.clear();
    if (!wallet_read.ok()) return fail(options, wallet_read.error);

    const std::string environment = environment_rpc();
    const std::string& wallet_rpc = wallet_read.wallet->rpc_url();
    const std::string primary_url = !options.rpc_url.empty()
        ? options.rpc_url
        : (!environment.empty() ? environment : wallet_rpc);
    NodeRpc primary(primary_url);
    if (!primary.ready()) return fail(options, primary.error());

    std::unique_ptr<NodeRpc> check;
    if (!options.check_rpc_url.empty()) {
        check = std::make_unique<NodeRpc>(options.check_rpc_url);
        if (!check->ready()) return fail(options, check->error());
    }

    WalletSigner signer(*wallet_read.wallet);
    SystemRunTimer timer;
    return emit(
        options,
        run_deploy(primary, check.get(), signer, timer, sources, params));
}

}

int run_command(const Options& options) {
    try {
        const auto sources = load_sources(options);
        if (!sources.ok) return fail(options, sources.error);
        if (options.command == Command::verify)
            return run_verify_command(options, sources.bundle);
        if (options.command == Command::deploy)
            return run_deploy_command(options, sources.bundle);
        return fail(options, "Program command is invalid");
    } catch (...) {
        return fail(options, "Program command failed");
    }
}

}