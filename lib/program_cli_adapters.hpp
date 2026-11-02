// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
// lambda0xE
// Arthur Edelstein
// Denis CMIX

#pragma once

#include <string>

#include "program_cli_runtime.hpp"
#include "program_rpc.hpp"
#include "program_wallet.hpp"

namespace octra::program_cli {

class NodeRpc final : public ProgramRpc {
    program_rpc::Client compile_client_;
    program_rpc::Client verify_client_;
    program_rpc::Client read_client_;

public:
    explicit NodeRpc(const std::string& url);

    bool ready() const noexcept;
    const std::string& error() const noexcept;
    RpcReply call(
        const std::string& method,
        const nlohmann::json& params) override;
    bool loopback() const noexcept override;
    bool same_origin(const ProgramRpc& other) const noexcept override;
};

class WalletSigner final : public ProgramSigner {
    ProgramWallet& wallet_;

public:
    explicit WalletSigner(ProgramWallet& wallet) noexcept;

    const std::string& address() const noexcept override;
    const std::string& public_key_b64() const noexcept override;
    bool sign(octra::Transaction& transaction) noexcept override;
    void clear() noexcept override;
};

class SystemRunTimer final : public RunTimer {
public:
    double now() const noexcept override;
    void pause(std::chrono::milliseconds duration) noexcept override;
};

}