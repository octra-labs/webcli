// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
// lambda0xE
// Arthur Edelstein
// Denis CMIX

#pragma once

#include <chrono>
#include <string>

#include "json.hpp"
#include "program_cli_plan.hpp"

namespace octra {

struct Transaction;

}

namespace octra::program_cli {

struct RpcReply {
    bool ok = false;
    bool remote_error = false;
    nlohmann::json value;
    int code = 0;
    bool timed_out = false;
};

class ProgramRpc {
public:
    virtual ~ProgramRpc() = default;
    virtual RpcReply call(
        const std::string& method,
        const nlohmann::json& params) = 0;
    virtual bool loopback() const noexcept = 0;
    virtual bool same_origin(const ProgramRpc& other) const noexcept = 0;
};

class ProgramSigner {
public:
    virtual ~ProgramSigner() = default;
    virtual const std::string& address() const noexcept = 0;
    virtual const std::string& public_key_b64() const noexcept = 0;
    virtual bool sign(octra::Transaction& transaction) noexcept = 0;
    virtual void clear() noexcept = 0;
};

class RunTimer {
public:
    virtual ~RunTimer() = default;
    virtual double now() const noexcept = 0;
    virtual void pause(std::chrono::milliseconds duration) noexcept = 0;
};

struct RunResult {
    bool ok = false;
    bool submitted = false;
    bool confirmed = false;
    bool verified = false;
    bool has_rpc_code = false;
    int rpc_code = 0;
    int nonce = 0;
    std::string action;
    std::string state;
    std::string address;
    std::string tx_hash;
    std::string code_hash;
    std::string error;
};

RunResult run_deploy(
    ProgramRpc& primary,
    ProgramRpc* check,
    ProgramSigner& signer,
    RunTimer& timer,
    const SourceBundle& sources,
    const std::string& params_json);
RunResult run_verify(
    ProgramRpc& primary,
    RunTimer& timer,
    const std::string& address,
    const SourceBundle& sources);
nlohmann::json run_json(const RunResult& result);
std::string run_text(const RunResult& result);

}