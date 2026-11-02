// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
// lambda0xE
// Arthur Edelstein
// Denis CMIX

#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

#include "program_terminal.hpp"

namespace octra::program_cli {

class ProgramWallet;
struct WalletRead;

WalletRead read_program_wallet(
    const std::filesystem::path& path,
    const TerminalPin& pin);

class ProgramWallet {
    std::string address_;
    std::string rpc_url_;
    std::string public_key_b64_;
    std::array<uint8_t, 64> secret_key_{};
    bool locked_ = false;

    ProgramWallet(
        std::string address,
        std::string rpc_url,
        std::string public_key_b64,
        const std::array<uint8_t, 64>& secret_key);

    friend struct WalletRead;
    friend WalletRead read_program_wallet(
        const std::filesystem::path& path,
        const TerminalPin& pin);

public:
    ProgramWallet(const ProgramWallet&) = delete;
    ProgramWallet& operator=(const ProgramWallet&) = delete;
    ProgramWallet(ProgramWallet&& other) noexcept;
    ProgramWallet& operator=(ProgramWallet&& other) noexcept;
    ~ProgramWallet();

    const std::string& address() const;
    const std::string& rpc_url() const;
    const std::string& public_key_b64() const;
    const uint8_t* secret_key() const;
    void clear();
};

struct WalletRead {
    std::optional<ProgramWallet> wallet;
    std::string error;

    bool ok() const;
};

}