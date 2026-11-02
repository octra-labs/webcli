// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
// lambda0xE
// Arthur Edelstein
// Denis CMIX

#pragma once

#include <array>
#include <cstddef>
#include <string>
#include <string_view>

namespace octra::program_cli {

class TerminalPin;

namespace program_terminal::detail {

TerminalPin make_pin(std::string_view value) noexcept;

}

class TerminalPin final {
public:
    static constexpr std::size_t max_size = 64;

    TerminalPin() noexcept = default;
    ~TerminalPin();
    TerminalPin(const TerminalPin&) = delete;
    TerminalPin& operator=(const TerminalPin&) = delete;
    TerminalPin(TerminalPin&& source) noexcept;
    TerminalPin& operator=(TerminalPin&& source) noexcept;

    std::string_view view() const noexcept;
    std::size_t size() const noexcept;
    bool empty() const noexcept;
    void clear() noexcept;

private:
    friend TerminalPin program_terminal::detail::make_pin(
        std::string_view value) noexcept;

    void assign(std::string_view value) noexcept;

    std::array<char, max_size> bytes_{};
    std::size_t size_ = 0;
};

struct TerminalPinResult final {
    bool ok = false;
    bool interrupted = false;
    int delivered_signal = 0;
    TerminalPin pin;
    std::string error;
};

TerminalPinResult read_terminal_pin();

}