// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once

#include <cstddef>
#include <filesystem>
#include <string>

namespace octra::program_cli::detail {

bool read_limited_file(
    const std::filesystem::path& path,
    size_t limit,
    const std::string& label,
    std::string& body,
    std::string& error);

}