// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
// lambda0xE
// Arthur Edelstein
// Denis CMIX

#pragma once

#include <string>
#include <vector>

#include "json.hpp"

namespace octra::program_cli {

enum class Command {
    none,
    help,
    deploy,
    verify
};

struct Options {
    Command command = Command::none;
    std::string source_path;
    std::string address;
    std::string wallet_path = "data/wallet.oct";
    std::string rpc_url;
    std::string check_rpc_url;
    std::string params_json;
    std::string params_path;
    std::vector<std::string> file_paths;
    bool json_output = false;
};

struct ParseResult {
    bool handled = false;
    bool ok = false;
    Options options;
    std::string error;
};

struct SourceFile {
    std::string path;
    std::string body;
};

struct SourceBundle {
    std::vector<SourceFile> files;
    std::string main_source;
};

struct SourceResult {
    bool ok = false;
    SourceBundle bundle;
    std::string error;
};

struct CompileArtifact {
    std::string envelope_b64;
    std::string package_b64;
    std::string version;
    int instructions = 0;
};

struct ArtifactResult {
    bool ok = false;
    CompileArtifact artifact;
    std::string error;
};

ParseResult parse(int argc, const char* const* argv);
std::string help_text(const std::string& name);
bool valid_address(const std::string& address);
bool valid_source_path(const std::string& path);
SourceResult load_sources(const Options& options);
ArtifactResult inspect_compile_package(
    const nlohmann::json& result,
    const SourceBundle& sources);
nlohmann::json compile_files_json(const SourceBundle& sources);
nlohmann::json verify_files_json(const SourceBundle& sources);
std::string deploy_params(const Options& options, std::string& error);

}