// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
// lambda0xE
// Arthur Edelstein
// Denis CMIX

#include "program_cli_plan.hpp"

#include <algorithm>
#include <charconv>

#include "program_cli_detail.hpp"

namespace octra::program_cli {

namespace {

bool decimal_port(const std::string& value) {
    if (value.empty()) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return c >= '0' && c <= '9';
    });
}

bool take_value(
    int argc,
    const char* const* argv,
    int& index,
    std::string& value,
    std::string& error) {
    if (index + 1 >= argc) {
        error = std::string("missing value for ") + argv[index];
        return false;
    }
    value = argv[++index];
    if (value.empty() || value.front() == '-') {
        error = std::string("missing value for ") + argv[index - 1];
        return false;
    }
    return true;
}

bool set_once(bool& present, const std::string& name, std::string& error) {
    if (present) {
        error = "duplicate option " + name;
        return false;
    }
    present = true;
    return true;
}

bool pin_option(const std::string& arg) {
    return arg == "--pin" || arg.rfind("--pin=", 0) == 0;
}

bool args_have_pin(int argc, const char* const* argv, int first) {
    for (int index = first; index < argc; ++index) {
        if (pin_option(argv[index])) return true;
    }
    return false;
}

}

ParseResult parse(int argc, const char* const* argv) {
    ParseResult out;
    if (argc <= 1) return out;
    const std::string first = argv[1];
    if (decimal_port(first)) {
        int port = 0;
        const auto parsed = std::from_chars(
            first.data(),
            first.data() + first.size(),
            port);
        if (parsed.ec == std::errc()
            && parsed.ptr == first.data() + first.size()
            && port > 0
            && port <= 65'535) return out;
        out.handled = true;
        out.error = "Webcli port is invalid";
        return out;
    }

    int index = 1;
    if (first == "-h" || first == "--help" || first == "help") {
        out.handled = true;
        if (argc != 2) {
            out.error = args_have_pin(argc, argv, 2)
                ? "PIN arguments are not supported"
                : "Webcli help does not accept options";
            return out;
        }
        out.ok = true;
        out.options.command = Command::help;
        return out;
    }
    if (first == "program") {
        out.handled = true;
        if (argc <= 2) {
            out.error = "Program command is required";
            return out;
        }
        const std::string action = argv[++index];
        if (action == "deploy") out.options.command = Command::deploy;
        else if (action == "verify") out.options.command = Command::verify;
        else if (action == "help" || action == "--help" || action == "-h") {
            if (argc != 3) {
                out.error = args_have_pin(argc, argv, 3)
                    ? "PIN arguments are not supported"
                    : "Program help does not accept options";
                return out;
            }
            out.ok = true;
            out.options.command = Command::help;
            return out;
        } else {
            out.error = "Unknown Program command";
            return out;
        }
    } else if (first == "-deploy" || first == "--deploy") {
        out.handled = true;
        out.options.command = Command::deploy;
    } else if (first == "-verify" || first == "--verify") {
        out.handled = true;
        out.options.command = Command::verify;
    } else if (!first.empty() && first.front() == '-') {
        out.handled = true;
        out.error = "Unknown webcli option";
        return out;
    } else {
        out.handled = true;
        out.error = "Webcli port is invalid";
        return out;
    }

    bool rpc_seen = false;
    bool check_rpc_seen = false;
    bool wallet_seen = false;
    bool params_seen = false;
    bool params_file_seen = false;
    bool json_seen = false;
    std::vector<std::string> positional;
    for (++index; index < argc; ++index) {
        const std::string arg = argv[index];
        if (arg == "--rpc") {
            if (!set_once(rpc_seen, arg, out.error)
                || !take_value(argc, argv, index, out.options.rpc_url, out.error)) return out;
        } else if (arg == "--check-rpc") {
            if (!set_once(check_rpc_seen, arg, out.error)
                || !take_value(argc, argv, index, out.options.check_rpc_url, out.error)) return out;
        } else if (arg == "--wallet") {
            if (!set_once(wallet_seen, arg, out.error)
                || !take_value(argc, argv, index, out.options.wallet_path, out.error)) return out;
        } else if (arg == "--params") {
            if (!set_once(params_seen, arg, out.error)
                || !take_value(argc, argv, index, out.options.params_json, out.error)) return out;
        } else if (arg == "--params-file") {
            if (!set_once(params_file_seen, arg, out.error)
                || !take_value(argc, argv, index, out.options.params_path, out.error)) return out;
        } else if (arg == "--file") {
            std::string path;
            if (!take_value(argc, argv, index, path, out.error)) return out;
            out.options.file_paths.push_back(std::move(path));
        } else if (arg == "--json") {
            if (!set_once(json_seen, arg, out.error)) return out;
            out.options.json_output = true;
        } else if (pin_option(arg)) {
            out.error = "PIN arguments are not supported";
            return out;
        } else if (!arg.empty() && arg.front() == '-') {
            out.error = "Unknown Program option";
            return out;
        } else {
            positional.push_back(arg);
        }
    }

    if (params_seen && params_file_seen) {
        out.error = "Use either --params or --params-file";
        return out;
    }
    if (out.options.command == Command::deploy) {
        if (positional.size() != 1) {
            out.error = "Program deploy requires one source path";
            return out;
        }
        out.options.source_path = positional[0];
        if (out.options.params_json.empty()) out.options.params_json = "[]";
        if (!out.options.params_path.empty()) out.options.params_json.clear();
        if (!out.options.params_json.empty()
            && !detail::params_json_ok(out.options.params_json, out.error)) return out;
    } else {
        if (positional.size() != 2) {
            out.error = "Program verify requires an address and source path";
            return out;
        }
        if (wallet_seen || params_seen || params_file_seen || check_rpc_seen) {
            out.error = "Program verify does not use wallet, parameter, or compiler check options";
            return out;
        }
        out.options.address = positional[0];
        out.options.source_path = positional[1];
        if (!valid_address(out.options.address)) {
            out.error = "Program address is invalid";
            return out;
        }
    }
    if (out.options.source_path.size() > detail::max_path_bytes
        || out.options.wallet_path.size() > detail::max_path_bytes
        || out.options.params_path.size() > detail::max_path_bytes
        || out.options.rpc_url.size() > detail::max_path_bytes
        || out.options.check_rpc_url.size() > detail::max_path_bytes
        || out.options.file_paths.size() >= detail::max_source_files) {
        out.error = "Program option exceeds local limit";
        return out;
    }
    out.ok = true;
    return out;
}

std::string help_text(const std::string& name) {
    const std::string bin = name.empty() ? "webcli" : name;
    return
        "usage = " + bin + " program deploy SOURCE [--file PATH] [--params JSON] [--params-file PATH] [--wallet PATH] [--rpc URL] [--check-rpc URL] [--json]\n"
        "usage = " + bin + " program verify ADDRESS SOURCE [--file PATH] [--rpc URL] [--json]\n"
        "alias = " + bin + " -deploy SOURCE\n"
        "alias = " + bin + " -verify ADDRESS SOURCE\n"
        "input = SOURCE may be main.aml, a project directory, or an .aml-project.json file\n"
        "input = --file paths are relative to the SOURCE directory\n"
        "network = remote deploy requires a separate operator-selected --check-rpc URL\n"
        "verify = successful verification publishes Program source metadata\n"
        "secret = deploy reads one PIN from the terminal; PIN arguments are refused\n";
}

bool valid_address(const std::string& address) {
    static const std::string base58 =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    return address.size() == 47
        && address.rfind("oct", 0) == 0
        && address.find_first_not_of(base58, 3) == std::string::npos;
}

}