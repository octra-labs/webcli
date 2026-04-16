/*
    This file is part of Octra Wallet (webcli).

    Octra Wallet is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    Octra Wallet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Octra Wallet.  If not, see <http://www.gnu.org/licenses/>.

    This program is released under the GPL with the additional exemption
    that compiling, linking, and/or using OpenSSL is allowed.
    You are free to remove this exemption from derived works.

    Copyright 2025-2026 Octra Labs
              2025-2026 David A.
              2025-2026 Alex T.
              2025-2026 Vadim S.
              2025-2026 Julia L.
*/

#pragma once
#include <string>
#include <vector>
#include <atomic>
#include <memory>
#include <cstdio>
#include <ctime>
#include <chrono>
#include "lib/json.hpp"

#include "lib/httplib.h"

namespace octra {

inline void timing_ms_esc(double ms, const char** open, const char** reset) {
    if (ms >= 10000.0) {
        *open = "\033[31m";
        *reset = "\033[0m";
    } else if (ms >= 1000.0) {
        *open = "\033[33m";
        *reset = "\033[0m";
    } else {
        *open = "";
        *reset = "";
    }
}

inline void get_wall_hms(char* buf, size_t cap) {
    using std::chrono::system_clock;
    std::time_t t = system_clock::to_time_t(system_clock::now());
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    snprintf(buf, cap, "%02d:%02d:%02d", tm.tm_hour, tm.tm_min, tm.tm_sec);
}

inline void log_event(const char* msg) {
    char buf[16];
    get_wall_hms(buf, sizeof(buf));
    fprintf(stderr, "[%s] %s\n", buf, msg);
}

struct ScopedTimer {
    char wall[16];
    const char* label;
    const char* dot;
    std::chrono::steady_clock::time_point start;

    explicit ScopedTimer(const char* l) : label(l), start(std::chrono::steady_clock::now()) {
        const char* p = l;
        while (*p && *p != '.') ++p;
        dot = *p == '.' ? p : nullptr;
        get_wall_hms(wall, sizeof(wall));
        if (dot)
            fprintf(stderr, "[%s] [%.*s] %s started\n", wall, (int)(dot - label), label, dot + 1);
        else
            fprintf(stderr, "[%s] [%s] started\n", wall, label);
    }

    ~ScopedTimer() {
        double ms = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - start).count();
        char wall_now[16];
        get_wall_hms(wall_now, sizeof(wall_now));
        const char* esc;
        const char* reset;
        timing_ms_esc(ms, &esc, &reset);
        if (dot)
            fprintf(stderr, "[%s] [%.*s] %s %s(%.3f ms)%s\n", wall_now, (int)(dot - label), label, dot + 1, esc, ms, reset);
        else
            fprintf(stderr, "[%s] [%s] %s(%.3f ms)%s\n", wall_now, label, esc, ms, reset);
    }
};

struct OpTimer {
    const char* op;
    std::chrono::steady_clock::time_point wall_start;
    std::chrono::steady_clock::time_point step_start;
    std::chrono::steady_clock::time_point op_start;
    bool has_op_start;

    explicit OpTimer(const char* name, const char* desc)
        : op(name)
        , wall_start(std::chrono::steady_clock::now())
        , step_start(wall_start)
        , op_start(wall_start)
        , has_op_start(false)
    {
        char tw[16]; get_wall_hms(tw, sizeof(tw));
        fprintf(stderr, "[%s] [%s] %s (0.000 ms)\n", tw, op, desc);
    }

    void mutex_acquired() {
        auto now = std::chrono::steady_clock::now();
        _log_step("mutex_wait", wall_start, now);
        op_start = now;
        step_start = now;
        has_op_start = true;
    }

    void step(const char* name) {
        auto now = std::chrono::steady_clock::now();
        _log_step(name, step_start, now);
        step_start = now;
    }

    void step_msg(const char* msg) {
        char tw[16]; get_wall_hms(tw, sizeof(tw));
        fprintf(stderr, "[%s] [%s] %s\n", tw, op, msg);
        step_start = std::chrono::steady_clock::now();
    }

    void reset_step() {
        step_start = std::chrono::steady_clock::now();
    }

    ~OpTimer() {
        auto now = std::chrono::steady_clock::now();
        char tw[16]; get_wall_hms(tw, sizeof(tw));
        const char* esc; const char* reset;
        if (has_op_start) {
            double ms = std::chrono::duration<double, std::milli>(now - op_start).count();
            timing_ms_esc(ms, &esc, &reset);
            fprintf(stderr, "[%s] [%s] total %s(%.3f ms)%s\n", tw, op, esc, ms, reset);
        }
        double wall_ms = std::chrono::duration<double, std::milli>(now - wall_start).count();
        timing_ms_esc(wall_ms, &esc, &reset);
        fprintf(stderr, "[%s] [%s] handler_wall_total %s(%.3f ms)%s\n", tw, op, esc, wall_ms, reset);
    }

private:
    void _log_step(const char* name,
                   std::chrono::steady_clock::time_point from,
                   std::chrono::steady_clock::time_point to) {
        double ms = std::chrono::duration<double, std::milli>(to - from).count();
        char tw[16]; get_wall_hms(tw, sizeof(tw));
        const char* esc; const char* reset;
        timing_ms_esc(ms, &esc, &reset);
        fprintf(stderr, "[%s] [%s] %s %s(%.3f ms)%s\n", tw, op, name, esc, ms, reset);
    }
};

struct RpcResult {
    bool ok;
    nlohmann::json result;
    std::string error;
};

class RpcClient {
    std::string host_;
    std::string path_;
    bool ssl_;
    int port_;
    std::atomic<int> id_{0};

    static std::string rpc_start_label(const std::string& method, const std::string& hint) {
        if (!hint.empty())
            return std::string("calling the contract ") + hint + "...";
        return method + "...";
    }

    static void rpc_log_start(const std::string& method, const std::string& hint = "") {
        char tw[16];
        get_wall_hms(tw, sizeof(tw));
        std::string label = rpc_start_label(method, hint);
        fprintf(stderr, "[%s] [rpc] %s started\n", tw, label.c_str());
    }

    static void rpc_log_one_line(const std::string& method, double ms, bool ok, const std::string& err,
                                  const std::string& hint = "") {
        char tw[16];
        get_wall_hms(tw, sizeof(tw));
        const char* esc;
        const char* reset;
        timing_ms_esc(ms, &esc, &reset);
        std::string label = rpc_start_label(method, hint);
        if (ok)
            fprintf(stderr, "[%s] [rpc] %s ok %s(%.3f ms)%s\n", tw, label.c_str(), esc, ms, reset);
        else
            fprintf(stderr, "[%s] [rpc] %s failed %s(%.3f ms)%s: %s\n", tw, label.c_str(), esc, ms, reset, err.c_str());
    }

    void parse_url(const std::string& url) {
        std::string u = url;
        ssl_ = false;
        port_ = 80;
        if (u.rfind("https://", 0) == 0) {
            ssl_ = true;
            port_ = 443;
            u = u.substr(8);
        } else if (u.rfind("http://", 0) == 0) {
            u = u.substr(7);
        }
        auto slash = u.find('/');
        if (slash != std::string::npos) {
            path_ = u.substr(slash);
            host_ = u.substr(0, slash);
        } else {
            path_ = "/rpc";
            host_ = u;
        }
        auto colon = host_.find(':');
        if (colon != std::string::npos) {
            port_ = std::stoi(host_.substr(colon + 1));
            host_ = host_.substr(0, colon);
        }
    }

public:
    RpcClient() : path_("/rpc"), ssl_(true), port_(443) {}
    explicit RpcClient(const std::string& url) { parse_url(url); }
    void set_url(const std::string& url) { parse_url(url); }

    RpcResult call(const std::string& method,
                   const nlohmann::json& params = nlohmann::json::array(),
                   int timeout_sec = 30,
                   const std::string& hint = "") {
        auto t0 = std::chrono::steady_clock::now();
        nlohmann::json req;
        req["jsonrpc"] = "2.0";
        req["method"] = method;
        req["params"] = params;
        req["id"] = ++id_;
        std::string body = req.dump();
        rpc_log_start(method, hint);
        auto res = post_json(body, timeout_sec);
        double ms = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - t0).count();
        if (!res) {
            rpc_log_one_line(method, ms, false, "connection failed", hint);
            return {false, {}, "connection failed"};
        }
        RpcResult out = parse_response(res->body);
        rpc_log_one_line(method, ms, out.ok, out.error, hint);
        return out;
    }

    RpcResult get_balance(const std::string& addr) {
        return call("octra_balance", {addr});
    }

    RpcResult get_account(const std::string& addr, int limit = 20) {
        return call("octra_account", {addr, limit});
    }

    RpcResult get_transaction(const std::string& hash) {
        return call("octra_transaction", {hash});
    }

    RpcResult submit_tx(const nlohmann::json& tx) {
        return call("octra_submit", nlohmann::json::array({tx}));
    }

    RpcResult get_view_pubkey(const std::string& addr) {
        return call("octra_viewPubkey", {addr});
    }

    RpcResult get_encrypted_balance(const std::string& addr,
                                    const std::string& sig_b64,
                                    const std::string& pub_b64) {
        return call("octra_encryptedBalance", {addr, sig_b64, pub_b64});
    }

    RpcResult get_encrypted_cipher(const std::string& addr) {
        return call("octra_encryptedCipher", {addr});
    }

    RpcResult register_pvac_pubkey(const std::string& addr,
                                   const std::string& pk_b64,
                                   const std::string& sig_b64,
                                   const std::string& pub_b64,
                                   const std::string& aes_kat_hex = "") {
        return call("octra_registerPvacPubkey", {addr, pk_b64, sig_b64, pub_b64, aes_kat_hex});
    }

    RpcResult get_pvac_pubkey(const std::string& addr) {
        return call("octra_pvacPubkey", {addr});
    }

    RpcResult register_public_key(const std::string& addr,
                                   const std::string& pub_b64,
                                   const std::string& sig_b64) {
        return call("octra_registerPublicKey", {addr, pub_b64, sig_b64});
    }

    RpcResult get_stealth_outputs(int from_epoch = 0) {
        return call("octra_stealthOutputs", {from_epoch});
    }

    RpcResult staging_view() {
        return call("staging_view", nlohmann::json::array(), 5);
    }

    RpcResult compile_assembly(const std::string& source) {
        return call("octra_compileAssembly", {source}, 10);
    }

    RpcResult compile_aml(const std::string& source) {
        return call("octra_compileAml", {source}, 10);
    }

    RpcResult compile_aml_multi(const nlohmann::json& files, const std::string& main_path) {
        nlohmann::json payload;
        payload["files"] = files;
        payload["main"] = main_path;
        return call("octra_compileAmlMulti", nlohmann::json::array({payload}), 15);
    }

    RpcResult compute_contract_address(const std::string& bytecode_b64,
                                        const std::string& deployer,
                                        int nonce = 0) {
        return call("octra_computeContractAddress", {bytecode_b64, deployer, nonce});
    }

    RpcResult vm_contract(const std::string& addr) {
        return call("vm_contract", {addr});
    }

    RpcResult contract_receipt(const std::string& hash) {
        return call("contract_receipt", {hash});
    }

    RpcResult contract_call_view(const std::string& addr,
                                  const std::string& method,
                                  const nlohmann::json& params,
                                  const std::string& caller) {
        return call("contract_call", {addr, method, params, caller}, 15,
                    "(" + addr + ") with (" + method + ")");
    }

    RpcResult list_contracts() {
        return call("octra_listContracts", nlohmann::json::array(), 10);
    }

    RpcResult contract_storage(const std::string& addr, const std::string& key) {
        return call("octra_contractStorage", {addr, key});
    }

    RpcResult contract_abi(const std::string& addr) {
        return call("octra_contractAbi", {addr});
    }

    RpcResult save_abi(const std::string& addr, const std::string& abi) {
        return call("contract_saveAbi", {addr, abi});
    }

    RpcResult get_txs_by_address(const std::string& addr, int limit = 50, int offset = 0) {
        return call("octra_transactionsByAddress", {addr, limit, offset}, 15);
    }

    std::vector<RpcResult> call_batch(
            const std::vector<std::string>& methods,
            const std::vector<nlohmann::json>& params_list = {},
            int timeout_sec = 10) {
        auto t0 = std::chrono::steady_clock::now();
        nlohmann::json batch = nlohmann::json::array();
        size_t count = methods.size();
        for (size_t i = 0; i < count; ++i) {
            nlohmann::json req;
            req["jsonrpc"] = "2.0";
            req["method"] = methods[i];
            req["params"] = (i < params_list.size()) ? params_list[i] : nlohmann::json::array();
            req["id"] = static_cast<int>(i + 1);
            batch.push_back(std::move(req));
        }
        std::string body = batch.dump();
        rpc_log_start("batch(" + std::to_string(count) + ")", "");
        auto res = post_json(body, timeout_sec);
        double ms = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - t0).count();
        std::vector<RpcResult> out(count, {false, {}, "no response"});
        if (!res) {
            rpc_log_one_line("batch(" + std::to_string(count) + ")", ms, false, "connection failed");
            return out;
        }
        try {
            auto arr = nlohmann::json::parse(res->body);
            if (arr.is_array()) {
                for (auto& item : arr) {
                    if (!item.contains("id") || !item["id"].is_number_integer()) continue;
                    int id = item["id"].get<int>();
                    if (id < 1 || id > static_cast<int>(count)) continue;
                    if (item.contains("result")) {
                        out[id - 1] = {true, item["result"], ""};
                    } else if (item.contains("error")) {
                        auto& e = item["error"];
                        std::string msg = e.is_object() ? e.value("message", "rpc error") : e.dump();
                        out[id - 1] = {false, {}, msg};
                    }
                }
            }
        } catch (const std::exception& ex) {
            rpc_log_one_line("batch(" + std::to_string(count) + ")", ms, false, std::string("parse error: ") + ex.what());
            return out;
        }
        rpc_log_one_line("batch(" + std::to_string(count) + ")", ms, true, "");
        return out;
    }

private:
    httplib::Result post_json(const std::string& body, int timeout_sec) {
        httplib::Headers hdrs = {{"Content-Type", "application/json"}};
        if (ssl_) {
            httplib::SSLClient cli(host_, port_);
            cli.set_connection_timeout(timeout_sec, 0);
            cli.set_read_timeout(timeout_sec, 0);
            cli.enable_server_certificate_verification(false);
            return cli.Post(path_, hdrs, body, "application/json");
        }
        httplib::Client cli(host_, port_);
        cli.set_connection_timeout(timeout_sec, 0);
        cli.set_read_timeout(timeout_sec, 0);
        return cli.Post(path_, hdrs, body, "application/json");
    }

    RpcResult parse_response_obj(const nlohmann::json& j) {
        if (j.contains("result"))
            return {true, j["result"], ""};
        if (j.contains("error")) {
            auto& e = j["error"];
            std::string msg = e.is_object() ? e.value("message", "rpc error") : e.dump();
            return {false, {}, msg};
        }
        return {false, {}, "unknown rpc response"};
    }

    RpcResult parse_response(const std::string& body) {
        try {
            auto j = nlohmann::json::parse(body);
            return parse_response_obj(j);
        } catch (const std::exception& ex) {
            return {false, {}, std::string("parse error: ") + ex.what()};
        }
    }
};

} // namespace octra