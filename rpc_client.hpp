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
#include "lib/json.hpp"

#include "lib/httplib.h"

namespace octra {

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
                   int timeout_sec = 30) {
        nlohmann::json req;
        req["jsonrpc"] = "2.0";
        req["method"] = method;
        req["params"] = params;
        req["id"] = ++id_;
        std::string body = req.dump();
        httplib::Headers hdrs = {{"Content-Type", "application/json"}};
        if (ssl_) {
            httplib::SSLClient cli(host_, port_);
            cli.set_connection_timeout(timeout_sec, 0);
            cli.set_read_timeout(timeout_sec, 0);
            cli.enable_server_certificate_verification(false);
            auto res = cli.Post(path_, hdrs, body, "application/json");
            if (!res) return {false, {}, "connection failed"};
            return parse_response(res->body);
        } else {
            httplib::Client cli(host_, port_);
            cli.set_connection_timeout(timeout_sec, 0);
            cli.set_read_timeout(timeout_sec, 0);
            auto res = cli.Post(path_, hdrs, body, "application/json");
            if (!res) return {false, {}, "connection failed"};
            return parse_response(res->body);
        }
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
                                   const std::string& pub_b64) {
        return call("octra_registerPvacPubkey", {addr, pk_b64, sig_b64, pub_b64});
    }

    RpcResult get_pvac_pubkey(const std::string& addr) {
        return call("octra_pvacPubkey", {addr});
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
        return call("contract_call", {addr, method, params, caller}, 15);
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

private:
    RpcResult parse_response(const std::string& body) {
        try {
            auto j = nlohmann::json::parse(body);
            if (j.contains("result"))
                return {true, j["result"], ""};
            if (j.contains("error")) {
                auto& e = j["error"];
                std::string msg = e.is_object() ? e.value("message", "rpc error") : e.dump();
                return {false, {}, msg};
            }
            return {false, {}, "unknown rpc response"};
        } catch (const std::exception& ex) {
            return {false, {}, std::string("parse error: ") + ex.what()};
        }
    }
};

} // namespace octra
