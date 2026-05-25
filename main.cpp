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

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>
#include <set>
#include <algorithm>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>
#include <optional>
#include <unordered_map>
#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <signal.h>
#include <sys/resource.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#endif

#include "lib/httplib.h"
#include "lib/json.hpp"

extern "C" {
#include "lib/tweetnacl.h"
}

#include "crypto_utils.hpp"
#include "wallet.hpp"
#include "rpc_client.hpp"
#include "lib/circle_hfhe_receipt.hpp"
#include "lib/tx_builder.hpp"
#include "lib/pvac_bridge.hpp"
#include "lib/stealth.hpp"
#include "lib/txcache.hpp"

using json = nlohmann::json;

static octra::Wallet g_wallet;
static octra::RpcClient g_rpc;
static octra::PvacBridge g_pvac;
static std::mutex g_mtx;
static bool g_pvac_confirmed = false;
static bool g_pvac_ok = false;
static std::atomic<bool> g_wallet_loaded{false};
static std::string g_wallet_path = "data/wallet.oct";
static std::string g_pin;
static TxCache g_txcache;

static nlohmann::json g_fee_cache;
static double g_fee_cache_ts = 0.0;
static std::mutex g_fee_mtx;

struct HistoryRuntimeState {
    double last_top_refresh_ts = 0.0;
    json rejected = json::array();
    int total = 0;
    std::unordered_map<std::string, json> pages;
    std::unordered_map<std::string, double> page_ts;
};

static std::unordered_map<std::string, HistoryRuntimeState> g_history_runtime;
static std::mutex g_history_runtime_mtx;

struct TokenHistoryRuntimeState {
    double ts = 0.0;
    json rows = json::array();
    int incoming = 0;
    int outgoing = 0;
};

static std::unordered_map<std::string, TokenHistoryRuntimeState> g_token_history_runtime;
static std::mutex g_token_history_runtime_mtx;

static std::unordered_map<std::string, std::vector<uint8_t>> g_pk_cache;
static std::mutex g_pk_mtx;

static std::optional<std::vector<uint8_t>> pk_cache_get(const std::string& addr) {
    std::lock_guard<std::mutex> lk(g_pk_mtx);
    auto it = g_pk_cache.find(addr);
    if (it == g_pk_cache.end()) return std::nullopt;
    return it->second;
}

static std::string current_public_rpc_url() {
    if (g_wallet_loaded) return g_wallet.rpc_url;
    const char* env_rpc = std::getenv("OCTRA_RPC_URL");
    if (env_rpc && *env_rpc) return env_rpc;
    return "http://127.0.0.1:8080";
}

struct RelayProxyResult {
    bool ok = false;
    int status = 0;
    std::string body;
    std::string error;
};

static std::string current_circle_relayer_url() {
    const char* env_relayer = std::getenv("OCTRA_CIRCLE_RELAYER_URL");
    if (env_relayer && *env_relayer) return env_relayer;
    return "http://127.0.0.1:9494";
}

static RelayProxyResult relay_http_get(const std::string& path) {
    httplib::Client cli(current_circle_relayer_url());
    cli.set_connection_timeout(5, 0);
    cli.set_read_timeout(30, 0);
    auto r = cli.Get(path.c_str());
    if (!r) return {false, 502, "", "relay unavailable"};
    return {true, r->status, r->body, ""};
}

static RelayProxyResult relay_http_post(const std::string& path, const std::string& body) {
    httplib::Client cli(current_circle_relayer_url());
    cli.set_connection_timeout(5, 0);
    cli.set_read_timeout(30, 0);
    auto r = cli.Post(path.c_str(), body, "application/json");
    if (!r) return {false, 502, "", "relay unavailable"};
    return {true, r->status, r->body, ""};
}

static void pk_cache_put(const std::string& addr, const std::vector<uint8_t>& pk) {
    if (pk.size() != 32) return;
    std::lock_guard<std::mutex> lk(g_pk_mtx);
    if (g_pk_cache.size() > 2048) g_pk_cache.clear();
    g_pk_cache[addr] = pk;
}

static void handle_signal(int) {
    octra::secure_zero(g_wallet.sk, 64);
    octra::secure_zero(g_wallet.pk, 32);
    if (!g_pin.empty()) octra::secure_zero(&g_pin[0], g_pin.size());
#ifdef _WIN32
    ExitProcess(0);
#else
    _exit(0);
#endif
}

static double now_ts() {
    auto d = std::chrono::system_clock::now().time_since_epoch();
    return std::chrono::duration<double>(d).count();
}

static json err_json(const std::string& msg) {
    return {{"error", msg}};
}

static bool tx_status_is_pending_like(const json& tx) {
    const std::string status = tx.value("status", "pending");
    return status.empty() || status == "pending";
}

static json history_tx_from_lookup(const json& lookup, const json& fallback) {
    json tx = fallback;
    tx["hash"] = lookup.value("tx_hash", fallback.value("hash", ""));
    tx["from"] = lookup.value("from", fallback.value("from", ""));
    tx["to_"] = lookup.value("to", lookup.value("to_", fallback.value("to_", fallback.value("to", ""))));
    tx["amount_raw"] = lookup.value("amount_raw", lookup.value("amount", fallback.value("amount_raw", "0")));
    tx["op_type"] = lookup.value("op_type", fallback.value("op_type", "standard"));
    tx["status"] = lookup.value("status", fallback.value("status", "pending"));

    double ts = fallback.value("timestamp", 0.0);
    if (lookup.contains("timestamp") && lookup["timestamp"].is_number())
        ts = lookup["timestamp"].get<double>();
    else if (lookup.contains("rejected_at") && lookup["rejected_at"].is_number())
        ts = lookup["rejected_at"].get<double>();
    tx["timestamp"] = ts;

    if (lookup.contains("message") && lookup["message"].is_string() && !lookup["message"].get<std::string>().empty())
        tx["message"] = lookup["message"];
    if (lookup.contains("encrypted_data") && lookup["encrypted_data"].is_string() && !lookup["encrypted_data"].get<std::string>().empty())
        tx["encrypted_data"] = lookup["encrypted_data"];
    if (lookup.contains("epoch"))
        tx["epoch"] = lookup["epoch"];
    else if (lookup.contains("epoch_id"))
        tx["epoch"] = lookup["epoch_id"];
    if (lookup.contains("block_height"))
        tx["block_height"] = lookup["block_height"];

    if (lookup.contains("error") && lookup["error"].is_object()) {
        tx["reject_reason"] = lookup["error"].value("reason", "");
        tx["reject_type"] = lookup["error"].value("type", "");
    } else {
        tx.erase("reject_reason");
        tx.erase("reject_type");
    }
    return tx;
}

static bool reconcile_history_rows(const std::string& addr, json& txs) {
    if (!txs.is_array() || txs.empty()) return false;
    std::vector<std::string> methods;
    std::vector<json> params_list;
    std::vector<size_t> positions;
    for (size_t i = 0; i < txs.size(); ++i) {
        if (!txs[i].is_object() || !tx_status_is_pending_like(txs[i])) continue;
        const std::string hash = txs[i].value("hash", "");
        if (hash.empty()) continue;
        methods.push_back("octra_transaction");
        params_list.push_back(json::array({hash}));
        positions.push_back(i);
    }
    if (methods.empty()) return false;
    auto results = g_rpc.call_batch(methods, params_list, 10);
    bool changed = false;
    for (size_t i = 0; i < results.size() && i < positions.size(); ++i) {
        if (!results[i].ok || !results[i].result.is_object()) continue;
        const std::string status = results[i].result.value("status", "");
        if (status.empty() || status == "pending") continue;
        json updated = history_tx_from_lookup(results[i].result, txs[positions[i]]);
        txs[positions[i]] = updated;
        if (g_txcache.is_open()) g_txcache.store_tx(addr, updated);
        changed = true;
    }
    return changed;
}

static HistoryRuntimeState history_runtime_get(const std::string& addr) {
    std::lock_guard<std::mutex> lk(g_history_runtime_mtx);
    auto it = g_history_runtime.find(addr);
    if (it == g_history_runtime.end()) return {};
    return it->second;
}

static void history_runtime_put(const std::string& addr, const HistoryRuntimeState& state) {
    std::lock_guard<std::mutex> lk(g_history_runtime_mtx);
    g_history_runtime[addr] = state;
}

static void history_runtime_clear(const std::string& addr) {
    std::lock_guard<std::mutex> lk(g_history_runtime_mtx);
    g_history_runtime.erase(addr);
}

static void history_runtime_clear_all() {
    std::lock_guard<std::mutex> lk(g_history_runtime_mtx);
    g_history_runtime.clear();
}

static std::optional<TokenHistoryRuntimeState> token_history_runtime_get(const std::string& addr) {
    std::lock_guard<std::mutex> lk(g_token_history_runtime_mtx);
    auto it = g_token_history_runtime.find(addr);
    if (it == g_token_history_runtime.end()) return std::nullopt;
    return it->second;
}

static void token_history_runtime_put(const std::string& addr, const TokenHistoryRuntimeState& state) {
    std::lock_guard<std::mutex> lk(g_token_history_runtime_mtx);
    g_token_history_runtime[addr] = state;
}

static void token_history_runtime_clear(const std::string& addr) {
    std::lock_guard<std::mutex> lk(g_token_history_runtime_mtx);
    g_token_history_runtime.erase(addr);
}

static void token_history_runtime_clear_all() {
    std::lock_guard<std::mutex> lk(g_token_history_runtime_mtx);
    g_token_history_runtime.clear();
}

static std::string parse_ou(const json& body, const std::string& fallback) {
    std::string val = body.value("ou", "");
    if (val.empty()) return fallback;
    try {
        long long v = std::stoll(val);
        if (v > 0) return val;
    } catch (...) {}
    return fallback;
}

static constexpr size_t CIRCLE_ASSET_MAX_RAW_BYTES = 33554432;
static constexpr size_t CIRCLE_ASSET_MAX_B64_BYTES = ((CIRCLE_ASSET_MAX_RAW_BYTES + 2) / 3) * 4;

static size_t circle_asset_decoded_size_upper_bound(size_t wire_len) {
    return ((wire_len + 3) / 4) * 3;
}

static int64_t circle_asset_ou_from_b64_len(size_t wire_len) {
    const size_t raw_upper_bound = circle_asset_decoded_size_upper_bound(wire_len);
    if (raw_upper_bound <= 4096) return 5000;
    if (raw_upper_bound <= 16384) return 10000;
    if (raw_upper_bound <= 32768) return 20000;
    if (raw_upper_bound <= 131072) return 40000;
    if (raw_upper_bound <= 524288) return 80000;
    if (raw_upper_bound <= 2097152) return 160000;
    if (raw_upper_bound <= 8388608) return 320000;
    return 640000;
}

static const int64_t MAX_OCT_RAW = 1000000000LL * 1000000LL;

static int64_t parse_amount_raw(const json& body) {
    try {
        std::string s;
        if (body.contains("amount")) {
            if (body["amount"].is_string()) s = body["amount"].get<std::string>();
            else if (body["amount"].is_number()) {
                s = body["amount"].dump();
            }
            else return -1;
        } else return -1;
        if (s.empty()) return -1;
        size_t dot = s.find('.');
        if (dot == std::string::npos) {
            for (char c : s) if (c < '0' || c > '9') return -1;
            int64_t v = std::stoll(s);
            if (v > MAX_OCT_RAW / 1000000) return -1;
            return v * 1000000;
        }
        std::string integer_part = s.substr(0, dot);
        std::string frac_part = s.substr(dot + 1);
        if (integer_part.empty() && frac_part.empty()) return -1;
        for (char c : integer_part) if (c < '0' || c > '9') return -1;
        for (char c : frac_part) if (c < '0' || c > '9') return -1;
        if (frac_part.size() > 6) frac_part = frac_part.substr(0, 6);
        while (frac_part.size() < 6) frac_part += '0';
        int64_t ip = integer_part.empty() ? 0 : std::stoll(integer_part);
        if (ip > MAX_OCT_RAW / 1000000) return -1;
        int64_t fp = std::stoll(frac_part);
        return ip * 1000000 + fp;
    } catch (const std::logic_error&) {
        return -1;
    }
}

struct BalanceInfo {
    int nonce;
    std::string balance_raw;
};

static BalanceInfo get_nonce_balance() {
    auto r = g_rpc.get_balance(g_wallet.addr);
    if (!r.ok) return {0, "0"};
    int nonce = r.result.value("pending_nonce", r.result.value("nonce", 0));
    std::string raw = "0";
    if (r.result.contains("balance_raw")) {
        auto& v = r.result["balance_raw"];
        raw = v.is_string() ? v.get<std::string>() : std::to_string(v.get<int64_t>());
    } else if (r.result.contains("balance")) {
        auto& v = r.result["balance"];
        json tmp;
        tmp["amount"] = v;
        int64_t parsed = parse_amount_raw(tmp);
        raw = std::to_string(parsed >= 0 ? parsed : 0);
    }
    auto pr = g_rpc.staging_view();
    if (pr.ok && pr.result.contains("transactions")) {
        for (auto& tx : pr.result["transactions"]) {
            if (tx.value("from", "") == g_wallet.addr) {
                int pn = tx.value("nonce", 0);
                if (pn > nonce) nonce = pn;
            }
        }
    }
    return {nonce, raw};
}

static void sign_tx_fields(octra::Transaction& tx) {
    std::string msg = octra::canonical_json(tx);
    tx.signature = octra::ed25519_sign_detached(
        reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), g_wallet.sk);
    tx.public_key = g_wallet.pub_b64;
}

static std::string sign_circle_read_request(const std::string& op,
                                            const std::string& circle_id,
                                            const std::string& subject = "") {
    return octra::sign_circle_read_request(
        op,
        circle_id,
        g_wallet.addr,
        subject,
        g_wallet.sk);
}

static std::string sign_circle_view_request(const std::string& circle_id,
                                            const std::string& method,
                                            const json& params,
                                            bool include_storage) {
    const std::string params_hash = octra::sha256_hex(params.dump());
    const std::string subject =
        method + "|" + params_hash + "|" + (include_storage ? "1" : "0");
    return sign_circle_read_request("octra_circle_view", circle_id, subject);
}

static octra::RpcResult circle_info_auth_rpc(const std::string& circle_id) {
    octra::RpcClient rpc(current_public_rpc_url());
    return rpc.circle_info_auth(
        circle_id,
        g_wallet.addr,
        g_wallet.pub_b64,
        sign_circle_read_request("octra_circle_info", circle_id));
}

static octra::RpcResult circle_hfhe_policy_auth_rpc(const std::string& circle_id) {
    octra::RpcClient rpc(current_public_rpc_url());
    return rpc.circle_hfhe_policy_auth(
        circle_id,
        g_wallet.addr,
        g_wallet.pub_b64,
        sign_circle_read_request("octra_circle_hfhe_policy", circle_id));
}

static octra::RpcResult circle_key_policy_auth_rpc(const std::string& circle_id,
                                                   const std::string& key_id) {
    octra::RpcClient rpc(current_public_rpc_url());
    return rpc.circle_key_policy_auth(
        circle_id,
        key_id,
        g_wallet.addr,
        g_wallet.pub_b64,
        sign_circle_read_request("octra_circle_key_policy", circle_id, key_id));
}

static octra::RpcResult circle_outbox_status_auth_rpc(const std::string& circle_id,
                                                      const std::string& intent_id) {
    octra::RpcClient rpc(current_public_rpc_url());
    return rpc.circle_outbox_status_auth(
        circle_id,
        intent_id,
        g_wallet.addr,
        g_wallet.pub_b64,
        sign_circle_read_request("octra_circle_outbox_status", circle_id, intent_id));
}

static bool circle_string_list_contains(const json& values, const std::string& target) {
    if (!values.is_array()) return false;
    for (const auto& value : values) {
        if (value.is_string() && value.get<std::string>() == target) {
            return true;
        }
    }
    return false;
}

static bool circle_hfhe_mode_allows(const std::string& mode,
                                    const std::string& owner,
                                    const std::string& caller,
                                    const std::string& subject,
                                    const std::vector<std::string>& active_relays) {
    const bool caller_is_active_relay =
        std::find(active_relays.begin(), active_relays.end(), caller) != active_relays.end();
    if (mode == "deny") return false;
    if (mode == "owner_only") return caller == owner;
    if (mode == "caller_self") return caller == subject;
    if (mode == "owner_or_caller") return caller == owner || caller == subject;
    if (mode == "any_registered") return !caller.empty();
    if (mode == "active_relay") return caller_is_active_relay;
    if (mode == "owner_or_active_relay") return caller == owner || caller_is_active_relay;
    return false;
}

static bool circle_hfhe_pk_allowed(const json& policy, const std::string& requested_addr) {
    if (!policy.contains("pk_allowlist") || policy["pk_allowlist"].is_null()) {
        return true;
    }
    return circle_string_list_contains(policy["pk_allowlist"], requested_addr);
}

static bool circle_key_policy_live(const std::string& circle_id,
                                   const std::string& key_id,
                                   std::string& error) {
    auto r = circle_key_policy_auth_rpc(circle_id, key_id);
    if (!r.ok) {
        error = r.error.empty() ? "circle key policy read failed" : r.error;
        return false;
    }
    if (!r.result.contains("live") || !r.result["live"].is_boolean()) {
        error = "circle key policy live status unavailable";
        return false;
    }
    if (!r.result["live"].get<bool>()) {
        error = "circle key policy is not live";
        return false;
    }
    return true;
}

static bool circle_hfhe_active_relays(const std::string& circle_id,
                                      const std::string& intent_id,
                                      std::vector<std::string>& active_relays,
                                      std::string& error) {
    auto status_r = circle_outbox_status_auth_rpc(circle_id, intent_id);
    if (!status_r.ok) {
        error = status_r.error.empty() ? "circle outbox status read failed" : status_r.error;
        return false;
    }
    if (status_r.result.value("status", "") != "claimed") {
        error = "circle outbox intent is not actively claimed";
        return false;
    }
    if (!status_r.result.value("claim_ready", false)) {
        error = "circle outbox intent relay quorum is not ready";
        return false;
    }
    active_relays.clear();
    const auto active_claims = status_r.result.value("active_claims", json::array());
    for (const auto& claim : active_claims) {
        if (claim.is_object()) {
            const std::string relay_id = claim.value("relay_id", "");
            if (!relay_id.empty()) {
                active_relays.push_back(relay_id);
            }
        }
    }
    if (active_relays.empty()) {
        error = "circle outbox active relays are unavailable";
        return false;
    }
    return true;
}

static bool circle_hfhe_authorize(const std::string& circle_id,
                                  const std::string& mode_key,
                                  const std::string& requested_addr,
                                  const std::string& key_id,
                                  const std::string& intent_id,
                                  std::string& error) {
    auto info_r = circle_info_auth_rpc(circle_id);
    if (!info_r.ok) {
        error = info_r.error.empty() ? "circle info read failed" : info_r.error;
        return false;
    }
    auto policy_r = circle_hfhe_policy_auth_rpc(circle_id);
    if (!policy_r.ok) {
        error = policy_r.error.empty() ? "circle hfhe policy read failed" : policy_r.error;
        return false;
    }
    json policy = policy_r.result.value("policy", json::object());
    if (mode_key == "load_pk_mode" && !circle_hfhe_pk_allowed(policy, requested_addr)) {
        error = "requested pubkey address is not allowed by circle hfhe policy";
        return false;
    }
    const std::string owner = info_r.result.value("owner", "");
    const std::string default_mode =
        mode_key == "load_pk_mode" ? "caller_self" : "owner_only";
    const std::string mode = policy.value(mode_key, default_mode);
    std::vector<std::string> active_relays;
    if (mode == "active_relay" || mode == "owner_or_active_relay") {
        if (intent_id.empty()) {
            error = "intent_id required by circle hfhe relay-scoped policy";
            return false;
        }
        if (!circle_hfhe_active_relays(circle_id, intent_id, active_relays, error)) {
            return false;
        }
    }
    const std::string subject =
        mode_key == "load_pk_mode" ? requested_addr : g_wallet.addr;
    if (!circle_hfhe_mode_allows(mode, owner, g_wallet.addr, subject, active_relays)) {
        error = "circle hfhe policy denied this operation";
        return false;
    }
    const bool require_live_key_policy = policy.value("require_live_key_policy", true);
    if (require_live_key_policy) {
        if (key_id.empty()) {
            error = "key_id required by circle hfhe policy";
            return false;
        }
        if (!circle_key_policy_live(circle_id, key_id, error)) {
            return false;
        }
    }
    return true;
}

static bool circle_decode_zero_proof(const std::string& encoded,
                                     pvac_zero_proof& proof,
                                     std::string& error) {
    proof = nullptr;
    if (encoded.rfind(octra::ZKZP_PREFIX, 0) != 0) {
        error = "invalid zero proof prefix";
        return false;
    }
    auto raw = octra::base64_decode(encoded.substr(std::strlen(octra::ZKZP_PREFIX)));
    if (raw.empty()) {
        error = "invalid zero proof encoding";
        return false;
    }
    proof = pvac_deserialize_zero_proof(raw.data(), raw.size());
    if (!proof) {
        error = "invalid zero proof";
        return false;
    }
    return true;
}

static bool circle_verify_zero_with_wallet(const std::string& ciphertext_b64,
                                           const std::string& zero_proof_b64,
                                           std::string& error) {
    auto raw = octra::base64_decode(ciphertext_b64);
    if (raw.empty()) {
        error = "invalid ciphertext";
        return false;
    }
    pvac_cipher ct = g_pvac.deserialize_cipher(raw.data(), raw.size());
    if (!ct) {
        error = "invalid ciphertext";
        return false;
    }
    pvac_zero_proof proof = nullptr;
    if (!circle_decode_zero_proof(zero_proof_b64, proof, error)) {
        g_pvac.free_cipher(ct);
        return false;
    }
    bool ok = pvac_verify_zero(g_pvac.pk(), ct, proof) != 0;
    pvac_free_zero_proof(proof);
    g_pvac.free_cipher(ct);
    if (!ok) error = "zero proof verification failed";
    return ok;
}

static bool circle_verify_bound_with_wallet(const std::string& ciphertext_b64,
                                            const std::string& zero_proof_b64,
                                            const std::string& amount_commitment_b64,
                                            std::string& error) {
    auto raw = octra::base64_decode(ciphertext_b64);
    if (raw.empty()) {
        error = "invalid ciphertext";
        return false;
    }
    auto commitment = octra::base64_decode(amount_commitment_b64);
    if (commitment.size() != 32) {
        error = "invalid amount commitment";
        return false;
    }
    pvac_cipher ct = g_pvac.deserialize_cipher(raw.data(), raw.size());
    if (!ct) {
        error = "invalid ciphertext";
        return false;
    }
    pvac_zero_proof proof = nullptr;
    if (!circle_decode_zero_proof(zero_proof_b64, proof, error)) {
        g_pvac.free_cipher(ct);
        return false;
    }
    bool ok = pvac_verify_zero_bound(g_pvac.pk(), ct, proof, commitment.data()) != 0;
    pvac_free_zero_proof(proof);
    g_pvac.free_cipher(ct);
    if (!ok) error = "bound proof verification failed";
    return ok;
}

static bool circle_verify_range_with_wallet(const std::string& ciphertext_b64,
                                            const std::string& range_proof_b64,
                                            std::string& error) {
    if (ciphertext_b64.rfind(octra::HFHE_PREFIX, 0) != 0) {
        error = "invalid ciphertext";
        return false;
    }
    if (range_proof_b64.rfind(octra::RP_PREFIX, 0) != 0) {
        error = "invalid range proof";
        return false;
    }
    auto raw = octra::base64_decode(ciphertext_b64.substr(strlen(octra::HFHE_PREFIX)));
    if (raw.empty()) {
        error = "invalid ciphertext";
        return false;
    }
    auto proof_raw = octra::base64_decode(range_proof_b64.substr(strlen(octra::RP_PREFIX)));
    if (proof_raw.empty()) {
        error = "invalid range proof";
        return false;
    }
    pvac_cipher ct = g_pvac.deserialize_cipher(raw.data(), raw.size());
    if (!ct) {
        error = "invalid ciphertext";
        return false;
    }
    bool ok = pvac_verify_range_any(g_pvac.pk(), ct, proof_raw.data(), proof_raw.size()) != 0;
    g_pvac.free_cipher(ct);
    if (!ok) error = "range proof verification failed";
    return ok;
}

static std::string circle_hfhe_policy_hash(const json& policy) {
    return octra::sha256_hex(policy.dump());
}

static std::string circle_hfhe_receipt_class_value(const json& policy) {
    std::string receipt_class = policy.value("proof_receipt_class", "");
    if (!receipt_class.empty()) {
        return receipt_class;
    }
    if (policy.value("require_receipt_transport_binding", false)) {
        return "transport_bound";
    }
    return "detached";
}

static bool circle_hfhe_receipt_required(const std::string& proof_kind) {
    return proof_kind == "zero_receipt_v1" ||
           proof_kind == "range_receipt_v1" ||
           proof_kind == "bound_zero_receipt_v1";
}

static bool circle_hfhe_proof_requires_commitment(const std::string& proof_kind) {
    return proof_kind == "bound_zero_v1" || proof_kind == "bound_zero_receipt_v1";
}

static bool circle_hfhe_proof_is_range(const std::string& proof_kind) {
    return proof_kind == "range_v1" || proof_kind == "range_receipt_v1";
}

static bool circle_hfhe_receipt_transport_bound(const json& policy,
                                                const std::string& intent_id,
                                                std::string& error) {
    const std::string receipt_class = circle_hfhe_receipt_class_value(policy);
    if ((receipt_class == "transport_bound" || receipt_class == "relay_witnessed") &&
        intent_id.empty()) {
        error = "intent_id required by circle hfhe receipt binding policy";
        return false;
    }
    return true;
}

static bool circle_hfhe_receipt_signer_allowed(const std::string& circle_id,
                                               const json& policy,
                                               const std::string& caller_addr,
                                               const std::string& signer_addr,
                                               const std::string& intent_id,
                                               std::string& error) {
    auto info_r = circle_info_auth_rpc(circle_id);
    if (!info_r.ok) {
        error = info_r.error.empty() ? "circle info read failed" : info_r.error;
        return false;
    }
    const std::string owner = info_r.result.value("owner", "");
    const std::string mode = policy.value("proof_receipt_signer_mode", "caller_self");
    const std::string receipt_class = circle_hfhe_receipt_class_value(policy);
    std::vector<std::string> active_relays;
    if (mode == "active_relay" || mode == "owner_or_active_relay" ||
        receipt_class == "relay_witnessed") {
        if (intent_id.empty()) {
            error = "intent_id required by circle hfhe receipt signer policy";
            return false;
        }
        if (!circle_hfhe_active_relays(circle_id, intent_id, active_relays, error)) {
            return false;
        }
    }
    if (receipt_class == "relay_witnessed" &&
        std::find(active_relays.begin(), active_relays.end(), signer_addr) == active_relays.end()) {
        error = "circle hfhe receipt signer must be an active relay";
        return false;
    }
    if (!circle_hfhe_mode_allows(mode, owner, signer_addr, caller_addr, active_relays)) {
        error = "circle hfhe receipt signer is not allowed by policy";
        return false;
    }
    return true;
}

static bool circle_hfhe_receipt_context(const std::string& circle_id,
                                        const std::string& verb,
                                        const std::string& caller_addr,
                                        const std::string& key_id,
                                        const std::string& intent_id,
                                        const std::string& proof_kind,
                                        const json& policy,
                                        const std::string& ciphertext_b64,
                                        const std::string& amount_commitment_b64,
                                        octra::CircleHfheReceiptContext& ctx,
                                        std::string& error) {
    if (!circle_hfhe_receipt_transport_bound(policy, intent_id, error)) {
        return false;
    }
    std::string ciphertext_hash = octra::circle_hfhe_hash_ciphertext(ciphertext_b64, error);
    if (ciphertext_hash.empty()) {
        return false;
    }
    std::string amount_commitment_hash;
    if (!amount_commitment_b64.empty()) {
        amount_commitment_hash = octra::circle_hfhe_hash_commitment(amount_commitment_b64, error);
        if (amount_commitment_hash.empty()) {
            return false;
        }
    }
    ctx = {
        circle_id,
        caller_addr,
        key_id,
        intent_id,
        verb,
        proof_kind,
        circle_hfhe_policy_hash(policy),
        ciphertext_hash,
        amount_commitment_hash
    };
    return true;
}

static bool circle_verify_proof_receipt(const std::string& circle_id,
                                        const std::string& verb,
                                        const std::string& caller_addr,
                                        const std::string& key_id,
                                        const std::string& intent_id,
                                        const std::string& proof_kind,
                                        const json& policy,
                                        const std::string& ciphertext_b64,
                                        const std::string& amount_commitment_b64,
                                        const json& receipt,
                                        std::string& error) {
    octra::CircleHfheReceiptContext ctx;
    if (!circle_hfhe_receipt_context(
            circle_id,
            verb,
            caller_addr,
            key_id,
            intent_id,
            proof_kind,
            policy,
            ciphertext_b64,
            amount_commitment_b64,
            ctx,
            error)) {
        return false;
    }
    if (!octra::verify_circle_hfhe_receipt_json(receipt, ctx, error)) {
        return false;
    }
    return circle_hfhe_receipt_signer_allowed(
        circle_id,
        policy,
        ctx.caller_addr,
        receipt.value("signer_addr", ""),
        ctx.intent_id,
        error);
}

static json submit_tx(const octra::Transaction& tx) {
    json j;
    j["from"] = tx.from;
    j["to_"] = tx.to_;
    j["amount"] = tx.amount;
    j["nonce"] = tx.nonce;
    j["ou"] = tx.ou;
    j["timestamp"] = tx.timestamp;
    j["signature"] = tx.signature;
    j["public_key"] = tx.public_key;
    if (!tx.op_type.empty()) j["op_type"] = tx.op_type;
    if (!tx.encrypted_data.empty()) j["encrypted_data"] = tx.encrypted_data;
    if (!tx.message.empty()) j["message"] = tx.message;
    auto r = g_rpc.submit_tx(j);
    if (!r.ok) return err_json(r.error);
    json res;
    std::string tx_hash = r.result.value("tx_hash", "");
    res["tx_hash"] = tx_hash;
    if (!tx_hash.empty()) {
        json cached;
        cached["hash"] = tx_hash;
        cached["from"] = tx.from;
        cached["to_"] = tx.to_;
        cached["amount_raw"] = tx.amount;
        cached["op_type"] = tx.op_type.empty() ? "standard" : tx.op_type;
        cached["status"] = "pending";
        cached["timestamp"] = tx.timestamp;
        if (!tx.encrypted_data.empty()) cached["encrypted_data"] = tx.encrypted_data;
        if (!tx.message.empty()) cached["message"] = tx.message;
        if (g_txcache.is_open()) {
            bool known = g_txcache.has_tx(tx_hash);
            g_txcache.store_tx(g_wallet.addr, cached);
            if (!known) {
                int cached_total = g_txcache.get_total(g_wallet.addr);
                g_txcache.set_total(g_wallet.addr, cached_total + 1);
            }
        }
        history_runtime_clear(g_wallet.addr);
        token_history_runtime_clear(g_wallet.addr);
    } else {
        history_runtime_clear(g_wallet.addr);
        token_history_runtime_clear(g_wallet.addr);
    }
    return res;
}

static json submit_program_call_tx(const std::string& target,
                                   const std::string& op_type,
                                   const std::string& method,
                                   const json& params,
                                   const json& body,
                                   const std::string& default_ou) {
    auto bi = get_nonce_balance();
    octra::Transaction tx;
    tx.from = g_wallet.addr;
    tx.to_ = target;
    tx.amount = body.value("amount", "0");
    tx.nonce = bi.nonce + 1;
    tx.ou = parse_ou(body, default_ou);
    tx.timestamp = now_ts();
    tx.op_type = op_type;
    tx.encrypted_data = method;
    tx.message = params.dump();
    sign_tx_fields(tx);
    return submit_tx(tx);
}

static void ensure_pubkey_registered(const std::string& addr, const uint8_t sk[64], const std::string& pub_b64) {
    auto vr = g_rpc.get_view_pubkey(addr);
    if (vr.ok && vr.result.is_object() && vr.result.contains("view_pubkey")
        && !vr.result["view_pubkey"].is_null() && vr.result["view_pubkey"].is_string())
        return;
    std::string msg = "register_pubkey:" + addr;
    std::string sig = octra::ed25519_sign_detached(
        reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), sk);
    auto rr = g_rpc.register_public_key(addr, pub_b64, sig);
    if (rr.ok) fprintf(stderr, "pubkey registered for %s\n", addr.c_str());
    else fprintf(stderr, "pubkey register failed for %s: %s\n", addr.c_str(), rr.error.c_str());
}

static bool g_pvac_foreign = false;

static std::string compute_aes_kat_hex() {
    uint8_t buf[16];
    pvac_aes_kat(buf);
    char hex[33];
    for (int i = 0; i < 16; i++) {
        hex[i*2]   = "0123456789abcdef"[(buf[i] >> 4) & 0xF];
        hex[i*2+1] = "0123456789abcdef"[buf[i] & 0xF];
    }
    hex[32] = 0;
    return std::string(hex);
}

static void ensure_pvac_registered() {
    if (!g_pvac_ok || g_pvac_confirmed || g_pvac_foreign) return;
    auto pr = g_rpc.get_pvac_pubkey(g_wallet.addr);
    if (pr.ok && pr.result.is_object() && !pr.result["pvac_pubkey"].is_null()) {
        std::string remote_pk = pr.result["pvac_pubkey"].get<std::string>();
        std::string local_pk = g_pvac.serialize_pubkey_b64();
        if (remote_pk == local_pk) {
            g_pvac_confirmed = true;
            return;
        }
        g_pvac_foreign = true;
        fprintf(stderr, "pvac key conflict: node has a different pvac key for %s\n",
                g_wallet.addr.c_str());
        return;
    }
    auto pk_raw = g_pvac.serialize_pubkey();
    std::string pk_blob(pk_raw.begin(), pk_raw.end());
    std::string pk_b64 = g_pvac.serialize_pubkey_b64();
    std::string reg_sig = octra::sign_register_request(g_wallet.addr, pk_blob, g_wallet.sk);
    std::string kat_hex = compute_aes_kat_hex();
    auto rr = g_rpc.register_pvac_pubkey(g_wallet.addr, pk_b64, reg_sig, g_wallet.pub_b64, kat_hex);
    if (rr.ok) {
        fprintf(stderr, "pvac pubkey registered\n");
        g_pvac_confirmed = true;
    } else {
        if (rr.error.find("already registered") != std::string::npos) {
            g_pvac_foreign = true;
            fprintf(stderr, "pvac key conflict: another client registered first\n");
        } else {
            fprintf(stderr, "pvac pubkey register failed: %s\n", rr.error.c_str());
        }
    }
}

struct EncBalResult {
    std::string cipher;
    int64_t decrypted;
};

static EncBalResult get_encrypted_balance() {
    std::string sig = octra::sign_balance_request(g_wallet.addr, g_wallet.sk);
    auto r = g_rpc.get_encrypted_balance(g_wallet.addr, sig, g_wallet.pub_b64);
    if (!r.ok || !r.result.is_object()) return {"0", 0};
    std::string cipher = r.result.value("cipher", "0");
    if (!g_pvac_ok || cipher.empty() || cipher == "0") return {cipher, 0};
    int64_t dec = g_pvac.get_balance(cipher);
    return {cipher, dec};
}

static void init_wallet_subsystems() {
    const char* env_rpc = std::getenv("OCTRA_RPC_URL");
    if (env_rpc && *env_rpc) g_wallet.rpc_url = env_rpc;
    g_rpc.set_url(g_wallet.rpc_url);
    g_pvac_ok = g_pvac.init(g_wallet.priv_b64);
    if (g_pvac_ok) {
        fprintf(stderr, "pvac initialized\n");
    } else {
        fprintf(stderr, "pvac init failed (libpvac not loaded?)\n");
    }
    g_txcache.close();
    std::string cache_path = "data/txcache_" + g_wallet.addr.substr(3, 8);
    if (g_txcache.open(cache_path)) {
        fprintf(stderr, "txcache opened: %s\n", cache_path.c_str());
        g_txcache.ensure_schema("v2_addr_idx_slim_history");
        g_txcache.ensure_rpc(g_wallet.rpc_url);
    } else {
        fprintf(stderr, "txcache open failed: %s\n", cache_path.c_str());
    }
    g_wallet_loaded = true;
}

#define WALLET_GUARD \
    if (!g_wallet_loaded) { \
        res.status = 503; \
        res.set_content(err_json("no wallet loaded").dump(), "application/json"); \
        return; \
    }

#define PVAC_GUARD \
    if (!g_pvac_ok) { \
        res.status = 500; \
        res.set_content(err_json("pvac not available").dump(), "application/json"); \
        return; \
    } \
    if (g_pvac_foreign) { \
        res.status = 400; \
        res.set_content(err_json("key mismatch: use key switch to reset encryption key").dump(), "application/json"); \
        return; \
    }

int main(int argc, char** argv) {
#ifdef _WIN32
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    SetConsoleCtrlHandler([](DWORD) -> BOOL {
        handle_signal(0);
        return TRUE;
    }, TRUE);
#else
    struct rlimit rl = {0, 0};
    setrlimit(RLIMIT_CORE, &rl);
#ifdef __linux__
    prctl(PR_SET_DUMPABLE, 0);
#endif
    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);
#endif

    int port = 8420;
    if (argc > 1) port = atoi(argv[1]);
    if (port <= 0) port = 8420;

    octra::ensure_data_dir();

    httplib::Server svr;
    svr.set_read_timeout(300, 0);
    svr.set_write_timeout(300, 0);
    svr.set_keep_alive_timeout(5);
    svr.set_keep_alive_max_count(100);

    svr.set_post_routing_handler([](const httplib::Request& req, httplib::Response& res) {
        bool is_circle_resource = req.path.rfind("/oct/", 0) == 0;
        if (!is_circle_resource) {
            res.set_header("X-Frame-Options", "DENY");
        }
        res.set_header("X-Content-Type-Options", "nosniff");
        if (is_circle_resource) {
            res.set_header("Content-Security-Policy",
                "default-src 'self' data: blob:; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: blob: https:; "
                "connect-src 'none'; "
                "object-src 'none'; "
                "base-uri 'self'");
        } else {
            res.set_header("Content-Security-Policy",
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "connect-src 'self' http://127.0.0.1:* http://178.62.60.204:8090 https://*.octra.network https://*.publicnode.com https://*.infura.io wss: ws:; "
                "frame-ancestors 'none'");
        }
        res.set_header("Cache-Control", "no-store");
    });

    svr.set_mount_point("/", "static");

    svr.set_exception_handler([](const httplib::Request& req, httplib::Response& res, std::exception_ptr ep) {
        std::string msg = "internal error";
        try { if (ep) std::rethrow_exception(ep); }
        catch (const std::exception& e) { msg = e.what(); }
        catch (...) {}
        fprintf(stderr, "[exception] %s %s: %s\n", req.method.c_str(), req.path.c_str(), msg.c_str());
        res.status = 500;
        json j; j["error"] = msg;
        res.set_content(j.dump(), "application/json");
    });

    svr.set_error_handler([](const httplib::Request& req, httplib::Response& res) {
        if (req.path.rfind("/api/", 0) == 0 && res.body.empty()) {
            json j;
            j["error"] = "unknown endpoint: " + req.method + " " + req.path;
            res.set_content(j.dump(), "application/json");
        }
    });

    svr.Get("/api/wallet/status", [](const httplib::Request&, httplib::Response& res) {
        json j;
        j["loaded"] = g_wallet_loaded.load();
        bool has_leg = octra::has_legacy_wallet();
        auto all = octra::scan_and_merge_oct_files();
        bool has_any_oct = false;
        json wallets = json::array();
        for (auto& e : all) {
            has_any_oct = true;
            json w;
            w["name"] = e.name;
            w["file"] = e.file;
            w["addr"] = e.addr;
            w["hd"] = e.hd;
            wallets.push_back(w);
        }
        j["has_legacy"] = !has_any_oct && has_leg;
        j["needs_pin"] = has_any_oct || has_leg;
        j["needs_create"] = !has_any_oct && !has_leg;
        j["wallets"] = wallets;
        res.set_content(j.dump(), "application/json");
    });

    svr.Post("/api/wallet/unlock", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(g_mtx);
        if (g_wallet_loaded) {
            res.status = 409;
            res.set_content(err_json("wallet already unlocked").dump(), "application/json");
            return;
        }
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string pin = body.value("pin", "");
        std::string addr_hint = body.value("addr", "");
        std::string file_hint = body.value("file", "");
        std::string name_hint = body.value("name", "");
        if (pin.size() != 6 || !std::all_of(pin.begin(), pin.end(), ::isdigit)) {
            res.status = 400;
            res.set_content(err_json("pin must be exactly 6 digits").dump(), "application/json");
            return;
        }

        std::string unlock_path = g_wallet_path;
        if (!file_hint.empty()) {

            if (file_hint.find("..") == std::string::npos &&
                file_hint.rfind("data/", 0) == 0 &&
                file_hint.substr(file_hint.size() - 4) == ".oct") {
                unlock_path = file_hint;
            }
        } else if (!addr_hint.empty()) {
            auto entries = octra::load_manifest();
            for (auto& e : entries) {
                if (e.addr == addr_hint) { unlock_path = e.file; break; }
            }
        }
        try {
            bool has_leg = octra::has_legacy_wallet();
            bool has_enc = octra::has_encrypted_wallet();
            if (has_leg && !has_enc && addr_hint.empty()) {
                g_wallet = octra::migrate_wallet(pin);
                g_wallet_path = octra::WALLET_FILE;
                fprintf(stderr, "wallet migrated: %s\n", g_wallet.addr.c_str());
            } else {
                g_wallet = octra::load_wallet_encrypted(unlock_path, pin);
                g_wallet_path = unlock_path;
                fprintf(stderr, "wallet unlocked: %s\n", g_wallet.addr.c_str());
            }

            try {
                octra::ManifestEntry me;
                me.name = name_hint;
                me.file = g_wallet_path;
                me.addr = g_wallet.addr;
                me.hd = g_wallet.has_master_seed();
                me.hd_version = g_wallet.hd_version;
                me.hd_index = g_wallet.hd_index;
                if (me.hd) me.master_seed_hash = octra::compute_seed_hash(g_wallet.master_seed_b64);
                octra::manifest_upsert(me);
                if (me.hd) octra::manifest_migrate_legacy(g_wallet.master_seed_b64, pin, g_wallet.hd_version);
            } catch (...) {}
            g_pin = pin;
            octra::try_mlock(&g_pin[0], g_pin.size());
            init_wallet_subsystems();
        } catch (const std::exception& e) {
            res.status = 403;
            res.set_content(err_json(e.what()).dump(), "application/json");
            return;
        }
        json j;
        j["address"] = g_wallet.addr;
        j["public_key"] = g_wallet.pub_b64;
        j["has_master_seed"] = g_wallet.has_master_seed();
        res.set_content(j.dump(), "application/json");
    });

    svr.Post("/api/wallet/lock", [](const httplib::Request&, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(g_mtx);
        if (!g_wallet_loaded) {
            res.status = 409;
            res.set_content(err_json("wallet not loaded").dump(), "application/json");
            return;
        }
        g_wallet_loaded = false;
        g_pvac_ok = false;
        g_pvac_confirmed = false;
        g_pvac_foreign = false;
        g_pvac.reset();

        leveldb::DB* old_db = g_txcache.detach();
        if (old_db) std::thread([old_db]() { delete old_db; }).detach();
        octra::secure_zero(g_wallet.sk, 64);
        octra::secure_zero(g_wallet.pk, 32);
        if (!g_pin.empty()) octra::secure_zero(&g_pin[0], g_pin.size());
        g_pin.clear();
        g_wallet.priv_b64.clear();
        g_wallet.pub_b64.clear();
        g_wallet.addr.clear();
        fprintf(stderr, "wallet locked\n");
        json j;
        j["ok"] = true;
        res.set_content(j.dump(), "application/json");
    });

    svr.Post("/api/wallet/create", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(g_mtx);
        if (g_wallet_loaded) {
            res.status = 409;
            res.set_content(err_json("wallet already loaded").dump(), "application/json");
            return;
        }
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string pin = body.value("pin", "");
        if (pin.size() != 6 || !std::all_of(pin.begin(), pin.end(), ::isdigit)) {
            res.status = 400;
            res.set_content(err_json("pin must be exactly 6 digits").dump(), "application/json");
            return;
        }
        std::string name = body.value("name", "wallet");
        std::string mnemonic;
        try {
            std::string tmp_path = std::string(octra::WALLET_DIR) + "/wallet_new.tmp";
            auto [wallet, mn] = octra::create_wallet(tmp_path, pin);
            g_wallet = wallet;
            mnemonic = mn;
            std::string named_path = octra::wallet_path_for(g_wallet.addr);
            if (std::rename(tmp_path.c_str(), named_path.c_str()) == 0)
                g_wallet_path = named_path;
            else
                g_wallet_path = tmp_path;
            {
                octra::ManifestEntry me;
                me.name = name;
                me.file = g_wallet_path;
                me.addr = g_wallet.addr;
                me.hd = true;
                me.hd_version = 2;
                me.hd_index = 0;
                me.master_seed_hash = octra::compute_seed_hash(g_wallet.master_seed_b64);
                octra::manifest_upsert(me);
            }
            g_pin = pin;
            octra::try_mlock(&g_pin[0], g_pin.size());
            fprintf(stderr, "wallet created: %s -> %s\n", g_wallet.addr.c_str(), g_wallet_path.c_str());
            init_wallet_subsystems();
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(err_json(e.what()).dump(), "application/json");
            return;
        }
        json j;
        j["address"] = g_wallet.addr;
        j["public_key"] = g_wallet.pub_b64;
        j["mnemonic"] = mnemonic;
        octra::secure_zero(&mnemonic[0], mnemonic.size());
        res.set_content(j.dump(), "application/json");
    });

    svr.Post("/api/wallet/import", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(g_mtx);
        bool already_loaded = g_wallet_loaded.load();
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string priv = body.value("priv", "");
        std::string mnemonic = body.value("mnemonic", "");
        std::string pin = body.value("pin", "");
        if (priv.empty() && mnemonic.empty()) {
            res.status = 400;
            res.set_content(err_json("priv or mnemonic required").dump(), "application/json");
            return;
        }
        if (pin.size() != 6 || !std::all_of(pin.begin(), pin.end(), ::isdigit)) {
            res.status = 400;
            res.set_content(err_json("pin must be exactly 6 digits").dump(), "application/json");
            return;
        }
        std::string name = body.value("name", "imported");
        bool is_mnemonic = false;
        try {
            std::string tmp_path = std::string(octra::WALLET_DIR) + "/wallet_imp.tmp";
            octra::Wallet imported;
            if (!mnemonic.empty() || octra::looks_like_mnemonic(priv)) {
                std::string mn = mnemonic.empty() ? priv : mnemonic;
                int hd_version = 2;
                {
                    std::string addr_v2 = octra::addr_from_mnemonic(mn, 2);
                    std::string addr_v1 = octra::addr_from_mnemonic(mn, 1);
                    std::string rpc_url = g_wallet_loaded ? g_wallet.rpc_url : "http://46.101.86.250:8080";
                    octra::RpcClient probe;
                    probe.set_url(rpc_url);
                    auto r2 = probe.get_balance(addr_v2);
                    auto r1 = probe.get_balance(addr_v1);
                    int64_t bal2 = 0, bal1 = 0;
                    auto parse_bal = [](const json& r) -> int64_t {
                        if (!r.is_object() || !r.contains("balance")) return 0;
                        auto& b = r["balance"];
                        if (b.is_number()) return b.get<int64_t>();
                        if (b.is_string()) { try { return std::stoll(b.get<std::string>()); } catch(...) {} }
                        return 0;
                    };
                    if (r2.ok) bal2 = parse_bal(r2.result);
                    if (r1.ok) bal1 = parse_bal(r1.result);
                    if (bal1 > 0 && bal2 == 0) hd_version = 1;
                    fprintf(stderr, "import autodetect: v2=%s (bal=%ld) v1=%s (bal=%ld) -> v%d\n",
                        addr_v2.c_str(), (long)bal2, addr_v1.c_str(), (long)bal1, hd_version);
                }
                imported = octra::import_wallet_mnemonic(tmp_path, mn, pin, hd_version);
                is_mnemonic = true;
                fprintf(stderr, "wallet imported (seed phrase, v%d): %s\n", hd_version, imported.addr.c_str());
            } else {
                imported = octra::import_wallet(tmp_path, priv, pin);
                fprintf(stderr, "wallet imported (private key): %s\n", imported.addr.c_str());
            }
            std::string named_path = octra::wallet_path_for(imported.addr);
            std::string final_path = tmp_path;
            if (std::rename(tmp_path.c_str(), named_path.c_str()) == 0)
                final_path = named_path;
            {
                octra::ManifestEntry me;
                me.name = name;
                me.file = final_path;
                me.addr = imported.addr;
                me.hd = is_mnemonic;
                me.hd_version = imported.hd_version;
                me.hd_index = 0;
                if (is_mnemonic) me.master_seed_hash = octra::compute_seed_hash(imported.master_seed_b64);
                octra::manifest_upsert(me);
            }
            if (!already_loaded) {

                g_wallet = imported;
                g_wallet_path = final_path;
                g_pin = pin;
                octra::try_mlock(&g_pin[0], g_pin.size());
                init_wallet_subsystems();
            } else {

                octra::secure_zero(imported.sk, 64);
                octra::secure_zero(imported.pk, 32);
            }
            json j;
            j["address"] = imported.addr;
            j["switched"] = !already_loaded;
            res.set_content(j.dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(err_json(e.what()).dump(), "application/json");
            return;
        }
    });

    svr.Get("/api/wallet", [](const httplib::Request&, httplib::Response& res) {
        WALLET_GUARD
        json j;
        j["address"] = g_wallet.addr;
        j["public_key"] = g_wallet.pub_b64;
        j["rpc_url"] = g_wallet.rpc_url;
        j["explorer_url"] = g_wallet.explorer_url;
        j["bridge_signer_url"] = g_wallet.bridge_signer_url;
        j["has_master_seed"] = g_wallet.has_master_seed();
        j["hd_index"] = g_wallet.hd_index;
        j["hd_version"] = g_wallet.hd_version;
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(j.dump(), "application/json");
    });

    svr.Get("/api/wallet/accounts", [](const httplib::Request&, httplib::Response& res) {
        auto entries = octra::load_manifest();
        json accounts = json::array();
        for (auto& e : entries) {
            json a;
            a["name"] = e.name;
            a["addr"] = e.addr;
            a["hd"] = e.hd;
            a["hd_version"] = e.hd_version;
            a["hd_index"] = e.hd_index;
            if (!e.parent_addr.empty()) a["parent_addr"] = e.parent_addr;
            a["active"] = (g_wallet_loaded && g_wallet.addr == e.addr);
            accounts.push_back(a);
        }
        json j;
        j["accounts"] = accounts;
        j["has_master_seed"] = (g_wallet_loaded && g_wallet.has_master_seed());
        if (g_wallet_loaded && g_wallet.has_master_seed()) {
            j["next_hd_index"] = octra::manifest_next_hd_index(g_wallet.master_seed_b64);
        }
        res.set_content(j.dump(), "application/json");
    });

    svr.Post("/api/wallet/switch", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(g_mtx);
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string addr = body.value("addr", "");
        std::string pin = body.value("pin", "");
        if (addr.empty() || pin.size() != 6) {
            res.status = 400;
            res.set_content(err_json("addr and 6-digit pin required").dump(), "application/json");
            return;
        }
        auto entries = octra::load_manifest();
        std::string target_path;
        for (auto& e : entries) {
            if (e.addr == addr) { target_path = e.file; break; }
        }
        if (target_path.empty()) {
            res.status = 404;
            res.set_content(err_json("account not found in manifest").dump(), "application/json");
            return;
        }

        if (g_wallet_loaded) {
            g_wallet_loaded = false;
            g_pvac_ok = false;
            g_pvac_confirmed = false;
            g_pvac_foreign = false;
            g_pvac.reset();
            leveldb::DB* old_db = g_txcache.detach();
            if (old_db) std::thread([old_db]() { delete old_db; }).detach();
            octra::secure_zero(g_wallet.sk, 64);
            octra::secure_zero(g_wallet.pk, 32);
        }

        try {
            g_wallet = octra::load_wallet_encrypted(target_path, pin);
            g_wallet_path = target_path;
            g_pin = pin;
            octra::try_mlock(&g_pin[0], g_pin.size());
            fprintf(stderr, "switched to wallet: %s\n", g_wallet.addr.c_str());
            init_wallet_subsystems();
        } catch (const std::exception& e) {
            res.status = 403;
            res.set_content(err_json(e.what()).dump(), "application/json");
            return;
        }
        json j;
        j["address"] = g_wallet.addr;
        j["public_key"] = g_wallet.pub_b64;
        j["has_master_seed"] = g_wallet.has_master_seed();
        res.set_content(j.dump(), "application/json");
    });

    svr.Post("/api/wallet/derive", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        if (!g_wallet.has_master_seed()) {
            res.status = 400;
            res.set_content(err_json("wallet has no master seed (imported via private key)").dump(), "application/json");
            return;
        }
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string pin = body.value("pin", "");
        std::string name = body.value("name", "");
        if (pin.size() != 6 || !std::all_of(pin.begin(), pin.end(), ::isdigit)) {
            res.status = 400;
            res.set_content(err_json("6-digit pin required").dump(), "application/json");
            return;
        }
        if (pin != g_pin) {
            res.status = 403;
            res.set_content(err_json("wrong pin").dump(), "application/json");
            return;
        }
        int next_index = octra::manifest_next_hd_index(g_wallet.master_seed_b64);
        if (name.empty()) name = "account " + std::to_string(next_index);
        try {
            auto w = octra::derive_hd_account(
                g_wallet.master_seed_b64, (uint32_t)next_index,
                g_wallet.rpc_url, g_wallet.explorer_url, pin,
                g_wallet.hd_version);
            std::string path = octra::wallet_path_for(w.addr);
            {
                octra::ManifestEntry me;
                me.name = name;
                me.file = path;
                me.addr = w.addr;
                me.hd = true;
                me.hd_version = g_wallet.hd_version;
                me.hd_index = next_index;
                me.parent_addr = g_wallet.addr;
                me.master_seed_hash = octra::compute_seed_hash(g_wallet.master_seed_b64);
                octra::manifest_upsert(me);
            }
            fprintf(stderr, "derived HD account #%d: %s\n", next_index, w.addr.c_str());
            if (g_pvac_ok) {
                octra::PvacBridge tmp_pvac;
                if (tmp_pvac.init(w.priv_b64)) {
                    auto pk_raw = tmp_pvac.serialize_pubkey();
                    std::string pk_blob(pk_raw.begin(), pk_raw.end());
                    std::string pk_b64 = tmp_pvac.serialize_pubkey_b64();
                    std::string reg_sig = octra::sign_register_request(w.addr, pk_blob, w.sk);
                    std::string kat = compute_aes_kat_hex();
                    auto rr = g_rpc.register_pvac_pubkey(w.addr, pk_b64, reg_sig, w.pub_b64, kat);
                    if (rr.ok) fprintf(stderr, "pvac registered for derived %s\n", w.addr.c_str());
                    else fprintf(stderr, "pvac register failed for %s: %s\n", w.addr.c_str(), rr.error.c_str());
                }
            }
            json j;
            j["address"] = w.addr;
            j["hd_index"] = next_index;
            j["name"] = name;
            res.set_content(j.dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(err_json(e.what()).dump(), "application/json");
        }
    });

    svr.Post("/api/wallet/rename", [](const httplib::Request& req, httplib::Response& res) {
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string addr = body.value("addr", "");
        std::string name = body.value("name", "");
        if (addr.empty() || name.empty()) {
            res.status = 400;
            res.set_content(err_json("addr and name required").dump(), "application/json");
            return;
        }
        octra::manifest_rename(addr, name);
        json j;
        j["ok"] = true;
        res.set_content(j.dump(), "application/json");
    });

    svr.Delete("/api/wallet/account", [](const httplib::Request& req, httplib::Response& res) {
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string addr = body.value("addr", "");
        if (addr.empty()) {
            res.status = 400;
            res.set_content(err_json("addr required").dump(), "application/json");
            return;
        }
        if (g_wallet_loaded && g_wallet.addr == addr) {
            res.status = 409;
            res.set_content(err_json("cannot remove active account").dump(), "application/json");
            return;
        }
        octra::manifest_remove(addr);
        json j;
        j["ok"] = true;
        res.set_content(j.dump(), "application/json");
    });

    svr.Get("/api/balance", [](const httplib::Request&, httplib::Response& res) {
        WALLET_GUARD

        std::string addr, pub_b64, sig_bal;
        bool pvac_ok;
        {
            std::lock_guard<std::mutex> lock(g_mtx);
            if (!g_wallet_loaded) {
                res.status = 503;
                res.set_content(err_json("no wallet loaded").dump(), "application/json");
                return;
            }
            addr = g_wallet.addr;
            pub_b64 = g_wallet.pub_b64;
            sig_bal = octra::sign_balance_request(addr, g_wallet.sk);
            pvac_ok = g_pvac_ok;
        }

        auto bi = get_nonce_balance();
        json j;
        j["public_balance"] = bi.balance_raw;
        j["nonce"] = bi.nonce;
        j["staging"] = 0;
        if (pvac_ok) {
            try {
                auto er = g_rpc.get_encrypted_balance(addr, sig_bal, pub_b64);
                if (er.ok && er.result.is_object()) {
                    std::string cipher = er.result.value("cipher", "0");
                    if (!cipher.empty() && cipher != "0") {
                        std::lock_guard<std::mutex> lock(g_mtx);
                        if (g_wallet_loaded && g_pvac_ok)
                            j["encrypted_balance"] = std::to_string(g_pvac.get_balance(cipher));
                        else
                            j["encrypted_balance"] = "0";
                    } else {
                        j["encrypted_balance"] = "0";
                    }
                } else {
                    j["encrypted_balance"] = "0";
                }
            } catch (...) {
                j["encrypted_balance"] = "0";
            }
        } else {
            j["encrypted_balance"] = "0";
        }
        if (g_pvac_foreign)
            j["pvac_foreign"] = true;
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(j.dump(), "application/json");
    });

    svr.Get("/api/history", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        int limit = 20, offset = 0;
        if (req.has_param("limit")) limit = std::stoi(req.get_param_value("limit"));
        if (req.has_param("offset")) offset = std::stoi(req.get_param_value("offset"));
        if (limit < 1) limit = 1;
        if (limit > 500) limit = 500;
        if (offset < 0) offset = 0;
        const std::string addr = g_wallet.addr;
        const double now = now_ts();
        const std::string page_key = std::to_string(limit) + ":" + std::to_string(offset);
        HistoryRuntimeState runtime = history_runtime_get(addr);

        auto convert_row = [](const json& row, const std::string& status) -> json {
            json tx;
            tx["hash"] = row.value("hash", "");
            tx["from"] = row.value("from", "");
            tx["to_"] = row.value("to", row.value("to_", ""));
            tx["amount_raw"] = row.value("amount", row.value("amount_raw", "0"));
            const std::string op_type = row.value("op_type", "standard");
            tx["op_type"] = op_type;
            tx["status"] = status;
            if (row.contains("timestamp")) tx["timestamp"] = row["timestamp"];
            const std::string enc_tag = row.value("encrypted_data", "");
            if (op_type == "call" && enc_tag == "transfer") {
                tx["encrypted_data"] = "transfer";
                if (row.contains("message") && row["message"].is_string())
                    tx["message"] = row["message"];
            }
            if (row.contains("reason") && row["reason"].is_string())
                tx["reject_reason"] = row["reason"];
            return tx;
        };

        json txs = json::array();
        json rejected = json::array();
        int total = 0;
        bool served = false;

        auto runtime_page_it = runtime.pages.find(page_key);
        auto runtime_page_ts_it = runtime.page_ts.find(page_key);
        const bool runtime_page_present = runtime_page_it != runtime.pages.end();
        const bool runtime_top_fresh = offset == 0
            && runtime_page_present
            && runtime_page_ts_it != runtime.page_ts.end()
            && (now - runtime_page_ts_it->second) < 10.0;
        const bool runtime_page_cached = offset > 0 && runtime_page_present;
        if (runtime_top_fresh || runtime_page_cached) {
            txs = runtime_page_it->second;
            rejected = offset == 0 ? runtime.rejected : json::array();
            total = runtime.total;
            served = true;
        }

        if (g_txcache.is_open()) {
            const int cached_total = g_txcache.get_total(addr);
            const bool top_page_fresh = offset == 0
                && cached_total > 0
                && (now - runtime.last_top_refresh_ts) < 10.0;
            const bool page_cached = cached_total > offset;
            if (!served && ((offset > 0 && page_cached) || top_page_fresh)) {
                json cached_page = g_txcache.load_page(addr, limit, offset);
                const bool cached_page_ok = !cached_page.empty() || cached_total == 0;
                if (cached_page_ok) {
                    txs = cached_page;
                    rejected = offset == 0 ? runtime.rejected : json::array();
                    total = cached_total;
                    runtime.pages[page_key] = txs;
                    runtime.page_ts[page_key] = now;
                    runtime.total = total;
                    history_runtime_put(addr, runtime);
                    served = true;
                }
            }
            if (!served && page_cached) {
                txs = g_txcache.load_page(addr, limit, offset);
                rejected = offset == 0 ? runtime.rejected : json::array();
                total = cached_total;
                runtime.pages[page_key] = txs;
                runtime.page_ts[page_key] = now;
                runtime.total = total;
                history_runtime_put(addr, runtime);
                served = true;
            }
        }
        if (!served) {
            int fetch_limit = limit;
            if (offset == 0) fetch_limit = std::max(limit, 50);
            auto fresh = g_rpc.get_txs_by_address(addr, fetch_limit, offset);
            if (fresh.ok && fresh.result.is_object()) {
                total = fresh.result.value("total", g_txcache.is_open() ? g_txcache.get_total(addr) : 0);
                if (total < 0) total = 0;
                if (fresh.result.contains("transactions")) {
                    json fetched_rows = json::array();
                    for (auto& row : fresh.result["transactions"]) {
                        json converted = convert_row(row, "confirmed");
                        fetched_rows.push_back(converted);
                    }
                    if (g_txcache.is_open()) {
                        if (!fetched_rows.empty()) g_txcache.store_txs(addr, fetched_rows);
                        g_txcache.set_total(addr, total);
                    }
                    for (int i = 0; i < static_cast<int>(fetched_rows.size()) && i < limit; ++i)
                        txs.push_back(fetched_rows[i]);
                }
                if (fresh.result.contains("rejected"))
                    for (auto& row : fresh.result["rejected"])
                        rejected.push_back(convert_row(row, "rejected"));
                if (offset == 0) {
                    runtime.last_top_refresh_ts = now;
                    runtime.rejected = rejected;
                }
                runtime.pages[page_key] = txs;
                runtime.page_ts[page_key] = now;
                runtime.total = total;
                history_runtime_put(addr, runtime);
            }
        }

        if (reconcile_history_rows(addr, txs)) {
            runtime.pages[page_key] = txs;
            runtime.page_ts[page_key] = now;
            history_runtime_put(addr, runtime);
        }

        json j;
        j["transactions"] = txs;
        j["rejected"] = rejected;
        j["count"] = txs.size();
        j["offset"] = offset;
        j["limit"] = limit;
        j["total"] = total;
        j["has_more"] = total > (offset + static_cast<int>(txs.size()));
        res.set_content(j.dump(), "application/json");
    });

    svr.Get("/api/token-history", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        int limit = 50, offset = 0;
        bool force = false;
        if (req.has_param("limit")) limit = std::stoi(req.get_param_value("limit"));
        if (req.has_param("offset")) offset = std::stoi(req.get_param_value("offset"));
        if (req.has_param("force")) {
            auto v = req.get_param_value("force");
            force = (v == "1" || v == "true");
        }
        if (limit < 1) limit = 1;
        if (limit > 500) limit = 500;
        if (offset < 0) offset = 0;
        const std::string addr = g_wallet.addr;
        const double now = now_ts();

        auto classify = [&](const json& tx) -> std::pair<bool, bool> {
            if (tx.value("op_type", "") != "call") return {false, false};
            if (tx.value("encrypted_data", "") != "transfer") return {false, false};
            bool incoming = false;
            try {
                if (tx.contains("message") && tx["message"].is_string()) {
                    auto parsed = json::parse(tx["message"].get<std::string>());
                    if (parsed.is_array() && !parsed.empty() && parsed[0].is_string()) {
                        std::string recipient = parsed[0].get<std::string>();
                        if (recipient == addr) incoming = true;
                    }
                }
            } catch (...) {}
            return {true, incoming};
        };

        if (!force) {
            if (auto cached = token_history_runtime_get(addr)) {
                if (now - cached->ts < 30.0) {
                    json page = json::array();
                    for (int i = offset; i < static_cast<int>(cached->rows.size()) && static_cast<int>(page.size()) < limit; ++i)
                        page.push_back(cached->rows[i]);
                    json j;
                    j["transactions"] = page;
                    j["count"] = page.size();
                    j["offset"] = offset;
                    j["limit"] = limit;
                    j["total"] = cached->rows.size();
                    j["has_more"] = offset + static_cast<int>(page.size()) < static_cast<int>(cached->rows.size());
                    j["incoming"] = cached->incoming;
                    j["outgoing"] = cached->outgoing;
                    res.set_content(j.dump(), "application/json");
                    return;
                }
            }
        }

        auto direct = g_rpc.get_token_txs_by_address(addr, limit, offset);
        if (direct.ok && direct.result.is_object()) {
            TokenHistoryRuntimeState state;
            state.ts = now;
            state.rows = direct.result.value("transactions", json::array());
            state.incoming = direct.result.value("incoming", 0);
            state.outgoing = direct.result.value("outgoing", 0);
            token_history_runtime_put(addr, state);
            res.set_content(direct.result.dump(), "application/json");
            return;
        }

        json rows = json::array();
        int incoming = 0;
        int outgoing = 0;
        std::set<std::string> seen_hashes;
        std::vector<std::string> token_addrs;

        auto toks = g_rpc.tokens_by_address(addr);
        if (toks.ok && toks.result.is_array()) {
            for (auto& tok : toks.result) {
                if (!tok.is_object()) continue;
                std::string token_addr = tok.value("address", "");
                if (!token_addr.empty())
                    token_addrs.push_back(token_addr);
            }
        }

        for (const auto& token_addr : token_addrs) {
            int batch_offset = 0;
            bool keep_going = true;
            while (keep_going) {
                auto batch = g_rpc.get_txs_by_address(token_addr, 200, batch_offset);
                if (!batch.ok || !batch.result.is_object()) break;
                auto txs = batch.result.value("transactions", json::array());
                for (auto& tx : txs) {
                    auto [is_token, is_incoming] = classify(tx);
                    if (!is_token) continue;
                    std::string tx_token = tx.value("to", tx.value("to_", ""));
                    if (tx_token != token_addr) continue;
                    bool is_outgoing = tx.value("from", "") == addr;
                    if (!is_incoming && !is_outgoing) continue;
                    std::string hash = tx.value("hash", "");
                    if (!hash.empty() && !seen_hashes.insert(hash).second) continue;
                    if (is_incoming) incoming++;
                    else outgoing++;
                    rows.push_back(tx);
                }
                bool has_more = batch.result.value("has_more", false);
                if (!has_more || txs.empty()) keep_going = false;
                batch_offset += static_cast<int>(txs.size());
                if (batch_offset >= 100000) keep_going = false;
            }
        }

        if (!rows.empty()) {
            std::vector<json> sorted;
            sorted.reserve(rows.size());
            for (auto& row : rows) sorted.push_back(row);
            std::sort(sorted.begin(), sorted.end(), [](const json& a, const json& b) {
                return a.value("timestamp", 0.0) > b.value("timestamp", 0.0);
            });
            rows = json::array();
            for (const auto& row : sorted) rows.push_back(row);
        }

        TokenHistoryRuntimeState state;
        state.ts = now;
        state.rows = rows;
        state.incoming = incoming;
        state.outgoing = outgoing;
        token_history_runtime_put(addr, state);

        json page = json::array();
        for (int i = offset; i < static_cast<int>(rows.size()) && static_cast<int>(page.size()) < limit; ++i)
            page.push_back(rows[i]);
        json j;
        j["transactions"] = page;
        j["count"] = page.size();
        j["offset"] = offset;
        j["limit"] = limit;
        j["total"] = rows.size();
        j["has_more"] = offset + static_cast<int>(page.size()) < static_cast<int>(rows.size());
        j["incoming"] = incoming;
        j["outgoing"] = outgoing;
        res.set_content(j.dump(), "application/json");
    });

    svr.Get("/api/contract-storage", [](const httplib::Request& req, httplib::Response& res) {
        auto addr = req.get_param_value("address");
        auto key = req.get_param_value("key");
        if (addr.empty() || key.empty()) {
            res.status = 400;
            res.set_content(err_json("address and key required").dump(), "application/json");
            return;
        }
        auto r = g_rpc.contract_storage(addr, key);
        json j;
        if (r.ok && r.result.contains("value") && !r.result["value"].is_null())
            j["value"] = r.result["value"];
        else
            j["value"] = nullptr;
        res.set_content(j.dump(), "application/json");
    });

    svr.Get("/api/fee", [](const httplib::Request&, httplib::Response& res) {
        double now = now_ts();
        {
            std::lock_guard<std::mutex> lock(g_fee_mtx);
            if (!g_fee_cache.empty() && (now - g_fee_cache_ts) < 30.0) {
                res.set_content(g_fee_cache.dump(), "application/json");
                return;
            }
        }
        std::vector<std::string> ops = {"standard", "encrypt", "decrypt", "stealth", "claim", "deploy", "call"};
        std::vector<std::string> methods(ops.size(), "octra_recommendedFee");
        std::vector<nlohmann::json> params;
        params.reserve(ops.size());
        for (auto& op : ops) params.push_back(nlohmann::json::array({op}));
        auto results = g_rpc.call_batch(methods, params, 10);
        json fees;
        for (size_t i = 0; i < ops.size(); ++i) {
            if (i < results.size() && results[i].ok) fees[ops[i]] = results[i].result;
            else fees[ops[i]] = {{"minimum", "1000"}, {"recommended", "1000"}, {"fast", "2000"}};
        }
        {
            std::lock_guard<std::mutex> lock(g_fee_mtx);
            g_fee_cache = fees;
            g_fee_cache_ts = now;
        }
        res.set_content(fees.dump(), "application/json");
    });

    svr.Post("/api/send", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string to = body.value("to", "");
        if (to.empty() || to.size() != 47 || to.substr(0, 3) != "oct") {
            res.status = 400;
            res.set_content(err_json("invalid address").dump(), "application/json");
            return;
        }
        int64_t raw = parse_amount_raw(body);
        if (raw <= 0) {
            res.status = 400;
            res.set_content(err_json("invalid amount (max 6 decimals, no extra dots)").dump(), "application/json");
            return;
        }
        auto bi = get_nonce_balance(); int nonce = bi.nonce;
        octra::Transaction tx;
        tx.from = g_wallet.addr;
        tx.to_ = to;
        tx.amount = std::to_string(raw);
        tx.nonce = nonce + 1;
        tx.ou = parse_ou(body, (raw < 1000000000) ? "10000" : "30000");
        tx.timestamp = now_ts();
        tx.op_type = "standard";
        std::string msg = body.value("message", "");
        if (!msg.empty()) tx.message = msg;
        sign_tx_fields(tx);
        auto result = submit_tx(tx);
        if (result.contains("error")) res.status = 500;
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/key_switch", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        auto nb = get_nonce_balance();
        octra::Transaction tx;
        tx.from = g_wallet.addr;
        tx.to_ = g_wallet.addr;
        tx.amount = "0";
        tx.nonce = nb.nonce + 1;
        tx.ou = "3000";
        tx.timestamp = now_ts();
        tx.op_type = "key_switch";
        if (!g_pvac_ok) {
            res.status = 500;
            res.set_content(err_json("pvac not available").dump(), "application/json");
            return;
        }
        size_t pk_len = 0;
        uint8_t* pk_data = pvac_serialize_pubkey(g_pvac.pk(), &pk_len);
        if (!pk_data || pk_len == 0) {
            res.status = 500;
            res.set_content(err_json("failed to serialize pubkey").dump(), "application/json");
            return;
        }
        std::string pk_b64 = octra::base64_encode(pk_data, pk_len);
        std::string kat_hex = compute_aes_kat_hex();
        json enc_data;
        enc_data["new_pubkey"] = pk_b64;
        enc_data["aes_kat"] = kat_hex;
        tx.encrypted_data = enc_data.dump();
        unsigned char old_hash[32];
        SHA256(pk_data, pk_len, old_hash);
        free(pk_data);
        char hex[17];
        for (int i = 0; i < 8; i++)
            snprintf(hex + i*2, 3, "%02x", old_hash[i]);
        tx.message = "encryption key switch | new_key:" + std::string(hex);
        sign_tx_fields(tx);
        auto result = submit_tx(tx);
        if (result.contains("error")) {
            res.status = 500;
        } else {
            g_pvac_foreign = false;
            g_pvac_confirmed = true;
        }
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/encrypt", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        PVAC_GUARD
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        int64_t raw = parse_amount_raw(body);
        if (raw <= 0) {
            res.status = 400;
            res.set_content(err_json("invalid amount (max 6 decimals, no extra dots)").dump(), "application/json");
            return;
        }
        ensure_pvac_registered();
        uint8_t seed[32];
        octra::random_bytes(seed, 32);
        pvac_cipher ct = g_pvac.encrypt((uint64_t)raw, seed);
        std::string cipher_str = g_pvac.encode_cipher(ct);

        uint8_t blinding[32];
        octra::random_bytes(blinding, 32);
        auto amt_commit = g_pvac.pedersen_commit((uint64_t)raw, blinding);
        std::string amt_commit_b64 = octra::base64_encode(amt_commit.data(), 32);
        pvac_zero_proof zkp = g_pvac.make_zero_proof_bound(ct, (uint64_t)raw, blinding);
        std::string zp_str = g_pvac.encode_zero_proof(zkp);
        g_pvac.free_zero_proof(zkp);
        g_pvac.free_cipher(ct);

        json enc_data;
        enc_data["cipher"] = cipher_str;
        enc_data["amount_commitment"] = amt_commit_b64;
        enc_data["zero_proof"] = zp_str;
        enc_data["blinding"] = octra::base64_encode(blinding, 32);

        auto bi = get_nonce_balance(); int nonce = bi.nonce;
        octra::Transaction tx;
        tx.from = g_wallet.addr;
        tx.to_ = g_wallet.addr;
        tx.amount = std::to_string(raw);
        tx.nonce = nonce + 1;
        tx.ou = parse_ou(body, "10000");
        tx.timestamp = now_ts();
        tx.op_type = "encrypt";
        tx.encrypted_data = enc_data.dump();
        sign_tx_fields(tx);
        auto result = submit_tx(tx);
        if (result.contains("error")) res.status = 500;
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/decrypt", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        PVAC_GUARD
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        int64_t raw = parse_amount_raw(body);
        if (raw <= 0) {
            res.status = 400;
            res.set_content(err_json("invalid amount (max 6 decimals, no extra dots)").dump(), "application/json");
            return;
        }
        auto eb = get_encrypted_balance();
        if (eb.decrypted < raw) {
            res.status = 400;
            char buf[128];
            snprintf(buf, sizeof(buf), "insufficient encrypted balance: have %ld, need %ld",
                (long)eb.decrypted, (long)raw);
            res.set_content(err_json(buf).dump(), "application/json");
            return;
        }
        ensure_pvac_registered();
        json steps = json::array();

        steps.push_back("[1/5] FHE encrypt amount (PVAC-HFHE)");
        uint8_t seed[32];
        octra::random_bytes(seed, 32);
        pvac_cipher ct = g_pvac.encrypt((uint64_t)raw, seed);
        std::string cipher_str = g_pvac.encode_cipher(ct);

        steps.push_back("[2/5] bound zero proof");

        uint8_t blinding[32];
        octra::random_bytes(blinding, 32);
        auto amt_commit = g_pvac.pedersen_commit((uint64_t)raw, blinding);
        std::string amt_commit_b64 = octra::base64_encode(amt_commit.data(), 32);
        pvac_zero_proof zkp = g_pvac.make_zero_proof_bound(ct, (uint64_t)raw, blinding);
        std::string zp_str = g_pvac.encode_zero_proof(zkp);
        g_pvac.free_zero_proof(zkp);

        steps.push_back("[3/5] range proof");

        pvac_cipher current_ct = g_pvac.decode_cipher(eb.cipher);
        pvac_cipher new_bal_ct = pvac_ct_sub(g_pvac.pk(), current_ct, ct);
        uint64_t new_bal_value = (uint64_t)(eb.decrypted - raw);
        pvac_agg_range_proof arp = pvac_make_aggregated_range_proof(
            g_pvac.pk(), g_pvac.sk(), new_bal_ct, new_bal_value);
        size_t arp_len = 0;
        uint8_t* arp_data = pvac_serialize_agg_range_proof(arp, &arp_len);
        std::string rp_bal_str = std::string("rp_v1|") +
            octra::base64_encode(arp_data, arp_len);
        pvac_free_bytes(arp_data);
        pvac_free_agg_range_proof(arp);
        pvac_free_cipher(new_bal_ct);
        pvac_free_cipher(current_ct);
        g_pvac.free_cipher(ct);

        json enc_data;
        enc_data["cipher"] = cipher_str;
        enc_data["amount_commitment"] = amt_commit_b64;
        enc_data["zero_proof"] = zp_str;
        enc_data["blinding"] = octra::base64_encode(blinding, 32);
        enc_data["range_proof_balance"] = rp_bal_str;

        steps.push_back("[4/5] building decrypt transaction");

        auto bi = get_nonce_balance(); int nonce = bi.nonce;
        octra::Transaction tx;
        tx.from = g_wallet.addr;
        tx.to_ = g_wallet.addr;
        tx.amount = std::to_string(raw);
        tx.nonce = nonce + 1;
        tx.ou = parse_ou(body, "10000");
        tx.timestamp = now_ts();
        tx.op_type = "decrypt";
        tx.encrypted_data = enc_data.dump();
        sign_tx_fields(tx);
        auto result = submit_tx(tx);

        steps.push_back("[5/5] submitted to node");
        result["steps"] = steps;

        if (result.contains("error")) res.status = 500;
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/stealth/send", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string to = body.value("to", "");
        int64_t raw = parse_amount_raw(body);
        if (to.empty() || to.size() != 47 || to.substr(0, 3) != "oct" || raw <= 0) {
            res.status = 400;
            res.set_content(err_json("invalid params").dump(), "application/json");
            return;
        }

        std::string from_addr, from_pub_b64, eb_sig;
        {
            std::lock_guard<std::mutex> lock(g_mtx);
            from_addr = g_wallet.addr;
            from_pub_b64 = g_wallet.pub_b64;
            eb_sig = octra::sign_balance_request(from_addr, g_wallet.sk);
        }

        std::vector<uint8_t> their_signing_pk;
        if (auto cached = pk_cache_get(to)) {
            their_signing_pk = *cached;
        } else {
            auto pr = g_rpc.get_public_key(to);
            if (!pr.ok || !pr.result.is_object() || !pr.result.contains("public_key")
                || pr.result["public_key"].is_null() || !pr.result["public_key"].is_string()) {
                res.status = 400;
                res.set_content(err_json("recipient has no public key registered").dump(), "application/json");
                return;
            }
            their_signing_pk = octra::base64_decode(pr.result["public_key"].get<std::string>());
            if (their_signing_pk.size() != 32) {
                res.status = 400;
                res.set_content(err_json("invalid signing pubkey size").dump(), "application/json");
                return;
            }
            pk_cache_put(to, their_signing_pk);
        }
        uint8_t their_vpub[32];
        if (!octra::ed25519_pub_to_x25519(their_signing_pk.data(), their_vpub)) {
            res.status = 400;
            res.set_content(err_json("ed25519->x25519 conversion failed").dump(), "application/json");
            return;
        }
        std::vector<uint8_t> their_vpub_raw(their_vpub, their_vpub + 32);

        try {

        json steps = json::array();

        steps.push_back("[1/8] ECDH x25519 key exchange");
        uint8_t eph_sk[32], eph_pk[32];
        octra::random_bytes(eph_sk, 32);
        crypto_scalarmult_base(eph_pk, eph_sk);
        auto shared = octra::ecdh_shared_secret(eph_sk, their_vpub_raw.data());

        steps.push_back("[2/8] stealth tag + claim key derivation");
        auto stag = octra::compute_stealth_tag(shared);
        auto claim_sec = octra::compute_claim_secret(shared);
        auto claim_pub = octra::compute_claim_pub(claim_sec, to);

        steps.push_back("[3/8] checking encrypted balance");
        auto eb_r = g_rpc.get_encrypted_balance(from_addr, eb_sig, from_pub_b64);
        if (!eb_r.ok || !eb_r.result.is_object()) {
            res.status = 500;
            res.set_content(err_json("failed to fetch encrypted balance").dump(), "application/json");
            return;
        }
        std::string eb_cipher = eb_r.result.value("cipher", "0");
        if (eb_cipher.empty() || eb_cipher == "0") {
            res.status = 400;
            res.set_content(err_json("no encrypted balance available").dump(), "application/json");
            return;
        }

        std::lock_guard<std::mutex> lock(g_mtx);
        PVAC_GUARD
        if (!g_wallet_loaded || g_wallet.addr != from_addr) {
            res.status = 409;
            res.set_content(err_json("wallet state changed during send").dump(), "application/json");
            return;
        }

        int64_t eb_decrypted = g_pvac_ok ? g_pvac.get_balance(eb_cipher) : 0;
        if (eb_decrypted < raw) {
            res.status = 400;
            char buf[128];
            snprintf(buf, sizeof(buf), "insufficient encrypted balance: have %ld, need %ld",
                (long)eb_decrypted, (long)raw);
            res.set_content(err_json(buf).dump(), "application/json");
            return;
        }

        steps.push_back("[4/8] FHE encrypt delta (PVAC-HFHE)");
        ensure_pvac_registered();
        uint8_t r_blind[32];
        octra::random_bytes(r_blind, 32);
        std::string enc_amount = octra::encrypt_stealth_amount(shared, (uint64_t)raw, r_blind);
        uint8_t seed[32];
        octra::random_bytes(seed, 32);
        pvac_cipher ct_delta = g_pvac.encrypt((uint64_t)raw, seed);
        std::string delta_cipher_str = g_pvac.encode_cipher(ct_delta);
        auto commitment = g_pvac.commit_ct(ct_delta);
        std::string commitment_b64 = octra::base64_encode(commitment.data(), 32);

        steps.push_back("[5/8] range proofs (delta + balance) - Bulletproofs R1CS");
        pvac_cipher current_ct = g_pvac.decode_cipher(eb_cipher);
        pvac_cipher new_ct = g_pvac.ct_sub(current_ct, ct_delta);
        uint64_t new_val = (uint64_t)(eb_decrypted - raw);

        pvac_range_proof rp_delta = nullptr;
        pvac_range_proof rp_bal = nullptr;

        // libpvac is not safe to call with the same pk/sk handles from two threads at once.
        rp_delta = pvac_make_range_proof(g_pvac.pk(), g_pvac.sk(), ct_delta, (uint64_t)raw);
        rp_bal = pvac_make_range_proof(g_pvac.pk(), g_pvac.sk(), new_ct, new_val);

        steps.push_back("[6/8] encoding proofs");
        std::string rp_delta_str = g_pvac.encode_range_proof(rp_delta);
        std::string rp_bal_str = g_pvac.encode_range_proof(rp_bal);
        g_pvac.free_range_proof(rp_delta);
        g_pvac.free_range_proof(rp_bal);

        steps.push_back("[7/8] Pedersen commitment + AES-GCM envelope");
        auto amt_commit = g_pvac.pedersen_commit((uint64_t)raw, r_blind);
        std::string amt_commit_b64 = octra::base64_encode(amt_commit.data(), 32);

        pvac_zero_proof send_zkp = g_pvac.make_zero_proof_bound(ct_delta, (uint64_t)raw, r_blind);
        std::string send_zp_str = g_pvac.encode_zero_proof(send_zkp);
        g_pvac.free_zero_proof(send_zkp);

        g_pvac.free_cipher(ct_delta);
        g_pvac.free_cipher(current_ct);
        g_pvac.free_cipher(new_ct);

        steps.push_back("[8/8] building stealth transaction");
        json stealth_data;
        stealth_data["version"] = 5;
        stealth_data["delta_cipher"] = delta_cipher_str;
        stealth_data["commitment"] = commitment_b64;
        stealth_data["range_proof_delta"] = rp_delta_str;
        stealth_data["range_proof_balance"] = rp_bal_str;
        stealth_data["eph_pub"] = octra::base64_encode(eph_pk, 32);
        stealth_data["stealth_tag"] = octra::hex_encode(stag.data(), 16);
        stealth_data["enc_amount"] = enc_amount;
        stealth_data["claim_pub"] = octra::hex_encode(claim_pub.data(), 32);
        stealth_data["amount_commitment"] = amt_commit_b64;
        stealth_data["send_zero_proof"] = send_zp_str;

        auto bi = get_nonce_balance(); int nonce = bi.nonce;
        octra::Transaction tx;
        tx.from = g_wallet.addr;
        tx.to_ = "stealth";
        tx.amount = "0";
        tx.nonce = nonce + 1;
        tx.ou = parse_ou(body, "5000");
        tx.timestamp = now_ts();
        tx.op_type = "stealth";
        tx.encrypted_data = stealth_data.dump();
        sign_tx_fields(tx);
        auto result = submit_tx(tx);
        if (result.contains("error")) res.status = 500;
        result["steps"] = steps;
        res.set_content(result.dump(), "application/json");

        } catch (const std::exception& e) {
            fprintf(stderr, "[stealth/send] exception: %s\n", e.what());
            res.status = 500;
            res.set_content(err_json(std::string("stealth send failed: ") + e.what()).dump(), "application/json");
        } catch (...) {
            fprintf(stderr, "[stealth/send] unknown exception\n");
            res.status = 500;
            res.set_content(err_json("stealth send failed: unknown error").dump(), "application/json");
        }
    });

    svr.Get("/api/stealth/scan", [](const httplib::Request&, httplib::Response& res) {
        WALLET_GUARD
        uint8_t view_sk[32];
        {
            uint8_t view_pk[32];
            std::lock_guard<std::mutex> lock(g_mtx);
            octra::derive_view_keypair(g_wallet.sk, view_sk, view_pk);
        }
        auto r = g_rpc.get_stealth_outputs(0);
        json outputs = json::array();
        if (!r.ok || !r.result.is_object() || !r.result.contains("outputs")) {
            json j;
            j["outputs"] = outputs;
            res.set_content(j.dump(), "application/json");
            return;
        }
        for (auto& out : r.result["outputs"]) {
            if (out.value("claimed", 0) != 0) continue;
            try {
                std::string eph_b64 = out["eph_pub"].get<std::string>();
                auto eph_raw = octra::base64_decode(eph_b64);
                if (eph_raw.size() != 32) continue;
                auto shared = octra::ecdh_shared_secret(view_sk, eph_raw.data());
                auto my_tag = octra::compute_stealth_tag(shared);
                std::string my_tag_hex = octra::hex_encode(my_tag.data(), 16);
                if (my_tag_hex != out.value("stealth_tag", "")) continue;
                auto dec = octra::decrypt_stealth_amount(shared, out.value("enc_amount", ""));
                if (!dec.has_value()) continue;
                auto cs = octra::compute_claim_secret(shared);
                json o;
                o["id"] = out.value("id", 0);
                o["amount_raw"] = std::to_string(dec->amount);
                o["epoch"] = out.value("epoch_id", 0);
                o["sender"] = out.value("sender_addr", "");
                o["tx_hash"] = out.value("tx_hash", "");
                o["claim_secret"] = octra::hex_encode(cs.data(), 32);
                o["blinding"] = octra::base64_encode(dec->blinding.data(), 32);
                o["claimed"] = false;
                outputs.push_back(o);
            } catch (...) {
                continue;
            }
        }
        json j;
        j["outputs"] = outputs;
        res.set_content(j.dump(), "application/json");
    });

    svr.Post("/api/stealth/claim", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        PVAC_GUARD
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        if (!body.contains("ids") || !body["ids"].is_array() || body["ids"].empty()) {
            res.status = 400;
            res.set_content(err_json("ids required").dump(), "application/json");
            return;
        }

        uint8_t view_sk[32], view_pk[32];
        octra::derive_view_keypair(g_wallet.sk, view_sk, view_pk);
        auto sr = g_rpc.get_stealth_outputs(0);
        if (!sr.ok || !sr.result.is_object()) {
            res.status = 500;
            res.set_content(err_json("failed to fetch outputs").dump(), "application/json");
            return;
        }

        ensure_pvac_registered();

        std::vector<std::string> req_ids;
        for (auto& id : body["ids"]) {
            if (id.is_string()) req_ids.push_back(id.get<std::string>());
            else req_ids.push_back(std::to_string(id.get<int>()));
        }

        auto bi = get_nonce_balance(); int nonce = bi.nonce;
        json results = json::array();

        for (auto& out : sr.result["outputs"]) {
            std::string out_id = out.contains("id") ?
                (out["id"].is_string() ? out["id"].get<std::string>() : std::to_string(out["id"].get<int>())) : "";
            bool wanted = false;
            for (auto& rid : req_ids) {
                if (rid == out_id) { wanted = true; break; }
            }
            if (!wanted) continue;
            if (out.value("claimed", 0) != 0) {
                results.push_back({{"id", out_id}, {"ok", false}, {"error", "already claimed"}});
                continue;
            }
            try {
                auto eph_raw = octra::base64_decode(out["eph_pub"].get<std::string>());
                if (eph_raw.size() != 32) throw std::runtime_error("bad eph_pub");
                auto shared = octra::ecdh_shared_secret(view_sk, eph_raw.data());
                auto dec = octra::decrypt_stealth_amount(shared, out.value("enc_amount", ""));
                if (!dec.has_value()) throw std::runtime_error("decrypt failed");
                auto cs = octra::compute_claim_secret(shared);

                uint8_t seed[32];
                octra::random_bytes(seed, 32);
                pvac_cipher ct_claim = g_pvac.encrypt(dec->amount, seed);
                std::string claim_cipher_str = g_pvac.encode_cipher(ct_claim);
                auto commit = g_pvac.commit_ct(ct_claim);
                std::string commit_b64 = octra::base64_encode(commit.data(), 32);
                pvac_zero_proof zkp = g_pvac.make_zero_proof_bound(ct_claim, dec->amount, dec->blinding.data());
                std::string zp_str = g_pvac.encode_zero_proof(zkp);
                g_pvac.free_cipher(ct_claim);
                g_pvac.free_zero_proof(zkp);

                json claim_data;
                claim_data["version"] = 5;
                claim_data["output_id"] = out["id"];
                claim_data["claim_cipher"] = claim_cipher_str;
                claim_data["commitment"] = commit_b64;
                claim_data["claim_secret"] = octra::hex_encode(cs.data(), 32);
                claim_data["zero_proof"] = zp_str;

                nonce++;
                octra::Transaction tx;
                tx.from = g_wallet.addr;
                tx.to_ = g_wallet.addr;
                tx.amount = "0";
                tx.nonce = nonce;
                tx.ou = parse_ou(body, "3000");
                tx.timestamp = now_ts();
                tx.op_type = "claim";
                tx.encrypted_data = claim_data.dump();
                sign_tx_fields(tx);
                auto sr2 = submit_tx(tx);
                if (sr2.contains("error")) {
                    results.push_back({{"id", out_id}, {"ok", false}, {"error", sr2["error"]}});
                } else {
                    results.push_back({{"id", out_id}, {"ok", true}, {"tx_hash", sr2.value("tx_hash", "")}});
                }
            } catch (const std::exception& e) {
                results.push_back({{"id", out_id}, {"ok", false}, {"error", e.what()}});
            }
        }
        json j;
        j["results"] = results;
        res.set_content(j.dump(), "application/json");
    });

    svr.Get("/api/tx", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string hash = req.get_param_value("hash");
        if (hash.empty()) {
            res.status = 400;
            res.set_content(err_json("hash required").dump(), "application/json");
            return;
        }
        auto r = g_rpc.get_transaction(hash);
        if (!r.ok) {
            res.status = 404;
            res.set_content(err_json("transaction not found").dump(), "application/json");
            return;
        }
        auto& t = r.result;
        json j;
        j["hash"] = t.value("tx_hash", hash);
        j["from"] = t.value("from", "");
        j["to_"] = t.value("to", t.value("to_", ""));
        j["amount_raw"] = t.value("amount_raw", t.value("amount", "0"));
        j["op_type"] = t.value("op_type", "standard");
        double ts = 0.0;
        if (t.contains("timestamp") && t["timestamp"].is_number())
            ts = t["timestamp"].get<double>();
        else if (t.contains("rejected_at") && t["rejected_at"].is_number())
            ts = t["rejected_at"].get<double>();
        j["timestamp"] = ts;
        j["nonce"] = t.value("nonce", 0);
        j["signature"] = t.value("signature", "");
        j["public_key"] = t.value("public_key", "");
        if (t.contains("message") && t["message"].is_string() && !t["message"].get<std::string>().empty())
            j["message"] = t["message"];
        if (t.contains("encrypted_data") && t["encrypted_data"].is_string() && !t["encrypted_data"].get<std::string>().empty())
            j["encrypted_data"] = t["encrypted_data"];
        if (t.contains("ou")) j["ou"] = t.value("ou", "");
        j["status"] = t.value("status", "pending");
        if (t.contains("epoch")) j["epoch"] = t["epoch"];
        else if (t.contains("epoch_id")) j["epoch"] = t["epoch_id"];
        if (t.contains("block_height")) j["block_height"] = t["block_height"];
        if (t.contains("error") && t["error"].is_object()) {
            j["reject_reason"] = t["error"].value("reason", "");
            j["reject_type"] = t["error"].value("type", "");
        }
        if (g_txcache.is_open() && g_wallet_loaded) {
            const std::string from = j.value("from", "");
            const std::string to = j.value("to_", "");
            if (from == g_wallet.addr || to == g_wallet.addr)
                g_txcache.store_tx(g_wallet.addr, j);
        }
        res.set_content(j.dump(), "application/json");
    });

    svr.Get("/api/keys", [](const httplib::Request&, httplib::Response& res) {
        WALLET_GUARD
        uint8_t view_sk[32], view_pk[32];
        octra::derive_view_keypair(g_wallet.sk, view_sk, view_pk);
        json j;
        j["address"] = g_wallet.addr;
        j["public_key"] = g_wallet.pub_b64;
        j["view_pubkey"] = octra::base64_encode(view_pk, 32);
        j["has_master_seed"] = g_wallet.has_master_seed();
        octra::secure_zero(view_sk, 32);
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(j.dump(), "application/json");
    });

    svr.Post("/api/keys/private", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string pin = body.value("pin", "");
        std::string confirm = body.value("confirm", "");
        if (confirm != "I_UNDERSTAND_KEY_EXPORT_RISK") {
            res.status = 403;
            res.set_content(err_json("missing or invalid confirmation; pass confirm=\"I_UNDERSTAND_KEY_EXPORT_RISK\" in body").dump(), "application/json");
            return;
        }
        try { octra::load_wallet_encrypted(g_wallet_path, pin); } catch (...) {
            res.status = 403;
            res.set_content(err_json("wrong PIN").dump(), "application/json");
            return;
        }
        json j;
        j["private_key"] = g_wallet.priv_b64;
        j["mnemonic"] = g_wallet.mnemonic;
        j["warning"] = "treat these values as plaintext secret; never paste into shared transcripts, screen-shares, or untrusted machines";
        res.set_content(j.dump(), "application/json");
    });

    svr.Post("/api/contract/compile", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string source = body.value("source", "");
        if (source.empty()) {
            res.status = 400;
            res.set_content(err_json("source required").dump(), "application/json");
            return;
        }
        auto r = g_rpc.compile_assembly(source);
        if (!r.ok) {
            res.status = 400;
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        json j;
        j["bytecode"] = r.result.value("bytecode", "");
        j["size"] = r.result.value("size", 0);
        j["instructions"] = r.result.value("instructions", 0);
        res.set_content(j.dump(), "application/json");
    });

    svr.Post("/api/contract/compile-aml", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        try {
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string source = body.value("source", "");
        if (source.empty()) {
            res.status = 400;
            res.set_content(err_json("source required").dump(), "application/json");
            return;
        }
        auto r = g_rpc.compile_aml(source);
        if (!r.ok) {
            res.status = 400;
            std::string safe_err = r.error;
            for (auto& ch : safe_err) { if ((unsigned char)ch > 127) ch = '?'; }
            res.set_content(err_json(safe_err).dump(), "application/json");
            return;
        }
        json j;
        j["bytecode"] = r.result.value("bytecode", "");
        j["size"] = r.result.value("size", 0);
        j["instructions"] = r.result.value("instructions", 0);
        j["version"] = r.result.value("version", "");
        if (r.result.contains("abi")) j["abi"] = r.result["abi"];
        if (r.result.contains("disasm")) j["disasm"] = r.result["disasm"];
        res.set_content(j.dump(), "application/json");
        } catch (const std::exception& ex) {
            res.status = 500;
            res.set_content(err_json(std::string("internal error: ") + ex.what()).dump(), "application/json");
        } catch (...) {
            res.status = 500;
            res.set_content(err_json("internal error").dump(), "application/json");
        }
    });

    svr.Post("/api/contract/compile-project", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        try {
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        auto files = body.value("files", json::array());
        std::string main_path = body.value("main", "main.aml");
        if (files.empty()) {
            res.status = 400;
            res.set_content(err_json("files required").dump(), "application/json");
            return;
        }
        auto r = g_rpc.compile_aml_multi(files, main_path);
        if (!r.ok) {
            res.status = 400;
            std::string safe_err = r.error;
            for (auto& ch : safe_err) { if ((unsigned char)ch > 127) ch = '?'; }
            res.set_content(err_json(safe_err).dump(), "application/json");
            return;
        }
        json j;
        j["bytecode"] = r.result.value("bytecode", "");
        j["size"] = r.result.value("size", 0);
        j["instructions"] = r.result.value("instructions", 0);
        j["version"] = r.result.value("version", "");
        if (r.result.contains("abi")) j["abi"] = r.result["abi"];
        if (r.result.contains("disasm")) j["disasm"] = r.result["disasm"];
        res.set_content(j.dump(), "application/json");
        } catch (const std::exception& ex) {
            res.status = 500;
            res.set_content(err_json(std::string("internal error: ") + ex.what()).dump(), "application/json");
        } catch (...) {
            res.status = 500;
            res.set_content(err_json("internal error").dump(), "application/json");
        }
    });

    svr.Post("/api/contract/address", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string bytecode = body.value("bytecode", "");
        if (bytecode.empty()) {
            res.status = 400;
            res.set_content(err_json("bytecode required").dump(), "application/json");
            return;
        }
        int nonce_val = 0;
        auto bi = get_nonce_balance();
        nonce_val = bi.nonce + 1;
        auto r = g_rpc.compute_contract_address(bytecode, g_wallet.addr, nonce_val);
        if (!r.ok) {
            res.status = 400;
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        json j;
        j["address"] = r.result.value("address", "");
        j["deployer"] = r.result.value("deployer", "");
        j["nonce"] = r.result.value("nonce", 0);
        res.set_content(j.dump(), "application/json");
    });

    svr.Post("/api/contract/deploy", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string bytecode = body.value("bytecode", "");
        if (bytecode.empty()) {
            res.status = 400;
            res.set_content(err_json("bytecode required").dump(), "application/json");
            return;
        }
        auto bi = get_nonce_balance();
        int nonce = bi.nonce;
        auto ar = g_rpc.compute_contract_address(bytecode, g_wallet.addr, nonce + 1);
        if (!ar.ok) {
            res.status = 400;
            res.set_content(err_json(ar.error).dump(), "application/json");
            return;
        }
        std::string contract_addr = ar.result.value("address", "");
        octra::Transaction tx;
        tx.from = g_wallet.addr;
        tx.to_ = contract_addr;
        tx.amount = "0";
        tx.nonce = nonce + 1;
        tx.ou = parse_ou(body, "50000000");
        tx.timestamp = now_ts();
        tx.op_type = "deploy";
        tx.encrypted_data = bytecode;
        std::string params_str = body.value("params", "");
        if (!params_str.empty()) tx.message = params_str;
        std::string source_text = body.value("source", "");
        std::string abi_text = body.value("abi", "");
        sign_tx_fields(tx);
        auto result = submit_tx(tx);
        if (result.contains("error")) {
            res.status = 500;
        } else {
            result["contract_address"] = contract_addr;
        }
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/contract/verify", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        try {
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string addr = body.value("address", "");
        std::string source = body.value("source", "");
        if (addr.empty() || source.empty()) {
            res.status = 400;
            res.set_content(err_json("address and source required").dump(), "application/json");
            return;
        }
        nlohmann::json verify_params = nlohmann::json::array({addr, source});
        if (body.contains("files") && body["files"].is_array()) {
            verify_params.push_back(body["files"]);
        }
        auto r = g_rpc.call("contract_verify", verify_params, 15);
        if (!r.ok) {
            res.status = 400;
            std::string safe_err = r.error;
            for (auto& ch : safe_err) { if ((unsigned char)ch > 127) ch = '?'; }
            res.set_content(err_json(safe_err).dump(), "application/json");
            return;
        }
        res.set_content(r.result.dump(), "application/json");
        } catch (const std::exception& ex) {
            res.status = 500;
            res.set_content(err_json(std::string("internal error: ") + ex.what()).dump(), "application/json");
        } catch (...) {
            res.status = 500;
            res.set_content(err_json("internal error").dump(), "application/json");
        }
    });

    svr.Post("/api/contract/call", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string addr = body.value("address", "");
        std::string method = body.value("method", "");
        if (addr.empty() || method.empty()) {
            res.status = 400;
            res.set_content(err_json("address and method required").dump(), "application/json");
            return;
        }
        std::string params_str = "[]";
        if (body.contains("params")) params_str = body["params"].dump();
        std::string amount_str = body.value("amount", "0");
        auto bi = get_nonce_balance();
        int nonce = bi.nonce;
        octra::Transaction tx;
        tx.from = g_wallet.addr;
        tx.to_ = addr;
        tx.amount = amount_str;
        tx.nonce = nonce + 1;
        tx.ou = parse_ou(body, "1000");
        tx.timestamp = now_ts();
        tx.op_type = "call";
        tx.encrypted_data = method;
        tx.message = params_str;
        sign_tx_fields(tx);
        auto result = submit_tx(tx);
        if (result.contains("error")) res.status = 500;
        res.set_content(result.dump(), "application/json");
    });

    svr.Get("/api/program/info", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string circle_id = req.get_param_value("circle_id");
        std::string addr = req.get_param_value("address");
        if (circle_id.empty() && addr.empty()) {
            res.status = 400;
            res.set_content(err_json("address or circle_id required").dump(), "application/json");
            return;
        }
        auto r = circle_id.empty()
          ? g_rpc.vm_contract(addr)
          : g_rpc.circle_program_info_auth(
              circle_id,
              g_wallet.addr,
              g_wallet.pub_b64,
              sign_circle_read_request("octra_circle_program_info", circle_id));
        if (!r.ok) {
            res.status = 404;
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Post("/api/program/view", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string circle_id = body.value("circle_id", "");
        std::string addr = body.value("address", "");
        std::string method = body.value("method", "");
        if ((circle_id.empty() && addr.empty()) || method.empty()) {
            res.status = 400;
            res.set_content(err_json("method and address or circle_id required").dump(), "application/json");
            return;
        }
        json params = json::array();
        if (body.contains("params")) params = body["params"];
        auto r = circle_id.empty()
          ? g_rpc.contract_call_view(addr, method, params, g_wallet.addr)
          : g_rpc.circle_view_auth(
              circle_id,
              method,
              params,
              g_wallet.addr,
              g_wallet.pub_b64,
              sign_circle_view_request(circle_id, method, params, false),
              false);
        if (!r.ok) {
            res.status = 400;
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Post("/api/program/call", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string circle_id = body.value("circle_id", "");
        std::string addr = body.value("address", "");
        std::string method = body.value("method", "");
        if ((circle_id.empty() && addr.empty()) || method.empty()) {
            res.status = 400;
            res.set_content(err_json("method and address or circle_id required").dump(), "application/json");
            return;
        }
        std::string params_str = "[]";
        if (body.contains("params")) params_str = body["params"].dump();
        std::string amount_str = body.value("amount", "0");
        auto bi = get_nonce_balance();
        octra::Transaction tx;
        tx.from = g_wallet.addr;
        tx.to_ = circle_id.empty() ? addr : circle_id;
        tx.amount = amount_str;
        tx.nonce = bi.nonce + 1;
        tx.ou = parse_ou(body, "1000");
        tx.timestamp = now_ts();
        tx.op_type = circle_id.empty() ? "call" : "circle_call";
        tx.encrypted_data = method;
        tx.message = params_str;
        sign_tx_fields(tx);
        auto result = submit_tx(tx);
        if (result.contains("error")) res.status = 500;
        res.set_content(result.dump(), "application/json");
    });

    svr.Get("/api/program/storage", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string circle_id = req.get_param_value("circle_id");
        std::string addr = req.get_param_value("address");
        std::string key = req.get_param_value("key");
        bool dump = req.has_param("dump") && req.get_param_value("dump") == "1";
        if (circle_id.empty() && (addr.empty() || key.empty())) {
            res.status = 400;
            res.set_content(err_json("address and key or circle_id required").dump(), "application/json");
            return;
        }
        if (!circle_id.empty() && key.empty() && dump) {
            auto r = g_rpc.circle_storage_dump_auth(
                circle_id,
                g_wallet.addr,
                g_wallet.pub_b64,
                sign_circle_read_request("octra_circle_storage_dump", circle_id));
            if (!r.ok) {
                res.status = 404;
                res.set_content(err_json(r.error).dump(), "application/json");
                return;
            }
            res.set_content(r.result.dump(), "application/json");
            return;
        }
        if (!circle_id.empty() && key.empty()) {
            res.status = 400;
            res.set_content(err_json("circle storage key required unless dump=1").dump(), "application/json");
            return;
        }
        auto r = circle_id.empty()
          ? g_rpc.contract_storage(addr, key)
          : g_rpc.circle_storage_auth(
              circle_id,
              key,
              g_wallet.addr,
              g_wallet.pub_b64,
              sign_circle_read_request("octra_circle_storage", circle_id, key));
        if (!r.ok) {
            res.status = 404;
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Get("/api/program/abi", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string addr = req.get_param_value("address");
        if (addr.empty()) {
            res.status = 400;
            res.set_content(err_json("address required").dump(), "application/json");
            return;
        }
        auto r = g_rpc.contract_abi(addr);
        if (!r.ok) {
            res.status = 404;
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Post("/api/bridge/signer", [](const httplib::Request& req, httplib::Response& res) {
        std::string signer_url;
        {
            std::lock_guard<std::mutex> lock(g_mtx);
            signer_url = g_wallet.bridge_signer_url;
        }
        if (signer_url.empty()) {
            const char* env_url = std::getenv("OCTRA_BRIDGE_SIGNER_URL");
            if (env_url) signer_url = env_url;
        }
        if (signer_url.empty()) {
            signer_url = "https://relayer-002838819188.octra.network";
        }
        try {
            auto body = json::parse(req.body);
            std::string method = body.value("method", "");
            if (method != "bridgeStatus" && method != "bridgeHeader" &&
                method != "bridgeMessagesByEpoch" && method != "bridgeProofByLeafIndex" &&
                method != "bridgeClaimCalldata") {
                res.status = 400;
                res.set_content("{\"error\":\"method not allowed\"}", "application/json");
                return;
            }
        } catch (...) {
            res.status = 400;
            res.set_content("{\"error\":\"invalid json\"}", "application/json");
            return;
        }
        httplib::Client cli(signer_url);
        cli.set_connection_timeout(10, 0);
        cli.set_read_timeout(15, 0);
        auto r = cli.Post("/", req.body, "application/json");
        if (r && r->status == 200) {
            res.set_content(r->body, "application/json");
        } else {
            res.status = 502;
            res.set_content("{\"error\":\"bridge signer unavailable\"}", "application/json");
        }
    });

    svr.Get("/api/relay/health", [](const httplib::Request&, httplib::Response& res) {
        auto relay = relay_http_get("/health");
        if (!relay.ok) {
            res.status = relay.status ? relay.status : 502;
            res.set_content(err_json(relay.error).dump(), "application/json");
            return;
        }
        res.status = relay.status;
        res.set_content(relay.body, "application/json");
    });

    svr.Get("/api/relay/status", [](const httplib::Request& req, httplib::Response& res) {
        std::string request_id = req.get_param_value("request_id");
        std::string path = "/status";
        if (!request_id.empty()) path += "?request_id=" + request_id;
        auto relay = relay_http_get(path);
        if (!relay.ok) {
            res.status = relay.status ? relay.status : 502;
            res.set_content(err_json(relay.error).dump(), "application/json");
            return;
        }
        res.status = relay.status;
        res.set_content(relay.body, "application/json");
    });

    svr.Post("/api/relay/request", [](const httplib::Request& req, httplib::Response& res) {
        auto relay = relay_http_post("/request", req.body);
        if (!relay.ok) {
            res.status = relay.status ? relay.status : 502;
            res.set_content(err_json(relay.error).dump(), "application/json");
            return;
        }
        res.status = relay.status;
        res.set_content(relay.body, "application/json");
    });

    svr.Get("/api/relay/response", [](const httplib::Request& req, httplib::Response& res) {
        std::string request_id = req.get_param_value("request_id");
        if (request_id.empty()) {
            res.status = 400;
            res.set_content(err_json("request_id required").dump(), "application/json");
            return;
        }
        auto relay = relay_http_get("/response/" + request_id);
        if (!relay.ok) {
            res.status = relay.status ? relay.status : 502;
            res.set_content(err_json(relay.error).dump(), "application/json");
            return;
        }
        res.status = relay.status;
        res.set_content(relay.body, "application/json");
    });

    svr.Get("/api/relay/receipt", [](const httplib::Request& req, httplib::Response& res) {
        std::string request_id = req.get_param_value("request_id");
        if (request_id.empty()) {
            res.status = 400;
            res.set_content(err_json("request_id required").dump(), "application/json");
            return;
        }
        auto relay = relay_http_get("/receipt/" + request_id);
        if (!relay.ok) {
            res.status = relay.status ? relay.status : 502;
            res.set_content(err_json(relay.error).dump(), "application/json");
            return;
        }
        res.status = relay.status;
        res.set_content(relay.body, "application/json");
    });

    svr.Get("/api/relay/ingress", [](const httplib::Request& req, httplib::Response& res) {
        std::string request_id = req.get_param_value("request_id");
        if (request_id.empty()) {
            res.status = 400;
            res.set_content(err_json("request_id required").dump(), "application/json");
            return;
        }
        auto relay = relay_http_get("/ingress/" + request_id);
        if (!relay.ok) {
            res.status = relay.status ? relay.status : 502;
            res.set_content(err_json(relay.error).dump(), "application/json");
            return;
        }
        res.status = relay.status;
        res.set_content(relay.body, "application/json");
    });

    svr.Get("/api/contract/view", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string addr = req.get_param_value("address");
        std::string method = req.get_param_value("method");
        if (addr.empty() || method.empty()) {
            res.status = 400;
            res.set_content(err_json("address and method required").dump(), "application/json");
            return;
        }
        std::string params_str = req.get_param_value("params");
        json params = json::array();
        if (!params_str.empty()) {
            try { params = json::parse(params_str); } catch (...) {}
        }
        auto r = g_rpc.contract_call_view(addr, method, params, g_wallet.addr);
        if (!r.ok) {
            res.status = 400;
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Post("/api/fhe/encrypt", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        res.set_header("Access-Control-Allow-Origin", "*");
        if (!g_pvac_ok) {
            res.status = 500;
            res.set_content(err_json("pvac not available").dump(), "application/json");
            return;
        }
        auto body = json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("value")) {
            res.status = 400;
            res.set_content(err_json("missing value").dump(), "application/json");
            return;
        }
        int64_t value = body["value"].get<int64_t>();
        uint8_t seed[32];
        octra::random_bytes(seed, 32);
        pvac_cipher ct = g_pvac.encrypt(static_cast<uint64_t>(value), seed);
        auto data = g_pvac.serialize_cipher(ct);
        std::string b64 = octra::base64_encode(data.data(), data.size());
        uint8_t blinding[32];
        octra::random_bytes(blinding, 32);
        auto amount_commitment = g_pvac.pedersen_commit(static_cast<uint64_t>(value), blinding);
        std::string amount_commitment_b64 = octra::base64_encode(amount_commitment.data(), 32);
        pvac_zero_proof proof = g_pvac.make_zero_proof_bound(ct, static_cast<uint64_t>(value), blinding);
        std::string zero_proof = g_pvac.encode_zero_proof(proof);
        g_pvac.free_zero_proof(proof);
        g_pvac.free_cipher(ct);
        json result;
        result["ciphertext"] = b64;
        result["amount_commitment"] = amount_commitment_b64;
        result["zero_proof"] = zero_proof;
        result["proof_kind"] = "bound_zero_v1";
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/fhe/decrypt", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        res.set_header("Access-Control-Allow-Origin", "*");
        if (!g_pvac_ok) {
            res.status = 500;
            res.set_content(err_json("pvac not available").dump(), "application/json");
            return;
        }
        auto body = json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("ciphertext")) {
            res.status = 400;
            res.set_content(err_json("missing ciphertext").dump(), "application/json");
            return;
        }
        std::string b64 = body["ciphertext"].get<std::string>();
        auto raw = octra::base64_decode(b64);
        if (raw.empty()) {
            res.status = 400;
            res.set_content(err_json("invalid base64").dump(), "application/json");
            return;
        }
        pvac_cipher ct = g_pvac.deserialize_cipher(raw.data(), raw.size());
        if (!ct) {
            res.status = 400;
            res.set_content(err_json("invalid ciphertext").dump(), "application/json");
            return;
        }
        uint64_t lo = 0, hi = 0;
        g_pvac.decrypt_fp(ct, lo, hi);
        g_pvac.free_cipher(ct);
        int64_t val;
        if (hi == 0) {
            val = static_cast<int64_t>(lo);
        } else {
            __uint128_t p = (__uint128_t(1) << 127) - 1;
            __uint128_t full = (__uint128_t(hi) << 64) | lo;
            if (full > p / 2) val = -static_cast<int64_t>(p - full);
            else val = static_cast<int64_t>(lo);
        }
        json result;
        result["value"] = val;
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/circle/fhe/load_pk", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        res.set_header("Access-Control-Allow-Origin", "*");
        auto body = json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string circle_id = body.value("circle_id", "");
        std::string requested_addr = body.value("addr", g_wallet.addr);
        std::string key_id = body.value("key_id", "");
        std::string intent_id = body.value("intent_id", "");
        if (circle_id.empty() || requested_addr.empty()) {
            res.status = 400;
            res.set_content(err_json("circle_id and addr required").dump(), "application/json");
            return;
        }
        std::string error;
        if (!circle_hfhe_authorize(circle_id, "load_pk_mode", requested_addr, key_id, intent_id, error)) {
            res.status = 403;
            res.set_content(err_json(error).dump(), "application/json");
            return;
        }
        octra::RpcClient rpc(current_public_rpc_url());
        auto r = rpc.get_pvac_pubkey(requested_addr);
        if (!r.ok) {
            res.status = 404;
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Post("/api/circle/fhe/encrypt", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        res.set_header("Access-Control-Allow-Origin", "*");
        if (!g_pvac_ok) {
            res.status = 500;
            res.set_content(err_json("pvac not available").dump(), "application/json");
            return;
        }
        auto body = json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("value")) {
            res.status = 400;
            res.set_content(err_json("missing value").dump(), "application/json");
            return;
        }
        std::string circle_id = body.value("circle_id", "");
        std::string key_id = body.value("key_id", "");
        std::string intent_id = body.value("intent_id", "");
        if (circle_id.empty()) {
            res.status = 400;
            res.set_content(err_json("circle_id required").dump(), "application/json");
            return;
        }
        std::string error;
        if (!circle_hfhe_authorize(circle_id, "encrypt_mode", g_wallet.addr, key_id, intent_id, error)) {
            res.status = 403;
            res.set_content(err_json(error).dump(), "application/json");
            return;
        }
        auto policy_r = circle_hfhe_policy_auth_rpc(circle_id);
        if (!policy_r.ok) {
            res.status = 400;
            res.set_content(err_json(policy_r.error.empty() ? "circle hfhe policy read failed" : policy_r.error).dump(), "application/json");
            return;
        }
        int64_t value = body["value"].get<int64_t>();
        uint8_t seed[32];
        octra::random_bytes(seed, 32);
        pvac_cipher ct = g_pvac.encrypt(static_cast<uint64_t>(value), seed);
        auto data = g_pvac.serialize_cipher(ct);
        std::string b64 = octra::base64_encode(data.data(), data.size());
        uint8_t blinding[32];
        octra::random_bytes(blinding, 32);
        auto amount_commitment = g_pvac.pedersen_commit(static_cast<uint64_t>(value), blinding);
        std::string amount_commitment_b64 = octra::base64_encode(amount_commitment.data(), 32);
        json result;
        result["ciphertext"] = b64;
        auto policy = policy_r.result.value("policy", json::object());
        std::string encrypt_proof = policy.value("encrypt_proof", "bound_zero_v1");
        if (encrypt_proof == "bound_zero_v1" || encrypt_proof == "bound_zero_receipt_v1") {
            pvac_zero_proof proof =
                g_pvac.make_zero_proof_bound(ct, static_cast<uint64_t>(value), blinding);
            std::string zero_proof = g_pvac.encode_zero_proof(proof);
            g_pvac.free_zero_proof(proof);
            result["amount_commitment"] = amount_commitment_b64;
            result["zero_proof"] = zero_proof;
            result["proof_kind"] = encrypt_proof;
        } else if (encrypt_proof == "range_v1" || encrypt_proof == "range_receipt_v1") {
            pvac_range_proof proof =
                g_pvac.make_range_proof(ct, static_cast<uint64_t>(value));
            std::string range_proof = g_pvac.encode_range_proof(proof);
            g_pvac.free_range_proof(proof);
            result["range_proof"] = range_proof;
            result["proof_kind"] = encrypt_proof;
        } else if (encrypt_proof == "zero_receipt_v1") {
            pvac_zero_proof proof = g_pvac.make_zero_proof(ct);
            std::string zero_proof = g_pvac.encode_zero_proof(proof);
            g_pvac.free_zero_proof(proof);
            result["zero_proof"] = zero_proof;
            result["proof_kind"] = encrypt_proof;
        } else if (encrypt_proof == "none") {
            result["proof_kind"] = "none";
        } else {
            g_pvac.free_cipher(ct);
            res.status = 400;
            res.set_content(err_json("unsupported circle hfhe encrypt proof policy").dump(), "application/json");
            return;
        }
        g_pvac.free_cipher(ct);
        if (circle_hfhe_receipt_required(encrypt_proof)) {
            std::string receipt_commitment =
                circle_hfhe_proof_requires_commitment(encrypt_proof)
                    ? amount_commitment_b64
                    : "";
            octra::CircleHfheReceiptContext receipt_ctx;
            if (!circle_hfhe_receipt_signer_allowed(
                    circle_id,
                    policy,
                    g_wallet.addr,
                    g_wallet.addr,
                    intent_id,
                    error)) {
                res.status = 403;
                res.set_content(err_json(error).dump(), "application/json");
                return;
            }
            if (!circle_hfhe_receipt_context(
                    circle_id,
                    "encrypt",
                    g_wallet.addr,
                    key_id,
                    intent_id,
                    encrypt_proof,
                    policy,
                    b64,
                    receipt_commitment,
                    receipt_ctx,
                    error)) {
                res.status = 400;
                res.set_content(err_json(error).dump(), "application/json");
                return;
            }
            result["proof_receipt"] =
                octra::make_circle_hfhe_receipt_json(
                    receipt_ctx,
                    g_wallet.addr,
                    g_wallet.pub_b64,
                    g_wallet.sk);
        }
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/circle/fhe/decrypt", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        res.set_header("Access-Control-Allow-Origin", "*");
        if (!g_pvac_ok) {
            res.status = 500;
            res.set_content(err_json("pvac not available").dump(), "application/json");
            return;
        }
        auto body = json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("ciphertext")) {
            res.status = 400;
            res.set_content(err_json("missing ciphertext").dump(), "application/json");
            return;
        }
        std::string circle_id = body.value("circle_id", "");
        std::string key_id = body.value("key_id", "");
        std::string intent_id = body.value("intent_id", "");
        if (circle_id.empty()) {
            res.status = 400;
            res.set_content(err_json("circle_id required").dump(), "application/json");
            return;
        }
        std::string error;
        if (!circle_hfhe_authorize(circle_id, "decrypt_mode", g_wallet.addr, key_id, intent_id, error)) {
            res.status = 403;
            res.set_content(err_json(error).dump(), "application/json");
            return;
        }
        auto policy_r = circle_hfhe_policy_auth_rpc(circle_id);
        if (!policy_r.ok) {
            res.status = 400;
            res.set_content(err_json(policy_r.error.empty() ? "circle hfhe policy read failed" : policy_r.error).dump(), "application/json");
            return;
        }
        auto policy = policy_r.result.value("policy", json::object());
        std::string decrypt_proof = policy.value("decrypt_proof", "none");
        if (decrypt_proof == "bound_zero_v1" || decrypt_proof == "bound_zero_receipt_v1") {
            std::string zero_proof = body.value("zero_proof", "");
            std::string amount_commitment = body.value("amount_commitment", "");
            if (zero_proof.empty() || amount_commitment.empty()) {
                res.status = 400;
                res.set_content(err_json("zero_proof and amount_commitment required by circle hfhe policy").dump(), "application/json");
                return;
            }
            if (!circle_verify_bound_with_wallet(body["ciphertext"].get<std::string>(), zero_proof, amount_commitment, error)) {
                res.status = 400;
                res.set_content(err_json(error).dump(), "application/json");
                return;
            }
            if (circle_hfhe_receipt_required(decrypt_proof)) {
                if (!body.contains("proof_receipt")) {
                    res.status = 400;
                    res.set_content(err_json("proof_receipt required by circle hfhe policy").dump(), "application/json");
                    return;
                }
                if (!circle_verify_proof_receipt(
                        circle_id,
                        "encrypt",
                        g_wallet.addr,
                        key_id,
                        intent_id,
                        decrypt_proof,
                        policy,
                        body["ciphertext"].get<std::string>(),
                        amount_commitment,
                        body["proof_receipt"],
                        error)) {
                    res.status = 400;
                    res.set_content(err_json(error).dump(), "application/json");
                    return;
                }
            }
        } else if (circle_hfhe_proof_is_range(decrypt_proof)) {
            std::string range_proof = body.value("range_proof", "");
            if (range_proof.empty()) {
                res.status = 400;
                res.set_content(err_json("range_proof required by circle hfhe policy").dump(), "application/json");
                return;
            }
            if (!circle_verify_range_with_wallet(
                    body["ciphertext"].get<std::string>(),
                    range_proof,
                    error)) {
                res.status = 400;
                res.set_content(err_json(error).dump(), "application/json");
                return;
            }
            if (circle_hfhe_receipt_required(decrypt_proof)) {
                if (!body.contains("proof_receipt")) {
                    res.status = 400;
                    res.set_content(err_json("proof_receipt required by circle hfhe policy").dump(), "application/json");
                    return;
                }
                if (!circle_verify_proof_receipt(
                        circle_id,
                        "encrypt",
                        g_wallet.addr,
                        key_id,
                        intent_id,
                        decrypt_proof,
                        policy,
                        body["ciphertext"].get<std::string>(),
                        "",
                        body["proof_receipt"],
                        error)) {
                    res.status = 400;
                    res.set_content(err_json(error).dump(), "application/json");
                    return;
                }
            }
        } else if (decrypt_proof == "zero_receipt_v1") {
            std::string zero_proof = body.value("zero_proof", "");
            if (zero_proof.empty()) {
                res.status = 400;
                res.set_content(err_json("zero_proof required by circle hfhe policy").dump(), "application/json");
                return;
            }
            if (!circle_verify_zero_with_wallet(body["ciphertext"].get<std::string>(), zero_proof, error)) {
                res.status = 400;
                res.set_content(err_json(error).dump(), "application/json");
                return;
            }
            if (!body.contains("proof_receipt")) {
                res.status = 400;
                res.set_content(err_json("proof_receipt required by circle hfhe policy").dump(), "application/json");
                return;
            }
            if (!circle_verify_proof_receipt(
                    circle_id,
                    "encrypt",
                    g_wallet.addr,
                    key_id,
                    intent_id,
                    decrypt_proof,
                    policy,
                    body["ciphertext"].get<std::string>(),
                    "",
                    body["proof_receipt"],
                    error)) {
                res.status = 400;
                res.set_content(err_json(error).dump(), "application/json");
                return;
            }
        } else if (decrypt_proof != "none") {
            res.status = 400;
            res.set_content(err_json("unsupported circle hfhe decrypt proof policy").dump(), "application/json");
            return;
        }
        std::string b64 = body["ciphertext"].get<std::string>();
        auto raw = octra::base64_decode(b64);
        if (raw.empty()) {
            res.status = 400;
            res.set_content(err_json("invalid base64").dump(), "application/json");
            return;
        }
        pvac_cipher ct = g_pvac.deserialize_cipher(raw.data(), raw.size());
        if (!ct) {
            res.status = 400;
            res.set_content(err_json("invalid ciphertext").dump(), "application/json");
            return;
        }
        uint64_t lo = 0, hi = 0;
        g_pvac.decrypt_fp(ct, lo, hi);
        g_pvac.free_cipher(ct);
        int64_t val;
        if (hi == 0) {
            val = static_cast<int64_t>(lo);
        } else {
            __uint128_t p = (__uint128_t(1) << 127) - 1;
            __uint128_t full = (__uint128_t(hi) << 64) | lo;
            if (full > p / 2) val = -static_cast<int64_t>(p - full);
            else val = static_cast<int64_t>(lo);
        }
        json result;
        result["value"] = val;
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/circle/fhe/commit", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        res.set_header("Access-Control-Allow-Origin", "*");
        if (!g_pvac_ok) {
            res.status = 500;
            res.set_content(err_json("pvac not available").dump(), "application/json");
            return;
        }
        auto body = json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("circle_id") || !body.contains("ciphertext")) {
            res.status = 400;
            res.set_content(err_json("circle_id and ciphertext required").dump(), "application/json");
            return;
        }
        std::string error;
        if (!circle_hfhe_authorize(
                body["circle_id"].get<std::string>(),
                "commit_mode",
                g_wallet.addr,
                body.value("key_id", ""),
                body.value("intent_id", ""),
                error)) {
            res.status = 403;
            res.set_content(err_json(error).dump(), "application/json");
            return;
        }
        auto raw = octra::base64_decode(body["ciphertext"].get<std::string>());
        if (raw.empty()) {
            res.status = 400;
            res.set_content(err_json("invalid ciphertext").dump(), "application/json");
            return;
        }
        pvac_cipher ct = g_pvac.deserialize_cipher(raw.data(), raw.size());
        if (!ct) {
            res.status = 400;
            res.set_content(err_json("invalid ciphertext").dump(), "application/json");
            return;
        }
        auto commitment = g_pvac.commit_ct(ct);
        g_pvac.free_cipher(ct);
        json result;
        result["ciphertext_commitment"] = octra::base64_encode(commitment.data(), commitment.size());
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/circle/fhe/pedersen", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        res.set_header("Access-Control-Allow-Origin", "*");
        if (!g_pvac_ok) {
            res.status = 500;
            res.set_content(err_json("pvac not available").dump(), "application/json");
            return;
        }
        auto body = json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("circle_id") || !body.contains("value")) {
            res.status = 400;
            res.set_content(err_json("circle_id and value required").dump(), "application/json");
            return;
        }
        std::string error;
        if (!circle_hfhe_authorize(
                body["circle_id"].get<std::string>(),
                "pedersen_mode",
                g_wallet.addr,
                body.value("key_id", ""),
                body.value("intent_id", ""),
                error)) {
            res.status = 403;
            res.set_content(err_json(error).dump(), "application/json");
            return;
        }
        int64_t value = body["value"].get<int64_t>();
        std::array<uint8_t, 32> blinding = {};
        bool provided_blinding = false;
        if (body.contains("blinding")) {
            std::string blinding_b64 = body["blinding"].get<std::string>();
            auto raw = octra::base64_decode(blinding_b64);
            if (raw.size() != blinding.size()) {
                res.status = 400;
                res.set_content(err_json("blinding must decode to 32 bytes").dump(), "application/json");
                return;
            }
            std::copy(raw.begin(), raw.end(), blinding.begin());
            provided_blinding = true;
        } else {
            octra::random_bytes(blinding.data(), blinding.size());
        }
        auto amount_commitment =
            g_pvac.pedersen_commit(static_cast<uint64_t>(value), blinding.data());
        json result;
        result["amount_commitment"] = octra::base64_encode(amount_commitment.data(), amount_commitment.size());
        result["blinding"] = octra::base64_encode(blinding.data(), blinding.size());
        result["generated_blinding"] = !provided_blinding;
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/circle/fhe/serialize_cipher", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        res.set_header("Access-Control-Allow-Origin", "*");
        if (!g_pvac_ok) {
            res.status = 500;
            res.set_content(err_json("pvac not available").dump(), "application/json");
            return;
        }
        auto body = json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("circle_id") || !body.contains("ciphertext")) {
            res.status = 400;
            res.set_content(err_json("circle_id and ciphertext required").dump(), "application/json");
            return;
        }
        std::string error;
        if (!circle_hfhe_authorize(
                body["circle_id"].get<std::string>(),
                "cipher_serde_mode",
                g_wallet.addr,
                body.value("key_id", ""),
                body.value("intent_id", ""),
                error)) {
            res.status = 403;
            res.set_content(err_json(error).dump(), "application/json");
            return;
        }
        auto raw = octra::base64_decode(body["ciphertext"].get<std::string>());
        if (raw.empty()) {
            res.status = 400;
            res.set_content(err_json("invalid ciphertext").dump(), "application/json");
            return;
        }
        pvac_cipher ct = g_pvac.deserialize_cipher(raw.data(), raw.size());
        if (!ct) {
            res.status = 400;
            res.set_content(err_json("invalid ciphertext").dump(), "application/json");
            return;
        }
        auto serialized = g_pvac.serialize_cipher(ct);
        g_pvac.free_cipher(ct);
        json result;
        result["serialized_cipher"] = octra::base64_encode(serialized.data(), serialized.size());
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/circle/fhe/deserialize_cipher", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        res.set_header("Access-Control-Allow-Origin", "*");
        if (!g_pvac_ok) {
            res.status = 500;
            res.set_content(err_json("pvac not available").dump(), "application/json");
            return;
        }
        auto body = json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("circle_id") || !body.contains("serialized_cipher")) {
            res.status = 400;
            res.set_content(err_json("circle_id and serialized_cipher required").dump(), "application/json");
            return;
        }
        std::string error;
        if (!circle_hfhe_authorize(
                body["circle_id"].get<std::string>(),
                "cipher_serde_mode",
                g_wallet.addr,
                body.value("key_id", ""),
                body.value("intent_id", ""),
                error)) {
            res.status = 403;
            res.set_content(err_json(error).dump(), "application/json");
            return;
        }
        auto raw = octra::base64_decode(body["serialized_cipher"].get<std::string>());
        if (raw.empty()) {
            res.status = 400;
            res.set_content(err_json("invalid serialized cipher").dump(), "application/json");
            return;
        }
        pvac_cipher ct = g_pvac.deserialize_cipher(raw.data(), raw.size());
        if (!ct) {
            res.status = 400;
            res.set_content(err_json("invalid serialized cipher").dump(), "application/json");
            return;
        }
        auto normalized = g_pvac.serialize_cipher(ct);
        g_pvac.free_cipher(ct);
        json result;
        result["ciphertext"] = octra::base64_encode(normalized.data(), normalized.size());
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/circle/fhe/verify_zero", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        res.set_header("Access-Control-Allow-Origin", "*");
        if (!g_pvac_ok) {
            res.status = 500;
            res.set_content(err_json("pvac not available").dump(), "application/json");
            return;
        }
        auto body = json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("circle_id") || !body.contains("ciphertext") || !body.contains("zero_proof")) {
            res.status = 400;
            res.set_content(err_json("circle_id, ciphertext and zero_proof required").dump(), "application/json");
            return;
        }
        std::string error;
        if (!circle_hfhe_authorize(
                body["circle_id"].get<std::string>(),
                "verify_zero_mode",
                g_wallet.addr,
                body.value("key_id", ""),
                body.value("intent_id", ""),
                error)) {
            res.status = 403;
            res.set_content(err_json(error).dump(), "application/json");
            return;
        }
        auto policy_r = circle_hfhe_policy_auth_rpc(body["circle_id"].get<std::string>());
        if (!policy_r.ok) {
            res.status = 400;
            res.set_content(err_json(policy_r.error.empty() ? "circle hfhe policy read failed" : policy_r.error).dump(), "application/json");
            return;
        }
        auto policy = policy_r.result.value("policy", json::object());
        std::string encrypt_proof = policy.value("encrypt_proof", "bound_zero_v1");
        if (encrypt_proof == "zero_receipt_v1") {
            if (!body.contains("proof_receipt")) {
                res.status = 400;
                res.set_content(err_json("proof_receipt required by circle hfhe policy").dump(), "application/json");
                return;
            }
            if (!circle_verify_proof_receipt(
                    body["circle_id"].get<std::string>(),
                    "encrypt",
                    g_wallet.addr,
                    body.value("key_id", ""),
                    body.value("intent_id", ""),
                    encrypt_proof,
                    policy,
                    body["ciphertext"].get<std::string>(),
                    "",
                    body["proof_receipt"],
                    error)) {
                res.status = 400;
                res.set_content(err_json(error).dump(), "application/json");
                return;
            }
        }
        bool ok = circle_verify_zero_with_wallet(
            body["ciphertext"].get<std::string>(),
            body["zero_proof"].get<std::string>(),
            error);
        if (!ok && !error.empty()) {
            res.status = 400;
            res.set_content(err_json(error).dump(), "application/json");
            return;
        }
        res.set_content(json({{"ok", ok}}).dump(), "application/json");
    });

    svr.Post("/api/circle/fhe/verify_range", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        res.set_header("Access-Control-Allow-Origin", "*");
        if (!g_pvac_ok) {
            res.status = 500;
            res.set_content(err_json("pvac not available").dump(), "application/json");
            return;
        }
        auto body = json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("circle_id") || !body.contains("ciphertext") || !body.contains("range_proof")) {
            res.status = 400;
            res.set_content(err_json("circle_id, ciphertext and range_proof required").dump(), "application/json");
            return;
        }
        std::string circle_id = body["circle_id"].get<std::string>();
        std::string key_id = body.value("key_id", "");
        std::string intent_id = body.value("intent_id", "");
        std::string error;
        if (!circle_hfhe_authorize(
                circle_id,
                "verify_range_mode",
                g_wallet.addr,
                key_id,
                intent_id,
                error)) {
            res.status = 403;
            res.set_content(err_json(error).dump(), "application/json");
            return;
        }
        auto policy_r = circle_hfhe_policy_auth_rpc(circle_id);
        if (!policy_r.ok) {
            res.status = 400;
            res.set_content(err_json(policy_r.error.empty() ? "circle hfhe policy read failed" : policy_r.error).dump(), "application/json");
            return;
        }
        auto policy = policy_r.result.value("policy", json::object());
        std::string encrypt_proof = policy.value("encrypt_proof", "bound_zero_v1");
        if (encrypt_proof == "range_receipt_v1") {
            if (!body.contains("proof_receipt")) {
                res.status = 400;
                res.set_content(err_json("proof_receipt required by circle hfhe policy").dump(), "application/json");
                return;
            }
            if (!circle_verify_proof_receipt(
                    circle_id,
                    "encrypt",
                    g_wallet.addr,
                    key_id,
                    intent_id,
                    encrypt_proof,
                    policy,
                    body["ciphertext"].get<std::string>(),
                    "",
                    body["proof_receipt"],
                    error)) {
                res.status = 400;
                res.set_content(err_json(error).dump(), "application/json");
                return;
            }
        }
        bool ok = circle_verify_range_with_wallet(
            body["ciphertext"].get<std::string>(),
            body["range_proof"].get<std::string>(),
            error);
        if (!ok && !error.empty()) {
            res.status = 400;
            res.set_content(err_json(error).dump(), "application/json");
            return;
        }
        res.set_content(json({{"ok", ok}}).dump(), "application/json");
    });

    svr.Post("/api/circle/fhe/verify_bound", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        res.set_header("Access-Control-Allow-Origin", "*");
        if (!g_pvac_ok) {
            res.status = 500;
            res.set_content(err_json("pvac not available").dump(), "application/json");
            return;
        }
        auto body = json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("circle_id") || !body.contains("ciphertext") || !body.contains("zero_proof") || !body.contains("amount_commitment")) {
            res.status = 400;
            res.set_content(err_json("circle_id, ciphertext, zero_proof and amount_commitment required").dump(), "application/json");
            return;
        }
        std::string error;
        if (!circle_hfhe_authorize(
                body["circle_id"].get<std::string>(),
                "verify_bound_mode",
                g_wallet.addr,
                body.value("key_id", ""),
                body.value("intent_id", ""),
                error)) {
            res.status = 403;
            res.set_content(err_json(error).dump(), "application/json");
            return;
        }
        auto policy_r = circle_hfhe_policy_auth_rpc(body["circle_id"].get<std::string>());
        if (!policy_r.ok) {
            res.status = 400;
            res.set_content(err_json(policy_r.error.empty() ? "circle hfhe policy read failed" : policy_r.error).dump(), "application/json");
            return;
        }
        auto policy = policy_r.result.value("policy", json::object());
        std::string encrypt_proof = policy.value("encrypt_proof", "bound_zero_v1");
        if (encrypt_proof == "bound_zero_receipt_v1") {
            if (!body.contains("proof_receipt")) {
                res.status = 400;
                res.set_content(err_json("proof_receipt required by circle hfhe policy").dump(), "application/json");
                return;
            }
            if (!circle_verify_proof_receipt(
                    body["circle_id"].get<std::string>(),
                    "encrypt",
                    g_wallet.addr,
                    body.value("key_id", ""),
                    body.value("intent_id", ""),
                    encrypt_proof,
                    policy,
                    body["ciphertext"].get<std::string>(),
                    body["amount_commitment"].get<std::string>(),
                    body["proof_receipt"],
                    error)) {
                res.status = 400;
                res.set_content(err_json(error).dump(), "application/json");
                return;
            }
        }
        bool ok = circle_verify_bound_with_wallet(
            body["ciphertext"].get<std::string>(),
            body["zero_proof"].get<std::string>(),
            body["amount_commitment"].get<std::string>(),
            error);
        if (!ok && !error.empty()) {
            res.status = 400;
            res.set_content(err_json(error).dump(), "application/json");
            return;
        }
        res.set_content(json({{"ok", ok}}).dump(), "application/json");
    });

    svr.Get("/api/contract/info", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string addr = req.get_param_value("address");
        if (addr.empty()) {
            res.status = 400;
            res.set_content(err_json("address required").dump(), "application/json");
            return;
        }
        auto r = g_rpc.vm_contract(addr);
        if (!r.ok) {
            res.status = 404;
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Get("/api/circle/info", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string circle_id = req.get_param_value("circle_id");
        if (circle_id.empty()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("circle_id required").dump(), "application/json");
            return;
        }
        octra::RpcClient rpc(current_public_rpc_url());
        auto r = rpc.circle_info(circle_id);
        if (!r.ok) {
            r = rpc.circle_info_auth(
                circle_id,
                g_wallet.addr,
                g_wallet.pub_b64,
                sign_circle_read_request("octra_circle_info", circle_id));
        }
        if (!r.ok) {
            res.status = 404;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Get("/api/circle/slot_policy", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string circle_id = req.get_param_value("circle_id");
        std::string slot_ref = req.get_param_value("slot_ref");
        if (circle_id.empty() || slot_ref.empty()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("circle_id and slot_ref required").dump(), "application/json");
            return;
        }
        octra::RpcClient rpc(current_public_rpc_url());
        auto r = rpc.circle_slot_policy_auth(
            circle_id,
            slot_ref,
            g_wallet.addr,
            g_wallet.pub_b64,
            sign_circle_read_request("octra_circle_slot_policy", circle_id, slot_ref));
        if (!r.ok) {
            res.status = 404;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Get("/api/circle/state_policy", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string circle_id = req.get_param_value("circle_id");
        std::string state_ref = req.get_param_value("state_ref");
        if (circle_id.empty() || state_ref.empty()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("circle_id and state_ref required").dump(), "application/json");
            return;
        }
        octra::RpcClient rpc(current_public_rpc_url());
        auto r = rpc.circle_state_policy_auth(
            circle_id,
            state_ref,
            g_wallet.addr,
            g_wallet.pub_b64,
            sign_circle_read_request("octra_circle_state_policy", circle_id, state_ref));
        if (!r.ok) {
            res.status = 404;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Get("/api/circle/state_descriptor", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string circle_id = req.get_param_value("circle_id");
        std::string state_ref = req.get_param_value("state_ref");
        if (circle_id.empty() || state_ref.empty()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("circle_id and state_ref required").dump(), "application/json");
            return;
        }
        octra::RpcClient rpc(current_public_rpc_url());
        auto r = rpc.circle_state_descriptor_auth(
            circle_id,
            state_ref,
            g_wallet.addr,
            g_wallet.pub_b64,
            sign_circle_read_request("octra_circle_state_descriptor", circle_id, state_ref));
        if (!r.ok) {
            res.status = 404;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Get("/api/circle/balance_cell", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string circle_id = req.get_param_value("circle_id");
        std::string state_ref = req.get_param_value("state_ref");
        if (circle_id.empty() || state_ref.empty()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("circle_id and state_ref required").dump(), "application/json");
            return;
        }
        octra::RpcClient rpc(current_public_rpc_url());
        auto r = rpc.circle_balance_cell_auth(
            circle_id,
            state_ref,
            g_wallet.addr,
            g_wallet.pub_b64,
            sign_circle_read_request("octra_circle_balance_cell", circle_id, state_ref));
        if (!r.ok) {
            res.status = 404;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Get("/api/circle/register_cell", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string circle_id = req.get_param_value("circle_id");
        std::string state_ref = req.get_param_value("state_ref");
        if (circle_id.empty() || state_ref.empty()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("circle_id and state_ref required").dump(), "application/json");
            return;
        }
        octra::RpcClient rpc(current_public_rpc_url());
        auto r = rpc.circle_register_cell_auth(
            circle_id,
            state_ref,
            g_wallet.addr,
            g_wallet.pub_b64,
            sign_circle_read_request("octra_circle_register_cell", circle_id, state_ref));
        if (!r.ok) {
            res.status = 404;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Get("/api/circle/balance_binding", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string circle_id = req.get_param_value("circle_id");
        std::string subject_addr = req.get_param_value("subject_addr");
        if (circle_id.empty() || subject_addr.empty()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("circle_id and subject_addr required").dump(), "application/json");
            return;
        }
        octra::RpcClient rpc(current_public_rpc_url());
        auto r = rpc.circle_balance_binding_auth(
            circle_id,
            subject_addr,
            g_wallet.addr,
            g_wallet.pub_b64,
            sign_circle_read_request("octra_circle_balance_binding", circle_id, subject_addr));
        if (!r.ok) {
            res.status = 404;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Get("/api/circle/register_binding", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string circle_id = req.get_param_value("circle_id");
        std::string register_ref = req.get_param_value("register_ref");
        if (circle_id.empty() || register_ref.empty()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("circle_id and register_ref required").dump(), "application/json");
            return;
        }
        octra::RpcClient rpc(current_public_rpc_url());
        auto r = rpc.circle_register_binding_auth(
            circle_id,
            register_ref,
            g_wallet.addr,
            g_wallet.pub_b64,
            sign_circle_read_request("octra_circle_register_binding", circle_id, register_ref));
        if (!r.ok) {
            res.status = 404;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Get("/api/circle/balance_workflow", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string circle_id = req.get_param_value("circle_id");
        std::string workflow_ref = req.get_param_value("workflow_ref");
        if (circle_id.empty() || workflow_ref.empty()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("circle_id and workflow_ref required").dump(), "application/json");
            return;
        }
        octra::RpcClient rpc(current_public_rpc_url());
        auto r = rpc.circle_balance_workflow_auth(
            circle_id,
            workflow_ref,
            g_wallet.addr,
            g_wallet.pub_b64,
            sign_circle_read_request("octra_circle_balance_workflow", circle_id, workflow_ref));
        if (!r.ok) {
            res.status = 404;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Get("/api/circle/register_workflow", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string circle_id = req.get_param_value("circle_id");
        std::string workflow_ref = req.get_param_value("workflow_ref");
        if (circle_id.empty() || workflow_ref.empty()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("circle_id and workflow_ref required").dump(), "application/json");
            return;
        }
        octra::RpcClient rpc(current_public_rpc_url());
        auto r = rpc.circle_register_workflow_auth(
            circle_id,
            workflow_ref,
            g_wallet.addr,
            g_wallet.pub_b64,
            sign_circle_read_request("octra_circle_register_workflow", circle_id, workflow_ref));
        if (!r.ok) {
            res.status = 404;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Get("/api/circle/object_summary", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string circle_id = req.get_param_value("circle_id");
        std::string object_ref = req.get_param_value("object_ref");
        if (circle_id.empty() || object_ref.empty()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("circle_id and object_ref required").dump(), "application/json");
            return;
        }
        octra::RpcClient rpc(current_public_rpc_url());
        auto r = rpc.circle_object_summary_auth(
            circle_id,
            object_ref,
            g_wallet.addr,
            g_wallet.pub_b64,
            sign_circle_read_request("octra_circle_object_summary", circle_id, object_ref));
        if (!r.ok) {
            res.status = 404;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Get("/api/circle/object_members", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string circle_id = req.get_param_value("circle_id");
        std::string object_ref = req.get_param_value("object_ref");
        if (circle_id.empty() || object_ref.empty()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("circle_id and object_ref required").dump(), "application/json");
            return;
        }
        octra::RpcClient rpc(current_public_rpc_url());
        auto r = rpc.circle_object_members_auth(
            circle_id,
            object_ref,
            g_wallet.addr,
            g_wallet.pub_b64,
            sign_circle_read_request("octra_circle_object_members", circle_id, object_ref));
        if (!r.ok) {
            res.status = 404;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Get("/api/circle/object_detail", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string circle_id = req.get_param_value("circle_id");
        std::string object_ref = req.get_param_value("object_ref");
        if (circle_id.empty() || object_ref.empty()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("circle_id and object_ref required").dump(), "application/json");
            return;
        }
        octra::RpcClient rpc(current_public_rpc_url());
        auto r = rpc.circle_object_detail_auth(
            circle_id,
            object_ref,
            g_wallet.addr,
            g_wallet.pub_b64,
            sign_circle_read_request("octra_circle_object_detail", circle_id, object_ref));
        if (!r.ok) {
            res.status = 404;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Get("/api/circle/object_member", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string circle_id = req.get_param_value("circle_id");
        std::string object_ref = req.get_param_value("object_ref");
        std::string member_ref = req.get_param_value("member_ref");
        if (circle_id.empty() || object_ref.empty() || member_ref.empty()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("circle_id, object_ref and member_ref required").dump(), "application/json");
            return;
        }
        octra::RpcClient rpc(current_public_rpc_url());
        auto r = rpc.circle_object_member_auth(
            circle_id,
            object_ref,
            member_ref,
            g_wallet.addr,
            g_wallet.pub_b64,
            sign_circle_read_request("octra_circle_object_member", circle_id, object_ref + "|" + member_ref));
        if (!r.ok) {
            res.status = 404;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Get("/api/circle/object_refs", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string circle_id = req.get_param_value("circle_id");
        if (circle_id.empty()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("circle_id required").dump(), "application/json");
            return;
        }
        octra::RpcClient rpc(current_public_rpc_url());
        auto r = rpc.circle_object_refs_auth(
            circle_id,
            g_wallet.addr,
            g_wallet.pub_b64,
            sign_circle_read_request("octra_circle_object_refs", circle_id));
        if (!r.ok) {
            res.status = 404;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Get("/api/circle/object_list", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string circle_id = req.get_param_value("circle_id");
        if (circle_id.empty()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("circle_id required").dump(), "application/json");
            return;
        }
        octra::RpcClient rpc(current_public_rpc_url());
        auto r = rpc.circle_object_list_auth(
            circle_id,
            g_wallet.addr,
            g_wallet.pub_b64,
            sign_circle_read_request("octra_circle_object_list", circle_id));
        if (!r.ok) {
            res.status = 404;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Post("/api/circle/object_policy_define", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        json body = json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string circle_id = body.value("circle_id", "");
        std::string object_ref = body.value("object_ref", "");
        std::string transition_mode = body.value("transition_mode", "");
        std::string required_proof_kind = body.value("required_proof_kind", "");
        if (circle_id.empty() || object_ref.empty() || transition_mode.empty() || required_proof_kind.empty()
            || !body.contains("member_quorum") || !body["member_quorum"].is_number_integer()
            || !body.contains("allow_detach") || !body["allow_detach"].is_boolean()
            || !body.contains("allow_root_state_rotation") || !body["allow_root_state_rotation"].is_boolean()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("circle_id, object_ref, transition_mode, required_proof_kind, member_quorum, allow_detach, and allow_root_state_rotation required").dump(), "application/json");
            return;
        }
        json params = json::array({
            object_ref,
            body.value("delivery_key_id", ""),
            body.value("activate_after_epoch", 0),
            body.value("expire_after_epoch", 0),
            transition_mode,
            required_proof_kind,
            body["member_quorum"].get<int>(),
            body["allow_detach"].get<bool>(),
            body["allow_root_state_rotation"].get<bool>()
        });
        auto result = submit_program_call_tx(
            circle_id,
            "circle_call",
            body.value("method", "define_object_policy_native"),
            params,
            body,
            "1000");
        if (result.contains("error")) res.status = 500;
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/circle/object_bind", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        json body = json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string circle_id = body.value("circle_id", "");
        std::string object_ref = body.value("object_ref", "");
        std::string state_ref = body.value("state_ref", "");
        std::string transition_ref = body.value("transition_ref", "");
        std::string status = body.value("status", "");
        if (circle_id.empty() || object_ref.empty() || state_ref.empty() || transition_ref.empty() || status.empty()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("circle_id, object_ref, state_ref, transition_ref, and status required").dump(), "application/json");
            return;
        }
        json params = json::array({object_ref, state_ref, transition_ref, status});
        auto result = submit_program_call_tx(
            circle_id,
            "circle_call",
            body.value("method", "bind_object_native"),
            params,
            body,
            "1000");
        if (result.contains("error")) res.status = 500;
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/circle/object_member_attach", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        json body = json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string circle_id = body.value("circle_id", "");
        std::string object_ref = body.value("object_ref", "");
        std::string member_ref = body.value("member_ref", "");
        std::string state_ref = body.value("state_ref", "");
        std::string member_kind = body.value("member_kind", "");
        std::string state_class = body.value("state_class", "");
        std::string codec = body.value("codec", "");
        std::string status = body.value("status", "");
        if (circle_id.empty() || object_ref.empty() || member_ref.empty() || state_ref.empty()
            || member_kind.empty() || state_class.empty() || codec.empty() || status.empty()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("circle_id, object_ref, member_ref, state_ref, member_kind, state_class, codec, and status required").dump(), "application/json");
            return;
        }
        json params = json::array({object_ref, member_ref, state_ref, member_kind, state_class, codec, status});
        auto result = submit_program_call_tx(
            circle_id,
            "circle_call",
            body.value("method", "attach_object_member_native"),
            params,
            body,
            "1000");
        if (result.contains("error")) res.status = 500;
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/circle/object_member_detach", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        json body = json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string circle_id = body.value("circle_id", "");
        std::string object_ref = body.value("object_ref", "");
        std::string member_ref = body.value("member_ref", "");
        if (circle_id.empty() || object_ref.empty() || member_ref.empty()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("circle_id, object_ref, and member_ref required").dump(), "application/json");
            return;
        }
        json params = json::array({object_ref, member_ref});
        auto result = submit_program_call_tx(
            circle_id,
            "circle_call",
            body.value("method", "detach_object_member_native"),
            params,
            body,
            "1000");
        if (result.contains("error")) res.status = 500;
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/circle/object_transition_apply", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        json body = json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string circle_id = body.value("circle_id", "");
        std::string transition_ref = body.value("transition_ref", "");
        std::string object_ref = body.value("object_ref", "");
        std::string next_state_ref = body.value("next_state_ref", "");
        std::string status = body.value("status", "");
        std::string intent_id = body.value("intent_id", "");
        if (circle_id.empty() || transition_ref.empty() || object_ref.empty() || next_state_ref.empty() || status.empty() || intent_id.empty()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("circle_id, transition_ref, object_ref, next_state_ref, status, and intent_id required").dump(), "application/json");
            return;
        }
        json params = json::array({
            transition_ref,
            object_ref,
            body.value("previous_state_ref", ""),
            next_state_ref,
            body.value("member_bundle", ""),
            body.value("touched_members_hash", ""),
            body.value("proof_kind", ""),
            body.value("proof_receipt_hash", ""),
            status,
            intent_id
        });
        auto result = submit_program_call_tx(
            circle_id,
            "circle_call",
            body.value("method", "apply_object_transition_native"),
            params,
            body,
            "1000");
        if (result.contains("error")) res.status = 500;
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(result.dump(), "application/json");
    });

    svr.Get("/api/circle/transport_policy", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string circle_id = req.get_param_value("circle_id");
        if (circle_id.empty()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("circle_id required").dump(), "application/json");
            return;
        }
        octra::RpcClient rpc(current_public_rpc_url());
        auto r = rpc.circle_transport_policy_auth(
            circle_id,
            g_wallet.addr,
            g_wallet.pub_b64,
            sign_circle_read_request("octra_circle_transport_policy", circle_id));
        if (!r.ok) {
            res.status = 404;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Get("/api/circle/hfhe_policy", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string circle_id = req.get_param_value("circle_id");
        if (circle_id.empty()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("circle_id required").dump(), "application/json");
            return;
        }
        octra::RpcClient rpc(current_public_rpc_url());
        auto r = rpc.circle_hfhe_policy_auth(
            circle_id,
            g_wallet.addr,
            g_wallet.pub_b64,
            sign_circle_read_request("octra_circle_hfhe_policy", circle_id));
        if (!r.ok) {
            res.status = 404;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Get("/api/circle/key_policy", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string circle_id = req.get_param_value("circle_id");
        std::string key_id = req.get_param_value("key_id");
        if (circle_id.empty() || key_id.empty()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("circle_id and key_id required").dump(), "application/json");
            return;
        }
        octra::RpcClient rpc(current_public_rpc_url());
        auto r = rpc.circle_key_policy_auth(
            circle_id,
            key_id,
            g_wallet.addr,
            g_wallet.pub_b64,
            sign_circle_read_request("octra_circle_key_policy", circle_id, key_id));
        if (!r.ok) {
            res.status = 404;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Get("/api/circle/outbox_intent", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string circle_id = req.get_param_value("circle_id");
        std::string intent_id = req.get_param_value("intent_id");
        if (circle_id.empty() || intent_id.empty()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("circle_id and intent_id required").dump(), "application/json");
            return;
        }
        octra::RpcClient rpc(current_public_rpc_url());
        auto r = rpc.circle_outbox_intent_auth(
            circle_id,
            intent_id,
            g_wallet.addr,
            g_wallet.pub_b64,
            sign_circle_read_request("octra_circle_outbox_intent", circle_id, intent_id));
        if (!r.ok) {
            res.status = 404;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Get("/api/circle/outbox_claim", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string circle_id = req.get_param_value("circle_id");
        std::string intent_id = req.get_param_value("intent_id");
        if (circle_id.empty() || intent_id.empty()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("circle_id and intent_id required").dump(), "application/json");
            return;
        }
        octra::RpcClient rpc(current_public_rpc_url());
        auto r = rpc.circle_outbox_claim_auth(
            circle_id,
            intent_id,
            g_wallet.addr,
            g_wallet.pub_b64,
            sign_circle_read_request("octra_circle_outbox_claim", circle_id, intent_id));
        if (!r.ok) {
            res.status = 404;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Get("/api/circle/outbox_status", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string circle_id = req.get_param_value("circle_id");
        std::string intent_id = req.get_param_value("intent_id");
        if (circle_id.empty() || intent_id.empty()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("circle_id and intent_id required").dump(), "application/json");
            return;
        }
        octra::RpcClient rpc(current_public_rpc_url());
        auto r = rpc.circle_outbox_status_auth(
            circle_id,
            intent_id,
            g_wallet.addr,
            g_wallet.pub_b64,
            sign_circle_read_request("octra_circle_outbox_status", circle_id, intent_id));
        if (!r.ok) {
            res.status = 404;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Get("/api/circle/ingress_packet", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string circle_id = req.get_param_value("circle_id");
        std::string intent_id = req.get_param_value("intent_id");
        if (circle_id.empty() || intent_id.empty()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("circle_id and intent_id required").dump(), "application/json");
            return;
        }
        octra::RpcClient rpc(current_public_rpc_url());
        auto r = rpc.circle_ingress_packet_auth(
            circle_id,
            intent_id,
            g_wallet.addr,
            g_wallet.pub_b64,
            sign_circle_read_request("octra_circle_ingress_packet", circle_id, intent_id));
        if (!r.ok) {
            res.status = 404;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Get("/api/circle/asset", [](const httplib::Request& req, httplib::Response& res) {
        std::string circle_id = req.get_param_value("circle_id");
        std::string path = req.get_param_value("path");
        if (circle_id.empty() || path.empty()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("circle_id and path required").dump(), "application/json");
            return;
        }
        octra::RpcClient rpc(current_public_rpc_url());
        auto r = rpc.circle_asset(circle_id, path);
        if (!r.ok) {
            res.status = 404;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Get("/api/circle/asset_ciphertext", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string circle_id = req.get_param_value("circle_id");
        std::string path = req.get_param_value("path");
        if (circle_id.empty() || path.empty()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("circle_id and path required").dump(), "application/json");
            return;
        }
        octra::RpcClient rpc(current_public_rpc_url());
        auto r = rpc.circle_asset_ciphertext(circle_id, path);
        if (!r.ok) {
            r = rpc.circle_asset_ciphertext_auth(
                circle_id,
                path,
                g_wallet.addr,
                g_wallet.pub_b64,
                sign_circle_read_request("octra_circle_asset_ciphertext", circle_id, "path|" + path));
        }
        if (!r.ok) {
            res.status = 404;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Get("/api/circle/asset_ciphertext_by_key", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string circle_id = req.get_param_value("circle_id");
        std::string resource_key = req.get_param_value("resource_key");
        if (circle_id.empty() || resource_key.empty()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("circle_id and resource_key required").dump(), "application/json");
            return;
        }
        octra::RpcClient rpc(current_public_rpc_url());
        auto r = rpc.circle_asset_ciphertext_by_resource_key(circle_id, resource_key);
        if (!r.ok) {
            r = rpc.circle_asset_ciphertext_by_resource_key_auth(
                circle_id,
                resource_key,
                g_wallet.addr,
                g_wallet.pub_b64,
                sign_circle_read_request("octra_circle_asset_ciphertext_by_resource_key", circle_id, "resource_key|" + resource_key));
        }
        if (!r.ok) {
            res.status = 404;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Get("/api/circle/asset_ciphertext_by_slot", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string circle_id = req.get_param_value("circle_id");
        std::string slot_ref = req.get_param_value("slot_ref");
        if (circle_id.empty() || slot_ref.empty()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("circle_id and slot_ref required").dump(), "application/json");
            return;
        }
        octra::RpcClient rpc(current_public_rpc_url());
        auto r = rpc.circle_asset_ciphertext_by_slot_ref(circle_id, slot_ref);
        if (!r.ok) {
            r = rpc.circle_asset_ciphertext_by_slot_ref_auth(
                circle_id,
                slot_ref,
                g_wallet.addr,
                g_wallet.pub_b64,
                sign_circle_read_request("octra_circle_asset_ciphertext_by_slot_ref", circle_id, "slot_ref|" + slot_ref));
        }
        if (!r.ok) {
            res.status = 404;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Get("/api/circle/asset_ciphertext_by_state", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string circle_id = req.get_param_value("circle_id");
        std::string state_ref = req.get_param_value("state_ref");
        if (circle_id.empty() || state_ref.empty()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("circle_id and state_ref required").dump(), "application/json");
            return;
        }
        octra::RpcClient rpc(current_public_rpc_url());
        auto r = rpc.circle_asset_ciphertext_by_state_ref(circle_id, state_ref);
        if (!r.ok) {
            r = rpc.circle_asset_ciphertext_by_state_ref_auth(
                circle_id,
                state_ref,
                g_wallet.addr,
                g_wallet.pub_b64,
                sign_circle_read_request("octra_circle_asset_ciphertext_by_state_ref", circle_id, "state_ref|" + state_ref));
        }
        if (!r.ok) {
            res.status = 404;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Post("/api/circle/deploy", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        res.set_header("Access-Control-Allow-Origin", "*");
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        auto read_string_or = [&](const char* key, const char* fallback) -> std::string {
            if (!body.contains(key) || body[key].is_null()) {
                return fallback;
            }
            if (body[key].is_string()) {
                return body[key].get<std::string>();
            }
            return fallback;
        };
        auto read_optional_string = [&](const char* key) -> std::string {
            return read_string_or(key, "");
        };
        std::string circle_id = read_string_or("circle_id", "");
        std::string runtime = read_string_or("runtime", "octb");
        std::string privacy_class = read_string_or("privacy_class", "sealed");
        std::string browser_mode = read_string_or("browser_mode", "native_sealed");
        std::string resource_mode = read_string_or("resource_mode", "sealed_read");
        std::string code_b64 = read_optional_string("code_b64");
        std::string policy_hash = read_optional_string("policy_hash");
        std::string members_root = read_optional_string("members_root");
        std::string export_policy = read_optional_string("export_policy");
        if (circle_id.empty()) {
            res.status = 400;
            res.set_content(err_json("circle_id required").dump(), "application/json");
            return;
        }
        auto read_limit = [&](const char* key, const char* fallback) -> std::string {
            if (!body.contains("limits") || !body["limits"].is_object()) {
                return fallback;
            }
            auto limits = body["limits"];
            if (!limits.contains(key)) {
                return fallback;
            }
            if (limits[key].is_string()) {
                return limits[key].get<std::string>();
            }
            if (limits[key].is_number_integer()) {
                return std::to_string(limits[key].get<long long>());
            }
            return fallback;
        };
        json payload;
        payload["runtime"] = runtime;
        payload["privacy_class"] = privacy_class;
        payload["browser_mode"] = browser_mode;
        payload["resource_mode"] = resource_mode;
        payload["limits"] = {
            {"max_stable_bytes", read_limit("max_stable_bytes", "33554432")},
            {"max_assets_bytes", read_limit("max_assets_bytes", "33554432")},
            {"max_inline_value", read_limit("max_inline_value", "65536")},
            {"max_wasm_bytes", read_limit("max_wasm_bytes", "33554432")}
        };
        if (!code_b64.empty()) payload["code_b64"] = code_b64;
        if (!policy_hash.empty()) payload["policy_hash"] = policy_hash;
        if (!members_root.empty()) payload["members_root"] = members_root;
        if (!export_policy.empty()) payload["export_policy"] = export_policy;
        auto bi = get_nonce_balance();
        octra::Transaction tx;
        tx.from = g_wallet.addr;
        tx.to_ = circle_id;
        tx.amount = "0";
        tx.nonce = bi.nonce + 1;
        tx.ou = parse_ou(body, "200000");
        tx.timestamp = now_ts();
        tx.op_type = "deploy_circle";
        tx.message = payload.dump();
        sign_tx_fields(tx);
        auto result = submit_tx(tx);
        if (result.contains("error")) res.status = 500;
        else result["circle_id"] = circle_id;
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/circle/asset_encrypted", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        res.set_header("Access-Control-Allow-Origin", "*");
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string circle_id = body.value("circle_id", "");
        std::string path = body.value("path", "");
        std::string slot_ref = body.value("slot_ref", "");
        std::string state_ref = body.value("state_ref", "");
        std::string content_type = body.value("content_type", "");
        std::string ciphertext_b64 = body.value("ciphertext_b64", "");
        std::string key_id = body.value("key_id", "");
        std::string plaintext_hash = body.value("plaintext_hash", "");
        std::string encoding = body.value("encoding", "");
        std::string padding_class = body.value("padding_class", "");
        auto read_optional_scalar = [&](const char* key) -> std::string {
            if (!body.contains(key)) {
                return "";
            }
            if (body[key].is_string()) {
                return body[key].get<std::string>();
            }
            if (body[key].is_number_integer()) {
                return std::to_string(body[key].get<long long>());
            }
            return "";
        };
        std::string activate_after_epoch = read_optional_scalar("activate_after_epoch");
        std::string expire_after_epoch = read_optional_scalar("expire_after_epoch");
        std::string metadata_mode = body.value("metadata_mode", "");
        if (circle_id.empty() || content_type.empty() || ciphertext_b64.empty() || key_id.empty() || plaintext_hash.empty()) {
            res.status = 400;
            res.set_content(err_json("circle_id, content_type, ciphertext_b64, key_id, and plaintext_hash required").dump(), "application/json");
            return;
        }
        int locator_count = 0;
        if (!path.empty()) locator_count += 1;
        if (!slot_ref.empty()) locator_count += 1;
        if (!state_ref.empty()) locator_count += 1;
        if (locator_count != 1) {
            res.status = 400;
            res.set_content(err_json("provide exactly one of path, slot_ref, or state_ref").dump(), "application/json");
            return;
        }
        if (ciphertext_b64.size() > CIRCLE_ASSET_MAX_B64_BYTES) {
            res.status = 400;
            res.set_content(err_json("circle asset body exceeds max encoded size").dump(), "application/json");
            return;
        }
        const std::string default_ou = std::to_string(circle_asset_ou_from_b64_len(ciphertext_b64.size()));
        auto bi = get_nonce_balance();
        octra::Transaction tx;
        tx.from = g_wallet.addr;
        tx.to_ = circle_id;
        tx.amount = "0";
        tx.nonce = bi.nonce + 1;
        tx.ou = parse_ou(body, default_ou);
        tx.timestamp = now_ts();
        tx.op_type = "circle_asset_put_encrypted";
        tx.encrypted_data = ciphertext_b64;
        json payload;
        if (!path.empty()) payload["path"] = path;
        if (!slot_ref.empty()) payload["slot_ref"] = slot_ref;
        if (!state_ref.empty()) payload["state_ref"] = state_ref;
        payload["content_type"] = content_type;
        payload["key_id"] = key_id;
        payload["plaintext_hash"] = plaintext_hash;
        if (!encoding.empty()) payload["encoding"] = encoding;
        if (!padding_class.empty()) payload["padding_class"] = padding_class;
        if (!activate_after_epoch.empty()) payload["activate_after_epoch"] = activate_after_epoch;
        if (!expire_after_epoch.empty()) payload["expire_after_epoch"] = expire_after_epoch;
        if (!metadata_mode.empty()) payload["metadata_mode"] = metadata_mode;
        tx.message = payload.dump();
        sign_tx_fields(tx);
        auto result = submit_tx(tx);
        if (result.contains("error")) res.status = 500;
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/circle/asset_plain", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        res.set_header("Access-Control-Allow-Origin", "*");
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string circle_id = body.value("circle_id", "");
        std::string path = body.value("path", "");
        std::string content_type = body.value("content_type", "");
        std::string body_b64 = body.value("body_b64", "");
        std::string encoding = body.value("encoding", "");
        if (circle_id.empty() || path.empty() || content_type.empty() || body_b64.empty()) {
            res.status = 400;
            res.set_content(err_json("circle_id, path, content_type, and body_b64 required").dump(), "application/json");
            return;
        }
        if (body_b64.size() > CIRCLE_ASSET_MAX_B64_BYTES) {
            res.status = 400;
            res.set_content(err_json("circle asset body exceeds max encoded size").dump(), "application/json");
            return;
        }
        const std::string default_ou = std::to_string(circle_asset_ou_from_b64_len(body_b64.size()));
        auto bi = get_nonce_balance();
        octra::Transaction tx;
        tx.from = g_wallet.addr;
        tx.to_ = circle_id;
        tx.amount = "0";
        tx.nonce = bi.nonce + 1;
        tx.ou = parse_ou(body, default_ou);
        tx.timestamp = now_ts();
        tx.op_type = "circle_asset_put";
        tx.encrypted_data = body_b64;
        json payload;
        payload["path"] = path;
        payload["content_type"] = content_type;
        if (!encoding.empty()) payload["encoding"] = encoding;
        tx.message = payload.dump();
        sign_tx_fields(tx);
        auto result = submit_tx(tx);
        if (result.contains("error")) res.status = 500;
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/circle/sealed_slot_put", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        res.set_header("Access-Control-Allow-Origin", "*");
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string circle_id = body.value("circle_id", "");
        std::string slot_ref = body.value("slot_ref", "");
        std::string state_ref = body.value("state_ref", "");
        std::string content_type = body.value("content_type", "");
        std::string ciphertext_b64 = body.value("ciphertext_b64", "");
        std::string key_id = body.value("key_id", "");
        std::string plaintext_hash = body.value("plaintext_hash", "");
        std::string encoding = body.value("encoding", "");
        std::string padding_class = body.value("padding_class", "");
        auto read_optional_scalar = [&](const char* key) -> std::string {
            if (!body.contains(key)) {
                return "";
            }
            if (body[key].is_string()) {
                return body[key].get<std::string>();
            }
            if (body[key].is_number_integer()) {
                return std::to_string(body[key].get<long long>());
            }
            return "";
        };
        std::string activate_after_epoch = read_optional_scalar("activate_after_epoch");
        std::string expire_after_epoch = read_optional_scalar("expire_after_epoch");
        std::string metadata_mode = body.value("metadata_mode", "");
        if (circle_id.empty() || content_type.empty() || ciphertext_b64.empty() || key_id.empty() || plaintext_hash.empty()) {
            res.status = 400;
            res.set_content(err_json("circle_id, content_type, ciphertext_b64, key_id, and plaintext_hash required").dump(), "application/json");
            return;
        }
        if ((slot_ref.empty() && state_ref.empty()) || (!slot_ref.empty() && !state_ref.empty())) {
            res.status = 400;
            res.set_content(err_json("provide exactly one of slot_ref or state_ref").dump(), "application/json");
            return;
        }
        if (ciphertext_b64.size() > CIRCLE_ASSET_MAX_B64_BYTES) {
            res.status = 400;
            res.set_content(err_json("circle asset body exceeds max encoded size").dump(), "application/json");
            return;
        }
        const std::string default_ou = std::to_string(circle_asset_ou_from_b64_len(ciphertext_b64.size()));
        auto bi = get_nonce_balance();
        octra::Transaction tx;
        tx.from = g_wallet.addr;
        tx.to_ = circle_id;
        tx.amount = "0";
        tx.nonce = bi.nonce + 1;
        tx.ou = parse_ou(body, default_ou);
        tx.timestamp = now_ts();
        tx.op_type = "circle_sealed_slot_put";
        tx.encrypted_data = ciphertext_b64;
        json payload;
        if (!slot_ref.empty()) payload["slot_ref"] = slot_ref;
        if (!state_ref.empty()) payload["state_ref"] = state_ref;
        payload["content_type"] = content_type;
        payload["key_id"] = key_id;
        payload["plaintext_hash"] = plaintext_hash;
        if (!encoding.empty()) payload["encoding"] = encoding;
        if (!padding_class.empty()) payload["padding_class"] = padding_class;
        if (!activate_after_epoch.empty()) payload["activate_after_epoch"] = activate_after_epoch;
        if (!expire_after_epoch.empty()) payload["expire_after_epoch"] = expire_after_epoch;
        if (!metadata_mode.empty()) payload["metadata_mode"] = metadata_mode;
        tx.message = payload.dump();
        sign_tx_fields(tx);
        auto result = submit_tx(tx);
        if (result.contains("error")) res.status = 500;
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/circle/slot_policy_put", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        res.set_header("Access-Control-Allow-Origin", "*");
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string circle_id = body.value("circle_id", "");
        std::string slot_ref = body.value("slot_ref", "");
        std::string state_ref = body.value("state_ref", "");
        std::string delivery_key_id = body.value("delivery_key_id", "");
        auto read_optional_scalar = [&](const char* key) -> std::string {
            if (!body.contains(key)) {
                return "";
            }
            if (body[key].is_string()) {
                return body[key].get<std::string>();
            }
            if (body[key].is_number_integer()) {
                return std::to_string(body[key].get<long long>());
            }
            return "";
        };
        std::string activate_after_epoch = read_optional_scalar("activate_after_epoch");
        std::string expire_after_epoch = read_optional_scalar("expire_after_epoch");
        bool tombstone = body.value("tombstone", false);
        bool revoked = body.value("revoked", false);
        if (circle_id.empty()) {
            res.status = 400;
            res.set_content(err_json("circle_id required").dump(), "application/json");
            return;
        }
        if ((slot_ref.empty() && state_ref.empty()) || (!slot_ref.empty() && !state_ref.empty())) {
            res.status = 400;
            res.set_content(err_json("provide exactly one of slot_ref or state_ref").dump(), "application/json");
            return;
        }
        auto bi = get_nonce_balance();
        octra::Transaction tx;
        tx.from = g_wallet.addr;
        tx.to_ = circle_id;
        tx.amount = "0";
        tx.nonce = bi.nonce + 1;
        tx.ou = parse_ou(body, "1000");
        tx.timestamp = now_ts();
        tx.op_type = "circle_slot_policy_put";
        json payload;
        if (!slot_ref.empty()) payload["slot_ref"] = slot_ref;
        if (!state_ref.empty()) payload["state_ref"] = state_ref;
        if (!delivery_key_id.empty()) payload["delivery_key_id"] = delivery_key_id;
        if (!activate_after_epoch.empty()) payload["activate_after_epoch"] = activate_after_epoch;
        if (!expire_after_epoch.empty()) payload["expire_after_epoch"] = expire_after_epoch;
        if (tombstone) payload["tombstone"] = tombstone;
        if (revoked) payload["revoked"] = revoked;
        tx.message = payload.dump();
        sign_tx_fields(tx);
        auto result = submit_tx(tx);
        if (result.contains("error")) res.status = 500;
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/circle/state_descriptor_put", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        res.set_header("Access-Control-Allow-Origin", "*");
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string circle_id = body.value("circle_id", "");
        std::string state_ref = body.value("state_ref", "");
        if (circle_id.empty() || state_ref.empty()) {
            res.status = 400;
            res.set_content(err_json("circle_id and state_ref required").dump(), "application/json");
            return;
        }
        auto bi = get_nonce_balance();
        octra::Transaction tx;
        tx.from = g_wallet.addr;
        tx.to_ = circle_id;
        tx.amount = "0";
        tx.nonce = bi.nonce + 1;
        tx.ou = parse_ou(body, "1000");
        tx.timestamp = now_ts();
        tx.op_type = "circle_state_descriptor_put";
        json payload;
        payload["state_ref"] = state_ref;
        if (body.contains("state_class")) payload["state_class"] = body["state_class"];
        if (body.contains("codec")) payload["codec"] = body["codec"];
        if (body.contains("schema_hash")) payload["schema_hash"] = body["schema_hash"];
        if (body.contains("subject_addr")) payload["subject_addr"] = body["subject_addr"];
        if (body.contains("hfhe_profile")) payload["hfhe_profile"] = body["hfhe_profile"];
        if (body.contains("mutable_state")) payload["mutable_state"] = body["mutable_state"];
        tx.message = payload.dump();
        sign_tx_fields(tx);
        auto result = submit_tx(tx);
        if (result.contains("error")) res.status = 500;
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/circle/balance_cell_put", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        res.set_header("Access-Control-Allow-Origin", "*");
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string circle_id = body.value("circle_id", "");
        std::string state_ref = body.value("state_ref", "");
        std::string ciphertext_b64 = body.value("ciphertext_b64", "");
        std::string key_id = body.value("key_id", "");
        std::string plaintext_hash = body.value("plaintext_hash", "");
        std::string ciphertext_commitment = body.value("ciphertext_commitment", "");
        std::string amount_commitment = body.value("amount_commitment", "");
        if (circle_id.empty() || state_ref.empty() || ciphertext_b64.empty() || key_id.empty() || plaintext_hash.empty() || ciphertext_commitment.empty() || amount_commitment.empty()) {
            res.status = 400;
            res.set_content(err_json("circle_id, state_ref, ciphertext_b64, key_id, plaintext_hash, ciphertext_commitment, and amount_commitment required").dump(), "application/json");
            return;
        }
        if (ciphertext_b64.size() > CIRCLE_ASSET_MAX_B64_BYTES) {
            res.status = 400;
            res.set_content(err_json("circle asset body exceeds max encoded size").dump(), "application/json");
            return;
        }
        auto read_optional_scalar = [&](const char* key) -> std::string {
            if (!body.contains(key)) {
                return "";
            }
            if (body[key].is_string()) {
                return body[key].get<std::string>();
            }
            if (body[key].is_number_integer()) {
                return std::to_string(body[key].get<long long>());
            }
            return "";
        };
        std::string activate_after_epoch = read_optional_scalar("activate_after_epoch");
        std::string expire_after_epoch = read_optional_scalar("expire_after_epoch");
        const std::string default_ou = std::to_string(circle_asset_ou_from_b64_len(ciphertext_b64.size()));
        auto bi = get_nonce_balance();
        octra::Transaction tx;
        tx.from = g_wallet.addr;
        tx.to_ = circle_id;
        tx.amount = "0";
        tx.nonce = bi.nonce + 1;
        tx.ou = parse_ou(body, default_ou);
        tx.timestamp = now_ts();
        tx.op_type = "circle_balance_cell_put";
        tx.encrypted_data = ciphertext_b64;
        json payload;
        payload["state_ref"] = state_ref;
        payload["key_id"] = key_id;
        payload["plaintext_hash"] = plaintext_hash;
        payload["ciphertext_commitment"] = ciphertext_commitment;
        payload["amount_commitment"] = amount_commitment;
        if (body.contains("content_type")) payload["content_type"] = body["content_type"];
        if (body.contains("encoding")) payload["encoding"] = body["encoding"];
        if (body.contains("padding_class")) payload["padding_class"] = body["padding_class"];
        if (body.contains("delivery_key_id")) payload["delivery_key_id"] = body["delivery_key_id"];
        if (!activate_after_epoch.empty()) payload["activate_after_epoch"] = activate_after_epoch;
        if (!expire_after_epoch.empty()) payload["expire_after_epoch"] = expire_after_epoch;
        if (body.contains("metadata_mode")) payload["metadata_mode"] = body["metadata_mode"];
        if (body.contains("codec")) payload["codec"] = body["codec"];
        if (body.contains("schema_hash")) payload["schema_hash"] = body["schema_hash"];
        if (body.contains("subject_addr")) payload["subject_addr"] = body["subject_addr"];
        if (body.contains("mutable_state")) payload["mutable_state"] = body["mutable_state"];
        if (body.contains("hfhe_profile")) payload["hfhe_profile"] = body["hfhe_profile"];
        if (body.contains("proof_kind")) payload["proof_kind"] = body["proof_kind"];
        if (body.contains("proof_receipt_hash")) payload["proof_receipt_hash"] = body["proof_receipt_hash"];
        tx.message = payload.dump();
        sign_tx_fields(tx);
        auto result = submit_tx(tx);
        if (result.contains("error")) res.status = 500;
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/circle/register_cell_put", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        res.set_header("Access-Control-Allow-Origin", "*");
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string circle_id = body.value("circle_id", "");
        std::string state_ref = body.value("state_ref", "");
        std::string ciphertext_b64 = body.value("ciphertext_b64", "");
        std::string key_id = body.value("key_id", "");
        std::string plaintext_hash = body.value("plaintext_hash", "");
        std::string ciphertext_commitment = body.value("ciphertext_commitment", "");
        if (circle_id.empty() || state_ref.empty() || ciphertext_b64.empty() || key_id.empty() || plaintext_hash.empty() || ciphertext_commitment.empty()) {
            res.status = 400;
            res.set_content(err_json("circle_id, state_ref, ciphertext_b64, key_id, plaintext_hash, and ciphertext_commitment required").dump(), "application/json");
            return;
        }
        if (ciphertext_b64.size() > CIRCLE_ASSET_MAX_B64_BYTES) {
            res.status = 400;
            res.set_content(err_json("circle asset body exceeds max encoded size").dump(), "application/json");
            return;
        }
        auto read_optional_scalar = [&](const char* key) -> std::string {
            if (!body.contains(key)) {
                return "";
            }
            if (body[key].is_string()) {
                return body[key].get<std::string>();
            }
            if (body[key].is_number_integer()) {
                return std::to_string(body[key].get<long long>());
            }
            return "";
        };
        std::string activate_after_epoch = read_optional_scalar("activate_after_epoch");
        std::string expire_after_epoch = read_optional_scalar("expire_after_epoch");
        const std::string default_ou = std::to_string(circle_asset_ou_from_b64_len(ciphertext_b64.size()));
        auto bi = get_nonce_balance();
        octra::Transaction tx;
        tx.from = g_wallet.addr;
        tx.to_ = circle_id;
        tx.amount = "0";
        tx.nonce = bi.nonce + 1;
        tx.ou = parse_ou(body, default_ou);
        tx.timestamp = now_ts();
        tx.op_type = "circle_register_cell_put";
        tx.encrypted_data = ciphertext_b64;
        json payload;
        payload["state_ref"] = state_ref;
        payload["key_id"] = key_id;
        payload["plaintext_hash"] = plaintext_hash;
        payload["ciphertext_commitment"] = ciphertext_commitment;
        if (body.contains("content_type")) payload["content_type"] = body["content_type"];
        if (body.contains("encoding")) payload["encoding"] = body["encoding"];
        if (body.contains("padding_class")) payload["padding_class"] = body["padding_class"];
        if (body.contains("delivery_key_id")) payload["delivery_key_id"] = body["delivery_key_id"];
        if (!activate_after_epoch.empty()) payload["activate_after_epoch"] = activate_after_epoch;
        if (!expire_after_epoch.empty()) payload["expire_after_epoch"] = expire_after_epoch;
        if (body.contains("metadata_mode")) payload["metadata_mode"] = body["metadata_mode"];
        if (body.contains("codec")) payload["codec"] = body["codec"];
        if (body.contains("schema_hash")) payload["schema_hash"] = body["schema_hash"];
        if (body.contains("subject_addr")) payload["subject_addr"] = body["subject_addr"];
        if (body.contains("mutable_state")) payload["mutable_state"] = body["mutable_state"];
        if (body.contains("hfhe_profile")) payload["hfhe_profile"] = body["hfhe_profile"];
        if (body.contains("proof_kind")) payload["proof_kind"] = body["proof_kind"];
        if (body.contains("proof_receipt_hash")) payload["proof_receipt_hash"] = body["proof_receipt_hash"];
        tx.message = payload.dump();
        sign_tx_fields(tx);
        auto result = submit_tx(tx);
        if (result.contains("error")) res.status = 500;
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/circle/transport_policy_put", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        res.set_header("Access-Control-Allow-Origin", "*");
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string circle_id = body.value("circle_id", "");
        if (circle_id.empty()) {
            res.status = 400;
            res.set_content(err_json("circle_id required").dump(), "application/json");
            return;
        }
        json payload = json::object();
        if (body.contains("relay_mode")) payload["relay_mode"] = body["relay_mode"];
        if (body.contains("lease_class")) payload["lease_class"] = body["lease_class"];
        if (body.contains("claim_strategy")) payload["claim_strategy"] = body["claim_strategy"];
        if (body.contains("claim_topology")) payload["claim_topology"] = body["claim_topology"];
        if (body.contains("quorum_mode")) payload["quorum_mode"] = body["quorum_mode"];
        if (body.contains("ingress_strategy")) payload["ingress_strategy"] = body["ingress_strategy"];
        if (body.contains("quorum_threshold")) payload["quorum_threshold"] = body["quorum_threshold"];
        if (body.contains("quorum_weight_threshold")) payload["quorum_weight_threshold"] = body["quorum_weight_threshold"];
        if (body.contains("max_active_claims")) payload["max_active_claims"] = body["max_active_claims"];
        if (body.contains("relay_allowlist")) payload["relay_allowlist"] = body["relay_allowlist"];
        if (body.contains("relay_weights")) payload["relay_weights"] = body["relay_weights"];
        if (body.contains("max_claim_window_epochs")) payload["max_claim_window_epochs"] = body["max_claim_window_epochs"];
        if (body.contains("max_response_bytes")) payload["max_response_bytes"] = body["max_response_bytes"];
        if (body.contains("require_response_ciphertext")) payload["require_response_ciphertext"] = body["require_response_ciphertext"];
        if (body.contains("require_external_receipt")) payload["require_external_receipt"] = body["require_external_receipt"];
        if (body.contains("accepted_result_codes")) payload["accepted_result_codes"] = body["accepted_result_codes"];
        auto bi = get_nonce_balance();
        octra::Transaction tx;
        tx.from = g_wallet.addr;
        tx.to_ = circle_id;
        tx.amount = "0";
        tx.nonce = bi.nonce + 1;
        tx.ou = parse_ou(body, "1000");
        tx.timestamp = now_ts();
        tx.op_type = "circle_transport_policy_put";
        tx.message = payload.dump();
        sign_tx_fields(tx);
        auto result = submit_tx(tx);
        if (result.contains("error")) res.status = 500;
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/circle/hfhe_policy_put", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        res.set_header("Access-Control-Allow-Origin", "*");
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string circle_id = body.value("circle_id", "");
        if (circle_id.empty()) {
            res.status = 400;
            res.set_content(err_json("circle_id required").dump(), "application/json");
            return;
        }
        json payload = json::object();
        if (body.contains("load_pk_mode")) payload["load_pk_mode"] = body["load_pk_mode"];
        if (body.contains("encrypt_mode")) payload["encrypt_mode"] = body["encrypt_mode"];
        if (body.contains("decrypt_mode")) payload["decrypt_mode"] = body["decrypt_mode"];
        if (body.contains("cipher_arithmetic_mode")) payload["cipher_arithmetic_mode"] = body["cipher_arithmetic_mode"];
        if (body.contains("commit_mode")) payload["commit_mode"] = body["commit_mode"];
        if (body.contains("pedersen_mode")) payload["pedersen_mode"] = body["pedersen_mode"];
        if (body.contains("cipher_serde_mode")) payload["cipher_serde_mode"] = body["cipher_serde_mode"];
        if (body.contains("pubkey_serde_mode")) payload["pubkey_serde_mode"] = body["pubkey_serde_mode"];
        if (body.contains("verify_zero_mode")) payload["verify_zero_mode"] = body["verify_zero_mode"];
        if (body.contains("verify_range_mode")) payload["verify_range_mode"] = body["verify_range_mode"];
        if (body.contains("verify_bound_mode")) payload["verify_bound_mode"] = body["verify_bound_mode"];
        if (body.contains("proof_receipt_signer_mode")) payload["proof_receipt_signer_mode"] = body["proof_receipt_signer_mode"];
        if (body.contains("proof_receipt_class")) payload["proof_receipt_class"] = body["proof_receipt_class"];
        if (body.contains("pk_allowlist")) payload["pk_allowlist"] = body["pk_allowlist"];
        if (body.contains("require_live_key_policy")) payload["require_live_key_policy"] = body["require_live_key_policy"];
        if (body.contains("require_receipt_transport_binding")) payload["require_receipt_transport_binding"] = body["require_receipt_transport_binding"];
        if (body.contains("encrypt_proof")) payload["encrypt_proof"] = body["encrypt_proof"];
        if (body.contains("decrypt_proof")) payload["decrypt_proof"] = body["decrypt_proof"];
        auto bi = get_nonce_balance();
        octra::Transaction tx;
        tx.from = g_wallet.addr;
        tx.to_ = circle_id;
        tx.amount = "0";
        tx.nonce = bi.nonce + 1;
        tx.ou = parse_ou(body, "1000");
        tx.timestamp = now_ts();
        tx.op_type = "circle_hfhe_policy_put";
        tx.message = payload.dump();
        sign_tx_fields(tx);
        auto result = submit_tx(tx);
        if (result.contains("error")) res.status = 500;
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/circle/key_grant", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        res.set_header("Access-Control-Allow-Origin", "*");
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string circle_id = body.value("circle_id", "");
        std::string key_id = body.value("key_id", "");
        if (circle_id.empty() || key_id.empty()) {
            res.status = 400;
            res.set_content(err_json("circle_id and key_id required").dump(), "application/json");
            return;
        }
        json payload = json::object();
        payload["key_id"] = key_id;
        if (body.contains("activate_after_epoch")) payload["activate_after_epoch"] = body["activate_after_epoch"];
        if (body.contains("expire_after_epoch")) payload["expire_after_epoch"] = body["expire_after_epoch"];
        auto bi = get_nonce_balance();
        octra::Transaction tx;
        tx.from = g_wallet.addr;
        tx.to_ = circle_id;
        tx.amount = "0";
        tx.nonce = bi.nonce + 1;
        tx.ou = parse_ou(body, "1000");
        tx.timestamp = now_ts();
        tx.op_type = "circle_key_grant";
        tx.message = payload.dump();
        sign_tx_fields(tx);
        auto result = submit_tx(tx);
        if (result.contains("error")) res.status = 500;
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/circle/key_extend", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        res.set_header("Access-Control-Allow-Origin", "*");
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string circle_id = body.value("circle_id", "");
        std::string key_id = body.value("key_id", "");
        if (circle_id.empty() || key_id.empty() || !body.contains("expire_after_epoch")) {
            res.status = 400;
            res.set_content(err_json("circle_id, key_id, and expire_after_epoch required").dump(), "application/json");
            return;
        }
        json payload = json::object();
        payload["key_id"] = key_id;
        payload["expire_after_epoch"] = body["expire_after_epoch"];
        auto bi = get_nonce_balance();
        octra::Transaction tx;
        tx.from = g_wallet.addr;
        tx.to_ = circle_id;
        tx.amount = "0";
        tx.nonce = bi.nonce + 1;
        tx.ou = parse_ou(body, "1000");
        tx.timestamp = now_ts();
        tx.op_type = "circle_key_extend";
        tx.message = payload.dump();
        sign_tx_fields(tx);
        auto result = submit_tx(tx);
        if (result.contains("error")) res.status = 500;
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/circle/key_revoke", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        res.set_header("Access-Control-Allow-Origin", "*");
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string circle_id = body.value("circle_id", "");
        std::string key_id = body.value("key_id", "");
        if (circle_id.empty() || key_id.empty()) {
            res.status = 400;
            res.set_content(err_json("circle_id and key_id required").dump(), "application/json");
            return;
        }
        json payload = json::object();
        payload["key_id"] = key_id;
        auto bi = get_nonce_balance();
        octra::Transaction tx;
        tx.from = g_wallet.addr;
        tx.to_ = circle_id;
        tx.amount = "0";
        tx.nonce = bi.nonce + 1;
        tx.ou = parse_ou(body, "1000");
        tx.timestamp = now_ts();
        tx.op_type = "circle_key_revoke";
        tx.message = payload.dump();
        sign_tx_fields(tx);
        auto result = submit_tx(tx);
        if (result.contains("error")) res.status = 500;
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/circle/key_erase", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        res.set_header("Access-Control-Allow-Origin", "*");
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string circle_id = body.value("circle_id", "");
        std::string key_id = body.value("key_id", "");
        if (circle_id.empty() || key_id.empty()) {
            res.status = 400;
            res.set_content(err_json("circle_id and key_id required").dump(), "application/json");
            return;
        }
        json payload = json::object();
        payload["key_id"] = key_id;
        auto bi = get_nonce_balance();
        octra::Transaction tx;
        tx.from = g_wallet.addr;
        tx.to_ = circle_id;
        tx.amount = "0";
        tx.nonce = bi.nonce + 1;
        tx.ou = parse_ou(body, "1000");
        tx.timestamp = now_ts();
        tx.op_type = "circle_key_erase";
        tx.message = payload.dump();
        sign_tx_fields(tx);
        auto result = submit_tx(tx);
        if (result.contains("error")) res.status = 500;
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/circle/key_policy_put", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        res.set_header("Access-Control-Allow-Origin", "*");
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string circle_id = body.value("circle_id", "");
        std::string key_id = body.value("key_id", "");
        if (circle_id.empty() || key_id.empty()) {
            res.status = 400;
            res.set_content(err_json("circle_id and key_id required").dump(), "application/json");
            return;
        }
        json payload = json::object();
        payload["key_id"] = key_id;
        if (body.contains("activate_after_epoch")) payload["activate_after_epoch"] = body["activate_after_epoch"];
        if (body.contains("expire_after_epoch")) payload["expire_after_epoch"] = body["expire_after_epoch"];
        payload["revoked"] = body.value("revoked", false);
        payload["erased"] = body.value("erased", false);
        auto bi = get_nonce_balance();
        octra::Transaction tx;
        tx.from = g_wallet.addr;
        tx.to_ = circle_id;
        tx.amount = "0";
        tx.nonce = bi.nonce + 1;
        tx.ou = parse_ou(body, "1000");
        tx.timestamp = now_ts();
        tx.op_type = "circle_key_policy_put";
        tx.message = payload.dump();
        sign_tx_fields(tx);
        auto result = submit_tx(tx);
        if (result.contains("error")) res.status = 500;
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/circle/relay_claim", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        res.set_header("Access-Control-Allow-Origin", "*");
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string circle_id = body.value("circle_id", "");
        std::string intent_id = body.value("intent_id", "");
        std::string claim_epoch;
        std::string claim_expiry_epoch;
        if (body.contains("claim_epoch")) {
            claim_epoch = body["claim_epoch"].is_string()
              ? body["claim_epoch"].get<std::string>()
              : std::to_string(body["claim_epoch"].get<long long>());
        }
        if (body.contains("claim_expiry_epoch")) {
            claim_expiry_epoch = body["claim_expiry_epoch"].is_string()
              ? body["claim_expiry_epoch"].get<std::string>()
              : std::to_string(body["claim_expiry_epoch"].get<long long>());
        }
        if (circle_id.empty() || intent_id.empty() || claim_epoch.empty() || claim_expiry_epoch.empty()) {
            res.status = 400;
            res.set_content(err_json("circle_id, intent_id, claim_epoch, and claim_expiry_epoch required").dump(), "application/json");
            return;
        }
        const std::string subject =
            "octra_circle_relay_claim|" + circle_id + "|" + intent_id + "|" +
            g_wallet.addr + "|" + claim_epoch + "|" + claim_expiry_epoch;
        const std::string signature = octra::ed25519_sign_detached(
            reinterpret_cast<const uint8_t*>(subject.data()),
            subject.size(),
            g_wallet.sk);
        json payload;
        payload["intent_id"] = intent_id;
        payload["relay_id"] = g_wallet.addr;
        payload["claim_epoch"] = claim_epoch;
        payload["claim_expiry_epoch"] = claim_expiry_epoch;
        payload["signature"] = signature;
        auto bi = get_nonce_balance();
        octra::Transaction tx;
        tx.from = g_wallet.addr;
        tx.to_ = circle_id;
        tx.amount = "0";
        tx.nonce = bi.nonce + 1;
        tx.ou = parse_ou(body, "2000");
        tx.timestamp = now_ts();
        tx.op_type = "circle_relay_claim";
        tx.message = payload.dump();
        sign_tx_fields(tx);
        auto result = submit_tx(tx);
        if (result.contains("error")) res.status = 500;
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/circle/relay_cancel", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        res.set_header("Access-Control-Allow-Origin", "*");
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string circle_id = body.value("circle_id", "");
        std::string intent_id = body.value("intent_id", "");
        std::string related_key_id = body.value("related_key_id", "");
        std::string cancel_epoch;
        if (body.contains("cancel_epoch")) {
            cancel_epoch = body["cancel_epoch"].is_string()
              ? body["cancel_epoch"].get<std::string>()
              : std::to_string(body["cancel_epoch"].get<long long>());
        }
        std::string reason = body.value("reason", "relay_cancelled");
        const std::array<std::string, 9> allowed_reasons = {
            "relay_cancelled",
            "owner_cancelled",
            "intent_expired",
            "claim_expired",
            "claim_set_exhausted",
            "delivery_key_inactive",
            "delivery_key_expired",
            "delivery_key_revoked",
            "delivery_key_erased"
        };
        if (circle_id.empty() || intent_id.empty() || cancel_epoch.empty()) {
            res.status = 400;
            res.set_content(err_json("circle_id, intent_id, and cancel_epoch required").dump(), "application/json");
            return;
        }
        if (std::find(allowed_reasons.begin(), allowed_reasons.end(), reason) == allowed_reasons.end()) {
            res.status = 400;
            res.set_content(err_json("invalid relay cancel reason").dump(), "application/json");
            return;
        }
        const std::string subject =
            "octra_circle_relay_cancel|" + circle_id + "|" + intent_id + "|" +
            g_wallet.addr + "|" + cancel_epoch + "|" + reason + "|" + related_key_id;
        const std::string signature = octra::ed25519_sign_detached(
            reinterpret_cast<const uint8_t*>(subject.data()),
            subject.size(),
            g_wallet.sk);
        json payload;
        payload["intent_id"] = intent_id;
        payload["relay_id"] = g_wallet.addr;
        payload["cancel_epoch"] = cancel_epoch;
        payload["reason"] = reason;
        payload["signature"] = signature;
        if (!related_key_id.empty()) payload["related_key_id"] = related_key_id;
        auto bi = get_nonce_balance();
        octra::Transaction tx;
        tx.from = g_wallet.addr;
        tx.to_ = circle_id;
        tx.amount = "0";
        tx.nonce = bi.nonce + 1;
        tx.ou = parse_ou(body, "2000");
        tx.timestamp = now_ts();
        tx.op_type = "circle_relay_cancel";
        tx.message = payload.dump();
        sign_tx_fields(tx);
        auto result = submit_tx(tx);
        if (result.contains("error")) res.status = 500;
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/circle/outbox_open", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        res.set_header("Access-Control-Allow-Origin", "*");
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string circle_id = body.value("circle_id", "");
        std::string intent_id = body.value("intent_id", "");
        std::string relay_policy_hash = body.value("relay_policy_hash", "");
        std::string payload_hash = body.value("payload_hash", "");
        std::string ciphertext_blob_hash = body.value("ciphertext_blob_hash", "");
        std::string delivery_key_id = body.value("delivery_key_id", "");
        std::string route_hint = body.value("route_hint", "");
        std::string callback_policy_hash = body.value("callback_policy_hash", "");
        auto read_required_scalar = [&](const char* key) -> std::string {
            if (!body.contains(key)) {
                return "";
            }
            if (body[key].is_string()) {
                return body[key].get<std::string>();
            }
            if (body[key].is_number_integer()) {
                return std::to_string(body[key].get<long long>());
            }
            return "";
        };
        std::string expiry_epoch = read_required_scalar("expiry_epoch");
        std::string max_response_bytes = read_required_scalar("max_response_bytes");
        std::string fee_budget = read_required_scalar("fee_budget");
        if (circle_id.empty() || intent_id.empty() || expiry_epoch.empty() || relay_policy_hash.empty() || payload_hash.empty() || max_response_bytes.empty() || fee_budget.empty()) {
            res.status = 400;
            res.set_content(err_json("circle_id, intent_id, expiry_epoch, relay_policy_hash, payload_hash, max_response_bytes, and fee_budget required").dump(), "application/json");
            return;
        }
        auto bi = get_nonce_balance();
        octra::Transaction tx;
        tx.from = g_wallet.addr;
        tx.to_ = circle_id;
        tx.amount = "0";
        tx.nonce = bi.nonce + 1;
        tx.ou = parse_ou(body, "3000");
        tx.timestamp = now_ts();
        tx.op_type = "circle_outbox_open";
        json payload;
        payload["intent_id"] = intent_id;
        payload["expiry_epoch"] = expiry_epoch;
        payload["relay_policy_hash"] = relay_policy_hash;
        payload["payload_hash"] = payload_hash;
        payload["max_response_bytes"] = max_response_bytes;
        payload["fee_budget"] = fee_budget;
        if (!ciphertext_blob_hash.empty()) payload["ciphertext_blob_hash"] = ciphertext_blob_hash;
        if (!delivery_key_id.empty()) payload["delivery_key_id"] = delivery_key_id;
        if (!route_hint.empty()) payload["route_hint"] = route_hint;
        if (!callback_policy_hash.empty()) payload["callback_policy_hash"] = callback_policy_hash;
        tx.message = payload.dump();
        sign_tx_fields(tx);
        auto result = submit_tx(tx);
        if (result.contains("error")) res.status = 500;
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/circle/ingress_commit", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        res.set_header("Access-Control-Allow-Origin", "*");
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string circle_id = body.value("circle_id", "");
        std::string intent_id = body.value("intent_id", "");
        std::string relay_id = body.value("relay_id", "");
        std::string response_payload_hash = body.value("response_payload_hash", "");
        std::string response_ciphertext_blob_hash = body.value("response_ciphertext_blob_hash", "");
        std::string external_receipt_hash = body.value("external_receipt_hash", "");
        std::string signature = body.value("signature", "");
        auto read_required_scalar = [&](const char* key) -> std::string {
            if (!body.contains(key)) {
                return "";
            }
            if (body[key].is_string()) {
                return body[key].get<std::string>();
            }
            if (body[key].is_number_integer()) {
                return std::to_string(body[key].get<long long>());
            }
            return "";
        };
        std::string ingress_nonce = read_required_scalar("ingress_nonce");
        std::string response_size_bytes = read_required_scalar("response_size_bytes");
        int result_code = body.value("result_code", 0);
        if (circle_id.empty() || intent_id.empty() || relay_id.empty() || ingress_nonce.empty() || response_payload_hash.empty() || response_size_bytes.empty() || signature.empty()) {
            res.status = 400;
            res.set_content(err_json("circle_id, intent_id, relay_id, ingress_nonce, response_payload_hash, response_size_bytes, and signature required").dump(), "application/json");
            return;
        }
        auto bi = get_nonce_balance();
        octra::Transaction tx;
        tx.from = g_wallet.addr;
        tx.to_ = circle_id;
        tx.amount = "0";
        tx.nonce = bi.nonce + 1;
        tx.ou = parse_ou(body, "3000");
        tx.timestamp = now_ts();
        tx.op_type = "circle_ingress_commit";
        json payload;
        payload["intent_id"] = intent_id;
        payload["relay_id"] = relay_id;
        payload["ingress_nonce"] = ingress_nonce;
        payload["result_code"] = result_code;
        payload["response_payload_hash"] = response_payload_hash;
        payload["response_size_bytes"] = response_size_bytes;
        payload["signature"] = signature;
        if (!response_ciphertext_blob_hash.empty()) payload["response_ciphertext_blob_hash"] = response_ciphertext_blob_hash;
        if (!external_receipt_hash.empty()) payload["external_receipt_hash"] = external_receipt_hash;
        tx.message = payload.dump();
        sign_tx_fields(tx);
        auto result = submit_tx(tx);
        if (result.contains("error")) res.status = 500;
        res.set_content(result.dump(), "application/json");
    });

    svr.Get(R"(/oct/([^/]+)(/.*)?)", [](const httplib::Request& req, httplib::Response& res) {
        std::string circle_id = req.matches.size() > 1 ? req.matches[1].str() : "";
        std::string raw_path = req.matches.size() > 2 ? req.matches[2].str() : "";
        std::string path = raw_path.empty() ? "/index.html" : raw_path;
        if (circle_id.empty()) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json("circle_id required").dump(), "application/json");
            return;
        }
        octra::RpcClient rpc(current_public_rpc_url());
        auto r = rpc.circle_asset(circle_id, path);
        if (!r.ok) {
            res.status = 404;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        auto content_type = r.result.value("content_type", "application/octet-stream");
        auto body_b64 = r.result.value("body_b64", "");
        auto raw = octra::base64_decode(body_b64);
        std::string body(raw.begin(), raw.end());
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Cache-Control", "no-store");
        res.set_header("X-Content-Type-Options", "nosniff");
        res.set_content(body, content_type.c_str());
    });

    svr.Get("/api/contract/receipt", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string hash = req.get_param_value("hash");
        if (hash.empty()) {
            res.status = 400;
            res.set_content(err_json("hash required").dump(), "application/json");
            return;
        }
        auto r = g_rpc.contract_receipt(hash);
        if (!r.ok) {
            res.status = 404;
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_content(r.result.dump(), "application/json");
    });

    static json g_token_cache;
    static double g_token_cache_ts = 0;
    static std::string g_token_cache_addr;

    svr.Get("/api/tokens", [](const httplib::Request&, httplib::Response& res) {
        WALLET_GUARD
        double now = (double)time(nullptr);
        if (!g_token_cache.empty() && g_token_cache_addr == g_wallet.addr
            && (now - g_token_cache_ts) < 30.0) {
            res.set_content(g_token_cache.dump(), "application/json");
            return;
        }
        auto fast = g_rpc.tokens_by_address(g_wallet.addr);
        if (fast.ok && fast.result.contains("tokens")) {
            g_token_cache = fast.result;
            g_token_cache_ts = now;
            g_token_cache_addr = g_wallet.addr;
            res.set_content(fast.result.dump(), "application/json");
            return;
        }
        auto lr = g_rpc.list_contracts();
        json tokens = json::array();
        if (lr.ok && lr.result.contains("contracts")) {
            auto& contracts = lr.result["contracts"];
            for (auto& c : contracts) {
                std::string addr = c.value("address", "");
                if (addr.empty()) continue;
                auto sr = g_rpc.contract_storage(addr, "symbol");
                if (!sr.ok || !sr.result.contains("value") || sr.result["value"].is_null()) continue;
                std::string sym = sr.result.value("value", "");
                if (sym.empty() || sym == "0") continue;
                if (sym.size() > 10) sym = sym.substr(0, 10);
                auto br = g_rpc.contract_call_view(addr, "balance_of",
                    json::array({g_wallet.addr}), g_wallet.addr);
                std::string bal = (br.ok && br.result.contains("result") && !br.result["result"].is_null())
                    ? br.result.value("result", "0") : "0";
                if (bal == "0" || bal.empty()) continue;
                auto nr = g_rpc.contract_storage(addr, "name");
                std::string name = (nr.ok && nr.result.contains("value") && !nr.result["value"].is_null())
                    ? nr.result.value("value", "") : sym;
                if (name.size() > 32) name = name.substr(0, 32);
                auto tr = g_rpc.contract_storage(addr, "total_supply");
                std::string supply = (tr.ok && tr.result.contains("value") && !tr.result["value"].is_null())
                    ? tr.result.value("value", "0") : "0";
                auto dr = g_rpc.contract_storage(addr, "decimals");
                std::string decimals = (dr.ok && dr.result.contains("value") && !dr.result["value"].is_null())
                    ? dr.result.value("value", "0") : "0";
                json tok;
                tok["address"] = addr;
                tok["name"] = name;
                tok["symbol"] = sym;
                tok["total_supply"] = supply;
                tok["balance"] = bal;
                tok["decimals"] = decimals;
                tok["owner"] = c.value("owner", "");
                tokens.push_back(tok);
            }
        }
        json j;
        j["tokens"] = tokens;
        j["count"] = tokens.size();
        j["wallet_address"] = g_wallet.addr;
        g_token_cache = j;
        g_token_cache_ts = now;
        g_token_cache_addr = g_wallet.addr;
        res.set_content(j.dump(), "application/json");
    });

    svr.Post("/api/token/transfer", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string token = body.value("token", "");
        std::string to = body.value("to", "");
        std::string amount_str = body.value("amount", "");
        if (token.empty() || to.empty() || amount_str.empty()) {
            res.status = 400;
            res.set_content(err_json("token, to, and amount required").dump(), "application/json");
            return;
        }
        long long amount_val = 0;
        try { amount_val = std::stoll(amount_str); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid amount").dump(), "application/json");
            return;
        }
        if (amount_val <= 0) {
            res.status = 400;
            res.set_content(err_json("amount must be positive").dump(), "application/json");
            return;
        }
        auto bi = get_nonce_balance();
        int nonce = bi.nonce;
        octra::Transaction tx;
        tx.from = g_wallet.addr;
        tx.to_ = token;
        tx.amount = "0";
        tx.nonce = nonce + 1;
        tx.ou = parse_ou(body, "1000");
        tx.timestamp = now_ts();
        tx.op_type = "call";
        tx.encrypted_data = "transfer";
        json params = json::array({to, amount_val});
        tx.message = params.dump();
        sign_tx_fields(tx);
        auto result = submit_tx(tx);
        if (result.contains("error")) res.status = 500;
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/settings", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string new_rpc = body.value("rpc_url", "");
        std::string new_explorer = body.value("explorer_url", "");
        std::string new_bridge_signer = body.value("bridge_signer_url", "");
        if (new_rpc.empty()) {
            res.status = 400;
            res.set_content(err_json("rpc_url required").dump(), "application/json");
            return;
        }
        bool cache_cleared = false;
        try {
            std::string old_rpc = g_wallet.rpc_url;
            if (!new_explorer.empty()) g_wallet.explorer_url = new_explorer;
            g_wallet.bridge_signer_url = new_bridge_signer;
            octra::save_settings(g_wallet_path, g_wallet, new_rpc, g_pin);
            g_rpc.set_url(g_wallet.rpc_url);
            if (old_rpc != g_wallet.rpc_url) {
                g_txcache.clear();
                g_txcache.put("meta:rpc_url", g_wallet.rpc_url);
                history_runtime_clear_all();
                token_history_runtime_clear_all();
                cache_cleared = true;
                fprintf(stderr, "txcache cleared: rpc changed %s -> %s\n",
                        old_rpc.c_str(), g_wallet.rpc_url.c_str());
            }
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(err_json(e.what()).dump(), "application/json");
            return;
        }
        json j;
        j["ok"] = true;
        j["rpc_url"] = g_wallet.rpc_url;
        j["explorer_url"] = g_wallet.explorer_url;
        j["bridge_signer_url"] = g_wallet.bridge_signer_url;
        j["cache_cleared"] = cache_cleared;
        res.set_content(j.dump(), "application/json");
    });

    svr.Post("/api/wallet/change-pin", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string cur_pin = body.value("current_pin", "");
        std::string new_pin = body.value("new_pin", "");
        if (cur_pin.size() != 6 || !std::all_of(cur_pin.begin(), cur_pin.end(), ::isdigit)) {
            res.status = 400;
            res.set_content(err_json("current PIN must be 6 digits").dump(), "application/json");
            return;
        }
        if (new_pin.size() != 6 || !std::all_of(new_pin.begin(), new_pin.end(), ::isdigit)) {
            res.status = 400;
            res.set_content(err_json("new PIN must be 6 digits").dump(), "application/json");
            return;
        }
        if (cur_pin != g_pin) {
            res.status = 403;
            res.set_content(err_json("wrong current PIN").dump(), "application/json");
            return;
        }
        try {
            octra::save_wallet_encrypted(g_wallet_path, g_wallet, new_pin);
            octra::secure_zero(&g_pin[0], g_pin.size());
            g_pin = new_pin;
            octra::try_mlock(&g_pin[0], g_pin.size());
            fprintf(stderr, "PIN changed\n");
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(err_json(e.what()).dump(), "application/json");
            return;
        }
        json j;
        j["ok"] = true;
        res.set_content(j.dump(), "application/json");
    });

    std::thread pvac_bg([&]() {
        std::this_thread::sleep_for(std::chrono::seconds(10));
        while (true) {
            try {
                if (g_wallet_loaded && g_pvac_ok) {
                    auto entries = octra::load_manifest();
                    for (auto& e : entries) {
                        if (e.addr.empty() || e.file.empty()) continue;
                        auto ar = g_rpc.get_account(e.addr);
                        if (!ar.ok) continue;
                        try {
                            auto w = octra::load_wallet_encrypted(e.file, g_pin);
                            ensure_pubkey_registered(w.addr, w.sk, w.pub_b64);
                            auto pr = g_rpc.get_pvac_pubkey(e.addr);
                            bool pvac_ok = pr.ok && pr.result.is_object() && !pr.result["pvac_pubkey"].is_null()
                                && pr.result["pvac_pubkey"].is_string() && !pr.result["pvac_pubkey"].get<std::string>().empty();
                            if (!pvac_ok) {
                                octra::PvacBridge tmp_pvac;
                                if (tmp_pvac.init(w.priv_b64)) {
                                    auto pk_raw = tmp_pvac.serialize_pubkey();
                                    std::string pk_blob(pk_raw.begin(), pk_raw.end());
                                    std::string pk_b64 = tmp_pvac.serialize_pubkey_b64();
                                    std::string reg_sig = octra::sign_register_request(w.addr, pk_blob, w.sk);
                                    std::string kat = compute_aes_kat_hex();
                                    auto rr = g_rpc.register_pvac_pubkey(w.addr, pk_b64, reg_sig, w.pub_b64, kat);
                                    if (rr.ok) fprintf(stderr, "[bg] pvac registered %s\n", w.addr.c_str());
                                    else fprintf(stderr, "[bg] pvac failed %s: %s\n", w.addr.c_str(), rr.error.c_str());
                                }
                            }
                            octra::secure_zero(w.sk, 64);
                        } catch (...) {}
                    }
                }
            } catch (...) {}
            std::this_thread::sleep_for(std::chrono::seconds(60));
        }
    });
    pvac_bg.detach();

    printf("octra_wallet listening on http://127.0.0.1:%d\n", port);
    svr.listen("127.0.0.1", port);
    return 0;
}