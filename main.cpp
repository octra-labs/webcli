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

static std::unordered_map<std::string, std::vector<uint8_t>> g_pk_cache;
static std::mutex g_pk_mtx;

static std::optional<std::vector<uint8_t>> pk_cache_get(const std::string& addr) {
    std::lock_guard<std::mutex> lk(g_pk_mtx);
    auto it = g_pk_cache.find(addr);
    if (it == g_pk_cache.end()) return std::nullopt;
    return it->second;
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

static std::string parse_ou(const json& body, const std::string& fallback) {
    std::string val = body.value("ou", "");
    if (val.empty()) return fallback;
    try {
        long long v = std::stoll(val);
        if (v > 0) return val;
    } catch (...) {}
    return fallback;
}

static const int64_t MAX_OCT_RAW = 1000000000LL * 1000000LL;

static int64_t parse_amount_raw(const json& body) {
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
    res["tx_hash"] = r.result.value("tx_hash", "");
    return res;
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
    g_rpc.set_url(g_wallet.rpc_url);
    ensure_pubkey_registered(g_wallet.addr, g_wallet.sk, g_wallet.pub_b64);
    g_pvac_ok = g_pvac.init(g_wallet.priv_b64);
    if (g_pvac_ok) {
        fprintf(stderr, "pvac initialized\n");
        ensure_pvac_registered();
    } else {
        fprintf(stderr, "pvac init failed (libpvac not loaded?)\n");
    }
    g_txcache.close();
    std::string cache_path = "data/txcache_" + g_wallet.addr.substr(3, 8);
    if (g_txcache.open(cache_path)) {
        fprintf(stderr, "txcache opened: %s\n", cache_path.c_str());
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


    //
    svr.set_keep_alive_timeout(5);
    svr.set_keep_alive_max_count(100);
    //

    svr.set_post_routing_handler([](const httplib::Request&, httplib::Response& res) {
        res.set_header("X-Frame-Options", "DENY");
        res.set_header("X-Content-Type-Options", "nosniff");
        res.set_header("Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "connect-src 'self' http://127.0.0.1:* http://178.62.60.204:8090 https://*.octra.network https://*.publicnode.com https://*.infura.io wss: ws:; "
            "frame-ancestors 'none'");
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
            if (res.status == 404) {
                j["error"] = "unknown endpoint: " + req.method + " " + req.path;
            } else {
                j["error"] = "internal error on: " + req.method + " " + req.path +
                             " (status " + std::to_string(res.status) + ")";
                auto it = res.headers.find("EXCEPTION_WHAT");
                if (it != res.headers.end()) {
                    j["detail"] = it->second;
                }
            }
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
            fprintf(stderr, "wallet created: %s → %s\n", g_wallet.addr.c_str(), g_wallet_path.c_str());
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
        res.set_content(j.dump(), "application/json");
    });

    svr.Get("/api/history", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        int limit = 20, offset = 0;
        if (req.has_param("limit")) limit = std::stoi(req.get_param_value("limit"));
        if (req.has_param("offset")) offset = std::stoi(req.get_param_value("offset"));

        auto convert_row = [](const json& row, const std::string& status) -> json {
            json tx;
            tx["hash"] = row.value("hash", "");
            tx["from"] = row.value("from", "");
            tx["to_"] = row.value("to", row.value("to_", ""));
            tx["amount_raw"] = row.value("amount", row.value("amount_raw", "0"));
            tx["op_type"] = row.value("op_type", "standard");
            tx["status"] = status;
            if (row.contains("timestamp")) tx["timestamp"] = row["timestamp"];
            if (row.contains("encrypted_data") && row["encrypted_data"].is_string())
                tx["encrypted_data"] = row["encrypted_data"];
            if (row.contains("message") && row["message"].is_string())
                tx["message"] = row["message"];
            if (row.contains("reason") && row["reason"].is_string())
                tx["reject_reason"] = row["reason"];
            return tx;
        };

        json txs = json::array();

        if (g_txcache.is_open()) {
            auto r = g_rpc.get_txs_by_address(g_wallet.addr, 1, 0);
            int node_total = 0;
            json rejected_buf = json::array();
            if (r.ok && r.result.is_object()) {
                node_total = r.result.value("total", 0);
                if (r.result.contains("rejected"))
                    for (auto& row : r.result["rejected"])
                        rejected_buf.push_back(convert_row(row, "rejected"));
            }
            int cached = g_txcache.get_total(g_wallet.addr);
            if (node_total > cached) {
                int delta = node_total - cached;
                auto dr = g_rpc.get_txs_by_address(g_wallet.addr, delta, 0);
                if (dr.ok && dr.result.is_object() && dr.result.contains("transactions")) {
                    json to_store = json::array();
                    for (auto& row : dr.result["transactions"]) {
                        std::string h = row.value("hash", "");
                        if (!h.empty() && !g_txcache.has_tx(h))
                            to_store.push_back(convert_row(row, "confirmed"));
                    }
                    if (!to_store.empty()) {
                        g_txcache.store_txs(to_store);
                        g_txcache.set_total(g_wallet.addr, cached + (int)to_store.size());
                    }
                    rejected_buf = json::array();
                    if (dr.result.contains("rejected"))
                        for (auto& row : dr.result["rejected"])
                            rejected_buf.push_back(convert_row(row, "rejected"));
                }
            }
            json cached_txs = g_txcache.load_page(limit, offset);
            for (auto& tx : cached_txs) txs.push_back(tx);
            for (auto& tx : rejected_buf) txs.push_back(tx);
        } else {
            auto r = g_rpc.get_txs_by_address(g_wallet.addr, limit, offset);
            if (r.ok && r.result.is_object()) {
                if (r.result.contains("transactions"))
                    for (auto& row : r.result["transactions"])
                        txs.push_back(convert_row(row, "confirmed"));
                if (r.result.contains("rejected"))
                    for (auto& row : r.result["rejected"])
                        txs.push_back(convert_row(row, "rejected"));
            }
        }

        json j;
        j["transactions"] = txs;
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
            res.set_content(err_json("ed25519→x25519 conversion failed").dump(), "application/json");
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

        steps.push_back("[5/8] range proofs (parallel) - Bulletproofs R1CS");
        pvac_cipher current_ct = g_pvac.decode_cipher(eb_cipher);
        pvac_cipher new_ct = g_pvac.ct_sub(current_ct, ct_delta);
        uint64_t new_val = (uint64_t)(eb_decrypted - raw);

        pvac_range_proof rp_delta = nullptr;
        pvac_range_proof rp_bal = nullptr;

        std::thread t_rp_delta([&]() {
            rp_delta = pvac_make_range_proof(g_pvac.pk(), g_pvac.sk(), ct_delta, (uint64_t)raw);
        });
        std::thread t_rp_bal([&]() {
            rp_bal = pvac_make_range_proof(g_pvac.pk(), g_pvac.sk(), new_ct, new_val);
        });
        t_rp_delta.join();
        t_rp_bal.join();

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
        try { octra::load_wallet_encrypted(g_wallet_path, pin); } catch (...) {
            res.status = 403;
            res.set_content(err_json("wrong PIN").dump(), "application/json");
            return;
        }
        json j;
        j["private_key"] = g_wallet.priv_b64;
        j["mnemonic"] = g_wallet.mnemonic;
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
        g_pvac.free_cipher(ct);
        json result;
        result["ciphertext"] = b64;
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/fhe/decrypt", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
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