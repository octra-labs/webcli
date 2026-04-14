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
    // Reject negative amounts explicitly
    if (s[0] == '-') return -1;
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
    if (port <= 0 || port > 65535) port = 8420;

    octra::ensure_data_dir();

    httplib::Server svr;
    svr.set_read_timeout(300, 0);
    svr.set_write_timeout(300, 0);

    svr.set_keep_alive_timeout(5);
    svr.set_keep_alive_max_count(100);

    svr.set_post_routing_handler([](const httplib::Request&, httplib::Response& res) {
        res.set_header("X-Frame-Options", "DENY");
        res.set_header("X-Content-Type-Options", "nosniff");
        res.set_header("Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'");
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
            // Strict path validation: must start with "data/", end with ".oct",
            // contain no ".." traversal, and only safe characters (alnum, /, -, _)
            bool path_safe = true;
            if (file_hint.find("..") != std::string::npos) path_safe = false;
            if (file_hint.rfind("data/", 0) != 0) path_safe = false;
            if (file_hint.size() < 9 || file_hint.substr(file_hint.size() - 4) != ".oct") path_safe = false;
            for (char c : file_hint) {
                if (!isalnum((unsigned char)c) && c != '/' && c != '-' && c != '_' && c != '.') {
                    path_safe = false; break;
                }
            }
            if (path_safe) {
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
        j["has_master_seed"] = g_wallet.has_master_seed();
        j["hd_index"] = g_wallet.hd_index;
        j["hd_version"] = g_wallet.hd_version;
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

    printf("octra_wallet listening on http://127.0.0.1:%d\n", port);
    svr.listen("127.0.0.1", port);
    return 0;
}
