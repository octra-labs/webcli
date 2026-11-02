// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cctype>
#include <string>
#include <vector>
#include <set>
#include <algorithm>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <future>
#include <atomic>
#include <chrono>
#include <optional>
#include <unordered_map>
#include <limits>
#include <array>
#include <cerrno>
#include <cctype>
#include <utility>
#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <signal.h>
#include <sys/resource.h>
#include <unistd.h>
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
#include "sanitize.hpp"
#include "wallet.hpp"
#include "rpc_client.hpp"
#include "lib/circle_asset_chunks.hpp"
#include "lib/circle_hfhe_receipt.hpp"
#include "lib/circle_verifier_policy.hpp"
#include "lib/endpoint_policy.hpp"
#include "lib/instance_lock.hpp"
#include "lib/api_access.hpp"
#include "lib/browser_open.hpp"
#include "lib/session_http.hpp"
#include "lib/wallet_change.hpp"
#include "lib/pvac_key_read.hpp"
#include "lib/pvac_tx_state.hpp"
#include "lib/proxy_http.hpp"
#include "lib/circle_input.hpp"
#include "lib/program_args.hpp"
#include "lib/display_values.hpp"
#include "lib/token_wire.hpp"
#include "lib/asset_mime.hpp"
#include "lib/pin_guard.hpp"
#include "lib/program_cli_app.hpp"
#include "lib/stealth_scan.hpp"
#include "lib/tx_builder.hpp"
#include "lib/pvac_bridge.hpp"
#include "lib/pvac_migration.hpp"
#include "lib/fhe_tools.hpp"
#include "lib/rpc_state.hpp"
#include "lib/stealth_claim.hpp"
#include "lib/pvac_map.hpp"
#include "lib/pvac_upgrade_policy.hpp"
#include "lib/resource_compute_intent.hpp"
#include "lib/stealth.hpp"
#include "lib/txcache.hpp"
#include "lib/tx_journal.hpp"
#include "lib/staging_view.hpp"

using json = nlohmann::json;

static octra::Wallet g_wallet;
static octra::RpcClient g_rpc;
static octra::PvacBridge g_pvac;
static std::mutex g_mtx;
static std::shared_mutex g_pvac_lifetime_mtx;
static std::atomic<unsigned> g_wallet_writers{0};
static octra::circle_verifier_policy::Lane g_circle_verifier_lane;
static bool g_pvac_confirmed = false;
static bool g_pvac_ok = false;
static std::string g_pvac_pubkey_b64;
static std::string g_pvac_remote_pubkey_b64;
static std::string g_pvac_repair_required_addr;
static std::string g_pvac_repair_blocked_addr;
static std::string g_pvac_repair_blocked_reason;
struct PvacRepairTx {
    uint64_t token = 0;
    std::string hash;
};
static PvacRepairTx g_pvac_repair_tx;
static std::atomic<bool> g_wallet_loaded{false};
static uint64_t g_wallet_generation = 0;
static std::atomic<bool> g_pvac_upgrade_inflight{false};
static std::mutex g_pvac_status_mtx;
static std::mutex g_pvac_upgrade_state_mtx;
static std::string g_pvac_upgrade_stage = "idle";
static std::string g_pvac_upgrade_detail;
static std::string g_pvac_upgrade_tx_hash;
struct PvacUpgradeRecord {
    std::string hash;
    std::string stage;
    std::string detail;
    double started = 0;
    double updated = 0;
};
static std::map<std::pair<std::string, std::string>, PvacUpgradeRecord> g_pvac_pending;
static std::pair<std::string, std::string> g_pvac_pending_account;
static double g_pvac_upgrade_started_ts = 0.0;
static double g_pvac_upgrade_updated_ts = 0.0;
static std::string g_wallet_path = "data/wallet.oct";
static octra::SessionPin g_pin_session;
static octra::PinAttempts g_pin_attempts;
static TxCache g_txcache;
static TxJournal g_own_history;
static uint64_t g_own_token = 0;
static std::string g_own_rpc;
static std::string g_own_chain;
static const char* const TXCACHE_SCHEMA = "v3_addr_hash_index";

static nlohmann::json g_fee_cache;
static double g_fee_cache_ts = 0.0;
static std::mutex g_fee_mtx;

struct PvacWalletSnapshot {
    bool loaded = false;
    bool pvac_ok = false;
    uint64_t generation = 0;
    std::string addr;
    std::string pub_b64;
    std::string priv_b64;
    std::array<uint8_t, 64> sk{};

    PvacWalletSnapshot() = default;
    PvacWalletSnapshot(const PvacWalletSnapshot&) = delete;
    PvacWalletSnapshot& operator=(const PvacWalletSnapshot&) = delete;

    PvacWalletSnapshot(PvacWalletSnapshot&& other) noexcept
        : loaded(other.loaded),
          pvac_ok(other.pvac_ok),
          generation(other.generation),
          addr(std::move(other.addr)),
          pub_b64(std::move(other.pub_b64)),
          priv_b64(std::move(other.priv_b64)),
          sk(other.sk) {
        other.clear_secrets();
    }

    PvacWalletSnapshot& operator=(PvacWalletSnapshot&&) = delete;

    ~PvacWalletSnapshot() {
        clear_secrets();
    }

    void clear_secrets() {
        if (!priv_b64.empty()) {
            octra::secure_zero(&priv_b64[0], priv_b64.size());
            priv_b64.clear();
        }
        octra::secure_zero(sk.data(), sk.size());
    }
};

struct HistoryRuntimeState {
    std::unordered_map<std::string, json> pages;
    std::unordered_map<std::string, double> page_ts;
    std::unordered_map<std::string, json> metadata;
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

struct AtomicFlagGuard {
    std::atomic<bool>& flag;
    explicit AtomicFlagGuard(std::atomic<bool>& f) : flag(f) {}
    ~AtomicFlagGuard() { flag.store(false); }
    AtomicFlagGuard(const AtomicFlagGuard&) = delete;
    AtomicFlagGuard& operator=(const AtomicFlagGuard&) = delete;
};

struct ScopedSecret64 {
    std::array<uint8_t, 64> bytes{};
    ~ScopedSecret64() { octra::secure_zero(bytes.data(), bytes.size()); }
    uint8_t* data() { return bytes.data(); }
    const uint8_t* data() const { return bytes.data(); }
};

struct WalletRead {
    std::string addr;
    std::string url;
    uint64_t generation;

    void check_request(const httplib::Request& request) const {
        if (!request.has_header("X-Webcli-Wallet") && !request.has_header("X-Webcli-Generation")) return;
        if (request.get_header_value("X-Webcli-Wallet") != addr
            || request.get_header_value("X-Webcli-Generation") != std::to_string(generation))
            throw octra::WalletSessionError("wallet request generation changed");
    }

    void check() const {
        if (!g_wallet_loaded || g_wallet.addr != addr || g_wallet.rpc_url != url
            || g_wallet_generation != generation)
            throw octra::WalletSessionError("wallet changed during read");
    }
};

static WalletRead wallet_read(const httplib::Request* request = nullptr) {
    std::lock_guard<std::mutex> lock(g_mtx);
    if (!g_wallet_loaded) throw octra::WalletSessionError("wallet locked");
    const WalletRead read{g_wallet.addr, g_wallet.rpc_url, g_wallet_generation};
    if (request) read.check_request(*request);
    return read;
}

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

static int stealth_scan_from_epoch(octra::RpcClient& rpc = g_rpc) {
    const char* env_from = std::getenv("OCTRA_STEALTH_SCAN_FROM");
    if (env_from && *env_from) {
        char* end = nullptr;
        long v = std::strtol(env_from, &end, 10);
        if (end == env_from || v < 0 || v > std::numeric_limits<int>::max()) return 0;
        return static_cast<int>(v);
    }

    long window = 50000;
    const char* env_window = std::getenv("OCTRA_STEALTH_SCAN_WINDOW");
    if (env_window && *env_window) {
        char* end = nullptr;
        long v = std::strtol(env_window, &end, 10);
        if (end != env_window && v > 0 && v <= std::numeric_limits<int>::max()) window = v;
    }

    auto status = rpc.node_status(5);
    if (status.ok && status.result.is_object()) {
        long epoch = 0;
        if (status.result.contains("current_epoch") && status.result["current_epoch"].is_number_integer()) {
            epoch = status.result["current_epoch"].get<long>();
        } else if (status.result.contains("epoch") && status.result["epoch"].is_number_integer()) {
            epoch = status.result["epoch"].get<long>();
        }
        if (epoch > 0) {
            long from = epoch > window ? epoch - window : 0;
            if (from > std::numeric_limits<int>::max()) return std::numeric_limits<int>::max();
            return static_cast<int>(from);
        }
    }

    return 0;
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
    const auto reply = octra::proxy_http(current_circle_relayer_url(), path, "", "GET");
    if (!reply.error.empty()) return {false, 502, "", reply.error};
    return {true, reply.status, reply.body, ""};
}

static RelayProxyResult relay_http_post(const std::string& path, const std::string& body) {
    const auto reply = octra::proxy_http(current_circle_relayer_url(), path, body, "POST");
    if (!reply.error.empty()) return {false, 502, "", reply.error};
    return {true, reply.status, reply.body, ""};
}

static void pk_cache_put(const std::string& addr, const std::vector<uint8_t>& pk) {
    if (pk.size() != 32) return;
    std::lock_guard<std::mutex> lk(g_pk_mtx);
    if (g_pk_cache.size() > 2048) g_pk_cache.clear();
    g_pk_cache[addr] = pk;
}

static void pk_cache_erase(const std::string& addr) {
    std::lock_guard<std::mutex> lk(g_pk_mtx);
    g_pk_cache.erase(addr);
}

static void handle_signal(int) {
    octra::secure_zero(g_wallet.sk, 64);
    octra::secure_zero(g_wallet.pk, 32);
    g_pin_session.clear();
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

static bool pvac_local_self_check_enabled() {
    const char* v = std::getenv("OCTRA_PVAC_LOCAL_SELF_CHECK");
    return v && (std::strcmp(v, "1") == 0 || std::strcmp(v, "true") == 0 || std::strcmp(v, "yes") == 0);
}

static void pvac_upgrade_stage_set(const std::string& stage,
                                   const std::string& detail = "",
                                   const std::string& tx_hash = "") {
    const double ts = now_ts();
    std::lock_guard<std::mutex> lk(g_pvac_upgrade_state_mtx);
    if (stage == "checking_fee" || stage == "idle") {
        g_pvac_upgrade_started_ts = ts;
        g_pvac_upgrade_tx_hash.clear();
    }
    g_pvac_upgrade_stage = stage;
    g_pvac_upgrade_detail = detail;
    if (!tx_hash.empty()) g_pvac_upgrade_tx_hash = tx_hash;
    g_pvac_upgrade_updated_ts = ts;
    if (!g_pvac_upgrade_tx_hash.empty() && stage == "submitted")
        g_pvac_pending[g_pvac_pending_account] = {g_pvac_upgrade_tx_hash, stage, detail,
            g_pvac_upgrade_started_ts, ts};
}

static void select_pvac_upgrade(const std::string& url, const std::string& address) {
    std::lock_guard<std::mutex> lock(g_pvac_upgrade_state_mtx);
    g_pvac_pending_account = {octra::endpoint_policy::rpc_identity(url), address};
    const auto found = g_pvac_pending.find(g_pvac_pending_account);
    const auto record = found == g_pvac_pending.end() ? PvacUpgradeRecord{} : found->second;
    g_pvac_upgrade_tx_hash = record.hash;
    g_pvac_upgrade_stage = record.stage;
    g_pvac_upgrade_detail = record.detail;
    g_pvac_upgrade_started_ts = record.started;
    g_pvac_upgrade_updated_ts = record.updated;
}

static json pvac_upgrade_state_json() {
    std::lock_guard<std::mutex> lk(g_pvac_upgrade_state_mtx);
    json j;
    j["can_submit"] = false;
    j["cipher_present"] = true;
    j["mode"] = "upgrade_inflight";
    j["reason"] = g_pvac_upgrade_detail.empty()
        ? "encrypted balance upgrade is running"
        : g_pvac_upgrade_detail;
    j["upgrade_inflight"] = true;
    j["stage"] = g_pvac_upgrade_stage;
    j["detail"] = g_pvac_upgrade_detail;
    j["tx_hash"] = g_pvac_upgrade_tx_hash;
    j["started_ts"] = g_pvac_upgrade_started_ts;
    j["updated_ts"] = g_pvac_upgrade_updated_ts;
    return j;
}

static bool pvac_upgrade_recent_json(json& out) {
    std::lock_guard<std::mutex> lk(g_pvac_upgrade_state_mtx);
    if (g_pvac_upgrade_tx_hash.empty()) return false;
    if (g_pvac_upgrade_stage != "submitted" && g_pvac_upgrade_stage != "confirmed") return false;
    out["can_submit"] = false;
    out["cipher_present"] = true;
    out["mode"] = "upgrade_recent";
    out["reason"] = g_pvac_upgrade_detail.empty()
        ? "encrypted balance upgrade transaction was submitted"
        : g_pvac_upgrade_detail;
    out["upgrade_inflight"] = false;
    out["stage"] = g_pvac_upgrade_stage;
    out["detail"] = out["reason"];
    out["tx_hash"] = g_pvac_upgrade_tx_hash;
    out["started_ts"] = g_pvac_upgrade_started_ts;
    out["updated_ts"] = g_pvac_upgrade_updated_ts;
    return true;
}

static bool pvac_upgrade_can_start(httplib::Response& response) {
    json recent;
    if (pvac_upgrade_recent_json(recent)) {
        recent["error"] = "encrypted balance upgrade already submitted";
        response.status = 409;
        response.set_content(recent.dump(), "application/json");
        return false;
    }
    std::lock_guard<std::mutex> lock(g_pvac_upgrade_state_mtx);
    if (g_pvac_pending.size() < 128) return true;
    response.status = 409;
    response.set_content(json({{"error", "pending upgrade account limit reached"}}).dump(), "application/json");
    return false;
}

static bool pvac_upgrade_ack(const std::string& tx_hash) {
    const double ts = now_ts();
    std::lock_guard<std::mutex> lk(g_pvac_upgrade_state_mtx);
    if (tx_hash.empty() || tx_hash != g_pvac_upgrade_tx_hash) return false;
    if (g_pvac_upgrade_stage != "submitted" && g_pvac_upgrade_stage != "confirmed") return false;
    g_pvac_upgrade_stage = "confirmed";
    g_pvac_pending.erase(g_pvac_pending_account);
    g_pvac_upgrade_detail = "transaction confirmed by chain";
    g_pvac_upgrade_tx_hash.clear();
    g_pvac_upgrade_updated_ts = ts;
    return true;
}

static bool pvac_upgrade_reject(const std::string& tx_hash, const std::string& detail) {
    const double ts = now_ts();
    std::lock_guard<std::mutex> lk(g_pvac_upgrade_state_mtx);
    if (tx_hash.empty() || tx_hash != g_pvac_upgrade_tx_hash) return false;
    if (g_pvac_upgrade_stage != "submitted") return false;
    g_pvac_upgrade_stage = "error";
    g_pvac_pending.erase(g_pvac_pending_account);
    g_pvac_upgrade_detail = detail.empty()
        ? "transaction rejected by chain"
        : detail;
    g_pvac_upgrade_tx_hash.clear();
    g_pvac_upgrade_updated_ts = ts;
    return true;
}

static json err_json(const std::string& msg) {
    return {{"error", msg}};
}

static std::string lower_ascii(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

static bool starts_with(const std::string& s, const std::string& prefix) {
    return s.rfind(prefix, 0) == 0;
}

static int hex_value(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    return -1;
}

static bool valid_utf8(const std::string& s) {
    size_t i = 0;
    while (i < s.size()) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (c <= 0x7f) {
            i++;
        } else if (c >= 0xc2 && c <= 0xdf) {
            if (i + 1 >= s.size()) return false;
            unsigned char c1 = static_cast<unsigned char>(s[i + 1]);
            if ((c1 & 0xc0) != 0x80) return false;
            i += 2;
        } else if (c == 0xe0) {
            if (i + 2 >= s.size()) return false;
            unsigned char c1 = static_cast<unsigned char>(s[i + 1]);
            unsigned char c2 = static_cast<unsigned char>(s[i + 2]);
            if (c1 < 0xa0 || c1 > 0xbf || (c2 & 0xc0) != 0x80) return false;
            i += 3;
        } else if ((c >= 0xe1 && c <= 0xec) || (c >= 0xee && c <= 0xef)) {
            if (i + 2 >= s.size()) return false;
            unsigned char c1 = static_cast<unsigned char>(s[i + 1]);
            unsigned char c2 = static_cast<unsigned char>(s[i + 2]);
            if ((c1 & 0xc0) != 0x80 || (c2 & 0xc0) != 0x80) return false;
            i += 3;
        } else if (c == 0xed) {
            if (i + 2 >= s.size()) return false;
            unsigned char c1 = static_cast<unsigned char>(s[i + 1]);
            unsigned char c2 = static_cast<unsigned char>(s[i + 2]);
            if (c1 < 0x80 || c1 > 0x9f || (c2 & 0xc0) != 0x80) return false;
            i += 3;
        } else if (c == 0xf0) {
            if (i + 3 >= s.size()) return false;
            unsigned char c1 = static_cast<unsigned char>(s[i + 1]);
            unsigned char c2 = static_cast<unsigned char>(s[i + 2]);
            unsigned char c3 = static_cast<unsigned char>(s[i + 3]);
            if (c1 < 0x90 || c1 > 0xbf || (c2 & 0xc0) != 0x80 || (c3 & 0xc0) != 0x80) return false;
            i += 4;
        } else if (c >= 0xf1 && c <= 0xf3) {
            if (i + 3 >= s.size()) return false;
            unsigned char c1 = static_cast<unsigned char>(s[i + 1]);
            unsigned char c2 = static_cast<unsigned char>(s[i + 2]);
            unsigned char c3 = static_cast<unsigned char>(s[i + 3]);
            if ((c1 & 0xc0) != 0x80 || (c2 & 0xc0) != 0x80 || (c3 & 0xc0) != 0x80) return false;
            i += 4;
        } else if (c == 0xf4) {
            if (i + 3 >= s.size()) return false;
            unsigned char c1 = static_cast<unsigned char>(s[i + 1]);
            unsigned char c2 = static_cast<unsigned char>(s[i + 2]);
            unsigned char c3 = static_cast<unsigned char>(s[i + 3]);
            if (c1 < 0x80 || c1 > 0x8f || (c2 & 0xc0) != 0x80 || (c3 & 0xc0) != 0x80) return false;
            i += 4;
        } else {
            return false;
        }
    }
    return true;
}

static bool circle_asset_path(const std::string& raw_path, std::string& out, std::string& error) {
    std::string decoded;
    const std::string initial = raw_path.empty() ? "/" : raw_path;
    decoded.reserve(initial.size());
    for (size_t i = 0; i < initial.size(); i++) {
        unsigned char c = static_cast<unsigned char>(initial[i]);
        if (c == '%') {
            if (i + 2 >= initial.size()) {
                error = "invalid percent escape";
                return false;
            }
            int hi = hex_value(static_cast<unsigned char>(initial[i + 1]));
            int lo = hex_value(static_cast<unsigned char>(initial[i + 2]));
            if (hi < 0 || lo < 0) {
                error = "invalid percent escape";
                return false;
            }
            decoded.push_back(static_cast<char>((hi << 4) | lo));
            i += 2;
        } else {
            decoded.push_back(static_cast<char>(c));
        }
    }
    if (!valid_utf8(decoded)) {
        error = "path is not valid utf-8";
        return false;
    }
    std::string with_slash =
        decoded.empty() ? "/" : (decoded[0] == '/' ? decoded : "/" + decoded);
    std::vector<std::string> segments;
    size_t start = 0;
    while (start <= with_slash.size()) {
        size_t end = with_slash.find('/', start);
        std::string seg = with_slash.substr(start, end == std::string::npos ? std::string::npos : end - start);
        if (!seg.empty() && seg != ".") {
            if (seg == "..") {
                error = "path traversal is not allowed";
                return false;
            }
            segments.push_back(seg);
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    if (segments.empty()) out = "/";
    else {
        out.clear();
        for (const auto& seg : segments) {
            out.push_back('/');
            out += seg;
        }
    }
    if (out.size() > 1024) {
        error = "path exceeds max length";
        return false;
    }
    return true;
}

static bool is_loopback_host(std::string host, int port) {
    host = lower_ascii(host);
    std::string suffix = ":" + std::to_string(port);
    if (host.size() > suffix.size() &&
        host.compare(host.size() - suffix.size(), suffix.size(), suffix) == 0) {
        host.resize(host.size() - suffix.size());
    }
    return host == "127.0.0.1" || host == "localhost" || host == "[::1]";
}

static bool is_allowed_webcli_origin(const std::string& origin, int port) {
    std::string o = lower_ascii(origin);
    std::string suffix = ":" + std::to_string(port);
    return o == "http://127.0.0.1" + suffix ||
           o == "http://localhost" + suffix ||
           o == "http://[::1]" + suffix;
}

static bool webcli_request_allowed(const httplib::Request& req, int port, std::string& reason) {
    if (!starts_with(req.path, "/api/")) {
        if (req.method != "GET" && req.method != "HEAD" && req.method != "OPTIONS") {
            reason = "non-GET on non-api path";
            return false;
        }
        return true;
    }

    std::string host = req.get_header_value("Host");
    if (!host.empty() && !is_loopback_host(host, port)) {
        reason = "non-loopback host";
        return false;
    }

    std::string fetch_site = lower_ascii(req.get_header_value("Sec-Fetch-Site"));
    if (!fetch_site.empty() && fetch_site != "same-origin" && fetch_site != "none") {
        reason = "cross-site fetch";
        return false;
    }

    std::string origin = req.get_header_value("Origin");
    if (!origin.empty() && !is_allowed_webcli_origin(origin, port)) {
        reason = "cross-origin request";
        return false;
    }

    bool same_origin_fetch = !fetch_site.empty() && (fetch_site == "same-origin" || fetch_site == "none");
    bool same_origin_header = !origin.empty() && is_allowed_webcli_origin(origin, port);
    bool state_changing = req.method == "POST" || req.method == "PUT" || req.method == "DELETE";
    if (state_changing && !same_origin_fetch && !same_origin_header) {
        reason = "unverified origin on state-changing request";
        return false;
    }

    return true;
}

static void set_same_origin_cors_if_needed(const httplib::Request& req,
                                           httplib::Response& res,
                                           int port) {
    std::string origin = req.get_header_value("Origin");
    if (!origin.empty() && is_allowed_webcli_origin(origin, port)) {
        res.set_header("Access-Control-Allow-Origin", origin.c_str());
        res.set_header("Vary", "Origin");
    }
}

static bool tx_status_is_pending_like(const json& tx) {
    const std::string status = tx.value("status", "pending");
    return status.empty() || status == "pending" || status == "unknown" || status == "dropped"
        || (status == "unaccepted" && tx.value("retryable", false));
}

static bool tx_lookup_needed(const json& row) {
    return tx_status_is_pending_like(row)
        || (row.value("status", "") == "replaced" && row.value("op_type", "") == "key_switch"
            && !row.contains("replacement_hash"));
}

static int confirmed_nonce(octra::RpcClient& rpc, const std::string& addr, const std::string& chain = "") {
    const auto result = rpc.call("octra_balance", {addr}, 5);
    if (!result.ok || !result.result.is_object() || !result.result.contains("nonce")) return -1;
    if ((result.result.contains("address") && result.result["address"] != addr)
        || (!chain.empty() && result.result.contains("chain_id") && result.result["chain_id"] != chain)) return -1;
    try { return octra::rpc_nonce(result.result["nonce"]); }
    catch (const octra::RpcStateError&) { return -1; }
}

static json replacement_rows(octra::RpcClient& rpc, const std::string& addr, const json& own) {
    const auto reply = rpc.call("octra_transactionsByAddress", {addr, 100, 0}, 5);
    if (!reply.ok || !reply.result.is_object()) return json::array();
    const auto rows = reply.result.value("transactions", json::array());
    if (!rows.is_array()) return json::array();
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    json result = json::array();
    std::set<std::string> seen;
    for (size_t i = 0; i < rows.size() && i < 100; ++i) {
        const auto& row = rows[i];
        if (!row.is_object() || !row.contains("from") || row["from"] != addr) continue;
        const auto id = row.contains("hash") ? row["hash"] : row.value("tx_hash", json());
        if (!id.is_string() || id == own["hash"]) continue;
        const auto hash = id.get<std::string>();
        if (hash.size() != 64 || !std::all_of(hash.begin(), hash.end(), [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        }) || !seen.insert(hash).second) continue;
        if (row.contains("nonce") && row.contains("status") && row.contains("epoch")) {
            result.push_back(row);
            continue;
        }
        const auto remaining = std::chrono::duration_cast<std::chrono::seconds>(
            deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0) break;
        const auto full = rpc.call("octra_transaction", {hash}, static_cast<int>(remaining));
        if (!full.ok || !full.result.is_object()) continue;
        const auto& tx = full.result;
        const auto got = tx.contains("hash") ? tx["hash"] : tx.value("tx_hash", json());
        if (got != id || (tx.contains("tx_hash") && tx["tx_hash"] != id)) continue;
        if (tx.value("from", "") != addr || tx.value("status", "") != "confirmed"
            || !tx.contains("nonce") || !tx.contains("epoch")) continue;
        try {
            if (octra::rpc_nonce(tx["nonce"]) != own.value("nonce", 0)) continue;
        } catch (const octra::RpcStateError&) { continue; }
        result.push_back(tx);
        break;
    }
    return result;
}

static bool needs_replacement(const json& row, const octra::RpcResult& reply, int nonce) {
    if (row.is_null() || !row.value("retryable", false)
        || nonce < row.value("nonce", std::numeric_limits<int>::max())) return false;
    return (reply.replied && !reply.ok && reply.code == 112)
        || (reply.ok && reply.result.is_object() && reply.result.value("status", "") == "dropped");
}

static void observe_own_tx(uint64_t token, const std::string& hash,
    const octra::RpcResult& reply, int nonce, const json& replacements) {
    const auto row = g_own_history.find(token, hash);
    if (row.is_null() || !tx_lookup_needed(row)) return;
    const auto status = reply.ok && reply.result.is_object() ? reply.result.value("status", "") : "";
    if (status == "pending" || status == "confirmed" || status == "rejected" || status == "dropped")
        g_own_history.update(token, hash, reply.result);
    if (needs_replacement(row, reply, nonce)) {
        for (const auto& tx : replacements) {
            if (!TxJournal::confirms_replacement(tx, row.value("from", ""), g_own_chain,
                row.value("nonce", 0), hash)) continue;
            g_own_history.replaced(token, hash, tx);
            break;
        }
    }
}

static uint64_t own_history_open(const std::string& addr, uint64_t generation, bool online = false) {
    std::string url;
    ScopedSecret64 seed;
    {
        std::lock_guard<std::mutex> lock(g_mtx);
        if (!g_wallet_loaded || g_wallet.addr != addr || g_wallet_generation != generation)
            throw octra::RpcStateError("history wallet changed");
        if (!online && g_own_rpc == g_wallet.rpc_url && g_own_history.is_open(g_own_token))
            return g_own_token;
        url = g_wallet.rpc_url;
    }
    octra::RpcClient rpc(url);
    const auto runtime = rpc.call("octra_runtimeVersion", json::array(), 5);
    std::string chain;
    if (runtime.ok && runtime.result.is_object()
        && runtime.result.contains("chain_id") && runtime.result["chain_id"].is_string())
        chain = runtime.result["chain_id"].get<std::string>();
    if (chain.empty() && online)
        throw octra::RpcStateError("history network identity unavailable");
    std::lock_guard<std::mutex> lock(g_mtx);
    if (!g_wallet_loaded || g_wallet.addr != addr || g_wallet_generation != generation
        || g_wallet.rpc_url != url) throw octra::RpcStateError("history wallet changed");
    std::memcpy(seed.data(), g_wallet.sk, 64);
    chain = TxJournal::network("data/history", addr, url, seed.data(), chain);
    if (chain.empty()) throw octra::RpcStateError("history network identity unavailable");
    if (g_own_rpc == url && g_own_chain == chain && g_own_history.is_open(g_own_token)) return g_own_token;
    g_own_token = 0;
    g_own_rpc.clear();
    g_own_chain.clear();
    g_own_token = g_own_history.open("data/history", addr, chain, seed.data());
    g_own_rpc = url;
    g_own_chain = chain;
    return g_own_token;
}

static void close_own_history() {
    g_own_token = 0;
    g_own_rpc.clear();
    g_own_chain.clear();
    g_own_history.close();
}

static json own_history_page(const std::string& addr, uint64_t generation,
    int limit, int offset, uint64_t& total) {
    const auto token = own_history_open(addr, generation);
    std::lock_guard<std::mutex> lock(g_mtx);
    if (!g_wallet_loaded || g_wallet.addr != addr || g_wallet_generation != generation
        || token != g_own_token)
        throw octra::RpcStateError("history wallet changed");
    total = g_own_history.count(token);
    return g_own_history.list(token, limit, offset);
}

static json wallet_staging(const WalletRead* identity = nullptr) {
    std::string addr;
    std::string url;
    uint64_t generation;
    {
        std::lock_guard<std::mutex> lock(g_mtx);
        if (identity) identity->check();
        if (!g_wallet_loaded) return octra::staging_status(json(), "");
        addr = g_wallet.addr;
        url = g_wallet.rpc_url;
        generation = g_wallet_generation;
    }
    octra::RpcClient rpc(url);
    const auto reply = rpc.staging_view();
    if (!reply.ok) return octra::staging_status(json(), addr);
    std::set<std::string> own;
    if (reply.result.is_object() && reply.result.contains("transactions")
        && reply.result["transactions"].is_array()) {
        try {
            const auto token = own_history_open(addr, generation);
            std::lock_guard<std::mutex> lock(g_mtx);
            if (!g_wallet_loaded || g_wallet.addr != addr || g_wallet_generation != generation
                || g_wallet.rpc_url != url || token != g_own_token)
                return octra::staging_status(json(), addr);
            for (const auto& tx : reply.result["transactions"]) {
                if (!tx.is_object() || !tx.contains("hash") || !tx["hash"].is_string()) continue;
                const auto hash = tx["hash"].get<std::string>();
                if (!g_own_history.find(token, hash).is_null()) own.insert(hash);
            }
        } catch (const std::exception&) {
            return octra::staging_status(json(), addr);
        }
    }
    return octra::staging_status(reply.result, addr, own);
}

static void refresh_own_rows(const std::string& addr, uint64_t generation, json& rows) {
    const auto token = own_history_open(addr, generation);
    std::string url;
    {
        std::lock_guard<std::mutex> lock(g_mtx);
        if (!g_wallet_loaded || g_wallet.addr != addr || g_wallet_generation != generation
            || token != g_own_token)
            throw octra::RpcStateError("history wallet changed");
        url = g_wallet.rpc_url;
    }
    std::vector<std::string> methods;
    std::vector<json> params;
    std::vector<size_t> positions;
    for (size_t i = 0; i < rows.size(); ++i) {
        if (!tx_lookup_needed(rows[i])) continue;
        methods.push_back("octra_transaction");
        params.push_back(json::array({rows[i].at("hash")}));
        positions.push_back(i);
    }
    if (methods.empty()) return;
    octra::RpcClient rpc(url);
    const int nonce = confirmed_nonce(rpc, addr);
    const auto replies = rpc.call_batch(methods, params, 5);
    json replacements = json::array();
    for (size_t i = 0; i < replies.size() && i < positions.size(); ++i) {
        if (!needs_replacement(rows[positions[i]], replies[i], nonce)) continue;
        replacements = replacement_rows(rpc, addr, rows[positions[i]]);
        break;
    }
    std::lock_guard<std::mutex> lock(g_mtx);
    if (!g_wallet_loaded || g_wallet.addr != addr || g_wallet_generation != generation
        || g_own_token != token || g_wallet.rpc_url != url)
        throw octra::RpcStateError("history wallet changed");
    for (size_t i = 0; i < replies.size() && i < positions.size(); ++i) {
        const auto& reply = replies[i];
        const auto hash = rows[positions[i]].at("hash").get<std::string>();
        observe_own_tx(token, hash, reply, nonce, replacements);
        rows[positions[i]] = g_own_history.find(token, hash);
    }
}

static json history_tx_from_lookup(const json& lookup, const json& saved) {
    json tx = saved;
    tx["hash"] = lookup.value("tx_hash", saved.value("hash", ""));
    tx["from"] = lookup.value("from", saved.value("from", ""));
    tx["to_"] = lookup.value("to", lookup.value("to_", saved.value("to_", saved.value("to", ""))));
    tx["amount_raw"] = lookup.value("amount_raw", lookup.value("amount", saved.value("amount_raw", "0")));
    tx["op_type"] = lookup.value("op_type", saved.value("op_type", "standard"));
    tx["status"] = lookup.value("status", saved.value("status", "pending"));

    double ts = saved.value("timestamp", 0.0);
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

static bool refresh_history_rows(const std::string& addr, json& txs, uint64_t generation = 0) {
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
    std::string url;
    {
        std::lock_guard<std::mutex> lock(g_mtx);
        if (!g_wallet_loaded || g_wallet.addr != addr
            || (generation != 0 && generation != g_wallet_generation)) return false;
        generation = g_wallet_generation;
        url = g_wallet.rpc_url;
    }
    octra::RpcClient rpc(url);
    const auto results = rpc.call_batch(methods, params_list, 10);
    std::lock_guard<std::mutex> lock(g_mtx);
    if (!g_wallet_loaded || g_wallet.addr != addr || generation != g_wallet_generation
        || url != g_wallet.rpc_url) return false;
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

static std::string token_amount_text(const json& value) {
    if (value.is_string()) return value.get<std::string>();
    if (value.is_number_integer() || value.is_number_unsigned()) return value.dump();
    return "";
}

static std::string object_string(const json& value, const char* key) {
    if (!value.is_object() || !value.contains(key) || !value[key].is_string()) return "";
    return value[key].get<std::string>();
}

static void bind_token_row(json& tx, bool finalized) {
    if (!tx.is_object()) return;
    for (const auto* field : {"to", "to_", "token_address", "recipient"}) {
        if (tx.contains(field) && (!tx[field].is_string()
            || !octra::program_cli::valid_address(tx[field].get<std::string>()))) tx.erase(field);
    }
    tx["token_transfer"] = true;
    std::string token = object_string(tx, "token_address");
    if (token.empty()) token = object_string(tx, "to_");
    if (token.empty()) token = object_string(tx, "to");
    if (token.empty()) { tx["token_transfer"] = false; return; }
    tx["token_address"] = token;
    const std::string status = object_string(tx, "status");
    if (finalized && (status.empty() || status == "pending")) tx["status"] = "confirmed";
    if (tx.contains("recipient") && tx.contains("token_amount_raw")) return;
    if (!tx.contains("message") || !tx["message"].is_string()) return;
    try {
        const auto& message = tx["message"].get_ref<const std::string&>();
        octra::JsonShape shape(16384);
        if (message.size() > 1024 * 1024 || !json::sax_parse(message, &shape)) return;
        const auto params = json::parse(message);
        if (!params.is_array() || params.size() < 2 || !params[0].is_string()) return;
        const std::string amount = token_amount_text(params[1]);
        if (amount.empty()) return;
        const auto recipient = params[0].get<std::string>();
        if (!octra::program_cli::valid_address(recipient)) return;
        tx["recipient"] = recipient;
        tx["token_amount_raw"] = amount;
    } catch (...) {}
}

static void hydrate_token_rows(const std::string& addr, json& rows, bool finalized) {
    if (!rows.is_array()) return;
    refresh_history_rows(addr, rows);
    for (auto& row : rows) bind_token_row(row, finalized);
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

static std::string parse_ou(const json& body, const std::string& default_ou) {
    std::string val = body.value("ou", "");
    if (val.empty()) val = body.value("fee", "");
    if (val.empty()) val = default_ou;
    val = octra::decimal_text(val);
    try {
        long long v = std::stoll(val);
        if (v > octra::pvac_upgrade_policy::max_fee_raw)
            throw octra::TxInputError("transaction fee exceeds wallet limit");
        if (v > 0) return val;
    } catch (const std::out_of_range&) {
        throw octra::TxInputError("transaction fee is out of range");
    }
    throw octra::TxInputError("transaction fee must be positive");
}

static std::string recommended_ou_for_op(const std::string& op, const std::string& default_ou) {
    auto r = g_rpc.call("octra_recommendedFee", json::array({op}), 10);
    if (!r.ok || !r.result.is_object()) return default_ou;
    for (const char* key : {"recommended", "base_fee", "minimum"}) {
        if (!r.result.contains(key)) continue;
        std::string val = r.result[key].is_string()
            ? r.result[key].get<std::string>()
            : r.result[key].dump();
        try {
            size_t pos = 0;
            const int64_t parsed = std::stoll(val, &pos);
            if (pos == val.size()
                && octra::pvac_upgrade_policy::fee_allowed(parsed))
                return std::to_string(parsed);
        } catch (...) {}
    }
    return default_ou;
}

static int64_t program_deploy_base_ou(size_t payload_size) {
    return 200000 + static_cast<int64_t>(
        ((payload_size + 1023) / 1024) * 1000);
}

static int64_t multi_exec_min_ou(size_t call_count) {
    return 1000 + static_cast<int64_t>(1000 * std::max<size_t>(1, call_count));
}

static int64_t program_deploy_required_ou(const std::string& payload) {
    const int64_t base = program_deploy_base_ou(payload.size());
    json hint = {
        {"encrypted_data_len", payload.size()}
    };
    auto r = g_rpc.call(
        "octra_recommendedFee",
        json::array({"program_deploy", hint}),
        10);
    if (!r.ok || !r.result.is_object() || !r.result.contains("minimum"))
        return base;
    try {
        std::string value = r.result["minimum"].is_string()
            ? r.result["minimum"].get<std::string>()
            : r.result["minimum"].dump();
        size_t pos = 0;
        const int64_t parsed = std::stoll(value, &pos);
        if (pos != value.size()) return base;
        if (parsed != base && parsed != base * 2 && parsed != base * 5)
            return base;
        if (!octra::pvac_upgrade_policy::fee_allowed(parsed))
            return base;
        return parsed;
    } catch (...) {
        return base;
    }
}

static void clear_fee_cache() {
    std::lock_guard<std::mutex> lock(g_fee_mtx);
    g_fee_cache.clear();
    g_fee_cache_ts = 0.0;
}

static bool is_octra_address(const std::string& addr) {
    return addr.size() == 47 && addr.substr(0, 3) == "oct";
}

static bool is_active_media_type(const std::string& media_type) {
    static const std::set<std::string> active = {
        "image/svg+xml",
        "text/html",
        "application/xhtml+xml",
        "application/javascript",
        "text/javascript",
        "application/ecmascript",
        "text/ecmascript",
        "application/x-javascript",
        "module",
        "application/wasm",
        "application/xslt+xml"
    };
    return active.count(media_type) > 0;
}

static bool is_inert_media_type(const std::string& media_type) {
    static const std::set<std::string> inert = {
        "text/plain",
        "text/css",
        "text/csv",
        "text/markdown",
        "application/json",
        "application/pdf",
        "application/font-woff",
        "application/font-woff2",
        "application/x-font-ttf",
        "application/x-font-otf",
        "application/vnd.ms-fontobject"
    };
    if (inert.count(media_type) > 0) return true;
    return starts_with(media_type, "image/")
        || starts_with(media_type, "audio/")
        || starts_with(media_type, "video/")
        || starts_with(media_type, "font/");
}

static bool cross_site_script_request(const httplib::Request& req) {
    const std::string site = lower_ascii(req.get_header_value("Sec-Fetch-Site"));
    const std::string destination = lower_ascii(req.get_header_value("Sec-Fetch-Dest"));
    return site == "cross-site" && destination == "script";
}

static bool serve_inline_allowed(const std::string& media_type, const httplib::Request& req) {
    if (!is_active_media_type(media_type)) return is_inert_media_type(media_type);
    const bool script_media =
        media_type == "application/javascript" ||
        media_type == "text/javascript" ||
        media_type == "application/ecmascript" ||
        media_type == "text/ecmascript" ||
        media_type == "application/x-javascript" ||
        media_type == "module";
    return script_media && cross_site_script_request(req);
}

static constexpr size_t CIRCLE_ASSET_MAX_RAW_BYTES = 33554432;
static constexpr size_t CIRCLE_ASSET_MAX_B64_BYTES = ((CIRCLE_ASSET_MAX_RAW_BYTES + 2) / 3) * 4;

static size_t circle_asset_size_limit(size_t wire_len) {
    return ((wire_len + 3) / 4) * 3;
}

static int64_t circle_asset_ou_from_b64_len(size_t wire_len) {
    const size_t raw_limit = circle_asset_size_limit(wire_len);
    if (raw_limit <= 4096) return 5000;
    if (raw_limit <= 16384) return 10000;
    if (raw_limit <= 32768) return 20000;
    if (raw_limit <= 131072) return 40000;
    if (raw_limit <= 524288) return 80000;
    if (raw_limit <= 2097152) return 160000;
    if (raw_limit <= 8388608) return 320000;
    return 640000;
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
    if (frac_part.size() > 6) return -1;
    while (frac_part.size() < 6) frac_part += '0';
    int64_t ip = integer_part.empty() ? 0 : std::stoll(integer_part);
    if (ip > MAX_OCT_RAW / 1000000) return -1;
    int64_t fp = std::stoll(frac_part);
    return ip * 1000000 + fp;
}

struct BalanceInfo {
    int nonce = 0;
    int confirmed_nonce = 0;
    int pending_nonce = 0;
    int staging_nonce = 0;
    std::string balance_raw = "0";
    bool ok = false;
};

static BalanceInfo get_nonce_balance_for(const std::string& addr, octra::RpcClient& rpc = g_rpc,
                                       bool allow_unknown = false) {
    const auto r = rpc.get_balance(addr);
    if (allow_unknown && !r.ok && r.replied && r.code == 100 && r.error == "sender not found")
        return BalanceInfo{};
    if (!r.ok || !r.result.is_object() || !r.result.contains("nonce"))
        throw octra::RpcStateError("cannot read account nonce");
    BalanceInfo info;
    info.ok = true;
    info.confirmed_nonce = octra::rpc_nonce(r.result["nonce"]);
    info.pending_nonce = r.result.contains("pending_nonce")
        ? octra::rpc_nonce(r.result["pending_nonce"]) : info.confirmed_nonce;
    if (info.pending_nonce < info.confirmed_nonce)
        throw octra::RpcStateError("pending nonce precedes confirmed nonce");
    info.nonce = info.pending_nonce;
    std::string raw = "0";
    if (r.result.contains("balance_raw")) {
        auto& v = r.result["balance_raw"];
        raw = v.is_string() ? v.get<std::string>() : std::to_string(v.get<int64_t>());
    } else if (r.result.contains("balance")) {
        auto& v = r.result["balance"];
        json input;
        input["amount"] = v;
        int64_t parsed = parse_amount_raw(input);
        raw = std::to_string(parsed >= 0 ? parsed : 0);
    }
    info.balance_raw = raw;
    if (!r.result.contains("pending_nonce")) {
        const auto pr = rpc.staging_view();
        if (!pr.ok || !pr.result.is_object() || !pr.result.contains("transactions") ||
            !pr.result["transactions"].is_array())
            throw octra::RpcStateError("cannot read pending transactions");
        for (auto& tx : pr.result["transactions"]) {
            if (!tx.is_object() || !tx.contains("from") || !tx["from"].is_string())
                throw octra::RpcStateError("invalid pending transaction");
            if (tx.value("from", "") == addr) {
                if (!tx.contains("nonce"))
                    throw octra::RpcStateError("pending transaction nonce missing");
                int pn = octra::rpc_nonce(tx["nonce"]);
                if (pn > info.staging_nonce) info.staging_nonce = pn;
                if (pn > info.nonce) info.nonce = pn;
            }
        }
        info.pending_nonce = info.nonce;
    }
    return info;
}

static BalanceInfo get_nonce_balance() {
    std::string addr;
    {
        std::lock_guard<std::mutex> lock(g_mtx);
        if (!g_wallet_loaded) return {};
        addr = g_wallet.addr;
    }
    return get_nonce_balance_for(addr);
}

static void sign_tx_fields_for(octra::Transaction& tx, const std::string& pub_b64, const uint8_t sk[64]) {
    std::string msg = octra::signing_json(tx);
    tx.signature = octra::ed25519_sign_detached(
        reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), sk);
    tx.public_key = pub_b64;
}

static void sign_tx_fields(octra::Transaction& tx) {
    sign_tx_fields_for(tx, g_wallet.pub_b64, g_wallet.sk);
}

static PvacWalletSnapshot pvac_wallet_snapshot() {
    PvacWalletSnapshot out;
    std::lock_guard<std::mutex> lock(g_mtx);
    out.loaded = g_wallet_loaded;
    out.pvac_ok = g_pvac_ok;
    out.generation = g_wallet_generation;
    if (!out.loaded || !out.pvac_ok) return out;
    out.addr = g_wallet.addr;
    out.pub_b64 = g_wallet.pub_b64;
    out.priv_b64 = g_wallet.priv_b64;
    std::memcpy(out.sk.data(), g_wallet.sk, out.sk.size());
    return out;
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
                                            const std::string& params,
                                            bool include_storage) {
    const std::string params_hash = octra::sha256_hex(params);
    const std::string subject =
        method + "|" + params_hash + "|" + (include_storage ? "1" : "0");
    return sign_circle_read_request("octra_circle_view", circle_id, subject);
}

static octra::RpcResult circle_info_auth_rpc(const std::string& circle_id) {
    octra::RpcClient rpc(current_public_rpc_url());
    auto result = rpc.circle_info_auth(
        circle_id,
        g_wallet.addr,
        g_wallet.pub_b64,
        sign_circle_read_request("octra_circle_info", circle_id));
    if (!result.ok || !result.result.is_object() ||
        !result.result.contains("owner") || !result.result["owner"].is_string() ||
        result.result["owner"].get<std::string>().empty())
        throw octra::RpcStateError("circle owner read failed");
    return result;
}

static octra::RpcResult circle_hfhe_policy_auth_rpc(const std::string& circle_id) {
    octra::RpcClient rpc(current_public_rpc_url());
    auto result = rpc.circle_hfhe_policy_auth(
        circle_id,
        g_wallet.addr,
        g_wallet.pub_b64,
        sign_circle_read_request("octra_circle_hfhe_policy", circle_id));
    if (!result.ok || !result.result.is_object() ||
        !result.result.contains("policy") || !result.result["policy"].is_object())
        throw octra::RpcStateError("circle hfhe policy read failed");
    return result;
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

static std::string remote_pvac_pubkey_b64(const std::string& addr,
    const WalletRead* identity = nullptr, bool* checked = nullptr,
    uint64_t* revision = nullptr);
static int read_proof_policy(const std::string& addr);

static bool circle_verifier_pvac(octra::PvacBridge& pvac,
                                 std::string& wallet_addr,
                                 uint64_t& wallet_generation,
                                 octra::circle_verifier_policy::Lane::Lease& lease,
                                 std::string& error) {
    auto wallet = pvac_wallet_snapshot();
    if (!wallet.loaded || !wallet.pvac_ok) {
        error = "pvac not available";
        return false;
    }
    wallet_addr = wallet.addr;
    wallet_generation = wallet.generation;
    const std::string remote_pubkey =
        remote_pvac_pubkey_b64(wallet_addr);
    const int policy = read_proof_policy(wallet_addr);
    lease = g_circle_verifier_lane.try_acquire();
    if (!lease) {
        wallet.clear_secrets();
        error = "circle verifier busy";
        return false;
    }
    const bool initialized =
        !remote_pubkey.empty()
        && pvac.init_registered(wallet.priv_b64, remote_pubkey);
    wallet.clear_secrets();
    if (!initialized) {
        error = "registered pvac key profile is unavailable";
        return false;
    }
    pvac.proof_policy(policy);
    return true;
}

static std::string circle_wallet_address() {
    std::lock_guard<std::mutex> lock(g_mtx);
    return g_wallet_loaded ? g_wallet.addr : "";
}

static bool circle_wallet_current(const std::string& addr, uint64_t generation) {
    std::lock_guard<std::mutex> lock(g_mtx);
    return g_wallet_loaded
        && g_wallet.addr == addr
        && g_wallet_generation == generation;
}

static bool circle_verifier_cipher(octra::PvacBridge& pvac,
                                   const std::string& ciphertext_b64,
                                   pvac_cipher& cipher,
                                   std::string& error) {
    cipher = nullptr;
    if (!octra::circle_verifier_policy::ciphertext_size_allowed(
            ciphertext_b64)) {
        error = "circle ciphertext exceeds resource policy";
        return false;
    }
    auto raw = octra::base64_decode(ciphertext_b64);
    if (raw.empty()) {
        error = "invalid ciphertext";
        return false;
    }
    cipher = pvac.deserialize_cipher(raw.data(), raw.size());
    if (!cipher) {
        error = "invalid ciphertext";
        return false;
    }
    if (!octra::circle_verifier_policy::cipher_shape_allowed(cipher)) {
        pvac.free_cipher(cipher);
        cipher = nullptr;
        error = "circle verifier ciphertext exceeds resource policy";
        return false;
    }
    return true;
}

static bool circle_verify_zero(octra::PvacBridge& pvac,
                               const std::string& ciphertext_b64,
                               const std::string& zero_proof_b64,
                               std::string& error) {
    if (!octra::circle_verifier_policy::encoded_size_allowed(
            ciphertext_b64,
            zero_proof_b64)) {
        error = "circle verifier input exceeds resource policy";
        return false;
    }
    pvac_cipher ct = nullptr;
    if (!circle_verifier_cipher(
            pvac,
            ciphertext_b64,
            ct,
            error)) {
        return false;
    }
    pvac_zero_proof proof = nullptr;
    if (!circle_decode_zero_proof(zero_proof_b64, proof, error)) {
        pvac.free_cipher(ct);
        return false;
    }
    bool ok = pvac.verify_zero(ct, proof);
    pvac_free_zero_proof(proof);
    pvac.free_cipher(ct);
    if (!ok) error = "zero proof verification failed";
    return ok;
}

static bool circle_verify_proof(octra::PvacBridge& pvac,
                                const std::string& ciphertext_b64,
                                const std::string& zero_proof_b64,
                                const std::string& amount_commitment_b64,
                                std::string& error) {
    if (!octra::circle_verifier_policy::encoded_size_allowed(
            ciphertext_b64,
            zero_proof_b64)) {
        error = "circle verifier input exceeds resource policy";
        return false;
    }
    if (!octra::circle_verifier_policy::commitment_size_allowed(
            amount_commitment_b64)) {
        error = "invalid amount commitment";
        return false;
    }
    auto commitment = octra::base64_decode(amount_commitment_b64);
    if (commitment.size() != 32) {
        error = "invalid amount commitment";
        return false;
    }
    pvac_cipher ct = nullptr;
    if (!circle_verifier_cipher(
            pvac,
            ciphertext_b64,
            ct,
            error)) {
        return false;
    }
    pvac_zero_proof proof = nullptr;
    if (!circle_decode_zero_proof(zero_proof_b64, proof, error)) {
        pvac.free_cipher(ct);
        return false;
    }
    std::array<uint8_t, 32> point{};
    std::copy(commitment.begin(), commitment.end(), point.begin());
    bool ok = pvac.verify_cipher_proof(ct, proof, point);
    pvac_free_zero_proof(proof);
    pvac.free_cipher(ct);
    if (!ok) error = "cipher proof verification failed";
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
    return proof_kind == "bound_zero_v1" ||
           proof_kind == "bound_zero_receipt_v1" ||
           proof_kind == "range_v1" ||
           proof_kind == "range_receipt_v1";
}

static bool circle_receipt_transport_valid(const json& policy,
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
    if (!circle_receipt_transport_valid(policy, intent_id, error)) {
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

static bool circle_cell_proof_payload(const json& body,
                                      json& payload,
                                      std::string& error) {
    const std::array<const char*, 5> fields = {
        "proof_kind",
        "zero_proof",
        "range_proof",
        "amount_commitment",
        "intent_id"
    };
    for (const char* field : fields) {
        if (body.contains(field)) payload[field] = body[field];
    }
    if (!body.contains("proof_receipt")) {
        if (body.contains("proof_receipt_hash")) {
            error = "proof_receipt_hash requires proof_receipt";
            return false;
        }
        return true;
    }
    if (!body["proof_receipt"].is_object()) {
        error = "proof_receipt must be an object";
        return false;
    }
    const std::string receipt_hash =
        octra::sha256_hex(body["proof_receipt"].dump());
    if (body.contains("proof_receipt_hash") &&
        body.value("proof_receipt_hash", "") != receipt_hash) {
        error = "proof_receipt_hash does not match proof_receipt";
        return false;
    }
    payload["proof_receipt"] = body["proof_receipt"];
    payload["proof_receipt_hash"] = receipt_hash;
    return true;
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

static json submit_tx_for_addr(const octra::Transaction& tx, const std::string& addr) {
    json j = octra::build_tx_json(tx);
    auto r = g_rpc.submit_tx(j);
    if (!r.ok) {
        fprintf(stderr, "event = submit op = %s status = failed error = %s\n",
            tx.op_type.empty() ? "standard" : tx.op_type.c_str(),
            r.error.c_str());
        return err_json(r.error);
    }
    json res;
    std::string tx_hash = r.result.value("tx_hash", "");
    fprintf(stderr, "event = submit op = %s status = accepted\n",
        tx.op_type.empty() ? "standard" : tx.op_type.c_str());
    res["tx_hash"] = tx_hash;
    {
        std::lock_guard<std::mutex> lock(g_mtx);
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
                g_txcache.store_tx(addr, cached);
                if (!known) {
                    int cached_total = g_txcache.get_total(addr);
                    g_txcache.set_total(addr, cached_total + 1);
                }
            }
        }
        history_runtime_clear(addr);
        token_history_runtime_clear(addr);
    }
    return res;
}

static json saved_reply(const json& row) {
    json reply = {{"tx_hash", row["hash"]}, {"status", row["status"]},
        {"retryable", row.value("retryable", false)}};
    if (row.contains("submit_error")) reply["submit_error"] = row["submit_error"];
    if (row.contains("discardable")) reply["discardable"] = row["discardable"];
    if (row["status"] == "unknown") reply["warning"] = row.value("op_type", "") == "key_switch"
        ? "submission outcome unknown; check encryption upgrade status for a same-nonce retry"
        : "submission status unknown; use the saved transaction in history";
    return reply;
}

static json send_saved_tx(const std::string& hash, const std::string& addr,
    uint64_t generation, uint64_t token, const std::string& url) {
    json send;
    {
        std::lock_guard<std::mutex> lock(g_mtx);
        if (!g_wallet_loaded || g_wallet.addr != addr || g_wallet_generation != generation
            || g_own_token != token || g_wallet.rpc_url != url)
            throw octra::RpcStateError("wallet changed before submission");
        send = g_own_history.start(token, hash);
    }
    octra::RpcClient rpc(url);
    const auto result = rpc.submit_tx(send["tx"]);
    auto state = TxJournal::Reply::unknown;
    const auto outcome = octra::pvac_submit_state(result.ok, result.replied, result.code,
        result.result, hash, result.http_status);
    if (outcome == "pending")
        state = TxJournal::Reply::accepted;
    else if (outcome == "unaccepted") state = TxJournal::Reply::retry;
    else if (outcome == "rejected") state = TxJournal::Reply::rejected;
    {
        std::lock_guard<std::mutex> lock(g_mtx);
        if (g_wallet_loaded && g_wallet.addr == addr && g_wallet_generation == generation
            && g_own_token == token && g_wallet.rpc_url == url) {
            g_own_history.finish(token, hash, state, send["uncertain"], result.error);
            history_runtime_clear(addr);
            return saved_reply(g_own_history.find(token, hash));
        }
    }
    return {{"tx_hash", hash}, {"status", "unknown"}, {"warning", "wallet changed; check saved history"}};
}

static std::string private_request_id(const json& body) {
    const auto id = body.value("request_id", "");
    if (!id.empty() && (id.size() != 64 || !std::all_of(id.begin(), id.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    }))) throw octra::TxInputError("invalid request id");
    return id;
}

static json private_cached(const std::string& addr, uint64_t generation,
    const std::string& id, const std::string& key) {
    if (id.empty()) return nullptr;
    const auto token = own_history_open(addr, generation, true);
    json row;
    {
        std::lock_guard<std::mutex> lock(g_mtx);
        if (!g_wallet_loaded || g_wallet.addr != addr || g_wallet_generation != generation
            || g_own_token != token) throw octra::RpcStateError("wallet changed before request lookup");
        try {
            row = g_own_history.find_request(token, id, key);
        } catch (const std::invalid_argument& error) {
            throw octra::TxInputError(error.what());
        }
    }
    if (row.is_null()) return nullptr;
    if (tx_status_is_pending_like(row)) {
        json rows = json::array({row});
        refresh_own_rows(addr, generation, rows);
        row = rows[0];
    }
    auto reply = saved_reply(row);
    reply["reused"] = true;
    return reply;
}

static json private_claim_output_cached(const std::string& addr, uint64_t generation,
    const std::string& output) {
    const auto token = own_history_open(addr, generation, true);
    json row;
    {
        std::lock_guard<std::mutex> lock(g_mtx);
        if (!g_wallet_loaded || g_wallet.addr != addr || g_wallet_generation != generation
            || g_own_token != token) throw octra::RpcStateError("wallet changed before claim output lookup");
        row = g_own_history.find_claim_output(token, output);
    }
    if (row.is_null()) return nullptr;
    if (tx_status_is_pending_like(row)) {
        json rows = json::array({row});
        refresh_own_rows(addr, generation, rows);
        row = rows[0];
    }
    auto reply = saved_reply(row);
    reply["reused"] = true;
    return reply;
}

static json submit_private_tx(const octra::Transaction& tx, uint64_t generation,
    const std::string& to, const std::string& amount, const std::string& output = "",
    const std::string& id = "", const std::string& key = "") {
    const auto hash = octra::tx_hash(tx);
    const auto token = own_history_open(tx.from, generation, true);
    json waiting;
    {
        std::lock_guard<std::mutex> lock(g_mtx);
        waiting = g_own_history.waiting(token);
    }
    if (!waiting.is_null()) {
        json rows = json::array({waiting});
        refresh_own_rows(tx.from, generation, rows);
    }
    std::string url;
    {
        std::lock_guard<std::mutex> lock(g_mtx);
        if (!g_wallet_loaded || g_wallet.addr != tx.from || g_wallet_generation != generation
            || token != g_own_token)
            throw octra::RpcStateError("wallet changed before private submission");
        url = g_wallet.rpc_url;
        json row = {{"hash", hash}, {"from", tx.from}, {"to_", to},
            {"amount_raw", amount}, {"op_type", tx.op_type}, {"timestamp", tx.timestamp}};
        if (!output.empty()) row["output_id"] = output;
        if (!id.empty()) {
            row["request_id"] = id;
            row["request_key"] = key;
        }
        const auto waiting = g_own_history.prepare(token, row, tx);
        if (!waiting.is_null() && waiting.value("reused", false)) {
            auto reply = saved_reply(waiting);
            reply["reused"] = true;
            return reply;
        }
        if (!waiting.is_null())
            return {{"error", "earlier transaction awaits a response; retry it from history"},
                {"tx_hash", waiting["hash"]}, {"status", waiting["status"]}, {"retryable", true}};
    }
    return send_saved_tx(hash, tx.from, generation, token, url);
}

static json submit_program_call_tx(const std::string& target,
                                   const std::string& op_type,
                                   const std::string& method,
                                   const json& params,
                                   const json& body,
                                   const std::string& default_ou) {
    if (octra::decimal_text(body.value("amount", "0")) != "0")
        throw octra::TxInputError("object management amount must be zero");
    if (body.contains("approved_params")
        && (!body["approved_params"].is_array() || body["approved_params"] != params))
        throw octra::TxInputError("object management parameters differ from approval");
    const auto ou = parse_ou(body, default_ou);
    auto bi = get_nonce_balance_for(g_wallet.addr);
    octra::Transaction tx;
    tx.from = g_wallet.addr;
    tx.to_ = target;
    tx.amount = "0";
    tx.nonce = bi.nonce + 1;
    tx.ou = ou;
    tx.timestamp = now_ts();
    tx.op_type = op_type;
    tx.encrypted_data = method;
    tx.message = params.dump();
    sign_tx_fields(tx);
    return submit_tx(tx);
}

static std::string compute_aes_kat_hex();
static bool g_pvac_foreign = false;

struct EncBalResult {
    std::string cipher;
    int64_t decrypted = 0;
    bool ok = false;
    bool amount_known = false;
    bool key_proven = false;
    bool legacy_owner_decoded = false;
    bool inspected = false;
    bool read_unavailable = false;
    std::string error;
    std::optional<std::string> public_key;
    bool public_key_compatible = false;
};

struct EncBalCache {
    uint64_t generation = 0;
    std::string addr;
    std::string cipher;
    std::string public_key;
    EncBalResult result;
    std::chrono::steady_clock::time_point expires{};
};

static std::mutex g_enc_bal_cache_mtx;
static std::timed_mutex g_balance_decode_mtx;
static std::timed_mutex g_key_read_mtx;
static octra::PvacKeyCache g_key_read_cache;
static uint64_t g_balance_revision = 0;
static uint64_t g_key_change_revision = 0;
static std::optional<EncBalCache> g_enc_bal_cache;
static std::optional<EncBalCache> g_opening_cache;

static void clear_enc_bal_cache() {
    std::lock_guard<std::mutex> lock(g_enc_bal_cache_mtx);
    g_key_read_cache.clear();
    ++g_balance_revision;
    for (auto* cache : {&g_enc_bal_cache, &g_opening_cache}) {
        if (*cache) octra::secure_zero(&(*cache)->result.decrypted, sizeof((*cache)->result.decrypted));
        cache->reset();
    }
}

static void remember_pvac_key(const std::string& key) {
    if (g_pvac_remote_pubkey_b64 != key) {
        clear_enc_bal_cache();
        g_key_change_revision = g_balance_revision;
    }
    g_pvac_remote_pubkey_b64 = key;
}

static EncBalResult get_encrypted_balance(const WalletRead* identity = nullptr);

static EncBalResult local_balance_opening(const WalletRead& read, const std::string& cipher,
    const std::string& remote = "") {
    const auto hash = octra::sha256_hex(cipher);
    const auto cached_opening = [&]() -> std::optional<EncBalResult> {
        std::lock_guard<std::mutex> lock(g_mtx);
        read.check();
        std::lock_guard<std::mutex> cache_lock(g_enc_bal_cache_mtx);
        if (g_opening_cache && g_opening_cache->generation == read.generation
            && g_opening_cache->addr == read.addr && g_opening_cache->cipher == hash
            && g_opening_cache->public_key == remote) return g_opening_cache->result;
        return std::nullopt;
    };
    if (const auto cached = cached_opening()) return *cached;
    std::unique_lock<std::timed_mutex> decode_lock(g_balance_decode_mtx, std::defer_lock);
    if (!decode_lock.try_lock_for(std::chrono::seconds(15)))
        throw octra::RpcStateError("balance decoding wait expired");
    if (const auto cached = cached_opening()) return *cached;
    uint64_t revision;
    std::unique_ptr<octra::PvacBridge> decoder;
    {
        std::lock_guard<std::mutex> cache_lock(g_enc_bal_cache_mtx);
        revision = g_balance_revision;
    }
    {
        std::lock_guard<std::mutex> lock(g_mtx);
        read.check();
        decoder = g_pvac.snapshot();
    }
    EncBalResult result;
    result.amount_known = remote.empty() ? decoder->try_get_balance(cipher, result.decrypted)
        : decoder->pubkey_matches_stored_secret(remote)
            && decoder->try_get_stored_balance(cipher, remote, result.decrypted);
    {
        std::lock_guard<std::mutex> lock(g_mtx);
        read.check();
        std::lock_guard<std::mutex> cache_lock(g_enc_bal_cache_mtx);
        if (revision != g_balance_revision)
            throw octra::WalletSessionError("balance state changed during read");
        g_opening_cache = EncBalCache{read.generation, read.addr, hash, remote, result};
    }
    return result;
}

struct LegacyCommitmentBlinding {
    bool ok = false;
    std::array<uint8_t, 32> blinding{};
    std::string error;
};

static LegacyCommitmentBlinding legacy_commitment_blinding_for_wallet(const std::string& addr,
                                                                      const std::array<uint8_t, 64>& sk,
                                                                      octra::PvacBridge& pvac) {
    LegacyCommitmentBlinding out;
    auto scan = octra::fetch_stealth_outputs(g_rpc, stealth_scan_from_epoch(), 30);
    if (!scan.ok) {
        out.error = scan.error.empty()
            ? "cannot scan stealth outputs for migration blinding"
            : scan.error;
        return out;
    }
    uint8_t view_sk[32];
    uint8_t view_pk[32];
    octra::derive_view_keypair(sk.data(), view_sk, view_pk);
    std::array<uint8_t, 32> acc{};
    for (auto& item : scan.outputs) {
        std::string sender = item.value("sender_addr", "");
        bool sent_by_wallet = sender == addr;
        bool claimed = item.value("claimed", 0) != 0;
        if (!sent_by_wallet && !claimed) continue;
        auto eph_raw = octra::base64_decode(item.value("eph_pub", ""));
        if (eph_raw.size() != 32) {
            if (sent_by_wallet) {
                out.error = "sent stealth output has invalid eph_pub";
                return out;
            }
            continue;
        }
        auto shared = octra::ecdh_shared_secret(view_sk, eph_raw.data());
        auto my_tag = octra::compute_stealth_tag(shared);
        if (octra::hex_encode(my_tag.data(), 16) != item.value("stealth_tag", "")) {
            if (sent_by_wallet) {
                out.error = "sent stealth output cannot be opened by this wallet";
                return out;
            }
            continue;
        }
        auto dec = octra::decrypt_stealth_amount(shared, item.value("enc_amount", ""));
        if (!dec.has_value()) {
            if (sent_by_wallet) {
                out.error = "sent stealth output amount cannot be opened";
                return out;
            }
            continue;
        }
        auto stored = octra::base64_decode(item.value("amount_commitment", ""));
        if (stored.size() != 32) {
            out.error = "stealth output amount commitment missing";
            return out;
        }
        auto local = pvac.pedersen_commit(dec->amount, dec->blinding.data());
        if (std::memcmp(local.data(), stored.data(), 32) != 0) {
            out.error = "stealth output commitment mismatch";
            return out;
        }
        if (sent_by_wallet) {
            acc = pvac.blinding_sub(acc, dec->blinding);
        }
        if (claimed) {
            acc = pvac.blinding_add(acc, dec->blinding);
        }
    }
    out.ok = true;
    out.blinding = acc;
    return out;
}

static bool fill_pvac_key_switch_tx(octra::Transaction& tx,
                                    const std::string& addr,
                                    const std::string& pub_b64,
                                    const uint8_t sk[64],
                                    octra::PvacBridge& pvac,
                                    int nonce,
                                    const std::string& ou,
                                    const json& migration,
                                    std::string& error) {
    size_t pk_len = 0;
    uint8_t* pk_data = pvac_serialize_pubkey(pvac.pk(), &pk_len);
    if (!pk_data || pk_len == 0) {
        error = "failed to serialize pubkey";
        return false;
    }
    std::string pk_b64 = octra::base64_encode(pk_data, pk_len);
    std::string kat_hex = compute_aes_kat_hex();
    json enc_data;
    enc_data["new_pubkey"] = pk_b64;
    enc_data["aes_kat"] = kat_hex;
    for (auto it = migration.begin(); it != migration.end(); ++it) {
        enc_data[it.key()] = it.value();
    }
    unsigned char key_hash[32];
    SHA256(pk_data, pk_len, key_hash);
    free(pk_data);
    if ((pvac.proof_policy() & 2) != 0) {
        try {
            std::string owner_input = "octra:pvac:key_owner";
            owner_input.push_back('\0');
            owner_input += addr;
            std::array<uint8_t, 32> blind;
            std::array<uint8_t, 32> seed;
            SHA256(reinterpret_cast<const unsigned char*>(owner_input.data()),
                   owner_input.size(), blind.data());
            octra::random_bytes(seed.data(), seed.size());
            std::unique_ptr<void, decltype(&pvac_free_cipher)> owner_ct(
                pvac.encrypt(0, seed.data()), &pvac_free_cipher);
            octra::secure_zero(seed.data(), seed.size());
            if (!owner_ct) throw std::runtime_error("key ownership cipher failed");
            std::unique_ptr<void, decltype(&pvac_free_zero_proof)> owner_proof(
                pvac.make_cipher_proof(owner_ct.get(), 0, blind.data()),
                &pvac_free_zero_proof);
            if (!owner_proof) throw std::runtime_error("key ownership proof failed");
            enc_data["owner_cipher"] = pvac.encode_proven_cipher(owner_ct.get());
            enc_data["owner_proof"] = pvac.encode_zero_proof(owner_proof.get());
        } catch (const std::exception& failure) {
            error = failure.what();
            return false;
        }
    }
    char hex[17];
    for (int i = 0; i < 8; i++)
        snprintf(hex + i * 2, 3, "%02x", key_hash[i]);
    tx.from = addr;
    tx.to_ = addr;
    tx.amount = "0";
    tx.nonce = nonce;
    tx.ou = ou;
    tx.timestamp = now_ts();
    tx.op_type = "key_switch";
    tx.encrypted_data = enc_data.dump();
    tx.message = "encryption key switch | new_key:" + std::string(hex);
    sign_tx_fields_for(tx, pub_b64, sk);
    return true;
}

static json submit_pvac_key_switch_tx(const std::string& addr,
                                      const std::string& pub_b64,
                                      const uint8_t sk[64],
                                      octra::PvacBridge& pvac,
                                      const json& migration,
                                      const std::string& ou,
                                      uint64_t generation,
                                      const json& retry) {
    std::string error;
    auto bi = get_nonce_balance_for(addr);
    octra::Transaction tx;
    const auto nonce = retry.is_null() ? bi.nonce + 1 : retry.at("retry_nonce").get<int>();
    if (!fill_pvac_key_switch_tx(tx, addr, pub_b64, sk, pvac, nonce, ou, migration, error)) {
        return err_json(error);
    }
    const auto hash = octra::tx_hash(tx);
    const auto token = own_history_open(addr, generation, true);
    std::string url;
    {
        std::lock_guard<std::mutex> lock(g_mtx);
        if (!g_wallet_loaded || g_wallet.addr != addr || g_wallet_generation != generation
            || token != g_own_token) throw octra::WalletSessionError("wallet changed before key submission");
        url = g_wallet.rpc_url;
        const auto prior = g_own_history.prepare_migration(token, {{"hash", hash}, {"from", addr},
            {"to_", addr}, {"amount_raw", "0"}, {"op_type", tx.op_type}, {"timestamp", tx.timestamp}}, tx,
            retry.is_null() ? "" : retry.at("tx_hash").get<std::string>());
        if (!prior.is_null()) {
            auto result = saved_reply(prior);
            result["reused"] = true;
            return result;
        }
        pvac_upgrade_stage_set("submitted", "submission outcome pending", hash);
    }
    octra::RpcClient rpc(url);
    const auto reply = rpc.submit_tx(octra::build_tx_json(tx));
    const auto state = octra::pvac_submit_state(reply.ok, reply.replied, reply.code,
        reply.result, hash, reply.http_status);
    std::lock_guard<std::mutex> lock(g_mtx);
    if (!g_wallet_loaded || g_wallet.addr != addr || g_wallet_generation != generation
        || token != g_own_token || g_wallet.rpc_url != url)
        throw octra::WalletSessionError("wallet changed after key submission");
    if (state != "unknown") g_own_history.update(token, hash, {{"hash", hash}, {"status", state}});
    history_runtime_clear(addr);
    auto result = saved_reply(g_own_history.find(token, hash));
    if (!reply.error.empty()) result["submit_error"] = reply.error;
    return result;
}

static bool build_pvac_migration_payload(octra::PvacBridge& pvac,
                                         const std::string& addr,
                                         const std::array<uint8_t, 64>& sk,
                                         const std::string& cipher,
                                         const std::string& old_pubkey,
                                         int64_t amount,
                                         const std::string& mode,
                                         const json& status,
                                         json& migration,
                                         std::string& error) {
    if (!pvac.pk() || !pvac.sk()) {
        error = "pvac not available";
        return false;
    }
    const bool legacy_zero_reset = mode == "legacy_zero_reset";
    const bool key_refresh =
        mode == "key_bound_migration" &&
        status.value("encrypted_balance_known", false);
    const bool valid_amount =
        legacy_zero_reset
            ? amount == 0
            : key_refresh
            ? amount >= 0
            : amount > 0;
    if (!valid_amount) {
        error = "encrypted balance is empty or unreadable";
        return false;
    }
    const bool legacy_public = mode == "legacy_public_migration";
    const bool legacy_commitment = mode == "legacy_commitment_migration";
    const bool key_proven = !legacy_public && !legacy_commitment && !legacy_zero_reset;
    if (!legacy_public && !legacy_commitment && !legacy_zero_reset &&
        !pvac.has_key_proof(cipher)) {
        error = "legacy encrypted balance needs ciphertext migration before upgrade";
        return false;
    }
    if (key_proven && old_pubkey.empty()) {
        error = "registered pvac key is unavailable";
        return false;
    }
    if (key_proven && !pvac.pubkey_matches_stored_secret(old_pubkey)) {
        error = "registered pvac key uses a different proof profile";
        return false;
    }
    if (key_proven) {
        int64_t old_amount = 0;
        if (!pvac.try_get_stored_balance(cipher, old_pubkey, old_amount) ||
            old_amount != amount) {
            error = "registered pvac key cannot open the current encrypted balance";
            return false;
        }
    }
    pvac_cipher old_ct = nullptr;
    std::string old_cipher = cipher;
    if (!legacy_public && !legacy_commitment && !legacy_zero_reset) {
        old_ct = pvac.decode_cipher(old_cipher);
        if (!old_ct) {
            error = "cannot decode encrypted balance";
            return false;
        }
    }
    uint8_t seed[32];
    uint8_t blinding[32];
    octra::random_bytes(seed, 32);
    octra::random_bytes(blinding, 32);
    std::array<uint8_t, 32> commitment_override{};
    bool has_commitment_override = false;
    if (legacy_commitment) {
        std::string commitment_b64 = status.value("legacy_commitment_net", "");
        auto commitment = octra::base64_decode(commitment_b64);
        if (commitment.size() != 32) {
            error = "legacy commitment migration requires network replay commitment";
            return false;
        }
        auto blinding_result = legacy_commitment_blinding_for_wallet(addr, sk, pvac);
        if (!blinding_result.ok) {
            error = blinding_result.error;
            return false;
        }
        std::memcpy(blinding, blinding_result.blinding.data(), 32);
        std::memcpy(commitment_override.data(), commitment.data(), 32);
        has_commitment_override = true;
    }
    pvac_cipher new_ct = nullptr;
    pvac_zero_proof old_zp = nullptr;
    pvac_zero_proof new_zp = nullptr;
    try {
        new_ct = pvac.encrypt(static_cast<uint64_t>(amount), seed);
        if (!new_ct) {
            error = "cannot encrypt migrated balance";
            pvac.free_cipher(old_ct);
            return false;
        }
        auto commit = pvac.pedersen_commit(static_cast<uint64_t>(amount), blinding);
        if (has_commitment_override && std::memcmp(commit.data(), commitment_override.data(), 32) != 0) {
            error = "local migration blinding does not match network replay commitment";
            pvac.free_cipher(new_ct);
            return false;
        }
        if (key_proven) {
            old_zp = pvac.make_switch_proof_with_key(
                old_pubkey,
                old_ct,
                static_cast<uint64_t>(amount),
                blinding);
            new_zp = pvac.make_cipher_proof(
                new_ct,
                static_cast<uint64_t>(amount),
                blinding);
        } else {
            new_zp = pvac.make_cipher_proof(new_ct, static_cast<uint64_t>(amount), blinding);
        }
        if ((!legacy_public && !legacy_commitment && !legacy_zero_reset && !old_zp) || !new_zp) {
            error = "cannot prove encrypted balance migration";
            pvac.free_cipher(old_ct);
            pvac.free_cipher(new_ct);
            pvac.free_zero_proof(old_zp);
            pvac.free_zero_proof(new_zp);
            return false;
        }
        const bool old_proof_ok = !key_proven ||
            pvac.verify_switch_proof_with_key(
                old_pubkey,
                old_ct,
                old_zp,
                commit);
        const bool new_proof_ok = pvac.verify_cipher_proof(new_ct, new_zp, commit);
        if (!old_proof_ok || !new_proof_ok) {
            error = old_proof_ok
                ? "local new encrypted balance proof verification failed"
                : "local old encrypted balance proof verification failed";
            pvac.free_cipher(old_ct);
            pvac.free_cipher(new_ct);
            pvac.free_zero_proof(old_zp);
            pvac.free_zero_proof(new_zp);
            return false;
        }
        migration["new_cipher"] = pvac.encode_proven_cipher(new_ct);
        migration["new_zero_proof"] = pvac.encode_zero_proof(new_zp);
        migration["amount_commitment"] = octra::base64_encode(commit.data(), commit.size());
        if (legacy_public) {
            migration["legacy_public_migration"] = true;
            migration["amount_blinding"] = octra::base64_encode(blinding, 32);
        } else if (legacy_commitment) {
            migration["legacy_commitment_migration"] = true;
        } else if (legacy_zero_reset) {
            migration["legacy_zero_reset"] = true;
            migration["amount_blinding"] = octra::base64_encode(blinding, 32);
        } else {
            migration["old_zero_proof"] = pvac.encode_zero_proof(old_zp);
            migration["source_cipher_hash"] = octra::sha256_hex(old_cipher);
        }
        pvac.free_cipher(old_ct);
        pvac.free_cipher(new_ct);
        pvac.free_zero_proof(old_zp);
        pvac.free_zero_proof(new_zp);
        return true;
    } catch (const std::exception& e) {
        error = e.what();
    } catch (...) {
        error = "cannot build encrypted balance migration";
    }
    pvac.free_cipher(old_ct);
    pvac.free_cipher(new_ct);
    pvac.free_zero_proof(old_zp);
    pvac.free_zero_proof(new_zp);
    return false;
}

static bool parse_positive_raw_string(const json& value, int64_t& out) {
    try {
        std::string s;
        if (value.is_string()) s = value.get<std::string>();
        else if (value.is_number_integer()) s = std::to_string(value.get<int64_t>());
        else return false;
        if (s.empty()) return false;
        size_t pos = 0;
        long long parsed = std::stoll(s, &pos);
        if (pos != s.size() || parsed <= 0) return false;
        out = static_cast<int64_t>(parsed);
        return true;
    } catch (...) {
        return false;
    }
}

static bool parse_balance_raw_string(const json& value, int64_t& out) {
    try {
        std::string s;
        if (value.is_string()) s = value.get<std::string>();
        else if (value.is_number_integer()) s = std::to_string(value.get<int64_t>());
        else return false;
        if (s.empty()) return false;
        for (char c : s)
            if (c < '0' || c > '9') return false;
        size_t pos = 0;
        long long parsed = std::stoll(s, &pos);
        if (pos != s.size() || parsed < 0 || parsed > MAX_OCT_RAW) return false;
        out = static_cast<int64_t>(parsed);
        return true;
    } catch (...) {
        return false;
    }
}

struct PvacUpgradeFee {
    bool ok = false;
    std::string raw;
    std::string error;
};

static PvacUpgradeFee pvac_key_switch_fee(const json& approved = nullptr, octra::RpcClient& rpc = g_rpc) {
    auto r = rpc.call("octra_recommendedFee", json::array({"key_switch"}), 10);
    if (!r.ok) return {false, "", "network key_switch fee unavailable"};
    if (!approved.is_null()) {
        int64_t amount = 0;
        int64_t minimum = 0;
        const auto floor = r.result.is_object() ? r.result.value("minimum", r.result.value("base_fee", json())) : json();
        if (!approved.is_string() || !parse_positive_raw_string(approved, amount)
            || approved.get<std::string>() != std::to_string(amount)
            || !octra::pvac_upgrade_policy::fee_allowed(amount))
            return {false, "", "approved key_switch fee is outside the wallet safety limit"};
        if (!parse_positive_raw_string(floor, minimum))
            return {false, "", "network key_switch minimum unavailable"};
        if (amount < std::max(minimum, octra::pvac_upgrade_policy::min_fee_raw))
            return {false, "", "approved key_switch fee is below the network minimum"};
        return {true, std::to_string(amount), ""};
    }
    if (!r.result.is_object() || !r.result.contains("recommended"))
        return {false, "", "network returned an invalid key_switch fee"};
    int64_t parsed = 0;
    if (!parse_positive_raw_string(r.result["recommended"], parsed) ||
        !octra::pvac_upgrade_policy::fee_allowed(std::max(parsed, octra::pvac_upgrade_policy::min_fee_raw))) {
        return {
            false,
            "",
            "network key_switch fee is outside the wallet safety limit"
        };
    }
    return {true, std::to_string(std::max(parsed, octra::pvac_upgrade_policy::min_fee_raw)), ""};
}

static bool raw_amount_ge(const std::string& have, const std::string& need) {
    try {
        size_t hp = 0, np = 0;
        long long have_n = std::stoll(have, &hp);
        long long need_n = std::stoll(need, &np);
        return hp == have.size() && np == need.size() && have_n >= need_n;
    } catch (...) {
        return false;
    }
}

static bool pvac_registered_key_compatible(octra::PvacBridge& pvac, const std::string& remote_pk,
                                           const std::string& local_pk) {
    if (remote_pk.empty()) return false;
    if (remote_pk == local_pk) return true;
    try {
        return pvac.pubkey_extends_local(remote_pk) ||
            pvac.pubkey_matches_legacy_v1(remote_pk) ||
            pvac.pubkey_matches_secret_profile(remote_pk);
    } catch (...) {
        return false;
    }
}

static int read_proof_policy(const std::string& addr) {
    const auto status = g_rpc.get_pvac_migration_status(addr, 8);
    if (!status.ok || !status.result.is_object() ||
        status.result.value("address", json{}) != addr)
        throw octra::RpcStateError("network proof arithmetic is unavailable");
    try {
        if (status.result.contains("proof_math"))
            return octra::proof_policy(status.result);
        const auto runtime = g_rpc.call("octra_runtimeVersion", json::array(), 8);
        if (!runtime.ok)
            throw octra::RpcStateError("network proof arithmetic is unavailable");
        return octra::profile_math(runtime.result);
    } catch (const std::runtime_error& error) {
        throw octra::RpcStateError(error.what());
    }
}

static void check_proof_policy(const std::string& addr, int prepared) {
    octra::require_proof_policy(prepared, read_proof_policy(addr));
}

static std::string local_pvac_pubkey_b64() {
    if (!g_pvac_pubkey_b64.empty()) return g_pvac_pubkey_b64;
    g_pvac_pubkey_b64 = g_pvac.serialize_pubkey_b64();
    return g_pvac_pubkey_b64;
}

static std::shared_ptr<const octra::PvacKeyRead> read_pvac_key(const WalletRead& read,
    bool reuse, std::optional<bool> present = {}) {
    const auto cached = [&]() {
        std::lock_guard<std::mutex> lock(g_mtx);
        read.check();
        return reuse ? g_key_read_cache.get(read.generation, read.addr, read.url, present)
            : std::shared_ptr<const octra::PvacKeyRead>{};
    };
    if (const auto value = cached()) return value;
    std::unique_lock<std::timed_mutex> key_lock(g_key_read_mtx, std::defer_lock);
    if (reuse && !key_lock.try_lock_for(std::chrono::seconds(15))) {
        std::lock_guard<std::mutex> lock(g_mtx);
        read.check();
        return {};
    }
    if (const auto value = cached()) return value;
    uint64_t revision;
    std::string local;
    {
        std::lock_guard<std::mutex> lock(g_mtx);
        read.check();
        if (!g_pvac_ok) return {};
        local = local_pvac_pubkey_b64();
        std::lock_guard<std::mutex> cache_lock(g_enc_bal_cache_mtx);
        revision = g_balance_revision;
    }
    octra::RpcClient rpc(read.url);
    const auto result = rpc.get_pvac_pubkey(read.addr, 20);
    const bool valid = result.ok && result.result.is_object()
        && result.result.contains("pvac_pubkey")
        && (result.result["pvac_pubkey"].is_null() || result.result["pvac_pubkey"].is_string());
    auto value = std::make_shared<octra::PvacKeyRead>();
    if (valid) {
        value->key = result.result["pvac_pubkey"].is_string()
            ? result.result["pvac_pubkey"].get<std::string>() : "";
        value->current = !value->key.empty() && value->key == local;
        value->compatible = value->current;
        if (!value->key.empty() && !value->current) {
            std::unique_ptr<octra::PvacBridge> decoder;
            {
                std::lock_guard<std::mutex> lock(g_mtx);
                read.check();
                std::lock_guard<std::mutex> cache_lock(g_enc_bal_cache_mtx);
                if (!octra::pvac_key_revision(revision, g_balance_revision, g_key_change_revision,
                    value->key == g_pvac_remote_pubkey_b64))
                    throw octra::WalletSessionError("balance state changed during key lookup");
                decoder = g_pvac.snapshot();
            }
            value->compatible = pvac_registered_key_compatible(*decoder, value->key, local);
        }
    }
    std::lock_guard<std::mutex> lock(g_mtx);
    read.check();
    if (!valid) return {};
    {
        std::lock_guard<std::mutex> cache_lock(g_enc_bal_cache_mtx);
        if (!octra::pvac_key_revision(revision, g_balance_revision, g_key_change_revision,
            value->key == g_pvac_remote_pubkey_b64))
            throw octra::WalletSessionError("balance state changed during key lookup");
    }
    remember_pvac_key(value->key);
    value->revision = g_balance_revision;
    g_key_read_cache.put(read.generation, read.addr, read.url, value);
    g_pvac_confirmed = value->current;
    g_pvac_foreign = !value->key.empty() && !value->compatible;
    return value;
}

static std::string remote_pvac_pubkey_b64(const std::string& addr,
    const WalletRead* identity, bool* checked, uint64_t* revision) {
    const auto read = identity ? *identity : wallet_read();
    if (read.addr != addr) throw octra::WalletSessionError("wallet changed during key lookup");
    const auto value = read_pvac_key(read, identity != nullptr);
    if (checked) *checked = bool(value);
    if (!value) throw octra::RpcStateError("registered pvac key is unavailable");
    if (revision) *revision = value->revision;
    return value->key;
}

static bool pvac_balance_needs_privacy_refresh(octra::PvacBridge& pvac, const std::string& cipher) {
    if (cipher.empty() || cipher == "0") return false;
    if (!pvac.has_key_proof(cipher)) return true;
    return !pvac.has_committed_r(cipher);
}

static bool pvac_repair_required_for_current_wallet() {
    return g_wallet_loaded && !g_pvac_repair_required_addr.empty() && g_pvac_repair_required_addr == g_wallet.addr;
}

static bool pvac_repair_blocked_for_current_wallet() {
    return g_wallet_loaded && !g_pvac_repair_blocked_addr.empty() && g_pvac_repair_blocked_addr == g_wallet.addr;
}

static void mark_pvac_repair_required(const std::string& addr) {
    g_pvac_repair_tx = {};
    g_pvac_repair_required_addr = addr;
    if (g_pvac_repair_blocked_addr != addr) return;
    g_pvac_repair_blocked_addr.clear();
    g_pvac_repair_blocked_reason.clear();
}

static void mark_pvac_repair_blocked(const std::string& addr, const std::string& reason) {
    g_pvac_repair_tx = {};
    g_pvac_repair_required_addr.clear();
    g_pvac_repair_blocked_addr = addr;
    g_pvac_repair_blocked_reason = reason;
}

static void clear_pvac_repair_required() {
    g_pvac_repair_tx = {};
    g_pvac_repair_required_addr.clear();
    g_pvac_repair_blocked_addr.clear();
    g_pvac_repair_blocked_reason.clear();
}

static bool settle_pvac_upgrade(const std::string& state, const std::string& hash,
    const std::string& detail, bool key_confirmed = false) {
    const auto cleared = state == "confirmed" ? pvac_upgrade_ack(hash) : pvac_upgrade_reject(hash, detail);
    if (!cleared) return false;
    if (state == "confirmed" || key_confirmed) {
        g_pvac_confirmed = false;
        g_pvac_foreign = false;
        g_pvac_remote_pubkey_b64.clear();
        clear_pvac_repair_required();
    } else if (pvac_repair_required_for_current_wallet() || pvac_repair_blocked_for_current_wallet()) {
        g_pvac_repair_tx = {g_own_token, hash};
    }
    clear_enc_bal_cache();
    return true;
}

static std::string finish_pvac_upgrade(const WalletRead& read, const std::string& hash,
    const std::string& expected = "") {
    octra::RpcClient rpc(read.url);
    const auto reply = rpc.get_transaction(hash, 5);
    const auto state = reply.ok ? octra::pvac_tx_terminal(reply.result, hash) : "";
    if (state.empty() || (!expected.empty() && state != expected)) return {};
    const auto token = own_history_open(read.addr, read.generation);
    std::lock_guard<std::mutex> lock(g_mtx);
    read.check();
    json recent;
    if (token != g_own_token || !pvac_upgrade_recent_json(recent)
        || recent["tx_hash"] != hash) return {};
    if ((reply.result.contains("chain_id") && reply.result["chain_id"] != g_own_chain)
        || (reply.result.contains("from") && reply.result["from"] != read.addr))
        throw octra::RpcStateError("upgrade transaction chain mismatch");
    if (!g_own_history.find(token, hash).is_null()) g_own_history.update(token, hash, reply.result);
    return settle_pvac_upgrade(state, hash, "transaction rejected by chain",
        g_own_history.migration_confirmed(token, hash)) ? state : std::string{};
}

static void apply_pvac_upgrade_fee_gate(json& j, const WalletRead& read) {
    if (!j.value("can_submit", false))
        return;
    octra::RpcClient rpc(read.url);
    const PvacUpgradeFee fee = pvac_key_switch_fee(nullptr, rpc);
    if (!fee.ok) {
        j["can_submit"] = false;
        j["mode"] = "fee_blocked";
        j["reason"] = fee.error;
        return;
    }
    auto bi = get_nonce_balance_for(read.addr, rpc);
    j["required_public_fee_raw"] = fee.raw;
    j["public_balance_raw"] = bi.balance_raw;
    if (!bi.ok) {
        j["can_submit"] = false;
        j["mode"] = "fee_blocked";
        j["reason"] = "cannot read public balance for upgrade fee";
    } else if (!raw_amount_ge(bi.balance_raw, fee.raw)) {
        j["can_submit"] = false;
        j["mode"] = "fee_blocked";
        j["reason"] = "public balance too low for encrypted balance upgrade fee: need " + fee.raw + " raw, have " + bi.balance_raw;
    }
}

static void settle_saved_upgrade(uint64_t token) {
    std::string hash;
    {
        std::lock_guard<std::mutex> lock(g_pvac_upgrade_state_mtx);
        const auto found = g_pvac_pending.find(g_pvac_pending_account);
        if (found != g_pvac_pending.end()) hash = found->second.hash;
    }
    if (hash.empty()) {
        if (g_pvac_repair_tx.token != token || g_pvac_repair_tx.hash.empty()
            || !g_own_history.migration_confirmed(token, g_pvac_repair_tx.hash)) return;
        hash = g_pvac_repair_tx.hash;
    }
    const auto saved = g_own_history.find(token, hash);
    pvac_upgrade_stage_set("submitted", "saved migration resolved", hash);
    settle_pvac_upgrade(!saved.is_null() && saved["status"] == "confirmed" ? "confirmed" : "rejected",
        hash, "saved migration resolved", g_own_history.migration_confirmed(token, hash));
}

static json pending_pvac_upgrade(const WalletRead& read) {
    const auto token = own_history_open(read.addr, read.generation);
    std::string chain;
    const auto load = [&]() {
        std::lock_guard<std::mutex> lock(g_mtx);
        read.check();
        if (token != g_own_token || g_own_rpc != read.url)
            throw octra::WalletSessionError("migration journal changed");
        chain = g_own_chain;
        const auto row = g_own_history.migration(token);
        if (!row.is_null()) pvac_upgrade_stage_set("submitted", "saved migration awaiting resolution",
            row.at("hash").get<std::string>());
        else settle_saved_upgrade(token);
        return row;
    };
    auto row = load();
    if (row.is_null()) return nullptr;
    octra::RpcClient rpc(read.url);
    const auto nonce = confirmed_nonce(rpc, read.addr, chain);
    const auto hash = row.at("hash").get<std::string>();
    const auto terminal = finish_pvac_upgrade(read, hash);
    std::string resolved = terminal;
    if (terminal.empty() && nonce >= row.value("nonce", std::numeric_limits<int>::max())) {
        const auto reply = rpc.call("octra_transaction", {hash}, 5);
        if (octra::pvac_nonce_used(nonce, row.value("nonce", 0), reply.ok, reply.replied,
            reply.code, reply.result, hash)) {
            std::lock_guard<std::mutex> lock(g_mtx);
            read.check();
            if (token != g_own_token || g_own_rpc != read.url)
                throw octra::WalletSessionError("migration journal changed");
            const auto current = g_own_history.find(token, hash);
            if (current["status"] == "unknown" || current["status"] == "pending" || current["status"] == "dropped") {
                g_own_history.migration_used(token, hash, nonce, reply.ok, reply.replied, reply.code, reply.result);
                settle_pvac_upgrade("rejected", hash, "account nonce used; original execution outcome unavailable",
                    g_own_history.migration_confirmed(token, hash));
                resolved = "replaced";
            }
        }
    }
    row = load();
    if (row.is_null() && resolved.empty()) resolved = "resolved";
    if (row.is_null()) return json{{"mode", "upgrade_" + resolved}, {"stage", resolved},
        {"tx_hash", hash}, {"can_submit", false}, {"upgrade_inflight", false},
        {"reason", resolved == "replaced" ? "account nonce used; checking actual key and balance next"
            : "transaction " + resolved + "; checking balance next"}};
    json result;
    pvac_upgrade_recent_json(result);
    const auto own_nonce = row.value("nonce", 0);
    result["reused"] = true;
    if (own_nonce > 0 && nonce >= 0 && nonce < own_nonce) {
        const auto retry_hash = row.at("hash").get<std::string>();
        const auto reply = rpc.get_transaction(retry_hash, 5);
        if (!octra::pvac_retry_lookup(reply.ok, reply.replied, reply.code, reply.result, retry_hash)
            || (reply.result.is_object() && reply.result.contains("chain_id") && reply.result["chain_id"] != chain)
            || (reply.result.is_object() && reply.result.contains("from") && reply.result["from"] != read.addr))
            return result;
        result["can_submit"] = true;
        result["retry_nonce"] = own_nonce;
        result["mode"] = "upgrade_retry";
        result["reason"] = "outcome unresolved; retry uses the same nonce so only one attempt can execute";
        apply_pvac_upgrade_fee_gate(result, read);
    }
    return result;
}

static bool pvac_start_plan(const WalletRead& read, const json& body,
    httplib::Response& response, json& retry) {
    std::lock_guard<std::mutex> status_lock(g_pvac_status_mtx);
    const auto recent = pending_pvac_upgrade(read);
    if (!recent.is_null() && recent.contains("retry_nonce") && recent.value("can_submit", false)
        && body.value("retry_hash", "") == recent.at("tx_hash").get<std::string>()) {
        retry = recent;
        return true;
    }
    if (!recent.is_null()) {
        response.status = 409;
        auto error = recent;
        error["reused"] = true;
        error["error"] = recent.value("reused", false)
            ? "saved migration requires current same-nonce retry approval"
            : "saved migration resolved; refresh status before submitting again";
        response.set_content(error.dump(), "application/json");
        return false;
    }
    if (body.contains("retry_hash")) {
        response.status = 409;
        response.set_content(err_json("migration retry no longer pending").dump(), "application/json");
        return false;
    }
    return pvac_upgrade_can_start(response);
}

static json pvac_upgrade_status_json(const WalletRead* identity = nullptr) {
    const auto read = identity ? *identity : wallet_read();
    octra::RpcClient rpc(read.url);
    json j;
    j["can_submit"] = false;
    j["cipher_present"] = false;
    j["encrypted_balance_raw"] = "0";
    j["encrypted_balance_known"] = false;
    j["repair_required"] = false;
    j["compact_refresh"] = false;
    j["private_spend_refresh_required"] = false;
    j["encrypt_refresh_required"] = true;
    j["encrypt_remaining"] = nullptr;
    j["mode"] = "unavailable";
    j["reason"] = "pvac not available";
    std::string addr;
    {
        std::lock_guard<std::mutex> lock(g_mtx);
        read.check();
        if (!g_wallet_loaded) {
            j["reason"] = "no wallet loaded";
            return j;
        }
        if (!g_pvac_ok) {
            return j;
        }
        addr = g_wallet.addr;
    }
    auto eb = get_encrypted_balance(identity ? &read : nullptr);
    if (!eb.ok || eb.read_unavailable) {
        j["mode"] = "unavailable";
        j["cipher_present"] = !eb.cipher.empty() && eb.cipher != "0";
        j["reason"] = eb.error.empty() ? "cannot read encrypted balance" : eb.error;
        return j;
    }
    bool locked = !eb.cipher.empty() && eb.cipher != "0";
    j["cipher_present"] = locked;
    j["encrypted_balance_known"] = eb.amount_known;
    j["legacy_owner_decoded"] = eb.legacy_owner_decoded;
    if (eb.amount_known)
        j["encrypted_balance_raw"] = std::to_string(eb.decrypted);
    std::string local_pk;
    bool key_proven = eb.key_proven;
    bool committed_r = false;
    size_t proof_base_layers = 0;
    {
        std::lock_guard<std::mutex> lock(g_mtx);
        if (!g_wallet_loaded || g_wallet.addr != addr || g_wallet_generation != read.generation) {
            j["mode"] = "blocked";
            j["reason"] = "wallet state changed while reading upgrade status";
            return j;
        }
        local_pk = local_pvac_pubkey_b64();
        if (locked && key_proven) {
            proof_base_layers = g_pvac.base_layer_count(eb.cipher);
            committed_r = g_pvac.has_committed_r(eb.cipher);
        }
    }
    if (key_proven) {
        j["base_layers"] = proof_base_layers;
        j["canonical_r_com"] = committed_r;
        j["private_spend_max_base_layers"] =
            octra::pvac_upgrade_policy::private_spend_refresh_base_layers;
    }
    auto read_remote_key = [&]() {
        json remote;
        remote["ok"] = false;
        remote["pk"] = "";
        remote["compatible"] = false;
        if (locked) {
            remote["pk"] = eb.public_key.value_or("");
            remote["ok"] = eb.public_key && !eb.public_key->empty();
            remote["compatible"] = eb.public_key_compatible;
            return remote;
        }
        const auto key = read_pvac_key(read, identity != nullptr);
        if (!key) throw octra::RpcStateError("registered pvac key is unavailable");
        const auto& remote_pk = key->key;
        remote["compatible"] = key->compatible;
        if (!remote_pk.empty()) {
            remote["ok"] = true;
            remote["pk"] = remote_pk;
        }
        return remote;
    };
    if (!locked) {
        auto remote = read_remote_key();
        std::string remote_pk = remote.value("pk", "");
        bool remote_ok = remote.value("ok", false);
        const bool registered_compatible = remote.value("compatible", false);
        std::lock_guard<std::mutex> lock(g_mtx);
        read.check();
        j["registered_key_present"] = remote_ok;
        j["registered_key_current"] = remote_ok && remote_pk == local_pk;
        j["registered_key_compatible"] = registered_compatible;
        if (remote_ok && remote_pk == local_pk) {
            j["encrypt_refresh_required"] = false;
            j["encrypt_remaining"] = octra::pvac_upgrade_policy::claim_capacity(0);
            j["mode"] = "current";
            j["reason"] = "pvac key already current";
            return j;
        }
        j["can_submit"] = true;
        j["mode"] = "empty_key_switch";
        j["reason"] = registered_compatible
            ? "compatible pvac key profile requires confirmation"
            : "encrypted balance is empty";
        return j;
    }
    auto ms = rpc.get_pvac_migration_status(addr, 8);
    if (!ms.ok || !ms.result.is_object() ||
        !ms.result.contains("address") || !ms.result["address"].is_string() ||
        ms.result["address"].get<std::string>() != addr ||
        !ms.result.contains("migration_route") || !ms.result["migration_route"].is_string()) {
        j["mode"] = "blocked";
        j["reason"] = "network migration status unavailable or invalid";
        return j;
    }
    const std::string route = ms.result["migration_route"].get<std::string>();
    const bool history_recovery = ms.result.value("history_recovery", false);
    if (octra::cipher_route(ms.result)) {
        j["mode"] = "cipher_proof";
        j["can_submit"] = eb.amount_known && eb.decrypted >= 0;
        j["reason"] = j["can_submit"].get<bool>()
            ? "historical balance can migrate with ciphertext proof"
            : "historical balance cannot be opened by this wallet";
        return j;
    }
    if (key_proven && !history_recovery && route != "history_migration" &&
        (route != "bound_migration" ||
         !ms.result.contains("can_v3_migrate") ||
         !ms.result["can_v3_migrate"].is_boolean() ||
         !ms.result["can_v3_migrate"].get<bool>())) {
        j["mode"] = "blocked";
        j["reason"] = "network does not permit encrypted balance refresh";
        return j;
    }
    if (!key_proven || history_recovery || route == "history_migration") {
        const json& replay = ms.result.value("legacy_public_replay", json::object());
        const json record = ms.result.value("migration_record", json::object());
        const std::string state = record.is_object() && record.contains("status") &&
            record["status"].is_string() ? record["status"].get<std::string>() :
            replay.is_object() && replay.contains("admission_status") &&
            replay["admission_status"].is_string() ? replay["admission_status"].get<std::string>() : "";
        if (state == "not_found" || state == "unavailable" ||
            state == "not_active" || state == "cipher_mismatch") {
            j["mode"] = "blocked";
            j["reason"] = state == "not_found" ? "migration record not found" :
                state == "unavailable" ? "migration records unavailable" :
                state == "not_active" ? "migration records not active" :
                "migration record ciphertext mismatch";
            return j;
        }
        const bool record_ready = history_recovery && state == "ready" &&
            replay.is_object() && replay.value("complete", false);
        if (history_recovery && !record_ready) {
            j["mode"] = "blocked";
            j["reason"] = "migration history is incomplete";
            return j;
        }
        if (record_ready && key_proven && !eb.amount_known) {
            const auto opening = local_balance_opening(read, eb.cipher);
            eb.amount_known = opening.amount_known;
            eb.decrypted = opening.decrypted;
            if (eb.amount_known) {
                j["encrypted_balance_known"] = true;
                j["encrypted_balance_raw"] = std::to_string(eb.decrypted);
            }
        }
        std::string audit_class = replay.is_object()
            ? replay.value("audit_class", "")
            : "";
        if (audit_class.empty()) {
            audit_class = ms.result.value("audit_class", "");
        }
        const std::string replay_reason = replay.is_object()
            ? replay.value("reason", "")
            : "";
        const std::string status_reason = ms.result.value("reason", "");
        if (audit_class.empty() &&
            (replay_reason == "legacy history needs hidden witness migration" ||
             status_reason == "legacy history needs hidden witness migration")) {
            audit_class = "hidden_witness";
        }
        bool can_public_migrate =
            replay.is_object() &&
            replay.value("can_public_migrate", false) &&
            ((replay.contains("public_net_raw") && !replay["public_net_raw"].is_null()) ||
             (replay.contains("public_net") && !replay["public_net"].is_null()));
        if (can_public_migrate) {
            std::string amount_raw =
                replay.contains("public_net_raw")
                    ? replay.value("public_net_raw", "0")
                    : replay.value("public_net", "0");
            int64_t replay_amount = 0;
            if (!parse_balance_raw_string(json(amount_raw), replay_amount)) {
                j["mode"] = "blocked";
                j["reason"] = "legacy public migration replay amount is invalid";
                return j;
            }
            if (!(record_ready && !eb.amount_known) &&
                !octra::pvac_upgrade_policy::replay_matches(
                    eb.amount_known, eb.decrypted, replay_amount)) {
                j["mode"] = "blocked";
                j["reason"] = "legacy public replay does not match the locally decoded balance";
                return j;
            }
            j["encrypted_balance_known"] = true;
            j["encrypted_balance_raw"] = amount_raw;
            if (replay_amount == 0) {
                j["can_submit"] = true;
                j["mode"] = "legacy_zero_reset";
                j["reason"] = "legacy public history proves a zero encrypted balance";
                return j;
            }
            j["can_submit"] = true;
            j["mode"] = "legacy_public_migration";
            j["reason"] = "legacy public encrypted balance can upgrade with network-replayed amount";
            j["legacy_public_replay_raw"] = amount_raw;
            return j;
        }
        if (audit_class == "hidden_witness") {
            const bool owner_ready = key_proven &&
                (record_ready ||
                 (ms.result.contains("can_owner_proof_migrate") &&
                  ms.result["can_owner_proof_migrate"].is_boolean() &&
                  ms.result["can_owner_proof_migrate"].get<bool>()));
            if (key_proven && !owner_ready) {
                j["mode"] = "blocked";
                j["reason"] = "network does not permit historical balance migration";
                return j;
            }
            if ((!eb.legacy_owner_decoded && !owner_ready) || !eb.amount_known || eb.decrypted <= 0) {
                j["mode"] = "blocked";
                j["reason"] = "legacy hidden encrypted balance is unreadable";
                return j;
            }
            std::string commitment_net = replay.is_object()
                ? replay.value("commitment_net", "")
                : "";
            if (commitment_net.empty()) {
                j["mode"] = "blocked";
                j["reason"] = "legacy hidden history has no reconstructable commitment";
                return j;
            }
            j["can_submit"] = true;
            j["mode"] = "legacy_commitment_migration";
            j["reason"] = "legacy hidden encrypted balance can upgrade with commitment-history proof";
            j["legacy_commitment_net"] = commitment_net;
            return j;
        }
        j["mode"] = "blocked";
        j["reason"] = audit_class == "poisoned"
            ? "legacy encrypted history is poisoned and cannot be migrated"
            : replay.is_object()
            ? replay.value("reason", "legacy encrypted balance is not public-replay migratable")
            : "legacy encrypted balance is not public-replay migratable";
        return j;
    }
    auto remote = read_remote_key();
    std::string remote_pk = remote.value("pk", "");
    bool remote_ok = remote.value("ok", false);
    const bool registered_compatible = remote.value("compatible", false);
    {
        std::lock_guard<std::mutex> lock(g_mtx);
        read.check();
    }
    j["registered_key_present"] = remote_ok;
    j["registered_key_current"] = remote_ok && remote_pk == local_pk;
    j["registered_key_compatible"] = registered_compatible;
    if (!remote_ok) {
        j["mode"] = "blocked";
        j["reason"] = "registered pvac key missing for locked encrypted balance";
        return j;
    }
    if (remote_pk != local_pk) {
        const auto opening = local_balance_opening(read, eb.cipher, remote_pk);
        if (!opening.amount_known) {
            j["mode"] = "key_mismatch";
            j["reason"] = "registered pvac key does not match this wallet";
            return j;
        }
        j["can_submit"] = true;
        j["mode"] = "key_bound_migration";
        j["private_spend_refresh_required"] = true;
        j["reason"] = "encrypted balance key profile refresh required";
        j["encrypted_balance_known"] = true;
        j["encrypted_balance_raw"] = std::to_string(opening.decrypted);
        return j;
    }
    if (!eb.amount_known || eb.decrypted < 0) {
        j["mode"] = "blocked";
        j["reason"] = "encrypted balance is unreadable";
        return j;
    }
    bool repair_blocked = false;
    bool repair_required = false;
    std::string repair_reason;
    {
        std::lock_guard<std::mutex> lock(g_mtx);
        read.check();
        if (!g_wallet_loaded || g_wallet.addr != addr) {
            j["mode"] = "blocked";
            j["reason"] = "wallet state changed while reading repair status";
            return j;
        }
        repair_blocked = pvac_repair_blocked_for_current_wallet();
        repair_required = pvac_repair_required_for_current_wallet();
        repair_reason = g_pvac_repair_blocked_reason;
    }
    if (repair_blocked) {
        j["mode"] = "blocked";
        j["reason"] = repair_reason.empty()
            ? "encrypted balance cannot be repaired automatically"
            : "encrypted balance cannot be repaired automatically: " + repair_reason;
        return j;
    }
    if (repair_required) {
        j["can_submit"] = true;
        j["mode"] = "key_bound_migration";
        j["repair_required"] = true;
        j["private_spend_refresh_required"] = true;
        j["reason"] = "encrypted balance repair required after local proof self-check failed";
        return j;
    }
    if (!committed_r) {
        j["can_submit"] = true;
        j["mode"] = "key_bound_migration";
        j["private_spend_refresh_required"] = true;
        j["reason"] = "encrypted balance privacy refresh required";
        return j;
    }
    j["encrypt_refresh_required"] =
        !octra::pvac_upgrade_policy::deposit_allowed(proof_base_layers);
    j["encrypt_remaining"] = octra::pvac_upgrade_policy::claim_capacity(proof_base_layers);
    if (octra::pvac_upgrade_policy::refresh_before_private_spend(
            proof_base_layers)) {
        j["can_submit"] = true;
        j["mode"] = "key_bound_migration";
        j["compact_refresh"] = true;
        j["private_spend_refresh_required"] = true;
        j["reason"] = "encrypted balance compact refresh required before private spend";
        return j;
    }
    j["mode"] = "current";
    j["reason"] = "encrypted balance is already key-linked to the current pvac key";
    return j;
}

static json submit_pvac_upgrade_tx(
    const json& request,
    int& http_status,
    bool force_refresh = false,
    const json& retry = nullptr) {
    http_status = 200;
    auto wallet = pvac_wallet_snapshot();
    if (!wallet.loaded) {
        http_status = 409;
        pvac_upgrade_stage_set("error", "no wallet loaded");
        return err_json("no wallet loaded");
    }
    if (!wallet.pvac_ok) {
        http_status = 500;
        pvac_upgrade_stage_set("error", "pvac not available");
        return err_json("pvac not available");
    }
    octra::PvacBridge pvac;
    bool local_pvac_ok = pvac.init(wallet.priv_b64);
    if (!wallet.priv_b64.empty()) {
        octra::secure_zero(&wallet.priv_b64[0], wallet.priv_b64.size());
        wallet.priv_b64.clear();
    }
    if (!local_pvac_ok) {
        http_status = 500;
        pvac_upgrade_stage_set("error", "pvac not available");
        return err_json("pvac not available");
    }
    pvac.proof_policy(read_proof_policy(wallet.addr));
    pvac_upgrade_stage_set("checking_fee", "checking encrypted balance and upgrade fee");
    json status = pvac_upgrade_status_json();
    {
        std::lock_guard<std::mutex> lock(g_mtx);
        if (!g_wallet_loaded || g_wallet.addr != wallet.addr) {
            http_status = 409;
            pvac_upgrade_stage_set("error", "wallet changed while preparing upgrade");
            return err_json("wallet changed while preparing upgrade");
        }
    }
    if (force_refresh && status.value("mode", "") == "current") {
        status["can_submit"] = true;
        status["mode"] = "key_bound_migration";
        status["reason"] = "encrypted balance refresh requested";
    }
    std::string mode = status.value("mode", "unavailable");
    if (!status.value("can_submit", false)) {
        http_status = 409;
        std::string msg = status.value("reason", "pvac upgrade is not available");
        pvac_upgrade_stage_set("error", msg);
        return err_json(msg);
    }
    if (mode == "legacy_zero_reset" &&
        !octra::pvac_upgrade_policy::reset_allowed(
            request.value("reset_confirm", ""))) {
        http_status = 409;
        const std::string msg = "legacy zero reset requires typed confirmation";
        pvac_upgrade_stage_set("error", msg);
        return err_json(msg);
    }
    const PvacUpgradeFee fee = pvac_key_switch_fee(request.value("ou", json()));
    if (!fee.ok) {
        http_status = 409;
        pvac_upgrade_stage_set("error", fee.error);
        return err_json(fee.error);
    }
    auto bi = get_nonce_balance_for(wallet.addr);
    if (!bi.ok) {
        http_status = 503;
        pvac_upgrade_stage_set("error", "cannot read public balance for upgrade fee");
        return err_json("cannot read public balance for upgrade fee");
    }
    if (!raw_amount_ge(bi.balance_raw, fee.raw)) {
        http_status = 402;
        std::string msg = "public balance too low for encrypted balance upgrade fee: need " + fee.raw + " raw, have " + bi.balance_raw;
        pvac_upgrade_stage_set("error", msg);
        return err_json(msg);
    }
    json migration = json::object();
    if (mode == "cipher_proof" || mode == "key_bound_migration" || mode == "legacy_public_migration" ||
        mode == "legacy_commitment_migration" || mode == "legacy_zero_reset") {
        auto eb = get_encrypted_balance();
        if (!eb.ok) {
            http_status = 503;
            std::string msg = eb.error.empty() ? "cannot read encrypted balance" : eb.error;
            pvac_upgrade_stage_set("error", msg);
            return err_json(msg);
        }
        {
            std::lock_guard<std::mutex> lock(g_mtx);
            if (!g_wallet_loaded || g_wallet.addr != wallet.addr) {
                http_status = 409;
                pvac_upgrade_stage_set("error", "wallet changed while building upgrade");
                return err_json("wallet changed while building upgrade");
            }
        }
        std::string error;
        int64_t amount = eb.decrypted;
        const std::string old_pubkey =
            (mode == "key_bound_migration" || mode == "cipher_proof")
                ? remote_pvac_pubkey_b64(wallet.addr)
                : "";
        if (mode == "key_bound_migration" && !eb.amount_known &&
            !pvac.try_get_stored_balance(eb.cipher, old_pubkey, amount)) {
            http_status = 409;
            const std::string msg =
                "registered pvac key cannot open the current encrypted balance";
            pvac_upgrade_stage_set("error", msg);
            return err_json(msg);
        }
        if (mode == "legacy_public_migration" || mode == "legacy_commitment_migration") {
            const auto& amount_raw = mode == "legacy_public_migration"
                ? status["legacy_public_replay_raw"] : status["encrypted_balance_raw"];
            if (!parse_positive_raw_string(amount_raw, amount)) {
                http_status = 409;
                std::string msg = "legacy public migration replay amount is invalid";
                pvac_upgrade_stage_set("error", msg);
                return err_json(msg);
            }
        }
        const std::string proof_label =
            mode == "cipher_proof"
                ? "building historical ciphertext and range proofs"
                : mode == "legacy_public_migration"
                ? "building public-history migration proof"
                : mode == "legacy_commitment_migration"
                ? "building commitment-history migration proof"
                : mode == "legacy_zero_reset"
                ? "building verified zero replacement proof"
                : force_refresh && mode == "key_bound_migration"
                ? "building key-linked encrypted balance refresh proof"
                : "building key-linked encrypted balance migration proofs";
        pvac_upgrade_stage_set("building_proof", proof_label);
        bool built = false;
        if (mode == "cipher_proof") {
            try {
                if (!eb.amount_known)
                    throw std::runtime_error("historical balance is unreadable");
                migration = octra::cipher_migration(pvac, old_pubkey, eb.cipher, amount);
                built = true;
            } catch (const std::exception& failure) {
                error = failure.what();
            }
        } else {
            built = build_pvac_migration_payload(
                pvac,
                wallet.addr,
                wallet.sk,
                eb.cipher,
                old_pubkey,
                amount,
                mode,
                status,
                migration,
                error);
        }
        if (!built) {
            http_status = 409;
            if (mode == "key_bound_migration") {
                std::lock_guard<std::mutex> lock(g_mtx);
                if (g_wallet_loaded && g_wallet.addr == wallet.addr) {
                    mark_pvac_repair_blocked(wallet.addr, error);
                }
            }
            pvac_upgrade_stage_set("error", error);
            return err_json(error);
        }
        if (mode == "key_bound_migration" || mode == "cipher_proof") {
            auto latest = get_encrypted_balance();
            {
                std::lock_guard<std::mutex> lock(g_mtx);
                if (!g_wallet_loaded || g_wallet.addr != wallet.addr) {
                    http_status = 409;
                    pvac_upgrade_stage_set("error", "wallet changed while checking refresh source");
                    return err_json("wallet changed while checking refresh source");
                }
            }
            if (!latest.ok) {
                http_status = 503;
                std::string msg = latest.error.empty()
                    ? "cannot verify encrypted balance refresh source"
                    : latest.error;
                pvac_upgrade_stage_set("error", msg);
                return err_json(msg);
            }
            const std::string source = migration.value("source_cipher_hash", "");
            if (source.empty() || source != octra::sha256_hex(latest.cipher)) {
                http_status = 409;
                std::string msg = "encrypted balance changed while building refresh; retry";
                pvac_upgrade_stage_set("error", msg);
                return err_json(msg);
            }
        }
    } else if (mode != "empty_key_switch") {
        http_status = 409;
        pvac_upgrade_stage_set("error", "pvac upgrade mode is not admitted");
        return err_json("pvac upgrade mode is not admitted");
    }
    pvac_upgrade_stage_set("submitting", "submitting key_switch transaction");
    check_proof_policy(wallet.addr, pvac.proof_policy());
    auto result = submit_pvac_key_switch_tx(
        wallet.addr,
        wallet.pub_b64,
        wallet.sk.data(),
        pvac,
        migration,
        fee.raw,
        wallet.generation,
        retry);
    if (result.contains("error")) {
        http_status = 500;
        pvac_upgrade_stage_set("error", result.value("error", "upgrade submission failed"));
    } else {
        result["mode"] = mode;
        result["refresh"] = force_refresh && mode == "key_bound_migration";
        result["migrated_cipher"] =
            (mode == "cipher_proof" || mode == "key_bound_migration" || mode == "legacy_public_migration" ||
             mode == "legacy_commitment_migration" || mode == "legacy_zero_reset");
        {
            std::lock_guard<std::mutex> lock(g_mtx);
            if (g_wallet_loaded && g_wallet.addr == wallet.addr) {
                g_pvac_foreign = false;
                g_pvac_confirmed = false;
                g_pvac_remote_pubkey_b64.clear();
                clear_enc_bal_cache();
            }
        }
        std::string tx_hash = result.value("tx_hash", result.value("hash", ""));
        const auto state = result.value("status", "unknown");
        if (state == "rejected" || state == "unaccepted") {
            pvac_upgrade_reject(tx_hash, result.value("submit_error", "transaction refused"));
            http_status = 409;
            result["error"] = result.value("submit_error", "transaction refused");
        } else {
            pvac_upgrade_stage_set("submitted", state == "pending" ? "transaction submitted to network"
                : "submission outcome unknown; check encryption upgrade status", tx_hash);
        }
    }
    return result;
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

static bool pvac_key_ready(httplib::Response& res) {
    const auto read = wallet_read();
    {
        std::lock_guard<std::mutex> lock(g_mtx);
        read.check();
        if (!g_pvac_ok) {
            res.status = 503;
            res.set_content(err_json("wallet encryption key unavailable").dump(), "application/json");
            return false;
        }
    }
    const auto key = read_pvac_key(read, false);
    if (!key) {
        res.status = 503;
        res.set_content(err_json("cannot read registered encryption key").dump(), "application/json");
        return false;
    }
    if (key->current) return true;
    res.status = 409;
    const auto message = !key->key.empty() && !key->compatible
        ? "registered encryption key does not match wallet; inspect encryption upgrade status"
        : "encryption key upgrade required before private operation";
    res.set_content(err_json(message).dump(), "application/json");
    return false;
}

static void refresh_pvac_key_state_readonly() {
    const auto read = wallet_read();
    {
        std::lock_guard<std::mutex> lock(g_mtx);
        read.check();
        if (!g_pvac_ok) return;
    }
    read_pvac_key(read, true);
}

static EncBalResult get_encrypted_balance(const WalletRead* identity) {
    const auto read = identity ? *identity : wallet_read();
    octra::RpcClient rpc(read.url);
    EncBalResult out;
    std::string addr;
    std::string pub_b64;
    std::string sig;
    bool pvac_ok;
    uint64_t generation;
    {
        std::lock_guard<std::mutex> lock(g_mtx);
        read.check();
        if (!g_wallet_loaded) {
            out.error = "no wallet loaded";
            return out;
        }
        addr = g_wallet.addr;
        pub_b64 = g_wallet.pub_b64;
        sig = octra::sign_balance_request(addr, g_wallet.sk);
        pvac_ok = g_pvac_ok;
        generation = g_wallet_generation;
    }
    auto r = rpc.get_encrypted_balance(addr, sig, pub_b64);
    {
        std::lock_guard<std::mutex> lock(g_mtx);
        read.check();
    }
    if (!r.ok || !r.result.is_object()) {
        out.error = r.error.empty() ? "cannot read encrypted balance" : r.error;
        return out;
    }
    out.cipher = r.result.value("cipher", "0");
    out.ok = true;
    if (out.cipher.size() > octra::wallet_cipher_limit) {
        out.error = "encrypted balance exceeds local input limit";
        return out;
    }
    if (out.cipher.empty() || out.cipher == "0") {
        out.amount_known = true;
        return out;
    }
    if (!pvac_ok) {
        out.read_unavailable = true;
        out.error = "pvac not available";
        return out;
    }
    const std::string cipher_hash = octra::sha256_hex(out.cipher);
    const auto cached_balance = [&]() -> std::optional<EncBalResult> {
        if (!identity) return std::nullopt;
        std::lock_guard<std::mutex> lock(g_mtx);
        read.check();
        std::lock_guard<std::mutex> cache_lock(g_enc_bal_cache_mtx);
        if (!g_enc_bal_cache || g_enc_bal_cache->generation != generation
            || g_enc_bal_cache->addr != addr || g_enc_bal_cache->cipher != cipher_hash
            || std::chrono::steady_clock::now() >= g_enc_bal_cache->expires)
            return std::nullopt;
        const auto& value = g_enc_bal_cache->result;
        if (r.result.contains("has_pvac_pubkey") && (!r.result["has_pvac_pubkey"].is_boolean()
            || r.result["has_pvac_pubkey"].get<bool>() != (value.public_key && !value.public_key->empty())))
            return std::nullopt;
        return value;
    };
    if (const auto cached = cached_balance()) return *cached;
    bool reuse_key = identity != nullptr;
    {
        std::lock_guard<std::mutex> lock(g_mtx);
        read.check();
        std::lock_guard<std::mutex> cache_lock(g_enc_bal_cache_mtx);
        if (g_enc_bal_cache && g_enc_bal_cache->cipher != cipher_hash) reuse_key = false;
    }
    std::optional<bool> present;
    if (r.result.contains("has_pvac_pubkey") && r.result["has_pvac_pubkey"].is_boolean())
        present = r.result["has_pvac_pubkey"].get<bool>();
    const auto key = read_pvac_key(read, reuse_key, present);
    if (!key) {
        if (!identity) throw octra::RpcStateError("registered pvac key is unavailable");
        out.read_unavailable = true;
        out.error = "registered pvac key is unavailable";
        return out;
    }
    std::unique_lock<std::timed_mutex> decode_lock(g_balance_decode_mtx, std::defer_lock);
    if (!decode_lock.try_lock_for(std::chrono::seconds(15))) {
        if (!identity) throw octra::RpcStateError("balance decoding wait expired");
        std::lock_guard<std::mutex> lock(g_mtx);
        read.check();
        out.error = "balance decoding wait expired";
        out.read_unavailable = true;
        return out;
    }
    if (const auto cached = cached_balance()) return *cached;
    const uint64_t revision = key->revision;
    const auto& remote_pk = key->key;
    out.public_key = remote_pk;
    out.public_key_compatible = key->compatible;
    std::unique_ptr<octra::PvacBridge> decoder;
    {
        std::lock_guard<std::mutex> lock(g_mtx);
        read.check();
        if (!g_wallet_loaded || g_wallet.addr != addr || !g_pvac_ok) {
            out.ok = false;
            out.error = "wallet state changed while reading encrypted balance";
            return out;
        }
        decoder = g_pvac.snapshot();
    }
    out.key_proven = decoder->has_key_proof(out.cipher);
    out.inspected = true;
    const bool within_resources = decoder->base_layer_count(out.cipher) <= octra::wallet_balance_layers;
    {
        std::lock_guard<std::mutex> lock(g_mtx);
        read.check();
        if (!g_wallet_loaded || g_wallet.addr != addr || !g_pvac_ok) {
            out.ok = false;
            out.error = "wallet state changed while reading encrypted balance";
            return out;
        }
    }
    if (within_resources) {
        if (out.key_proven && !remote_pk.empty()) {
            out.amount_known =
                decoder->try_get_balance_with_pubkey(
                    out.cipher,
                    remote_pk,
                    out.decrypted);
        } else if (!out.key_proven && !remote_pk.empty()) {
            out.legacy_owner_decoded =
                decoder->try_get_legacy_v1_balance(out.cipher, remote_pk, out.decrypted);
            out.amount_known = out.legacy_owner_decoded;
        }
        if (!out.key_proven && !out.amount_known)
            out.amount_known = decoder->try_get_balance(out.cipher, out.decrypted);
    }
    if (!within_resources)
        out.error = "encrypted balance exceeds local decoding work limit; ciphertext preserved";
    else if (out.key_proven && remote_pk.empty())
        out.error = "registered pvac key is unavailable";
    else if (!out.amount_known)
        out.error = "encrypted balance amount is outside the valid balance domain";
    {
        std::lock_guard<std::mutex> lock(g_mtx);
        if (!g_wallet_loaded ||
            g_wallet_generation != generation ||
            g_wallet.addr != addr ||
            !g_pvac_ok) {
            out.ok = false;
            out.error = "wallet state changed while caching encrypted balance";
            return out;
        }
        std::lock_guard<std::mutex> cache_lock(g_enc_bal_cache_mtx);
        if (revision != g_balance_revision)
            throw octra::WalletSessionError("balance state changed during read");
        g_enc_bal_cache = EncBalCache{generation, addr, cipher_hash, "", out, key->expires};
    }
    return out;
}

static void init_wallet_subsystems() {
    close_own_history();
    clear_enc_bal_cache();
    const char* env_rpc = std::getenv("OCTRA_RPC_URL");
    if (env_rpc && *env_rpc) g_wallet.rpc_url = env_rpc;
    g_rpc.set_url(g_wallet.rpc_url);
    select_pvac_upgrade(g_wallet.rpc_url, g_wallet.addr);
    clear_fee_cache();
    g_pvac_remote_pubkey_b64.clear();
    try {
        g_pvac_ok = g_pvac.init(g_wallet.priv_b64);
    } catch (const std::exception& e) {
        g_pvac_ok = false;
        fprintf(stderr, "pvac init exception: %s\n", e.what());
    } catch (...) {
        g_pvac_ok = false;
        fprintf(stderr, "pvac init exception: unknown\n");
    }
    if (g_pvac_ok) {
        g_pvac_pubkey_b64 = g_pvac.serialize_pubkey_b64();
        fprintf(stderr, "pvac initialized\n");
    } else {
        fprintf(stderr, "pvac init failed (libpvac not loaded?)\n");
    }
    g_txcache.close();
    std::string cache_path = "data/txcache_" + g_wallet.addr.substr(3, 8);
    if (g_txcache.open(cache_path)) {
        fprintf(stderr, "txcache opened: %s\n", cache_path.c_str());
        g_txcache.ensure_identity(TXCACHE_SCHEMA, g_wallet.rpc_url);
    } else {
        fprintf(stderr, "txcache open failed: %s\n", cache_path.c_str());
    }
    g_wallet_loaded = true;
    ++g_wallet_generation;
}

#define WALLET_GUARD \
    if (!g_wallet_loaded) { \
        res.status = 503; \
        res.set_content(err_json("no wallet loaded").dump(), "application/json"); \
        return; \
    }

static bool private_rpc_ok(httplib::Response& res, const std::string& url = "") {
    if (octra::endpoint_policy::secure_rpc(url.empty() ? current_public_rpc_url() : url))
        return true;
    res.status = 409;
    res.set_content(
        err_json("private operations require https for remote RPC").dump(),
        "application/json");
    return false;
}

static void pin_reply(httplib::Response& res, int status, const std::string& message) {
    const auto wait = g_pin_attempts.wait_state();
    auto body = err_json(wait.checking && status == 429 ? "PIN check in progress" : message);
    body["retry_after"] = wait.seconds;
    body["pin_checking"] = wait.checking;
    res.status = status;
    if (wait.seconds) res.set_header("Retry-After", std::to_string(wait.seconds));
    res.set_content(body.dump(), "application/json");
}

static bool wallet_pin_ok(const json& body, httplib::Response& res) {
    if (!g_wallet_loaded) {
        res.status = 503;
        res.set_content(err_json("no wallet loaded").dump(), "application/json");
        return false;
    }
    std::string pin = body.value("pin", "");
    octra::WalletWipe<std::string> wipe_pin{pin};
    if (pin.empty()) {
        res.status = 403;
        res.set_content(err_json("PIN required to authorize this operation").dump(), "application/json");
        return false;
    }
    const auto verified = g_pin_attempts.verify([&] { return g_pin_session.matches(pin); });
    if (verified == octra::PinResult::wait) {
        pin_reply(res, 429, "PIN attempts delayed");
        return false;
    }
    if (verified != octra::PinResult::accepted) {
        pin_reply(res, 403, "wrong PIN");
        return false;
    }
    if (body.contains("expected_wallet") || body.contains("expected_generation")) {
        if (!body.contains("expected_wallet") || !body["expected_wallet"].is_string()
            || !body.contains("expected_generation") || !body["expected_generation"].is_string()) {
            res.status = 400;
            res.set_content(err_json("expected_wallet and expected_generation must both be strings").dump(), "application/json");
            return false;
        }
        if (body["expected_wallet"].get<std::string>() != g_wallet.addr
            || body["expected_generation"].get<std::string>() != std::to_string(g_wallet_generation)) {
            res.status = 409;
            res.set_content(err_json("wallet session changed; approve the request again").dump(), "application/json");
            return false;
        }
    }
    return true;
}

static std::shared_mutex g_session_lifetime;

static bool wallet_http_session(const httplib::Request& request, httplib::Response& response) {
    const auto wallets = request.get_header_value_count("X-Webcli-Wallet");
    const auto generations = request.get_header_value_count("X-Webcli-Generation");
    if (wallets == 0 && generations == 0) return true;
    if (wallets == 1 && generations == 1 && g_wallet_loaded
        && request.get_header_value("X-Webcli-Wallet") == g_wallet.addr
        && request.get_header_value("X-Webcli-Generation") == std::to_string(g_wallet_generation)) return true;
    response.status = 409;
    response.set_content(err_json("wallet session changed; approve the request again").dump(), "application/json");
    return false;
}

#define PVAC_LIFETIME_GUARD \
    if (g_wallet_writers.load()) throw octra::RpcStateError("wallet change in progress"); \
    std::shared_lock<std::shared_mutex> pvac_lifetime_lock(g_pvac_lifetime_mtx); \
    if (g_wallet_writers.load()) throw octra::RpcStateError("wallet change in progress");

#define PVAC_LIFETIME_WRITE_GUARD \
    octra::WalletChange wallet_write(g_wallet_writers, g_session_lifetime, g_pvac_lifetime_mtx); \
    if (!wallet_write.acquire()) { \
        res.status = 409; \
        res.set_content(err_json("wallet operation active; retry after completion").dump(), "application/json"); \
        return; \
    }

int main(int argc, char** argv) {
#ifdef _WIN32
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
#else
    struct rlimit rl = {0, 0};
    setrlimit(RLIMIT_CORE, &rl);
#ifdef __linux__
    prctl(PR_SET_DUMPABLE, 0);
#endif
#endif

    const auto program_command = octra::program_cli::parse(argc, argv);
    if (program_command.handled) {
        if (!program_command.ok) {
            fprintf(stderr, "action = parse status = error error = %s\n",
                program_command.error.c_str());
            return 2;
        }
        if (program_command.options.command ==
            octra::program_cli::Command::help) {
            fputs(octra::program_cli::help_text("webcli").c_str(), stdout);
            return 0;
        }
        octra::ensure_data_dir();
        octra::InstanceLock instance_lock;
        std::string lock_error;
        if (!instance_lock.acquire("data/webcli.lock", lock_error)) {
            fprintf(stderr, "event = startup status = refused reason = %s\n",
                lock_error.c_str());
            return 1;
        }
        return octra::program_cli::run_command(program_command.options);
    }

#ifdef _WIN32
    SetConsoleCtrlHandler([](DWORD) -> BOOL {
        handle_signal(0);
        return TRUE;
    }, TRUE);
#else
    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);
#endif

    int port = 8420;
    if (argc > 1) port = atoi(argv[1]);
    if (port <= 0) port = 8420;

    octra::ensure_data_dir();

    octra::InstanceLock instance_lock;
    std::string lock_error;
    if (!instance_lock.acquire("data/webcli.lock", lock_error)) {
        fprintf(stderr, "event = startup status = refused reason = %s\n",
            lock_error.c_str());
        return 1;
    }

    octra::ApiAccess access;
    octra::scan_and_merge_oct_files();
    const auto check_access = [&access](const auto& request, auto& response) {
        std::lock_guard<std::mutex> lock(g_mtx);
        return access.scope(request, response, g_wallet_loaded, g_wallet.addr, g_wallet_generation)
            && wallet_http_session(request, response);
    };
    octra::SessionServer svr(g_session_lifetime, check_access, &g_wallet_writers,
        [&access](const auto& request) { return access.scoped(request); });
    svr.set_socket_options([](socket_t socket) {
        const int enabled = 1;
#ifdef _WIN32
        setsockopt(socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
            reinterpret_cast<const char*>(&enabled), sizeof(enabled));
#else
        setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
#endif
    });
    svr.set_read_timeout(300, 0);
    svr.set_write_timeout(300, 0);
    svr.set_keep_alive_timeout(5);
    svr.set_keep_alive_max_count(100);
    svr.set_payload_max_length(CIRCLE_ASSET_MAX_B64_BYTES + 1024u * 1024u);

    svr.set_pre_routing_handler([port, &access](const httplib::Request& req, httplib::Response& res) {
        std::string reason;
        if (!webcli_request_allowed(req, port, reason)) {
            res.status = 403;
            res.set_header("Content-Type", "application/json");
            res.set_content(err_json("cross-origin webcli request blocked").dump(), "application/json");
            fprintf(stderr, "[csrf] blocked %s %s origin=%s sec-fetch-site=%s host=%s reason=%s\n",
                    req.method.c_str(), req.path.c_str(),
                    req.get_header_value("Origin", "-").c_str(),
                    req.get_header_value("Sec-Fetch-Site", "-").c_str(),
                    req.get_header_value("Host", "-").c_str(),
                    reason.c_str());
            return httplib::Server::HandlerResponse::Handled;
        }

        if (starts_with(req.path, "/api/") && req.method == "OPTIONS") {
            set_same_origin_cors_if_needed(req, res, port);
            res.status = 204;
            res.set_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
            res.set_header("Access-Control-Allow-Headers", "Content-Type");
            res.set_header("Access-Control-Max-Age", "600");
            return httplib::Server::HandlerResponse::Handled;
        }

        if (!access.check(req, res)) return httplib::Server::HandlerResponse::Handled;
        if (req.path == "/access.html") {
            res.set_redirect("/", 302);
            return httplib::Server::HandlerResponse::Handled;
        }
        if (!octra::circle_body_headers(req, res)) return httplib::Server::HandlerResponse::Handled;
        return httplib::Server::HandlerResponse::Unhandled;
    });

    svr.set_post_routing_handler([port](const httplib::Request& req, httplib::Response& res) {
        bool is_circle_resource = req.path.rfind("/oct/", 0) == 0;
        if (!is_circle_resource) {
            res.set_header("X-Frame-Options", "DENY");
        }
        res.set_header("X-Content-Type-Options", "nosniff");
        if (is_circle_resource) {
            res.set_header("Content-Security-Policy",
                "default-src 'none'; "
                "sandbox; "
                "base-uri 'none'; "
                "form-action 'none'; "
                "frame-ancestors 'self'");
        } else {
            std::string script_policy = req.path == "/circles.html"
                ? "script-src 'self' data:; "
                : "script-src 'self'; ";
            res.set_header("Content-Security-Policy",
                std::string("default-src 'self'; ") +
                script_policy +
                "base-uri 'none'; "
                "form-action 'none'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "connect-src 'self' http://127.0.0.1:* http://178.62.60.204:8090 https://devnet.octrascan.io https://*.octra.network https://*.publicnode.com https://*.infura.io wss: ws:; "
                "frame-ancestors 'none'");
        }
        res.set_header("Cache-Control", "no-store");
        res.headers.erase("Access-Control-Allow-Origin");
        set_same_origin_cors_if_needed(req, res, port);
    });

    svr.set_mount_point("/", "static");

    svr.Get("/api/access/key", [&access](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(g_mtx);
        WALLET_GUARD
        res.set_content(json({{"key", access.api_key(req)}}).dump(), "application/json");
    });

    svr.set_exception_handler([](const httplib::Request& req, httplib::Response& res, std::exception_ptr ep) {
        std::string msg = "internal error";
        int status = 500;
        try { if (ep) std::rethrow_exception(ep); }
        catch (const octra::TxInputError& e) { msg = e.what(); status = 400; }
        catch (const octra::WalletSessionError& e) { msg = e.what(); status = 409; }
        catch (const octra::RpcStateError& e) { msg = e.what(); status = 503; }
        catch (const json::exception&) { msg = "invalid JSON field type"; status = 400; }
        catch (const std::exception& e) { msg = e.what(); }
        catch (...) {}
        fprintf(stderr, "[exception] %s %s: %s\n", req.method.c_str(), req.path.c_str(), msg.c_str());
        res.status = status;
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

    svr.Get("/api/wallet/session", [&access](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(g_mtx);
        json result = {{"address", g_wallet_loaded ? g_wallet.addr : ""},
            {"generation", std::to_string(g_wallet_generation)},
            {"local_decrypt_without_pin", g_wallet_loaded && access.browser(req)}};
        res.set_content(result.dump(), "application/json");
    });

    const auto wallet_status = [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(g_mtx);
        const bool entry = req.path == "/api/browser/status";
        json j;
        j["loaded"] = !entry && g_wallet_loaded.load();
        bool has_leg = octra::has_legacy_wallet();
        auto all = entry ? octra::load_manifest() : octra::scan_and_merge_oct_files();
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
        j["setup_required"] = entry && !has_any_oct;
        j["pin_entry"] = entry;
        res.set_content(j.dump(), "application/json");
    };
    svr.Get("/api/wallet/status", wallet_status);
    svr.Get("/api/browser/status", wallet_status);

    svr.Post("/api/wallet/unlock", [&check_access](const httplib::Request& req, httplib::Response& res) {
        PVAC_LIFETIME_WRITE_GUARD
        if (!check_access(req, res)) return;
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
        if (pin.empty() || pin.size() > 1024) {
            res.status = 400;
            res.set_content(err_json("pin required").dump(), "application/json");
            return;
        }

        std::string unlock_path = g_wallet_path;
        if (!file_hint.empty()) {
            if (file_hint.find("..") != std::string::npos
                || file_hint.rfind("data/", 0) != 0 || file_hint.size() < 9
                || file_hint.substr(file_hint.size() - 4) != ".oct") {
                res.status = 400;
                res.set_content(err_json("invalid wallet path").dump(), "application/json");
                return;
            }
            unlock_path = file_hint;
        } else if (!addr_hint.empty()) {
            auto entries = octra::load_manifest();
            for (auto& e : entries) {
                if (e.addr == addr_hint) { unlock_path = e.file; break; }
            }
        }
        try {
            const bool migrate = body.value("migrate_legacy", false);
            if (migrate) {
                if (!file_hint.empty() || !addr_hint.empty() || !octra::has_legacy_wallet()
                    || !octra::scan_and_merge_oct_files().empty())
                    throw std::runtime_error("legacy migration unavailable");
                const auto error = octra::validate_pin(pin);
                if (!error.empty()) throw std::runtime_error(error);
            }
            const auto verified = g_pin_attempts.verify([&] {
                if (migrate) {
                    g_wallet = octra::migrate_wallet(pin);
                    g_wallet_path = octra::WALLET_FILE;
                } else {
                    g_wallet = octra::load_wallet_encrypted(unlock_path, pin);
                    g_wallet_path = unlock_path;
                }
                return true;
            });
            if (verified == octra::PinResult::wait) {
                pin_reply(res, 429, "PIN attempts delayed");
                return;
            }
            if (verified != octra::PinResult::accepted)
                throw std::runtime_error("PIN refused");

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
            g_pin_session.set(pin);
            init_wallet_subsystems();
        } catch (const std::exception& e) {
            g_wallet_loaded = false;
            g_wallet.clear_secrets();
            g_pin_session.clear();
            pin_reply(res, 403, e.what());
            return;
        }
        json j;
        j["address"] = g_wallet.addr;
        j["public_key"] = g_wallet.pub_b64;
        j["has_master_seed"] = g_wallet.has_master_seed();
        res.set_content(j.dump(), "application/json");
    });

    svr.Post("/api/wallet/lock", [&access, &check_access](const httplib::Request& req, httplib::Response& res) {
        PVAC_LIFETIME_WRITE_GUARD
        if (!check_access(req, res)) return;
        std::lock_guard<std::mutex> lock(g_mtx);
        if (!g_wallet_loaded) {
            res.status = 409;
            res.set_content(err_json("wallet not loaded").dump(), "application/json");
            return;
        }
        g_wallet_loaded = false;
        ++g_wallet_generation;
        close_own_history();
        history_runtime_clear_all();
        token_history_runtime_clear_all();
        clear_enc_bal_cache();
        g_pvac_ok = false;
        g_pvac_confirmed = false;
        g_pvac_foreign = false;
        g_pvac_pubkey_b64.clear();
        g_pvac_remote_pubkey_b64.clear();
        clear_pvac_repair_required();
        g_pvac.reset();

        leveldb::DB* old_db = g_txcache.detach();
        if (old_db) std::thread([old_db]() { delete old_db; }).detach();
        g_wallet.clear_secrets();
        g_pin_session.clear();
        g_wallet.pub_b64.clear();
        g_wallet.addr.clear();
        if (access.scoped(req)) res.set_header("X-Webcli-Session", "signed-out");
        fprintf(stderr, "wallet locked\n");
        json j;
        j["ok"] = true;
        res.set_content(j.dump(), "application/json");
    });

    svr.Post("/api/wallet/create", [&check_access](const httplib::Request& req, httplib::Response& res) {
        PVAC_LIFETIME_WRITE_GUARD
        if (!check_access(req, res)) return;
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
        {
            std::string verr = octra::validate_pin(pin);
            if (!verr.empty()) {
                res.status = 400;
                res.set_content(err_json(verr).dump(), "application/json");
                return;
            }
        }
        std::string name = body.value("name", "wallet");
        std::string mnemonic;
        octra::WalletWipe<std::string> wipe_mnemonic{mnemonic};
        octra::WalletWipe<std::string> wipe_pin{pin};
        try {
            mnemonic = octra::generate_mnemonic_12();
            auto wallet = octra::wallet_from_mnemonic(mnemonic, 2);
            const auto named_path = octra::new_wallet_path(wallet.addr);
            octra::save_wallet_encrypted(named_path, wallet, pin);
            {
                octra::ManifestEntry me;
                me.name = name;
                me.file = named_path;
                me.addr = wallet.addr;
                me.hd = true;
                me.hd_version = 2;
                me.hd_index = 0;
                me.master_seed_hash = octra::compute_seed_hash(wallet.master_seed_b64);
                octra::manifest_upsert(me);
            }
            g_wallet.clear_secrets();
            g_wallet = wallet;
            g_wallet_path = named_path;
            g_pin_session.set(pin);
            fprintf(stderr, "wallet created: %s -> %s\n", g_wallet.addr.c_str(), g_wallet_path.c_str());
            init_wallet_subsystems();
        } catch (const std::exception& e) {
            g_wallet_loaded = false;
            g_wallet.clear_secrets();
            g_pin_session.clear();
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

    svr.Post("/api/wallet/import", [&check_access](const httplib::Request& req, httplib::Response& res) {
        PVAC_LIFETIME_WRITE_GUARD
        if (!check_access(req, res)) return;
        std::unique_lock<std::mutex> lock(g_mtx);
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
        octra::WalletWipe<std::string> wipe_priv{priv};
        octra::WalletWipe<std::string> wipe_mnemonic{mnemonic};
        octra::WalletWipe<std::string> wipe_pin{pin};
        const bool recover = body.value("recover", false);
        const std::string recovery_address = body.value("address", "");
        if (recover && (already_loaded || recovery_address.empty())) {
            res.status = 409;
            res.set_content(err_json("recovery requires a locked session and account address").dump(), "application/json");
            return;
        }
        if (priv.empty() && mnemonic.empty()) {
            res.status = 400;
            res.set_content(err_json("priv or mnemonic required").dump(), "application/json");
            return;
        }
        {
            std::string verr = octra::validate_pin(pin);
            if (!verr.empty()) {
                res.status = 400;
                res.set_content(err_json(verr).dump(), "application/json");
                return;
            }
        }
        std::string name = body.value("name", "imported");
        bool is_mnemonic = false;
        bool publishing = false;
        try {
            octra::Wallet imported;
            if (!mnemonic.empty() || octra::looks_like_mnemonic(priv)) {
                std::string mn = mnemonic.empty() ? priv : mnemonic;
                octra::WalletWipe<std::string> wipe_mn{mn};
                int hd_version = 2;
                int hd_index = 0;
                if (recover) {
                    for (const auto& entry : octra::load_manifest()) {
                        if (entry.addr != recovery_address) continue;
                        hd_index = entry.hd_index;
                        hd_version = entry.hd_version == 1 ? 1 : 2;
                        break;
                    }
                    imported = octra::wallet_from_mnemonic(mn, hd_version, hd_index);
                    if (imported.addr != recovery_address) {
                        hd_version = hd_version == 1 ? 2 : 1;
                        imported.clear_secrets();
                        imported = octra::wallet_from_mnemonic(mn, hd_version, hd_index);
                    }
                    if (imported.addr != recovery_address)
                        throw std::runtime_error("recovery secret does not match account address");
                } else {
                    std::string addr_v2 = octra::addr_from_mnemonic(mn, 2);
                    std::string addr_v1 = octra::addr_from_mnemonic(mn, 1);
                    std::string rpc_url = g_wallet_loaded ? g_wallet.rpc_url : "https://devnet.octrascan.io/rpc";
                    octra::RpcClient probe;
                    probe.set_url(rpc_url);
                    const auto generation = g_wallet_generation;
                    lock.unlock();
                    wallet_write.release();
                    auto r2 = probe.get_balance(addr_v2);
                    auto r1 = probe.get_balance(addr_v1);
                    if (!wallet_write.acquire()) {
                        res.status = 409;
                        res.set_content(err_json("wallet operation active; import not applied").dump(), "application/json");
                        return;
                    }
                    lock.lock();
                    if (generation != g_wallet_generation || already_loaded != g_wallet_loaded.load()) {
                        res.status = 409;
                        res.set_content(err_json("wallet changed during import; import not applied").dump(), "application/json");
                        return;
                    }
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
                    imported = octra::wallet_from_mnemonic(mn, hd_version);
                }
                is_mnemonic = true;
                fprintf(stderr, "wallet imported (seed phrase, v%d): %s\n", hd_version, imported.addr.c_str());
            } else {
                imported = octra::wallet_from_key(priv);
                fprintf(stderr, "wallet imported (private key): %s\n", imported.addr.c_str());
            }
            if (already_loaded && imported.addr == g_wallet.addr)
                throw std::runtime_error("active wallet already exists");
            std::string final_path;
            if (recover) {
                if (imported.addr != recovery_address)
                    throw std::runtime_error("recovery secret does not match account address");
                const auto entries = octra::load_manifest();
                const bool known = std::any_of(entries.begin(), entries.end(), [&](const auto& entry) {
                    return entry.addr == recovery_address;
                });
                std::ifstream existing(octra::wallet_path_for(recovery_address), std::ios::binary);
                if (!known && !existing.good()) throw std::runtime_error("recovery account not found");
                final_path = std::string(octra::WALLET_DIR) + "/wallet_" + imported.addr.substr(3)
                    + "_recovered_" + octra::wallet_file_nonce() + ".oct";
            } else {
                final_path = octra::new_wallet_path(imported.addr);
            }
            octra::save_wallet_encrypted(final_path, imported, pin);
            {
                octra::ManifestEntry me;
                me.name = name;
                me.file = final_path;
                me.addr = imported.addr;
                me.hd = is_mnemonic;
                me.hd_version = imported.hd_version;
                me.hd_index = imported.hd_index;
                if (is_mnemonic) me.master_seed_hash = octra::compute_seed_hash(imported.master_seed_b64);
                octra::manifest_upsert(me);
            }
            if (!already_loaded) {
                publishing = true;
                g_wallet.clear_secrets();
                g_wallet = imported;
                g_wallet_path = final_path;
                g_pin_session.set(pin);
                init_wallet_subsystems();
            }
            json j;
            j["address"] = imported.addr;
            j["switched"] = !already_loaded;
            res.set_content(j.dump(), "application/json");
        } catch (const std::exception& e) {
            if (!lock.owns_lock()) lock.lock();
            if (publishing) {
                g_wallet_loaded = false;
                g_wallet.clear_secrets();
                g_pin_session.clear();
            }
            res.status = 400;
            res.set_content(err_json(e.what()).dump(), "application/json");
            return;
        }
    });

    svr.Get("/api/wallet", [](const httplib::Request&, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(g_mtx);
        WALLET_GUARD
        json j;
        j["address"] = g_wallet.addr;
        j["public_key"] = g_wallet.pub_b64;
        j["generation"] = std::to_string(g_wallet_generation);
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
        std::lock_guard<std::mutex> lock(g_mtx);
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

    const auto switch_wallet = [&access, &check_access](const httplib::Request& req, httplib::Response& res) {
        if (octra::ApiAccess::entry(req) && (req.body.size() > 4096
            || req.get_header_value_count("Content-Type") != 1
            || req.get_header_value("Content-Type") != "application/json")) {
            res.status = 400;
            res.set_content(err_json("small JSON sign-in request required").dump(), "application/json");
            return;
        }
        PVAC_LIFETIME_WRITE_GUARD
        if (!check_access(req, res)) return;
        std::lock_guard<std::mutex> lock(g_mtx);
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string addr = body.value("addr", "");
        const std::string file = body.value("file", "");
        std::string pin = body.value("pin", "");
        octra::WalletWipe<std::string> wipe_pin{pin};
        if ((addr.empty() && file.empty()) || pin.empty() || pin.size() > 1024
            || body.value("migrate_legacy", false)) {
            res.status = 400;
            res.set_content(err_json("addr and pin required").dump(), "application/json");
            return;
        }
        auto entries = octra::load_manifest();
        std::string target_path;
        for (auto& e : entries) {
            if ((!addr.empty() && e.addr == addr && (file.empty() || e.file == file))
                || (addr.empty() && e.file == file)) { target_path = e.file; addr = e.addr; break; }
        }
        if (target_path.empty()) {
            res.status = 404;
            res.set_content(err_json("account not found in manifest").dump(), "application/json");
            return;
        }

        octra::Wallet next_wallet;
        octra::SessionPin next_pin;
        const bool same = octra::ApiAccess::entry(req) && g_wallet_loaded && g_wallet_path == target_path;
        try {
            const auto verified = g_pin_attempts.verify([&] {
                if (same) return g_pin_session.matches(pin);
                next_wallet = octra::load_wallet_encrypted(target_path, pin);
                if (!addr.empty() && next_wallet.addr != addr)
                    throw std::runtime_error("wallet address differs from selection");
                return true;
            });
            if (verified == octra::PinResult::wait) {
                pin_reply(res, 429, "PIN attempts delayed");
                return;
            }
            if (verified != octra::PinResult::accepted)
                throw std::runtime_error("PIN refused");
            if (same) {
                access.renew(req, res, g_wallet.addr, g_wallet_generation);
                res.set_content(json({{"address", g_wallet.addr}, {"public_key", g_wallet.pub_b64},
                    {"has_master_seed", g_wallet.has_master_seed()}}).dump(), "application/json");
                return;
            }
            next_pin.set(pin);
        } catch (const std::exception& error) {
            pin_reply(res, 403, error.what());
            return;
        }

        if (g_wallet_loaded) {
            g_wallet_loaded = false;
            ++g_wallet_generation;
            close_own_history();
            history_runtime_clear_all();
            token_history_runtime_clear_all();
            clear_enc_bal_cache();
            g_pvac_ok = false;
            g_pvac_confirmed = false;
            g_pvac_foreign = false;
            g_pvac_pubkey_b64.clear();
            g_pvac_remote_pubkey_b64.clear();
            clear_pvac_repair_required();
            g_pvac.reset();
            leveldb::DB* old_db = g_txcache.detach();
            if (old_db) std::thread([old_db]() { delete old_db; }).detach();
            g_wallet.clear_secrets();
            g_pin_session.clear();
        }

        try {
            g_wallet = next_wallet;
            g_wallet_path = target_path;
            g_pin_session.exchange(next_pin);
            fprintf(stderr, "switched to wallet: %s\n", g_wallet.addr.c_str());
            init_wallet_subsystems();
            access.renew(req, res, g_wallet.addr, g_wallet_generation);
        } catch (const std::exception& e) {
            g_wallet_loaded = false;
            g_wallet.clear_secrets();
            g_pin_session.clear();
            res.status = 403;
            res.set_content(err_json(e.what()).dump(), "application/json");
            return;
        }
        json j;
        j["address"] = g_wallet.addr;
        j["public_key"] = g_wallet.pub_b64;
        j["has_master_seed"] = g_wallet.has_master_seed();
        res.set_content(j.dump(), "application/json");
    };
    svr.Post("/api/wallet/switch", switch_wallet);
    svr.Post("/api/browser/login", switch_wallet);

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
        if (pin.empty()) {
            res.status = 400;
            res.set_content(err_json("pin required").dump(), "application/json");
            return;
        }
        if (!wallet_pin_ok(body, res)) return;
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
        std::lock_guard<std::mutex> lock(g_mtx);
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
        std::lock_guard<std::mutex> lock(g_mtx);
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

    svr.Get("/api/staging", [](const httplib::Request&, httplib::Response& res) {
        WALLET_GUARD
        res.set_content(wallet_staging().dump(), "application/json");
    });

    svr.Get("/api/balance", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        const auto read = wallet_read(&req);

        bool pvac_ok;
        bool pvac_foreign;
        std::string address;
        std::string generation;
        {
            std::lock_guard<std::mutex> lock(g_mtx);
            if (!g_wallet_loaded) {
                res.status = 503;
                res.set_content(err_json("no wallet loaded").dump(), "application/json");
                return;
            }
            pvac_ok = g_pvac_ok;
            pvac_foreign = g_pvac_foreign;
            address = g_wallet.addr;
            generation = std::to_string(g_wallet_generation);
        }

        auto balance_future = std::async(
            std::launch::async,
            [read]() {
                octra::RpcClient rpc(read.url);
                return get_nonce_balance_for(read.addr, rpc, true);
            });
        auto staging_future = std::async(std::launch::async, [read]() { return wallet_staging(&read); });
        std::optional<EncBalResult> eb;
        if (pvac_ok)
            eb = get_encrypted_balance(&read);
        auto bi = balance_future.get();
        json j = staging_future.get();
        j["address"] = address;
        j["generation"] = generation;
        j["public_balance"] = bi.balance_raw;
        j["nonce"] = bi.confirmed_nonce;
        j["pending_nonce"] = bi.pending_nonce;
        j["encrypted_cipher_present"] = false;
        j["encrypted_balance_known"] = false;
        if (!bi.ok)
            j["account_unknown"] = true;
        if (eb) {
            j["encrypted_balance_error"] = eb->error;
            if (eb->ok) {
                const bool present = !eb->cipher.empty() && eb->cipher != "0";
                j["encrypted_cipher_present"] = present;
                j["encrypted_balance_known"] = eb->amount_known;
                if (eb->amount_known) {
                    j["encrypted_balance"] = std::to_string(eb->decrypted);
                } else {
                    j["encrypted_balance_unknown"] = true;
                    j["encrypted_balance_state"] = eb->read_unavailable ? "unavailable"
                        : eb->inspected && !eb->key_proven ? "legacy_upgrade_required" : "unreadable";
                }
            } else {
                j["encrypted_balance_unknown"] = true;
                j["encrypted_balance_state"] = "unavailable";
            }
        } else {
            j["encrypted_balance_unknown"] = true;
        }
        if (pvac_foreign)
            j["pvac_foreign"] = true;
        std::lock_guard<std::mutex> lock(g_mtx);
        read.check();
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(j.dump(), "application/json");
    });

    svr.Get("/api/pvac/cipher_structure", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        const auto read = wallet_read(&req);
        octra::RpcClient rpc(read.url);
        const auto publish = [&](const json& value) {
            std::lock_guard<std::mutex> lock(g_mtx);
            read.check();
            res.set_content(value.dump(), "application/json");
        };

        std::string addr;
        {
            std::lock_guard<std::mutex> lock(g_mtx);
            if (!g_wallet_loaded) {
                res.status = 503;
                res.set_content(err_json("no wallet loaded").dump(), "application/json");
                return;
            }
            addr = g_wallet.addr;
        }

        auto remote = rpc.get_encrypted_cipher(read.addr);
        if (!remote.ok) {
            res.status = 502;
            res.set_content(err_json("encrypted ciphertext lookup failed").dump(), "application/json");
            return;
        }
        {
            std::lock_guard<std::mutex> lock(g_mtx);
            read.check();
            if (!g_wallet_loaded || g_wallet.addr != addr) {
                res.status = 409;
                res.set_content(err_json("active wallet changed").dump(), "application/json");
                return;
            }
        }

        const std::string cipher = remote.result.value("cipher", "0");
        const std::string cipher_type = remote.result.value("cipher_type", "none");
        json j;
        j["address"] = addr;
        j["cipher_type"] = cipher_type;
        j["present"] = !cipher.empty() && cipher != "0";
        if (cipher.empty() || cipher == "0") {
            j["supported"] = true;
            j["layers"] = json::array();
            j["edge_samples"] = json::array();
            publish(j);
            return;
        }
        if (cipher.rfind(octra::HFHE_PREFIX, 0) != 0) {
            j["supported"] = false;
            j["reason"] = "legacy ciphertext structure is unavailable";
            publish(j);
            return;
        }

        octra::CipherMap map;
        std::string error;
        if (!octra::PvacMap::read(cipher, map, error)) {
            res.status = 422;
            res.set_content(err_json(error).dump(), "application/json");
            return;
        }

        const auto density = [](uint64_t ones, uint64_t bits) {
            return bits == 0 ? 0.0 :
                static_cast<double>(ones) / static_cast<double>(bits);
        };
        j["supported"] = true;
        j["format"] = "hfhe_v1";
        j["wire_bytes"] = map.wire_bytes;
        j["wire_hash"] = map.wire_hash;
        j["slots"] = map.slots;
        j["c0_count"] = map.c0_count;
        j["layer_count"] = map.layers.size();
        j["base_layers"] = map.base_layers;
        j["prod_layers"] = map.prod_layers;
        j["max_depth"] = map.max_depth;
        j["edge_count"] = map.edge_count;
        j["sigma_density"] = density(map.sigma_ones, map.sigma_bits);
        j["sigma_sampled_edges"] = map.sigma_samples;
        j["sigma_exact"] = map.sigma_exact;
        j["private_spend_max_base_layers"] =
            octra::pvac_upgrade_policy::private_spend_refresh_base_layers;
        j["layers"] = json::array();
        for (const auto& layer : map.layers) {
            json item;
            item["id"] = layer.id;
            item["rule"] = layer.rule == 0 ? "base" : "prod";
            if (layer.rule != 0) {
                item["parent_a"] = layer.parent_a;
                item["parent_b"] = layer.parent_b;
            }
            item["depth"] = layer.depth;
            item["edge_count"] = layer.edge_count;
            item["r_pc_count"] = layer.r_pc_count;
            item["pc_count"] = layer.pc_count;
            item["has_r_com"] = layer.has_r_com;
            item["sigma_density"] = density(layer.sigma_ones, layer.sigma_bits);
            item["sigma_sampled_edges"] = layer.sigma_samples;
            item["sigma_exact"] = layer.sigma_exact;
            j["layers"].push_back(std::move(item));
        }
        j["edge_samples"] = json::array();
        for (const auto& edge : map.edges) {
            json item;
            item["layer_id"] = edge.layer_id;
            item["idx"] = edge.idx;
            item["sign"] = edge.channel == 0 ? "+" : "-";
            item["weight_slots"] = edge.weight_slots;
            item["sigma_density"] = density(edge.sigma_ones, edge.sigma_bits);
            j["edge_samples"].push_back(std::move(item));
        }
        publish(j);
    });

    svr.Get("/api/history", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string addr;
        std::string rpc_url;
        uint64_t generation = 0;
        {
            std::lock_guard<std::mutex> lock(g_mtx);
            if (!g_wallet_loaded) {
                res.status = 503;
                res.set_content(err_json("no wallet loaded").dump(), "application/json");
                return;
            }
            addr = g_wallet.addr;
            rpc_url = g_wallet.rpc_url;
            generation = g_wallet_generation;
        }
        int limit = 20, offset = 0;
        if (req.has_param("limit")) limit = std::stoi(req.get_param_value("limit"));
        if (req.has_param("offset")) offset = std::stoi(req.get_param_value("offset"));
        if (limit < 1) limit = 1;
        if (limit > 500) limit = 500;
        if (offset < 0) offset = 0;
        json own = json::array();
        uint64_t own_total = 0;
        std::string own_error;
        try {
            own = own_history_page(addr, generation, limit, offset, own_total);
            refresh_own_rows(addr, generation, own);
        } catch (const std::exception& error) {
            own_error = error.what();
        }
        const auto wallet_current = [&]() {
            std::lock_guard<std::mutex> lock(g_mtx);
            return g_wallet_loaded && g_wallet.addr == addr
                && g_wallet_generation == generation && g_wallet.rpc_url == rpc_url;
        };
        const auto own_only = [&]() {
            if (!wallet_current()) {
                res.status = 409;
                res.set_content(err_json("history wallet changed").dump(), "application/json");
                return;
            }
            json result = {{"transactions", json::array()}, {"rejected", json::array()},
                {"local", own}, {"local_total", own_total}, {"total", own_total},
                {"offset", offset}, {"limit", limit}, {"history_status", "unavailable"},
                {"has_more", own_total > static_cast<uint64_t>(offset) + own.size()}};
            if (!own_error.empty()) result["local_error"] = own_error;
            res.set_content(result.dump(), "application/json");
        };
        const double now = now_ts();
        const std::string source = req.has_param("source") ? req.get_param_value("source") : "";
        if (!source.empty() && source != "archive" && source != "live") {
            res.status = 400;
            res.set_content(err_json("invalid history source").dump(), "application/json");
            return;
        }
        const std::string page_key = source + ":" + std::to_string(limit) + ":" + std::to_string(offset);
        HistoryRuntimeState runtime = history_runtime_get(addr);

        auto convert_row = [](const json& row, const std::string& status) -> json {
            json tx;
            tx["hash"] = row.value("hash", "");
            tx["from"] = row.value("from", "");
            tx["to_"] = row.value("to", row.value("to_", ""));
            if (tx["to_"] != "stealth" && tx["to_"] != "multi_exec"
                && !octra::program_cli::valid_address(tx["to_"].get<std::string>())) tx["to_"] = "";
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
                tx["reject_reason"] = row["reason"].get<std::string>();
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
        const bool runtime_page_fresh = offset > 0 && runtime_page_present
            && runtime_page_ts_it != runtime.page_ts.end()
            && (now - runtime_page_ts_it->second) < 10.0;
        if (runtime_top_fresh || runtime_page_fresh) {
            txs = runtime_page_it->second;
            const auto& metadata = runtime.metadata.at(page_key);
            rejected = metadata.at("rejected");
            total = metadata.at("total").get<int>();
            served = true;
        }

        if (!served) {
            int fetch_limit = limit;
            if (offset == 0) fetch_limit = std::max(limit, 50);
            octra::RpcClient history(octra::endpoint_policy::history_url(rpc_url));
            const auto fresh = history.get_txs_by_address(addr, fetch_limit, offset, source);
            const auto& page = fresh.result;
            if (!fresh.ok || !page.is_object() || !page.contains("transactions") ||
                !page["transactions"].is_array() || !page.contains("total") ||
                !page["total"].is_number_integer() || page["total"] < 0 ||
                page["total"] > INT_MAX) {
                own_only();
                return;
            }
            for (const char* key : {"transactions", "rejected", "dropped"}) {
                if (!page.contains(key)) continue;
                if (!page[key].is_array() || std::any_of(page[key].begin(), page[key].end(),
                    [](const json& row) {
                        return !row.is_object() || !row.contains("hash") ||
                            !row["hash"].is_string() || row["hash"].get<std::string>().empty();
                    })) {
                    own_only();
                    return;
                }
            }
            {
                if (runtime.pages.size() >= 64 && !runtime.pages.count(page_key))
                    runtime = {};
                total = page["total"].get<int>();
                if (fresh.result.contains("transactions")) {
                    json fetched_rows = json::array();
                    for (auto& row : fresh.result["transactions"]) {
                        json converted = convert_row(row, "confirmed");
                        fetched_rows.push_back(converted);
                    }
                    std::lock_guard<std::mutex> lock(g_mtx);
                    if (!g_wallet_loaded || g_wallet_generation != generation
                        || g_wallet.rpc_url != rpc_url || g_wallet.addr != addr) {
                        res.status = 409;
                        res.set_content(err_json("history wallet changed").dump(), "application/json");
                        return;
                    }
                    if (g_txcache.is_open()) {
                        if (!fetched_rows.empty()) g_txcache.store_txs(addr, fetched_rows);
                        g_txcache.set_total(addr, std::max(total, g_txcache.get_total(addr)));
                    }
                    for (int i = 0; i < static_cast<int>(fetched_rows.size()) && i < limit; ++i)
                        txs.push_back(fetched_rows[i]);
                }
                if (fresh.result.contains("rejected"))
                    for (auto& row : fresh.result["rejected"])
                        rejected.push_back(convert_row(row, "rejected"));
                if (fresh.result.contains("dropped"))
                    for (auto& row : fresh.result["dropped"])
                        rejected.push_back(convert_row(row, "dropped"));
                runtime.metadata[page_key] = {
                    {"history_status", page.value("scanner_history", "indexed")},
                    {"history_source", page.value("scanner_source", "rpc")},
                    {"history_archive", page.value("scanner_archive", false)},
                    {"total", total},
                    {"rejected", rejected}
                };
                runtime.pages[page_key] = txs;
                runtime.page_ts[page_key] = now;
                {
                    std::lock_guard<std::mutex> lock(g_mtx);
                    if (!g_wallet_loaded || g_wallet_generation != generation
                        || g_wallet.rpc_url != rpc_url || g_wallet.addr != addr) {
                        res.status = 409;
                        res.set_content(err_json("history wallet changed").dump(), "application/json");
                        return;
                    }
                    history_runtime_put(addr, runtime);
                }
            }
        }

        if (refresh_history_rows(addr, txs, generation)) {
            runtime.pages[page_key] = txs;
            runtime.page_ts[page_key] = now;
            std::lock_guard<std::mutex> lock(g_mtx);
            if (g_wallet_loaded && g_wallet_generation == generation
                && g_wallet.rpc_url == rpc_url && g_wallet.addr == addr)
                history_runtime_put(addr, runtime);
        }

        json j = runtime.metadata.count(page_key) ? runtime.metadata.at(page_key) : json::object();
        if (!wallet_current()) {
            res.status = 409;
            res.set_content(err_json("history wallet changed").dump(), "application/json");
            return;
        }
        j["local"] = own;
        if (offset == 0) {
            std::lock_guard<std::mutex> lock(g_mtx);
            if (g_wallet_loaded && g_wallet_generation == generation
                && g_wallet.rpc_url == rpc_url && g_txcache.is_open()) {
                for (const auto& row : g_txcache.load_page(addr, 50, 0)) {
                    const auto op = row.value("op_type", "");
                    if (op != "stealth" && op != "claim" && tx_status_is_pending_like(row))
                        j["local"].push_back(row);
                }
            }
        }
        j["local_total"] = own_total;
        if (!own_error.empty()) j["local_error"] = own_error;
        j["transactions"] = txs;
        j["rejected"] = rejected;
        j["count"] = txs.size();
        j["offset"] = offset;
        j["limit"] = limit;
        j["public_total"] = total;
        j["total"] = static_cast<uint64_t>(total) + own_total;
        j["has_more"] = total > (offset + static_cast<int>(txs.size()))
            || own_total > static_cast<uint64_t>(offset) + own.size();
        res.set_content(j.dump(), "application/json");
    });

    svr.Get("/api/token-history", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string addr;
        {
            std::lock_guard<std::mutex> lock(g_mtx);
            if (!g_wallet_loaded) {
                res.status = 503;
                res.set_content(err_json("no wallet loaded").dump(), "application/json");
                return;
            }
            addr = g_wallet.addr;
        }
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
        const double now = now_ts();

        auto classify = [&](const json& tx) -> std::pair<bool, bool> {
            if (tx.value("op_type", "") != "call") return {false, false};
            if (tx.value("encrypted_data", "") != "transfer") return {false, false};
            bool incoming = false;
            try {
                if (tx.contains("message") && tx["message"].is_string()) {
                    const auto& message = tx["message"].get_ref<const std::string&>();
                    octra::JsonShape shape(16384);
                    if (message.size() > 1024 * 1024 || !json::sax_parse(message, &shape))
                        return {true, false};
                    auto parsed = json::parse(message);
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
            json payload = direct.result;
            json rows = payload.value("transactions", json::array());
            hydrate_token_rows(addr, rows, true);
            payload["transactions"] = rows;
            TokenHistoryRuntimeState state;
            state.ts = now;
            state.rows = rows;
            state.incoming = payload.value("incoming", 0);
            state.outgoing = payload.value("outgoing", 0);
            token_history_runtime_put(addr, state);
            res.set_content(payload.dump(), "application/json");
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
        hydrate_token_rows(addr, rows, true);

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
        auto limit = req.get_param_value("limit");
        if (addr.empty() || key.empty()) {
            res.status = 400;
            res.set_content(err_json("address and key required").dump(), "application/json");
            return;
        }
        auto r = g_rpc.contract_storage(addr, key, limit);
        json j;
        if (r.ok && r.result.contains("value") && !r.result["value"].is_null()) {
            j["value"] = r.result["value"];
            j["size"] = r.result.value("size", 0);
            j["truncated"] = r.result.value("truncated", false);
            j["limit"] = r.result.value("limit", 0);
        } else {
            j["value"] = nullptr;
            j["size"] = 0;
            j["truncated"] = false;
        }
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
        std::vector<std::string> ops = {
            "standard",
            "encrypt",
            "decrypt",
            "stealth",
            "claim",
            "deploy",
            "program_deploy",
            "call",
            "program_exec",
            "multi_exec",
            "key_switch"
        };
        std::vector<std::string> methods(ops.size(), "octra_recommendedFee");
        std::vector<nlohmann::json> params;
        params.reserve(ops.size());
        for (auto& op : ops) params.push_back(nlohmann::json::array({op}));
        auto results = g_rpc.call_batch(methods, params, 10);
        json fees;
        for (size_t i = 0; i < ops.size(); ++i) {
            fees[ops[i]] = i < results.size() && results[i].ok
                ? octra::fee_quote(results[i].result) : json(nullptr);
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

        std::string from_addr;
        std::string from_pub_b64;
        ScopedSecret64 from_sk;
        {
            std::lock_guard<std::mutex> lock(g_mtx);
            if (!g_wallet_loaded) {
                res.status = 503;
                res.set_content(err_json("no wallet loaded").dump(), "application/json");
                return;
            }
            if (!wallet_pin_ok(body, res)) return;
            from_addr = g_wallet.addr;
            from_pub_b64 = g_wallet.pub_b64;
            std::memcpy(from_sk.data(), g_wallet.sk, 64);
        }

        auto bi = get_nonce_balance_for(from_addr);
        int nonce = bi.nonce;
        octra::Transaction tx;
        tx.from = from_addr;
        tx.to_ = to;
        tx.amount = std::to_string(raw);
        tx.nonce = nonce + 1;
        tx.ou = parse_ou(body, (raw < 1000000000) ? "10000" : "30000");
        tx.timestamp = now_ts();
        tx.op_type = "standard";
        std::string msg = body.value("message", "");
        if (!msg.empty()) tx.message = msg;
        sign_tx_fields_for(tx, from_pub_b64, from_sk.data());
        auto result = submit_tx_for_addr(tx, from_addr);
        if (result.contains("error")) res.status = 500;
        res.set_content(result.dump(), "application/json");
    });

    svr.Get("/api/pvac/upgrade_status", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        const auto read = wallet_read(&req);
        if (!private_rpc_ok(res, read.url)) return;
        if (g_pvac_upgrade_inflight.load()) {
            auto j = pvac_upgrade_state_json();
            std::lock_guard<std::mutex> lock(g_mtx);
            read.check();
            res.set_content(j.dump(), "application/json");
            return;
        }
        json recent;
        {
            std::lock_guard<std::mutex> status_lock(g_pvac_status_mtx);
            recent = pending_pvac_upgrade(read);
        }
        if (!recent.is_null()) {
            if (recent.contains("retry_nonce")) {
                const auto actual = pvac_upgrade_status_json(&read);
                recent["retry_mode"] = actual.value("mode", "unavailable");
                for (const auto* field : {"encrypted_balance_raw", "encrypted_balance_known", "cipher_present",
                    "repair_required", "compact_refresh", "private_spend_refresh_required", "encrypt_refresh_required"})
                    if (actual.contains(field)) recent[field] = actual[field];
                if (!actual.value("can_submit", false)) {
                    recent["can_submit"] = false;
                    recent["reason"] = actual.value("reason", "migration state unavailable");
                }
            }
            std::lock_guard<std::mutex> lock(g_mtx);
            read.check();
            res.set_content(recent.dump(), "application/json");
            return;
        }
        auto j = pvac_upgrade_status_json(&read);
        apply_pvac_upgrade_fee_gate(j, read);
        j["upgrade_inflight"] = false;
        std::lock_guard<std::mutex> lock(g_mtx);
        read.check();
        res.set_content(j.dump(), "application/json");
    });

    svr.Post("/api/pvac/upgrade_ack", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        PVAC_LIFETIME_GUARD
        json body;
        try { body = json::parse(req.body); } catch (...) { body = json::object(); }
        const std::string tx_hash = body.value("tx_hash", "");
        if (finish_pvac_upgrade(wallet_read(&req), tx_hash, "confirmed").empty()) {
            res.status = 409;
            res.set_content(err_json("encrypted balance upgrade acknowledgement mismatch").dump(), "application/json");
            return;
        }
        refresh_pvac_key_state_readonly();
        res.set_content(json({{"ok", true}}).dump(), "application/json");
    });

    svr.Post("/api/pvac/upgrade_reject", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        PVAC_LIFETIME_GUARD
        json body;
        try { body = json::parse(req.body); } catch (...) { body = json::object(); }
        {
            std::lock_guard<std::mutex> lock(g_mtx);
            if (!wallet_pin_ok(body, res)) return;
        }
        const std::string tx_hash = body.value("tx_hash", "");
        if (finish_pvac_upgrade(wallet_read(&req), tx_hash, "rejected").empty()) {
            res.status = 409;
            res.set_content(err_json("encrypted balance upgrade rejection mismatch").dump(), "application/json");
            return;
        }
        res.set_content(json({{"ok", true}}).dump(), "application/json");
    });

    svr.Post("/api/pvac/upgrade", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        PVAC_LIFETIME_GUARD
        if (!private_rpc_ok(res)) return;
        if (g_pvac_upgrade_inflight.exchange(true)) {
            res.status = 409;
            res.set_content(err_json("encrypted balance upgrade already in progress").dump(), "application/json");
            return;
        }
        AtomicFlagGuard inflight_guard(g_pvac_upgrade_inflight);
        json body;
        try { body = json::parse(req.body); } catch (...) { body = json::object(); }
        json retry;
        if (!pvac_start_plan(wallet_read(&req), body, res, retry)) return;
        pvac_upgrade_stage_set("checking_fee", "waiting for wallet authorization");
        {
            std::lock_guard<std::mutex> lock(g_mtx);
            if (!wallet_pin_ok(body, res)) {
                pvac_upgrade_stage_set("error", "wallet authorization failed");
                return;
            }
        }
        int http_status = 200;
        auto result = submit_pvac_upgrade_tx(body, http_status, false, retry);
        if (result.contains("error")) res.status = http_status;
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/key_switch", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        PVAC_LIFETIME_GUARD
        if (!private_rpc_ok(res)) return;
        if (g_pvac_upgrade_inflight.exchange(true)) {
            res.status = 409;
            res.set_content(err_json("encrypted balance upgrade already in progress").dump(), "application/json");
            return;
        }
        AtomicFlagGuard inflight_guard(g_pvac_upgrade_inflight);
        json body;
        try { body = json::parse(req.body); } catch (...) { body = json::object(); }
        json retry;
        if (!pvac_start_plan(wallet_read(&req), body, res, retry)) return;
        pvac_upgrade_stage_set("checking_fee", "waiting for wallet authorization");
        {
            std::lock_guard<std::mutex> lock(g_mtx);
            if (!wallet_pin_ok(body, res)) {
                pvac_upgrade_stage_set("error", "wallet authorization failed");
                return;
            }
        }
        int http_status = 200;
        bool force_refresh = body.value("force_refresh", false) || body.value("refresh", false);
        auto result = submit_pvac_upgrade_tx(body, http_status, force_refresh, retry);
        if (result.contains("error")) res.status = http_status;
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/encrypt", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        PVAC_LIFETIME_GUARD
        if (!private_rpc_ok(res)) return;
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        if (std::stoull(parse_ou(body, "5000")) < 5000) {
            res.status = 400;
            res.set_content(err_json("encrypt fee must be at least 5000 OU").dump(), "application/json");
            return;
        }
        int64_t raw = parse_amount_raw(body);
        if (raw <= 0) {
            res.status = 400;
            res.set_content(err_json("invalid amount (max 6 decimals, no extra dots)").dump(), "application/json");
            return;
        }
        {
            std::lock_guard<std::mutex> lock(g_mtx);
            if (!wallet_pin_ok(body, res)) return;
        }
        auto wallet = pvac_wallet_snapshot();
        if (!wallet.loaded) {
            res.status = 503;
            res.set_content(err_json("no wallet loaded").dump(), "application/json");
            return;
        }
        if (!wallet.pvac_ok) {
            res.status = 500;
            res.set_content(err_json("pvac not available").dump(), "application/json");
            return;
        }
        octra::PvacBridge pvac;
        if (!pvac.init(wallet.priv_b64)) {
            if (!wallet.priv_b64.empty()) octra::secure_zero(&wallet.priv_b64[0], wallet.priv_b64.size());
            res.status = 500;
            res.set_content(err_json("pvac init failed").dump(), "application/json");
            return;
        }
        if (!wallet.priv_b64.empty()) octra::secure_zero(&wallet.priv_b64[0], wallet.priv_b64.size());
        wallet.priv_b64.clear();
        pvac.proof_policy(read_proof_policy(wallet.addr));
        std::string local_pk = pvac.serialize_pubkey_b64();
        auto remote = g_rpc.get_pvac_pubkey(wallet.addr, 5);
        if (!remote.ok || !remote.result.is_object() ||
            !remote.result.contains("pvac_pubkey")) {
            res.status = 503;
            res.set_content(err_json("cannot read registered encryption key").dump(), "application/json");
            return;
        }
        bool remote_ok = remote.ok && remote.result.is_object() && !remote.result["pvac_pubkey"].is_null();
        if (remote_ok) {
            std::string remote_pk = remote.result.value("pvac_pubkey", "");
            if (remote_pk != local_pk && !pvac.pubkey_extends_local(remote_pk)) {
                {
                    std::lock_guard<std::mutex> lock(g_mtx);
                    if (g_wallet_loaded && g_wallet.addr == wallet.addr) {
                        g_pvac_foreign = true;
                    }
                }
                res.status = 400;
                res.set_content(err_json("key mismatch: use key switch to reset encryption key").dump(), "application/json");
                return;
            }
        } else {
            res.status = 409;
            res.set_content(err_json("pvac key is not registered; run encryption key upgrade first").dump(), "application/json");
            return;
        }
        {
            std::lock_guard<std::mutex> lock(g_mtx);
            if (!g_wallet_loaded || g_wallet.addr != wallet.addr) {
                res.status = 409;
                res.set_content(err_json("wallet state changed during encrypt").dump(), "application/json");
                return;
            }
            g_pvac_confirmed = true;
            g_pvac_foreign = false;
        }
        auto current_eb = get_encrypted_balance();
        if (!current_eb.ok) {
            res.status = 503;
            res.set_content(err_json(current_eb.error.empty() ? "cannot read encrypted balance" : current_eb.error).dump(), "application/json");
            return;
        }
        if (pvac_balance_needs_privacy_refresh(pvac, current_eb.cipher)) {
            {
                std::lock_guard<std::mutex> lock(g_mtx);
                mark_pvac_repair_required(wallet.addr);
            }
            res.status = 409;
            res.set_content(err_json("encrypted balance privacy refresh required before encrypt").dump(), "application/json");
            return;
        }
        if (current_eb.key_proven &&
            !octra::pvac_upgrade_policy::deposit_allowed(
                pvac.base_layer_count(current_eb.cipher))) {
            res.status = 409;
            res.set_content(err_json("encrypted balance compact refresh required before encrypt").dump(), "application/json");
            return;
        }
        fprintf(stderr, "event = encrypt stage = pin_ok\n");
        fprintf(stderr, "event = encrypt stage = pvac_registered\n");
        uint8_t seed[32];
        octra::random_bytes(seed, 32);
        pvac_cipher ct = pvac.encrypt((uint64_t)raw, seed);
        std::string cipher_str = pvac.encode_proven_cipher(ct);
        fprintf(stderr, "event = encrypt stage = cipher_ready\n");

        uint8_t blinding[32];
        octra::random_bytes(blinding, 32);
        auto amt_commit = pvac.pedersen_commit((uint64_t)raw, blinding);
        std::string amt_commit_b64 = octra::base64_encode(amt_commit.data(), 32);
        pvac_zero_proof zkp = pvac.make_cipher_proof(ct, (uint64_t)raw, blinding);
        if (!zkp) {
            pvac.free_cipher(ct);
            res.status = 500;
            res.set_content(err_json("encrypt proof generation failed").dump(), "application/json");
            return;
        }
        std::string zp_str = pvac.encode_zero_proof(zkp);
        pvac.free_zero_proof(zkp);
        pvac.free_cipher(ct);
        fprintf(stderr, "event = encrypt stage = proof_ready\n");

        json enc_data;
        enc_data["cipher"] = cipher_str;
        enc_data["amount_commitment"] = amt_commit_b64;
        enc_data["zero_proof"] = zp_str;
        enc_data["blinding"] = octra::base64_encode(blinding, 32);

        auto bi = get_nonce_balance_for(wallet.addr); int nonce = bi.nonce;
        octra::Transaction tx;
        tx.from = wallet.addr;
        tx.to_ = wallet.addr;
        tx.amount = std::to_string(raw);
        tx.nonce = nonce + 1;
        tx.ou = parse_ou(body, recommended_ou_for_op("encrypt", "1000000"));
        tx.timestamp = now_ts();
        tx.op_type = "encrypt";
        tx.encrypted_data = enc_data.dump();
        check_proof_policy(wallet.addr, pvac.proof_policy());
        sign_tx_fields_for(tx, wallet.pub_b64, wallet.sk.data());
        auto result = submit_tx_for_addr(tx, wallet.addr);
        fprintf(stderr, "event = encrypt stage = submitted ok = %s\n",
            result.contains("error") ? "false" : "true");
        if (result.contains("error")) res.status = 500;
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/decrypt", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        PVAC_LIFETIME_GUARD
        if (!private_rpc_ok(res)) return;
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        if (std::stoull(parse_ou(body, "5000")) < 5000) {
            res.status = 400;
            res.set_content(err_json("decrypt fee must be at least 5000 OU").dump(), "application/json");
            return;
        }
        int64_t raw = parse_amount_raw(body);
        if (raw <= 0) {
            res.status = 400;
            res.set_content(err_json("invalid amount (max 6 decimals, no extra dots)").dump(), "application/json");
            return;
        }
        double decrypt_t0 = now_ts();
        std::string from_addr;
        std::string from_pub_b64;
        std::string from_priv_b64;
        octra::WalletWipe<std::string> wipe_priv{from_priv_b64};
        ScopedSecret64 from_sk;
        {
            std::lock_guard<std::mutex> lock(g_mtx);
            if (!g_wallet_loaded) {
                res.status = 503;
                res.set_content(err_json("no wallet loaded").dump(), "application/json");
                return;
            }
            if (!wallet_pin_ok(body, res)) return;
            if (!g_pvac_ok) {
                res.status = 500;
                res.set_content(err_json("pvac not available").dump(), "application/json");
                return;
            }
            from_addr = g_wallet.addr;
            from_pub_b64 = g_wallet.pub_b64;
            from_priv_b64 = g_wallet.priv_b64;
            std::memcpy(from_sk.data(), g_wallet.sk, 64);
        }

        if (!pvac_key_ready(res)) {
            if (!from_priv_b64.empty()) octra::secure_zero(&from_priv_b64[0], from_priv_b64.size());
            return;
        }

        octra::PvacBridge pvac;
        if (!pvac.init(from_priv_b64)) {
            if (!from_priv_b64.empty()) octra::secure_zero(&from_priv_b64[0], from_priv_b64.size());
            res.status = 500;
            res.set_content(err_json("pvac init failed").dump(), "application/json");
            return;
        }
        if (!from_priv_b64.empty()) octra::secure_zero(&from_priv_b64[0], from_priv_b64.size());
        from_priv_b64.clear();

        fprintf(stderr, "event = decrypt stage = pin_ok\n");
        pvac.proof_policy(read_proof_policy(from_addr));
        std::string bal_sig = octra::sign_balance_request(from_addr, from_sk.data());
        auto eb_r = g_rpc.get_encrypted_balance(from_addr, bal_sig, from_pub_b64);
        EncBalResult eb;
        if (!eb_r.ok || !eb_r.result.is_object()) {
            eb.error = eb_r.error.empty() ? "cannot read encrypted balance" : eb_r.error;
        } else {
            eb.cipher = eb_r.result.value("cipher", "0");
            eb.ok = true;
            eb.amount_known = eb.cipher.empty() || eb.cipher == "0"
                || pvac.try_get_balance(eb.cipher, eb.decrypted);
            if (!eb.amount_known)
                eb.error = "encrypted balance amount is outside the valid balance domain";
        }
        fprintf(stderr, "event = decrypt stage = balance_ready elapsed = %.3f\n", now_ts() - decrypt_t0);
        if (!eb.ok) {
            res.status = 503;
            res.set_content(err_json(eb.error.empty() ? "cannot read encrypted balance" : eb.error).dump(), "application/json");
            return;
        }
        if (pvac_balance_needs_privacy_refresh(pvac, eb.cipher)) {
            {
                std::lock_guard<std::mutex> lock(g_mtx);
                mark_pvac_repair_required(from_addr);
            }
            res.status = 409;
            res.set_content(err_json("encrypted balance privacy refresh required before decrypt").dump(), "application/json");
            return;
        }
        if (octra::pvac_upgrade_policy::refresh_before_private_spend(
                pvac.base_layer_count(eb.cipher))) {
            res.status = 409;
            res.set_content(err_json("encrypted balance compact refresh required before decrypt").dump(), "application/json");
            return;
        }
        if (!eb.amount_known) {
            res.status = 409;
            res.set_content(err_json("encrypted balance upgrade required before decrypt").dump(), "application/json");
            return;
        }
        if (eb.decrypted < raw) {
            res.status = 400;
            char buf[128];
            snprintf(buf, sizeof(buf), "insufficient encrypted balance: have %ld, need %ld",
                (long)eb.decrypted, (long)raw);
            res.set_content(err_json(buf).dump(), "application/json");
            return;
        }
        json steps = json::array();

        steps.push_back("[1/5] FHE encrypt amount (PVAC-HFHE)");
        uint8_t seed[32];
        octra::random_bytes(seed, 32);
        pvac_cipher ct = pvac.encrypt((uint64_t)raw, seed);
        std::string cipher_str = pvac.encode_proven_cipher(ct);
        fprintf(stderr, "event = decrypt stage = cipher_ready elapsed = %.3f\n", now_ts() - decrypt_t0);

        uint8_t blinding[32];
        octra::random_bytes(blinding, 32);
        auto amt_commit = pvac.pedersen_commit((uint64_t)raw, blinding);
        std::string amt_commit_b64 = octra::base64_encode(amt_commit.data(), 32);

        pvac_cipher current_ct = pvac.decode_cipher(eb.cipher);
        if (!current_ct) {
            pvac.free_cipher(ct);
            res.status = 500;
            res.set_content(err_json("cannot decode encrypted balance").dump(), "application/json");
            return;
        }
        pvac_cipher new_bal_ct = pvac.ct_sub(current_ct, ct);
        uint64_t new_bal_value = (uint64_t)(eb.decrypted - raw);

        steps.push_back("[2/5] cipher proofs (parallel)");

        double proof_t0 = now_ts();
        fprintf(stderr, "event = decrypt stage = proof_start\n");
        uint8_t balance_blinding[32];
        octra::random_bytes(balance_blinding, 32);
        auto balance_commit =
            pvac.pedersen_commit(new_bal_value, balance_blinding);
        pvac_zero_proof zkp = nullptr;
        pvac_zero_proof rp_bal = nullptr;
        std::thread proof_task([&]() {
            zkp = pvac.make_cipher_proof(ct, (uint64_t)raw, blinding);
        });
        std::thread t_range([&]() {
            rp_bal = pvac.make_range_proof(new_bal_ct, new_bal_value, balance_blinding);
        });
        proof_task.join();
        t_range.join();
        fprintf(stderr, "event = decrypt stage = proofs_ready elapsed = %.3f proof_elapsed = %.3f\n",
            now_ts() - decrypt_t0,
            now_ts() - proof_t0);
        if (!zkp || !rp_bal ||
            !pvac.verify_range_proof(new_bal_ct, rp_bal, balance_commit)) {
            if (zkp) pvac.free_zero_proof(zkp);
            if (rp_bal) pvac.free_zero_proof(rp_bal);
            pvac.free_cipher(new_bal_ct);
            pvac.free_cipher(current_ct);
            pvac.free_cipher(ct);
            {
                std::lock_guard<std::mutex> lock(g_mtx);
                mark_pvac_repair_required(from_addr);
            }
            res.status = 409;
            res.set_content(err_json("encrypted balance repair required before decrypt").dump(), "application/json");
            return;
        }
        std::string zp_str = pvac.encode_zero_proof(zkp);
        pvac.free_zero_proof(zkp);
        std::string rp_bal_str = pvac.encode_cipher_range(rp_bal);
        pvac.free_zero_proof(rp_bal);
        pvac.free_cipher(new_bal_ct);
        pvac.free_cipher(current_ct);
        pvac.free_cipher(ct);

        json enc_data;
        enc_data["cipher"] = cipher_str;
        enc_data["amount_commitment"] = amt_commit_b64;
        enc_data["zero_proof"] = zp_str;
        enc_data["blinding"] = octra::base64_encode(blinding, 32);
        enc_data["range_proof_balance"] = rp_bal_str;

        steps.push_back("[4/5] building decrypt transaction");

        auto bi = get_nonce_balance_for(from_addr); int nonce = bi.nonce;
        octra::Transaction tx;
        tx.from = from_addr;
        tx.to_ = from_addr;
        tx.amount = std::to_string(raw);
        tx.nonce = nonce + 1;
        tx.ou = parse_ou(body, recommended_ou_for_op("decrypt", "1000000"));
        tx.timestamp = now_ts();
        tx.op_type = "decrypt";
        tx.encrypted_data = enc_data.dump();
        check_proof_policy(from_addr, pvac.proof_policy());
        sign_tx_fields_for(tx, from_pub_b64, from_sk.data());
        json result;
        {
            std::lock_guard<std::mutex> lock(g_mtx);
            if (!g_wallet_loaded || g_wallet.addr != from_addr) {
                res.status = 409;
                res.set_content(err_json("wallet state changed during decrypt").dump(), "application/json");
                return;
            }
            result = submit_tx(tx);
        }
        fprintf(stderr, "event = decrypt stage = submitted elapsed = %.3f ok = %s\n",
            now_ts() - decrypt_t0,
            result.contains("error") ? "false" : "true");

        steps.push_back("[5/5] submitted to network");
        result["steps"] = steps;

        if (result.contains("error")) res.status = 500;
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/stealth/send", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        if (!private_rpc_ok(res)) return;
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
        const auto approved_fee = parse_ou(body, recommended_ou_for_op("stealth", "1000000"));
        if (std::stoull(approved_fee) < 5000) {
            res.status = 400;
            res.set_content(err_json("stealth fee must be at least 5000 OU").dump(), "application/json");
            return;
        }

        std::string from_addr, from_pub_b64, from_priv_b64, eb_sig;
        std::array<uint8_t, 64> from_sk{};
        uint64_t generation = 0;
        {
            std::lock_guard<std::mutex> lock(g_mtx);
            if (!wallet_pin_ok(body, res)) return;
            if (!g_wallet_loaded || !g_pvac_ok) {
                res.status = 500;
                res.set_content(err_json("pvac not available").dump(), "application/json");
                return;
            }
            from_addr = g_wallet.addr;
            generation = g_wallet_generation;
            from_pub_b64 = g_wallet.pub_b64;
            from_priv_b64 = g_wallet.priv_b64;
            eb_sig = octra::sign_balance_request(from_addr, g_wallet.sk);
            std::memcpy(from_sk.data(), g_wallet.sk, 64);
        }
        const auto request_id = private_request_id(body);
        const auto request_key = octra::sha256_hex(json::array({"stealth", to,
            std::to_string(raw), approved_fee}).dump());
        if (const auto saved = private_cached(from_addr, generation, request_id, request_key); !saved.is_null()) {
            if (!from_priv_b64.empty()) octra::secure_zero(from_priv_b64.data(), from_priv_b64.size());
            octra::secure_zero(from_sk.data(), from_sk.size());
            res.set_content(saved.dump(), "application/json");
            return;
        }
        octra::PvacBridge pvac;
        if (!pvac.init(from_priv_b64)) {
            if (!from_priv_b64.empty()) octra::secure_zero(&from_priv_b64[0], from_priv_b64.size());
            res.status = 500;
            res.set_content(err_json("pvac init failed").dump(), "application/json");
            return;
        }
        if (!from_priv_b64.empty()) octra::secure_zero(&from_priv_b64[0], from_priv_b64.size());
        from_priv_b64.clear();
        pvac.proof_policy(read_proof_policy(from_addr));
        if (to == from_addr) {
            ensure_pubkey_registered(from_addr, from_sk.data(), from_pub_b64);
            pk_cache_erase(to);
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
        if (their_signing_pk.size() != 32 || octra::derive_address(their_signing_pk.data()) != to) {
            pk_cache_erase(to);
            res.status = 400;
            res.set_content(err_json("recipient public key does not match address").dump(), "application/json");
            return;
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

        steps.push_back("[1/8] key exchange");
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
        if (pvac_balance_needs_privacy_refresh(pvac, eb_cipher)) {
            {
                std::lock_guard<std::mutex> repair_lock(g_mtx);
                mark_pvac_repair_required(from_addr);
            }
            res.status = 409;
            res.set_content(err_json("encrypted balance privacy refresh required before stealth send").dump(), "application/json");
            return;
        }
        if (octra::pvac_upgrade_policy::refresh_before_private_spend(
                pvac.base_layer_count(eb_cipher))) {
            res.status = 409;
            res.set_content(err_json("encrypted balance compact refresh required before stealth send").dump(), "application/json");
            return;
        }

        {
            std::lock_guard<std::mutex> state_lock(g_mtx);
            if (!g_wallet_loaded || g_wallet.addr != from_addr) {
                res.status = 409;
                res.set_content(err_json("wallet state changed during send").dump(), "application/json");
                return;
            }
        }

        int64_t eb_decrypted = 0;
        if (!pvac.try_get_balance(eb_cipher, eb_decrypted)) {
            res.status = 409;
            res.set_content(err_json("encrypted balance upgrade required before stealth send").dump(), "application/json");
            return;
        }
        if (eb_decrypted < raw) {
            res.status = 400;
            char buf[128];
            snprintf(buf, sizeof(buf), "insufficient encrypted balance: have %ld, need %ld",
                (long)eb_decrypted, (long)raw);
            res.set_content(err_json(buf).dump(), "application/json");
            return;
        }

        steps.push_back("[4/8] FHE encrypt delta (PVAC-HFHE)");
        uint8_t r_blind[32];
        octra::random_bytes(r_blind, 32);
        std::string enc_amount = octra::encrypt_stealth_amount(shared, (uint64_t)raw, r_blind);
        uint8_t seed[32];
        octra::random_bytes(seed, 32);
        pvac_cipher ct_delta = pvac.encrypt((uint64_t)raw, seed);
        std::string delta_cipher_str = pvac.encode_proven_cipher(ct_delta);
        auto commitment = pvac.commit_ct(ct_delta);
        std::string commitment_b64 = octra::base64_encode(commitment.data(), 32);

        steps.push_back("[5/8] compact cipher range proofs (parallel)");
        pvac_cipher current_ct = pvac.decode_cipher(eb_cipher);
        pvac_cipher new_ct = pvac.ct_sub(current_ct, ct_delta);
        uint64_t new_val = (uint64_t)(eb_decrypted - raw);
        pvac_zero_proof rp_delta = nullptr;
        pvac_zero_proof rp_bal = nullptr;
        pvac_zero_proof send_zkp = nullptr;
        uint8_t delta_range_blind[32];
        uint8_t balance_range_blind[32];
        octra::random_bytes(delta_range_blind, 32);
        octra::random_bytes(balance_range_blind, 32);
        auto delta_range_commit =
            pvac.pedersen_commit(static_cast<uint64_t>(raw), delta_range_blind);
        auto balance_range_commit =
            pvac.pedersen_commit(new_val, balance_range_blind);

        double stealth_range_t0 = now_ts();
        fprintf(stderr, "event = stealth stage = range_proofs_start\n");
        std::thread t_rp_delta([&]() {
            rp_delta = pvac.make_range_proof(ct_delta, (uint64_t)raw, delta_range_blind);
        });
        std::thread t_rp_bal([&]() {
            rp_bal = pvac.make_range_proof(new_ct, new_val, balance_range_blind);
        });
        std::thread send_proof_task([&]() {
            send_zkp = pvac.make_cipher_proof(ct_delta, (uint64_t)raw, r_blind);
        });
        t_rp_delta.join();
        t_rp_bal.join();
        send_proof_task.join();
        fprintf(stderr, "event = stealth stage = range_proofs_ready elapsed = %.3f\n",
            now_ts() - stealth_range_t0);
        if (!send_zkp || !rp_delta ||
            !pvac.verify_range_proof(
                ct_delta,
                rp_delta,
                delta_range_commit)) {
            if (rp_delta) pvac.free_zero_proof(rp_delta);
            if (rp_bal) pvac.free_zero_proof(rp_bal);
            if (send_zkp) pvac.free_zero_proof(send_zkp);
            pvac.free_cipher(ct_delta);
            pvac.free_cipher(current_ct);
            pvac.free_cipher(new_ct);
            res.status = 500;
            res.set_content(err_json("local delta range proof self-check failed").dump(), "application/json");
            return;
        }
        if (!rp_bal ||
            !pvac.verify_range_proof(
                new_ct,
                rp_bal,
                balance_range_commit)) {
            if (rp_delta) pvac.free_zero_proof(rp_delta);
            if (rp_bal) pvac.free_zero_proof(rp_bal);
            if (send_zkp) pvac.free_zero_proof(send_zkp);
            pvac.free_cipher(ct_delta);
            pvac.free_cipher(current_ct);
            pvac.free_cipher(new_ct);
            {
                std::lock_guard<std::mutex> repair_lock(g_mtx);
                mark_pvac_repair_required(from_addr);
            }
            res.status = 500;
            res.set_content(err_json("encrypted balance repair required before stealth send").dump(), "application/json");
            return;
        }

        steps.push_back("[6/8] encoding proofs");
        std::string rp_delta_str = pvac.encode_cipher_range(rp_delta);
        std::string rp_bal_str = pvac.encode_cipher_range(rp_bal);
        std::string send_zp_str = pvac.encode_zero_proof(send_zkp);
        pvac.free_zero_proof(rp_delta);
        pvac.free_zero_proof(rp_bal);
        pvac.free_zero_proof(send_zkp);

        steps.push_back("[7/8] Pedersen commitment + envelope");
        auto amt_commit = pvac.pedersen_commit((uint64_t)raw, r_blind);
        std::string amt_commit_b64 = octra::base64_encode(amt_commit.data(), 32);

        pvac.free_cipher(ct_delta);
        pvac.free_cipher(current_ct);
        pvac.free_cipher(new_ct);

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

        auto bi = get_nonce_balance_for(from_addr); int nonce = bi.nonce;
        octra::Transaction tx;
        tx.from = from_addr;
        tx.to_ = "stealth";
        tx.amount = "0";
        tx.nonce = nonce + 1;
        tx.ou = approved_fee;
        tx.timestamp = now_ts();
        tx.op_type = "stealth";
        tx.encrypted_data = stealth_data.dump();
        check_proof_policy(from_addr, pvac.proof_policy());
        sign_tx_fields_for(tx, from_pub_b64, from_sk.data());
        auto result = submit_private_tx(tx, generation, to, std::to_string(raw), "", request_id, request_key);
        if (result.contains("error")) res.status = 500;
        result["steps"] = steps;
        res.set_content(result.dump(), "application/json");

        } catch (const octra::TxInputError&) {
            throw;
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

    svr.Get("/api/stealth/scan", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        const auto read = wallet_read(&req);
        octra::RpcClient rpc(read.url);
        if (!private_rpc_ok(res, read.url)) return;
        ScopedSecret64 view_sk;
        {
            uint8_t view_pk[32];
            std::lock_guard<std::mutex> lock(g_mtx);
            read.check();
            octra::derive_view_keypair(g_wallet.sk, view_sk.data(), view_pk);
        }
        refresh_pvac_key_state_readonly();
        const int from_epoch = stealth_scan_from_epoch(rpc);
        auto scan = octra::fetch_stealth_outputs(rpc, from_epoch, 5);
        json outputs = json::array();
        if (!scan.ok) {
            res.status = 503;
            res.set_content(
                err_json(scan.error.empty() ? "stealth scan failed" : scan.error).dump(),
                "application/json");
            return;
        }
        int raw_count = 0;
        int skipped_claimed = 0;
        int skipped_tag = 0;
        int skipped_decrypt = 0;
        for (auto& out : scan.outputs) {
            raw_count++;
            if (out.value("claimed", 0) != 0) {
                skipped_claimed++;
                continue;
            }
            try {
                std::string eph_b64 = out["eph_pub"].get<std::string>();
                auto eph_raw = octra::base64_decode(eph_b64);
                if (eph_raw.size() != 32) continue;
                auto shared = octra::ecdh_shared_secret(view_sk.data(), eph_raw.data());
                auto my_tag = octra::compute_stealth_tag(shared);
                std::string my_tag_hex = octra::hex_encode(my_tag.data(), 16);
                if (my_tag_hex != out.value("stealth_tag", "")) {
                    skipped_tag++;
                    continue;
                }
                auto dec = octra::decrypt_stealth_amount(shared, out.value("enc_amount", ""));
                if (!dec.has_value()) {
                    skipped_decrypt++;
                    continue;
                }
                json o;
                o["id"] = out.value("id", 0);
                o["amount_raw"] = std::to_string(dec->amount);
                o["epoch"] = out.value("epoch_id", 0);
                o["sender"] = out.value("sender_addr", "");
                o["tx_hash"] = out.value("tx_hash", "");
                o["claimed"] = false;
                auto stored_commitment = octra::base64_decode(out.value("amount_commitment", ""));
                std::string amount_hash = out.value("amount_hash", "");
                {
                    std::lock_guard<std::mutex> lock(g_mtx);
                    read.check();
                    if (g_pvac_foreign) {
                        o["claimable"] = false;
                        o["claim_status"] = "pvac_key_upgrade_required";
                    } else if (!g_pvac_confirmed) {
                        o["claimable"] = false;
                        o["claim_status"] = "pvac_key_not_confirmed";
                    } else if (amount_hash != "pvac_key_bound_output_v1") {
                        o["claimable"] = false;
                        o["claim_status"] = "legacy_stealth_output";
                    } else if (stored_commitment.size() == 32 && g_pvac_ok) {
                        auto local_commitment = g_pvac.pedersen_commit(dec->amount, dec->blinding.data());
                        bool commitment_ok = std::memcmp(local_commitment.data(), stored_commitment.data(), 32) == 0;
                        o["claimable"] = commitment_ok;
                        o["claim_status"] = commitment_ok ? "ready" : "amount_commitment_mismatch";
                    } else {
                        o["claimable"] = false;
                        o["claim_status"] = "amount_commitment_missing";
                    }
                }
                outputs.push_back(o);
            } catch (...) {
                continue;
            }
        }
        json j;
        j["from_epoch"] = from_epoch;
        j["raw_count"] = raw_count;
        j["skipped_claimed"] = skipped_claimed;
        j["skipped_tag"] = skipped_tag;
        j["skipped_decrypt"] = skipped_decrypt;
        j["pages"] = scan.pages;
        j["outputs"] = outputs;
        std::lock_guard<std::mutex> lock(g_mtx);
        read.check();
        res.set_content(j.dump(), "application/json");
    });

    svr.Post("/api/stealth/claim", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        PVAC_LIFETIME_GUARD
        if (!private_rpc_ok(res)) return;
        uint64_t generation = 0;
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        {
            std::lock_guard<std::mutex> lock(g_mtx);
            if (!wallet_pin_ok(body, res)) return;
            generation = g_wallet_generation;
        }
        std::vector<uint64_t> ids;
        try {
            ids = octra::claim_ids(body.value("ids", json{}));
        } catch (const std::invalid_argument& error) {
            res.status = 400;
            res.set_content(err_json(error.what()).dump(), "application/json");
            return;
        }
        const auto request_id = private_request_id(body);
        const auto request_fee = parse_ou(body, "3000");
        if (std::stoull(request_fee) < 3000)
            throw octra::TxInputError("claim fee must be at least 3000 OU");
        const auto claim_id = [&](const std::string& output) {
            return request_id.empty() ? std::string() : octra::sha256_hex(request_id + "/" + output);
        };
        const auto claim_key = [&](const std::string& output) {
            return octra::sha256_hex(json::array({"claim", output, request_fee}).dump());
        };
        json previous = json::object();
        for (const auto id : ids) {
            const auto output = std::to_string(id);
            auto saved = private_cached(g_wallet.addr, generation, claim_id(output), claim_key(output));
            if (saved.is_null()) saved = private_claim_output_cached(g_wallet.addr, generation, output);
            if (!saved.is_null()) previous[output] = saved;
        }
        if (!ids.empty() && previous.size() == ids.size()) {
            json results = json::array();
            for (const auto id : ids) {
                auto saved = previous[std::to_string(id)];
                saved["id"] = std::to_string(id);
                saved["ok"] = true;
                results.push_back(saved);
            }
            res.set_content(json{{"results", results}}.dump(), "application/json");
            return;
        }
        if (!pvac_key_ready(res)) return;
        auto current_eb = get_encrypted_balance();
        if (!current_eb.ok) {
            res.status = 503;
            res.set_content(err_json(current_eb.error.empty() ? "cannot read encrypted balance" : current_eb.error).dump(), "application/json");
            return;
        }
        if (pvac_balance_needs_privacy_refresh(g_pvac, current_eb.cipher)) {
            {
                std::lock_guard<std::mutex> lock(g_mtx);
                mark_pvac_repair_required(g_wallet.addr);
            }
            res.status = 409;
            res.set_content(err_json("encrypted balance privacy refresh required before claim").dump(), "application/json");
            return;
        }

        uint8_t view_sk[32], view_pk[32];
        octra::derive_view_keypair(g_wallet.sk, view_sk, view_pk);
        auto sr = g_rpc.get_stealth_outputs_by_id(ids, 10);
        if (!sr.ok) {
            res.status = 503;
            res.set_content(err_json("failed to fetch every requested output").dump(), "application/json");
            return;
        }
        const auto outputs = octra::claim_outputs(ids, sr.result);

        const auto available = octra::pvac_upgrade_policy::claim_capacity(
            g_pvac.base_layer_count(current_eb.cipher));
        const auto requested = std::count_if(outputs.begin(), outputs.end(), [&](const json& output) {
            return output.value("claimed", 0) == 0
                && !previous.contains(std::to_string(octra::claim_id(output["id"])))
                && output.value("amount_hash", "") == "pvac_key_bound_output_v1";
        });
        if (static_cast<size_t>(requested) > available) {
            res.status = 409;
            res.set_content(json{{"error", "encrypted balance claim capacity exceeded; refresh balance or request fewer outputs"},
                {"claim_capacity", available}}.dump(), "application/json");
            return;
        }

        int nonce = 0;
        json results = json::array();
        bool submission_failed = false;

        for (const auto& out : outputs) {
            const auto out_id = std::to_string(octra::claim_id(out["id"]));
            if (previous.contains(out_id)) {
                auto saved = previous[out_id];
                saved["id"] = out_id;
                saved["ok"] = true;
                results.push_back(saved);
                if (saved.value("status", "unknown") != "pending"
                    && saved.value("status", "unknown") != "confirmed") submission_failed = true;
                continue;
            }
            if (submission_failed) {
                results.push_back({{"id", out_id}, {"ok", false},
                    {"error", "claim batch stopped after submission failure; check transaction status before retry"}});
                continue;
            }
            if (out.value("claimed", 0) != 0) {
                results.push_back({{"id", out_id}, {"ok", false}, {"error", "already claimed"}});
                continue;
            }
            if (out.value("amount_hash", "") != "pvac_key_bound_output_v1") {
                results.push_back({{"id", out_id}, {"ok", false}, {"error", "legacy_stealth_output"}});
                continue;
            }
            bool submit_attempted = false;
            try {
                const int math = read_proof_policy(g_wallet.addr);
                auto eph_raw = octra::base64_decode(out.at("eph_pub").get<std::string>());
                if (eph_raw.size() != 32) throw std::runtime_error("bad eph_pub");
                auto shared = octra::ecdh_shared_secret(view_sk, eph_raw.data());
                auto dec = octra::decrypt_stealth_amount(shared, out.value("enc_amount", ""));
                if (!dec.has_value()) throw std::runtime_error("decrypt failed");
                auto cs = octra::compute_claim_secret(shared);
                auto stored_commitment = octra::base64_decode(out.value("amount_commitment", ""));
                if (stored_commitment.size() != 32)
                    throw std::runtime_error("stored amount commitment missing");
                auto local_commitment = g_pvac.pedersen_commit(dec->amount, dec->blinding.data());
                if (std::memcmp(local_commitment.data(), stored_commitment.data(), 32) != 0)
                    throw std::runtime_error("stored amount commitment does not match decrypted stealth envelope");

                uint8_t seed[32];
                octra::random_bytes(seed, 32);
                pvac_cipher ct_claim = g_pvac.encrypt(dec->amount, seed);
                std::string claim_cipher_str = g_pvac.encode_proven_cipher(ct_claim);
                auto commit = g_pvac.commit_ct(ct_claim);
                std::string commit_b64 = octra::base64_encode(commit.data(), 32);
                pvac_zero_proof zkp = g_pvac.make_cipher_proof(ct_claim, dec->amount, dec->blinding.data(), math);
                if (pvac_local_self_check_enabled()) {
                    if (!g_pvac.verify_cipher_proof(ct_claim, zkp, local_commitment, math)) {
                        g_pvac.free_cipher(ct_claim);
                        g_pvac.free_zero_proof(zkp);
                        throw std::runtime_error("local claim proof self-check failed");
                    }
                }
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

                const auto balance = get_nonce_balance();
                nonce = std::max(nonce, balance.nonce);
                if (nonce >= std::numeric_limits<int>::max() - 1)
                    throw octra::RpcStateError("account nonce exhausted");
                octra::Transaction tx;
                tx.from = g_wallet.addr;
                tx.to_ = g_wallet.addr;
                tx.amount = "0";
                tx.nonce = nonce + 1;
                tx.ou = parse_ou(body, "3000");
                tx.timestamp = now_ts();
                tx.op_type = "claim";
                tx.encrypted_data = claim_data.dump();
                check_proof_policy(tx.from, math);
                sign_tx_fields(tx);
                submit_attempted = true;
                auto sr2 = submit_private_tx(tx, generation, tx.from,
                    std::to_string(dec->amount), out_id, claim_id(out_id), claim_key(out_id));
                if (sr2.contains("error")) {
                    submission_failed = true;
                    results.push_back({{"id", out_id}, {"ok", false}, {"error", sr2["error"]}});
                } else {
                    const auto hash = sr2.value("tx_hash", "");
                    if (hash.empty()) throw octra::RpcStateError("submission returned no transaction hash");
                    if (!sr2.value("reused", false)) nonce = tx.nonce;
                    sr2["id"] = out_id;
                    sr2["ok"] = true;
                    results.push_back(sr2);
                    if (sr2.value("status", "unknown") != "pending") submission_failed = true;
                }
            } catch (const std::exception& e) {
                if (submit_attempted) submission_failed = true;
                results.push_back({{"id", out_id}, {"ok", false}, {"error", e.what()}});
            }
        }
        json j;
        j["results"] = results;
        res.set_content(j.dump(), "application/json");
    });

    const auto saved_action = [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        const auto body = json::parse(req.body);
        const auto hash = body.value("hash", "");
        if (hash.size() != 64 || !std::all_of(hash.begin(), hash.end(), [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        })) throw octra::TxInputError("invalid transaction hash");
        std::string addr;
        std::string url;
        uint64_t generation = 0;
        {
            std::lock_guard<std::mutex> lock(g_mtx);
            if (!g_wallet_loaded) throw octra::RpcStateError("wallet locked");
            if (!wallet_http_session(req, res)) return;
            if (!wallet_pin_ok(body, res)) return;
            addr = g_wallet.addr;
            url = g_wallet.rpc_url;
            generation = g_wallet_generation;
        }
        const auto token = own_history_open(addr, generation, true);
        json rows;
        {
            std::lock_guard<std::mutex> lock(g_mtx);
            const auto row = g_own_history.find(token, hash);
            if (row.is_null()) throw octra::RpcStateError("saved transaction not found");
            rows = json::array({row});
        }
        refresh_own_rows(addr, generation, rows);
        {
            std::lock_guard<std::mutex> lock(g_mtx);
            if (!g_wallet_loaded || g_wallet.addr != addr || g_wallet_generation != generation
                || g_wallet.rpc_url != url || g_own_token != token)
                throw octra::RpcStateError("wallet changed before retry");
            const auto row = g_own_history.find(token, hash);
            if (row.is_null()) throw octra::RpcStateError("saved transaction not found");
            if (req.path == "/api/tx/discard") {
                if (!row.value("discardable", false))
                    throw octra::TxInputError("saved transaction may have been accepted");
                g_own_history.discard(token, hash);
                res.set_content(saved_reply(g_own_history.find(token, hash)).dump(), "application/json");
                return;
            }
            if (!row.value("retryable", false)) {
                res.set_content(saved_reply(row).dump(), "application/json");
                return;
            }
        }
        res.set_content(send_saved_tx(hash, addr, generation, token, url).dump(), "application/json");
    };
    svr.Post("/api/tx/retry", saved_action);
    svr.Post("/api/tx/discard", saved_action);

    svr.Get("/api/tx", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::string hash = req.get_param_value("hash");
        if (hash.empty()) {
            res.status = 400;
            res.set_content(err_json("hash required").dump(), "application/json");
            return;
        }
        json own;
        uint64_t generation = 0;
        uint64_t token = 0;
        std::string addr;
        std::string url;
        {
            std::lock_guard<std::mutex> lock(g_mtx);
            if (!g_wallet_loaded) {
                res.status = 409;
                res.set_content(err_json("wallet locked").dump(), "application/json");
                return;
            }
            generation = g_wallet_generation;
            addr = g_wallet.addr;
            url = g_wallet.rpc_url;
        }
        try {
            token = own_history_open(addr, generation);
            std::lock_guard<std::mutex> lock(g_mtx);
            if (g_wallet_loaded && g_wallet_generation == generation && g_wallet.addr == addr
                && g_wallet.rpc_url == url && g_own_token == token)
                own = g_own_history.find(token, hash);
        } catch (const std::exception&) {}
        octra::RpcClient rpc(url);
        const int nonce = own.is_null() ? -1 : confirmed_nonce(rpc, addr);
        auto r = rpc.get_transaction(hash);
        const auto replacements = needs_replacement(own, r, nonce)
            ? replacement_rows(rpc, addr, own) : json::array();
        if (!own.is_null()) {
            std::lock_guard<std::mutex> lock(g_mtx);
            if (!g_wallet_loaded || g_wallet_generation != generation || g_wallet.addr != addr
                || g_wallet.rpc_url != url || g_own_token != token) {
                res.status = 409;
                res.set_content(err_json("history wallet changed").dump(), "application/json");
                return;
            }
            observe_own_tx(token, hash, r, nonce, replacements);
            own = g_own_history.find(token, hash);
            res.set_content(own.dump(), "application/json");
            return;
        }
        json history_tx;
        if (!r.ok) {
            if (!addr.empty()) {
                auto hr = rpc.get_txs_by_address(addr, 100, 0);
                if (hr.ok && hr.result.is_object()) {
                    auto scan_rows = [&](const json& rows) {
                        if (!rows.is_array()) return;
                        for (auto& row : rows) {
                            if (row.is_object() && row.value("hash", "") == hash) {
                                history_tx = row;
                                return;
                            }
                        }
                    };
                    if (hr.result.contains("transactions")) scan_rows(hr.result["transactions"]);
                    if (history_tx.is_null() && hr.result.contains("rejected")) scan_rows(hr.result["rejected"]);
                    if (history_tx.is_null() && hr.result.contains("dropped")) scan_rows(hr.result["dropped"]);
                }
            }
            if (history_tx.is_null()) {
                res.status = 404;
                res.set_content(err_json("transaction not found").dump(), "application/json");
                return;
            }
        }
        auto& t = r.ok ? r.result : history_tx;
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
        if (t.contains("reason") && t["reason"].is_string())
            j["reject_reason"] = t["reason"].get<std::string>();
        if (t.contains("detail") && t["detail"].is_string())
            j["reject_detail"] = t["detail"].get<std::string>();
        if (t.contains("epoch")) j["epoch"] = t["epoch"];
        else if (t.contains("epoch_id")) j["epoch"] = t["epoch_id"];
        if (t.contains("block_height")) j["block_height"] = t["block_height"];
        if (t.contains("error") && t["error"].is_object()) {
            j["reject_reason"] = t["error"].value("reason", "");
            j["reject_type"] = t["error"].value("type", "");
        }
        std::lock_guard<std::mutex> lock(g_mtx);
        if (!g_wallet_loaded || g_wallet_generation != generation || g_wallet.addr != addr
            || g_wallet.rpc_url != url) {
            res.status = 409;
            res.set_content(err_json("history wallet changed").dump(), "application/json");
            return;
        }
        if (g_txcache.is_open()) {
            const std::string from = j.value("from", "");
            const std::string to = j.value("to_", "");
            if (from == g_wallet.addr || to == g_wallet.addr)
                g_txcache.store_tx(g_wallet.addr, j);
        }
        res.set_content(j.dump(), "application/json");
    });

    svr.Get("/api/keys", [](const httplib::Request&, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(g_mtx);
        WALLET_GUARD
        uint8_t view_sk[32], view_pk[32];
        octra::derive_view_keypair(g_wallet.sk, view_sk, view_pk);
        json j;
        j["address"] = g_wallet.addr;
        j["public_key"] = g_wallet.pub_b64;
        j["generation"] = std::to_string(g_wallet_generation);
        j["view_pubkey"] = octra::base64_encode(view_pk, 32);
        j["has_master_seed"] = g_wallet.has_master_seed();
        octra::secure_zero(view_sk, 32);
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(j.dump(), "application/json");
    });

    svr.Post("/api/keys/private", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        std::string confirm = body.value("confirm", "");
        if (confirm != "I_UNDERSTAND_KEY_EXPORT_RISK") {
            res.status = 403;
            res.set_content(err_json("missing or invalid confirmation; pass confirm=\"I_UNDERSTAND_KEY_EXPORT_RISK\" in body").dump(), "application/json");
            return;
        }
        if (!wallet_pin_ok(body, res)) return;
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
        bool program = body.value("program", false);
        auto r = g_rpc.compile_aml(source, program);
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
        j["version"] = octra::compiler_version(r.result.value("version", json()));
        if (r.result.contains("abi")) j["abi"] = r.result["abi"];
        if (r.result.contains("disasm")) j["disasm"] = r.result["disasm"];
        if (r.result.contains("verification")) j["verification"] = r.result["verification"];
        if (r.result.contains("certificate")) j["certificate"] = r.result["certificate"];
        if (r.result.contains("program_envelope")) j["program_envelope"] = r.result["program_envelope"];
        if (r.result.contains("deploy_payload")) {
            j["deploy_payload"] = r.result["deploy_payload"];
            const std::string payload =
                r.result["deploy_payload"].get<std::string>();
            j["program_min_ou"] =
                std::to_string(program_deploy_required_ou(payload));
        }
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
        bool program = body.value("program", false);
        if (files.empty()) {
            res.status = 400;
            res.set_content(err_json("files required").dump(), "application/json");
            return;
        }
        auto r = g_rpc.compile_aml_multi(files, main_path, program);
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
        j["version"] = octra::compiler_version(r.result.value("version", json()));
        if (r.result.contains("abi")) j["abi"] = r.result["abi"];
        if (r.result.contains("disasm")) j["disasm"] = r.result["disasm"];
        if (r.result.contains("verification")) j["verification"] = r.result["verification"];
        if (r.result.contains("certificate")) j["certificate"] = r.result["certificate"];
        if (r.result.contains("program_envelope")) j["program_envelope"] = r.result["program_envelope"];
        if (r.result.contains("deploy_payload")) {
            j["deploy_payload"] = r.result["deploy_payload"];
            const std::string payload =
                r.result["deploy_payload"].get<std::string>();
            j["program_min_ou"] =
                std::to_string(program_deploy_required_ou(payload));
        }
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
        if (!wallet_pin_ok(body, res)) return;
        std::string bytecode = body.value("bytecode", "");
        std::string deploy_payload = body.value("deploy_payload", "");
        if (bytecode.empty()) {
            res.status = 400;
            res.set_content(err_json("bytecode required").dump(), "application/json");
            return;
        }
        auto bi = get_nonce_balance_for(g_wallet.addr);
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
        long long program_min_ou = deploy_payload.empty()
            ? 200000
            : program_deploy_required_ou(deploy_payload);
        std::string required_program_ou = std::to_string(program_min_ou);
        tx.ou = parse_ou(body, required_program_ou);
        if (!deploy_payload.empty()) {
            std::string provided_ou = body.value("ou", "");
            if (provided_ou.empty()) provided_ou = body.value("fee", "");
            if (!provided_ou.empty() && provided_ou != required_program_ou) {
                res.status = 400;
                res.set_content(
                    err_json("Program package fee must equal required fee").dump(),
                    "application/json");
                return;
            }
            tx.ou = required_program_ou;
        }
        tx.timestamp = now_ts();
        tx.op_type = deploy_payload.empty() ? "deploy" : "program_deploy";
        tx.encrypted_data = deploy_payload.empty() ? bytecode : deploy_payload;
        std::string params_str = body.value("params", "");
        if (!params_str.empty() && !octra::program_args(params_str)) {
            res.status = 400;
            res.set_content(err_json("invalid program params").dump(), "application/json");
            return;
        }
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
        if (!wallet_pin_ok(body, res)) return;
        std::string addr = body.value("address", "");
        std::string method = body.value("method", "");
        if (addr.empty() || method.empty()) {
            res.status = 400;
            res.set_content(err_json("address and method required").dump(), "application/json");
            return;
        }
        std::string params_str = "[]";
        if (body.contains("params_raw")) {
            if (!body["params_raw"].is_string() || body.contains("params")) {
                res.status = 400;
                res.set_content(err_json("invalid program params").dump(), "application/json");
                return;
            }
            params_str = body["params_raw"].get<std::string>();
        } else if (body.contains("params")) params_str = body["params"].dump();
        if (!octra::program_args(params_str)) {
            res.status = 400;
            res.set_content(err_json("invalid program params").dump(), "application/json");
            return;
        }
        std::string amount_str = body.value("amount", "0");
        auto bi = get_nonce_balance_for(g_wallet.addr);
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
        std::string params_text;
        try { params_text = octra::program_compact(octra::program_params(body)); } catch (const std::exception& error) {
            res.status = 400;
            res.set_content(err_json(error.what()).dump(), "application/json");
            return;
        }
        auto r = circle_id.empty()
          ? g_rpc.program_view_raw(addr, method, params_text, g_wallet.addr)
          : g_rpc.circle_view_raw(
              circle_id,
              method,
              params_text,
              g_wallet.addr,
              g_wallet.pub_b64,
              sign_circle_view_request(circle_id, method, params_text, false));
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
        if (!wallet_pin_ok(body, res)) return;
        std::string params_str;
        try { params_str = octra::program_params(body); } catch (const std::exception& error) {
            res.status = 400;
            res.set_content(err_json(error.what()).dump(), "application/json");
            return;
        }
        std::string amount_str = body.value("amount", "0");
        auto bi = get_nonce_balance_for(g_wallet.addr);
        octra::Transaction tx;
        tx.from = g_wallet.addr;
        tx.to_ = circle_id.empty() ? addr : circle_id;
        tx.amount = amount_str;
        tx.nonce = bi.nonce + 1;
        tx.ou = parse_ou(body, "1000");
        tx.timestamp = now_ts();
        tx.op_type = circle_id.empty() ? "program_exec" : "circle_call";
        tx.encrypted_data = method;
        tx.message = params_str;
        sign_tx_fields(tx);
        auto result = submit_tx(tx);
        if (result.contains("error")) res.status = 500;
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/program/multi_exec", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        if (!body.contains("calls") || !body["calls"].is_array() || body["calls"].empty()) {
            res.status = 400;
            res.set_content(err_json("calls array required").dump(), "application/json");
            return;
        }
        if (body["calls"].size() > 8) {
            res.status = 400;
            res.set_content(err_json("too many calls").dump(), "application/json");
            return;
        }
        if (!wallet_pin_ok(body, res)) return;
        std::string calls_text = "[";
        for (size_t i = 0; i < body["calls"].size(); ++i) {
            const auto& item = body["calls"][i];
            if (!item.is_object()) {
                res.status = 400;
                res.set_content(err_json("call must be object").dump(), "application/json");
                return;
            }
            std::string target = item.value("address", "");
            if (target.empty()) target = item.value("to", "");
            std::string method = item.value("method", "");
            if (!is_octra_address(target) || method.empty()) {
                res.status = 400;
                res.set_content(err_json("call address and method required").dump(), "application/json");
                return;
            }
            std::string params;
            try { params = octra::program_params(item); } catch (const std::exception& error) {
                res.status = 400;
                res.set_content(err_json(error.what()).dump(), "application/json");
                return;
            }
            std::string amount = "0";
            if (item.contains("amount")) {
                if (item["amount"].is_string()) amount = item["amount"].get<std::string>();
                else if (item["amount"].is_number_integer() || item["amount"].is_number_unsigned()) amount = item["amount"].dump();
                else {
                    res.status = 400;
                    res.set_content(err_json("call amount must be string or integer").dump(), "application/json");
                    return;
                }
            }
            if (amount.empty() || amount.find_first_not_of("0123456789") != std::string::npos) {
                res.status = 400;
                res.set_content(err_json("call amount must contain decimal digits only").dump(), "application/json");
                return;
            }
            if (i) calls_text += ',';
            calls_text += "{\"to\":" + json(target).dump() + ",\"method\":" + json(method).dump()
                + ",\"params\":" + params + ",\"amount\":" + json(amount).dump() + "}";
        }
        calls_text += ']';
        auto bi = get_nonce_balance_for(g_wallet.addr);
        octra::Transaction tx;
        tx.from = g_wallet.addr;
        tx.to_ = "multi_exec";
        tx.amount = "0";
        tx.nonce = bi.nonce + 1;
        const int64_t minimum_ou = multi_exec_min_ou(body["calls"].size());
        const std::string selected_ou = parse_ou(body, std::to_string(minimum_ou));
        if (std::stoll(selected_ou) < minimum_ou) {
            res.status = 400;
            json error = err_json("fee too low");
            error["minimum_ou"] = std::to_string(minimum_ou);
            res.set_content(error.dump(), "application/json");
            return;
        }
        tx.ou = selected_ou;
        tx.timestamp = now_ts();
        tx.op_type = "multi_exec";
        tx.message = "{\"calls\":" + calls_text + "}";
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
        std::string limit = req.get_param_value("limit");
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
          ? g_rpc.contract_storage(addr, key, limit)
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
        const auto reply = octra::proxy_http(signer_url, "/", req.body, "POST");
        if (reply.error.empty() && reply.status == 200) {
            res.set_content(reply.body, "application/json");
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
        if (!request_id.empty()) path += "?request_id=" + httplib::detail::encode_query_param(request_id);
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
        if (request_id.empty() || request_id == "." || request_id == "..") {
            res.status = 400;
            res.set_content(err_json("valid request_id required").dump(), "application/json");
            return;
        }
        auto relay = relay_http_get("/response/" + httplib::detail::encode_query_param(request_id));
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
        if (request_id.empty() || request_id == "." || request_id == "..") {
            res.status = 400;
            res.set_content(err_json("request_id required").dump(), "application/json");
            return;
        }
        auto relay = relay_http_get("/receipt/" + httplib::detail::encode_query_param(request_id));
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
        if (request_id.empty() || request_id == "." || request_id == "..") {
            res.status = 400;
            res.set_content(err_json("request_id required").dump(), "application/json");
            return;
        }
        auto relay = relay_http_get("/ingress/" + httplib::detail::encode_query_param(request_id));
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
        if (params_str.empty()) params_str = "[]";
        if (!octra::program_args(params_str)) throw octra::TxInputError("invalid program parameters");
        const auto read = wallet_read(&req);
        octra::RpcClient rpc(read.url);
        auto r = rpc.program_view_raw(addr, method, params_str, read.addr);
        std::lock_guard<std::mutex> lock(g_mtx);
        read.check();
        if (!r.ok) {
            res.status = 400;
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        res.set_content(r.result.dump(), "application/json");
    });

    svr.Post("/api/fhe/encrypt", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        PVAC_LIFETIME_GUARD
        res.set_header("Access-Control-Allow-Origin", "*");
        if (!g_pvac_ok) {
            res.status = 500;
            res.set_content(err_json("pvac not available").dump(), "application/json");
            return;
        }
        try {
            const auto input = octra::fhe_input(json::parse(req.body, nullptr, false));
            std::array<uint8_t, 32> seed{};
            std::array<uint8_t, 32> blinding{};
            octra::random_bytes(seed.data(), seed.size());
            if (input.proof) octra::random_bytes(blinding.data(), blinding.size());
            const int math = input.proof ? read_proof_policy(g_wallet.addr) : false;
            const auto result = octra::fhe_encrypt(g_pvac, input, seed, blinding, math);
            if (input.proof) check_proof_policy(g_wallet.addr, math);
            res.set_content(result.dump(), "application/json");
        } catch (const octra::RpcStateError& error) {
            res.status = 503;
            res.set_content(err_json(error.what()).dump(), "application/json");
        } catch (const std::invalid_argument& error) {
            res.status = 400;
            res.set_content(err_json(error.what()).dump(), "application/json");
        } catch (const std::exception& error) {
            res.status = 500;
            res.set_content(err_json(error.what()).dump(), "application/json");
        }
    });

    svr.Post("/api/fhe/decrypt", [&access](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        PVAC_LIFETIME_GUARD
        if (!g_pvac_ok) {
            res.status = 500;
            res.set_content(err_json("pvac not available").dump(), "application/json");
            return;
        }
        auto body = json::parse(req.body, nullptr, false);
        if (!body.is_object() || !body.contains("ciphertext") || !body["ciphertext"].is_string()) {
            res.status = 400;
            res.set_content(err_json("missing ciphertext").dump(), "application/json");
            return;
        }
        {
            std::lock_guard<std::mutex> lock(g_mtx);
            if ((body.contains("pin") || !access.browser(req)) && !wallet_pin_ok(body, res)) return;
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
        try {
            const auto result = octra::fhe_decrypt(g_pvac, ct);
            res.set_content(result.dump(), "application/json");
        } catch (const std::domain_error& error) {
            res.status = 422;
            res.set_content(err_json(error.what()).dump(), "application/json");
        }
    });

    svr.Post("/api/circle/fhe/load_pk", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        PVAC_LIFETIME_GUARD
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
        PVAC_LIFETIME_GUARD
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
        auto policy = policy_r.result.value("policy", json::object());
        const std::string encrypt_proof = policy.value("encrypt_proof", "bound_zero_v1");
        if (circle_hfhe_receipt_required(encrypt_proof)) {
            std::lock_guard<std::mutex> lock(g_mtx);
            if (!wallet_pin_ok(body, res)) return;
        }
        const int math = encrypt_proof == "none" ? false : read_proof_policy(g_wallet.addr);
        int64_t value = body["value"].get<int64_t>();
        uint8_t seed[32];
        octra::random_bytes(seed, 32);
        pvac_cipher ct = g_pvac.encrypt(static_cast<uint64_t>(value), seed);
        auto data = g_pvac.serialize_cipher_public(ct);
        std::string b64 = octra::base64_encode(data.data(), data.size());
        uint8_t blinding[32];
        octra::random_bytes(blinding, 32);
        auto amount_commitment = g_pvac.pedersen_commit(static_cast<uint64_t>(value), blinding);
        std::string amount_commitment_b64 = octra::base64_encode(amount_commitment.data(), 32);
        json result;
        result["ciphertext"] = b64;
        result["amount_commitment"] = amount_commitment_b64;
        pvac_zero_proof proof = nullptr;
        std::string proof_field;
        if (encrypt_proof == "bound_zero_v1" || encrypt_proof == "bound_zero_receipt_v1") {
            proof = g_pvac.make_cipher_proof(ct, static_cast<uint64_t>(value), blinding, math);
            proof_field = "zero_proof";
        } else if (encrypt_proof == "range_v1" || encrypt_proof == "range_receipt_v1") {
            proof = g_pvac.make_range_proof(ct, static_cast<uint64_t>(value), blinding, math);
            proof_field = "range_proof";
        } else if (encrypt_proof == "zero_receipt_v1") {
            proof = g_pvac.make_zero_proof(ct, math);
            proof_field = "zero_proof";
        } else if (encrypt_proof != "none") {
            g_pvac.free_cipher(ct);
            res.status = 400;
            res.set_content(err_json("unsupported circle hfhe encrypt proof policy").dump(), "application/json");
            return;
        }
        if (!proof_field.empty()) {
            if (!proof) {
                g_pvac.free_cipher(ct);
                res.status = 500;
                res.set_content(err_json("circle proof generation failed").dump(), "application/json");
                return;
            }
            result[proof_field] = g_pvac.encode_zero_proof(proof);
            g_pvac.free_zero_proof(proof);
        }
        result["proof_kind"] = encrypt_proof;
        g_pvac.free_cipher(ct);
        if (encrypt_proof != "none") check_proof_policy(g_wallet.addr, math);
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

    svr.Post("/api/circle/fhe/decrypt", [](const httplib::Request&, httplib::Response& res) {
        res.status = 403;
        res.set_content(err_json("circle plaintext disclosure disabled").dump(), "application/json");
    });

    svr.Post("/api/circle/fhe/commit", [](const httplib::Request& req, httplib::Response& res) {
        if (!octra::circle_cipher_request(req, res)) return;
        WALLET_GUARD
        PVAC_LIFETIME_GUARD
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
        PVAC_LIFETIME_GUARD
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
        if (!octra::circle_cipher_request(req, res)) return;
        WALLET_GUARD
        PVAC_LIFETIME_GUARD
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
        auto serialized = g_pvac.serialize_cipher_public(ct);
        g_pvac.free_cipher(ct);
        json result;
        result["serialized_cipher"] = octra::base64_encode(serialized.data(), serialized.size());
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/circle/fhe/deserialize_cipher", [](const httplib::Request& req, httplib::Response& res) {
        if (!octra::circle_cipher_request(req, res)) return;
        WALLET_GUARD
        PVAC_LIFETIME_GUARD
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
        auto normalized = g_pvac.serialize_cipher_public(ct);
        g_pvac.free_cipher(ct);
        json result;
        result["ciphertext"] = octra::base64_encode(normalized.data(), normalized.size());
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/circle/fhe/verify_zero", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::shared_lock<std::shared_mutex> wallet_lifetime_lock(g_pvac_lifetime_mtx);
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
        if (!body["ciphertext"].is_string() || !body["zero_proof"].is_string()
            || !octra::circle_verifier_policy::encoded_size_allowed(body["ciphertext"], body["zero_proof"])) {
            res.status = 413;
            res.set_content(err_json("circle verifier input exceeds resource policy").dump(), "application/json");
            return;
        }
        octra::circle_verifier_policy::Lane::Lease lease;
        const std::string caller_addr = circle_wallet_address();
        std::string error;
        if (!circle_hfhe_authorize(
                body["circle_id"].get<std::string>(),
                "verify_zero_mode",
                caller_addr,
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
                    caller_addr,
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
        wallet_lifetime_lock.unlock();
        octra::PvacBridge pvac;
        std::string wallet_addr;
        uint64_t wallet_generation = 0;
        if (!circle_verifier_pvac(
                pvac,
                wallet_addr,
                wallet_generation,
                lease,
                error)) {
            res.status = error == "circle verifier busy" ? 429 : 500;
            res.set_content(err_json(error).dump(), "application/json");
            return;
        }
        if (wallet_addr != caller_addr) {
            res.status = 409;
            res.set_content(
                err_json("wallet changed during circle authorization").dump(),
                "application/json");
            return;
        }
        bool ok = circle_verify_zero(
            pvac,
            body["ciphertext"].get<std::string>(),
            body["zero_proof"].get<std::string>(),
            error);
        if (!ok && !error.empty()) {
            res.status = 400;
            res.set_content(err_json(error).dump(), "application/json");
            return;
        }
        if (!circle_wallet_current(wallet_addr, wallet_generation)) {
            res.status = 409;
            res.set_content(
                err_json("wallet changed during circle verification").dump(),
                "application/json");
            return;
        }
        lease = {};
        check_proof_policy(wallet_addr, pvac.proof_policy());
        res.set_content(json({{"ok", ok}}).dump(), "application/json");
    });

    svr.Post("/api/circle/fhe/verify_range", [](const httplib::Request&, httplib::Response& res) {
        res.status = 410;
        res.set_content(err_json("unlinked range verification disabled").dump(), "application/json");
    });

    svr.Post("/api/circle/fhe/verify_bound", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::shared_lock<std::shared_mutex> wallet_lifetime_lock(g_pvac_lifetime_mtx);
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
        if (!body["ciphertext"].is_string() || !body["zero_proof"].is_string()
            || !body["amount_commitment"].is_string()
            || !octra::circle_verifier_policy::encoded_size_allowed(body["ciphertext"], body["zero_proof"])
            || !octra::circle_verifier_policy::commitment_size_allowed(body["amount_commitment"])) {
            res.status = 413;
            res.set_content(err_json("circle verifier input exceeds resource policy").dump(), "application/json");
            return;
        }
        octra::circle_verifier_policy::Lane::Lease lease;
        const std::string caller_addr = circle_wallet_address();
        std::string error;
        if (!circle_hfhe_authorize(
                body["circle_id"].get<std::string>(),
                "verify_bound_mode",
                caller_addr,
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
                    caller_addr,
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
        wallet_lifetime_lock.unlock();
        octra::PvacBridge pvac;
        std::string wallet_addr;
        uint64_t wallet_generation = 0;
        if (!circle_verifier_pvac(
                pvac,
                wallet_addr,
                wallet_generation,
                lease,
                error)) {
            res.status = error == "circle verifier busy" ? 429 : 500;
            res.set_content(err_json(error).dump(), "application/json");
            return;
        }
        if (wallet_addr != caller_addr) {
            res.status = 409;
            res.set_content(
                err_json("wallet changed during circle authorization").dump(),
                "application/json");
            return;
        }
        bool ok = circle_verify_proof(
            pvac,
            body["ciphertext"].get<std::string>(),
            body["zero_proof"].get<std::string>(),
            body["amount_commitment"].get<std::string>(),
            error);
        if (!ok && !error.empty()) {
            res.status = 400;
            res.set_content(err_json(error).dump(), "application/json");
            return;
        }
        if (!circle_wallet_current(wallet_addr, wallet_generation)) {
            res.status = 409;
            res.set_content(
                err_json("wallet changed during circle verification").dump(),
                "application/json");
            return;
        }
        lease = {};
        check_proof_policy(wallet_addr, pvac.proof_policy());
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

    svr.Post("/api/circle/compute", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        if (req.body.size() > 70u * 1024u) {
            res.status = 413;
            res.set_content(err_json("compute request exceeds limit").dump(), "application/json");
            return;
        }
        json request;
        try {
            request = json::parse(req.body);
        } catch (...) {
            res.status = 400;
            res.set_content(err_json("compute request is not json").dump(), "application/json");
            return;
        }
        if (!request.is_object()) {
            res.status = 400;
            res.set_content(err_json("compute request rejected").dump(), "application/json");
            return;
        }
        std::set<std::string> actual_keys;
        for (auto it = request.begin(); it != request.end(); ++it) {
            actual_keys.insert(it.key());
        }
        std::set<std::string> expected_keys = {
            "unit_price",
            "fee_cap",
            "pin",
            "circle_id",
            "executor_root",
            "graph_root",
            "max_output_bytes",
            "method_name",
            "model_root",
            "params",
            "program_root",
            "sequence",
            "session_id"
        };
        if (request.contains("memory_bytes")) expected_keys.insert("memory_bytes");
        if (actual_keys != expected_keys
            || !request["pin"].is_string()
            || !request["circle_id"].is_string()
            || !request["executor_root"].is_string()
            || !request["graph_root"].is_string()
            || !request["max_output_bytes"].is_number_unsigned()
            || !request["method_name"].is_string()
            || !request["model_root"].is_string()
            || !request["params"].is_array()
            || !request["program_root"].is_string()
            || !request["sequence"].is_string()
            || !request["session_id"].is_string()) {
            res.status = 400;
            res.set_content(err_json("compute request fields differ").dump(), "application/json");
            return;
        }
        uint64_t authorized_generation = 0;
        {
            std::lock_guard<std::mutex> lock(g_mtx);
            if (!wallet_http_session(req, res)) return;
            if (!wallet_pin_ok(request, res)) return;
            authorized_generation = g_wallet_generation;
        }
        uint64_t sequence = 0;
        try {
            size_t sequence_end = 0;
            const std::string sequence_raw = request["sequence"].get<std::string>();
            sequence = std::stoull(sequence_raw, &sequence_end);
            if (sequence_end != sequence_raw.size()) {
                throw std::invalid_argument("compute integer trailing bytes");
            }
        } catch (...) {
            res.status = 400;
            res.set_content(err_json("compute request integer refused").dump(), "application/json");
            return;
        }
        const auto max_output_raw = request["max_output_bytes"].get<uint64_t>();
        if (max_output_raw == 0 || max_output_raw > 262144) {
            res.status = 400;
            res.set_content(err_json("compute output limit refused").dump(), "application/json");
            return;
        }
        octra::RpcClient rpc(current_public_rpc_url());
        const auto status = rpc.node_status();
        const auto proof = rpc.validator_set_proof();
        if (!status.ok
            || !status.result.is_object()
            || !status.result.contains("head_epoch")
            || !status.result["head_epoch"].is_number_unsigned()
            || !status.result.contains("state_root")
            || !status.result["state_root"].is_string()) {
            res.status = 502;
            res.set_content(err_json(status.ok ? "node status differs" : status.error).dump(), "application/json");
            return;
        }
        if (!proof.ok
            || !proof.result.is_object()
            || !proof.result.contains("chain_id")
            || !proof.result["chain_id"].is_string()) {
            res.status = 502;
            res.set_content(err_json(proof.ok ? "validator set proof differs" : proof.error).dump(), "application/json");
            return;
        }
        octra::ResourceComputeIntent intent;
        try {
            intent.unit_price = octra::compute_decimal_u64(request["unit_price"], "unit price");
            intent.fee_cap = octra::compute_decimal_u64(request["fee_cap"], "fee cap");
        } catch (const std::exception&) {
            res.status = 400;
            res.set_content(err_json("compute fee terms refused").dump(), "application/json");
            return;
        }
        intent.chain_id = proof.result["chain_id"].get<std::string>();
        intent.circle_id = request["circle_id"].get<std::string>();
        intent.model_epoch = status.result["head_epoch"].get<uint64_t>();
        if (intent.model_epoch > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) - 64) {
            res.status = 502;
            res.set_content(err_json("compute epoch exceeds limit").dump(), "application/json");
            return;
        }
        intent.valid_until = intent.model_epoch + 64;
        intent.fuel_limit = 2000000000U;
        intent.guest_bytes = 67108864U;
        intent.memory_bytes = 1073741824U;
        if (request.contains("memory_bytes")) {
            const auto& bytes = request["memory_bytes"];
            if (!bytes.is_number_unsigned() || bytes.get<uint64_t>() == 0
                || bytes.get<uint64_t>() > 2147483648ULL) {
                res.status = 400;
                res.set_content(err_json("compute memory limit refused").dump(), "application/json");
                return;
            }
            intent.memory_bytes = bytes.get<uint32_t>();
        }
        intent.model_state_root = status.result["state_root"].get<std::string>();
        intent.graph_root = request["graph_root"].get<std::string>();
        intent.model_root = request["model_root"].get<std::string>();
        intent.program_root = request["program_root"].get<std::string>();
        intent.executor_root = request["executor_root"].get<std::string>();
        intent.session_id = request["session_id"].get<std::string>();
        intent.sequence = sequence;
        intent.method_name = request["method_name"].get<std::string>();
        intent.params_json = request["params"].dump();
        intent.max_output_bytes = static_cast<uint32_t>(max_output_raw);
        std::string caller_public_key_b64;
        uint64_t wallet_generation = 0;
        ScopedSecret64 secret_key;
        {
            std::lock_guard<std::mutex> lock(g_mtx);
            if (!g_wallet_loaded || g_wallet_generation != authorized_generation) {
                res.status = 503;
                res.set_content(err_json("no wallet loaded").dump(), "application/json");
                return;
            }
            intent.caller = g_wallet.addr;
            std::memcpy(intent.caller_public_key.data(), g_wallet.pk, 32);
            std::memcpy(secret_key.data(), g_wallet.sk, 64);
            caller_public_key_b64 = g_wallet.pub_b64;
            wallet_generation = g_wallet_generation;
        }
        json signed_request;
        try {
            signed_request = octra::signed_resource_compute_params(
                intent,
                caller_public_key_b64,
                secret_key.data());
        } catch (const std::exception& error) {
            res.status = 400;
            res.set_content(err_json(error.what()).dump(), "application/json");
            return;
        }
        const auto submitted = rpc.resource_compute_submit(signed_request);
        if (!submitted.ok
            || !submitted.result.is_object()
            || submitted.result.value("status", "") != "waiting"
            || !submitted.result.contains("job_id")
            || !submitted.result["job_id"].is_string()
            || !submitted.result.contains("node_id")
            || !submitted.result["node_id"].is_string()) {
            res.status = submitted.ok ? 502 : 409;
            res.set_content(err_json(submitted.ok ? "compute submit response differs" : submitted.error).dump(), "application/json");
            return;
        }
        const std::string job_id = submitted.result["job_id"].get<std::string>();
        octra::ComputeRead read;
        read.chain_id = intent.chain_id;
        read.node_id = submitted.result["node_id"].get<std::string>();
        read.caller = intent.caller;
        read.public_key = intent.caller_public_key;
        read.job_id = job_id;
        read.epoch_id = intent.model_epoch;
        bool refresh_read = false;
        for (int attempt = 0; attempt < 720; ++attempt) {
            if (!circle_wallet_current(intent.caller, wallet_generation)) {
                res.status = 409;
                res.set_content(err_json("wallet changed during compute request").dump(), "application/json");
                return;
            }
            if (refresh_read) {
                const auto head = rpc.node_status();
                if (!head.ok || !head.result.is_object()
                    || !head.result.contains("head_epoch")
                    || !head.result["head_epoch"].is_number_unsigned()) {
                    res.status = 502;
                    res.set_content(err_json("compute read epoch unavailable").dump(), "application/json");
                    return;
                }
                read.epoch_id = head.result["head_epoch"].get<uint64_t>();
            }
            json signed_read;
            try {
                if (read.epoch_id > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) - 16) {
                    throw std::invalid_argument("compute read epoch exceeds limit");
                }
                read.expires_epoch = read.epoch_id + 16;
                signed_read = octra::signed_compute_read(read, secret_key.data());
            } catch (const std::exception& error) {
                res.status = 400;
                res.set_content(err_json(error.what()).dump(), "application/json");
                return;
            }
            const auto status = rpc.resource_compute_status(signed_read);
            refresh_read = !status.ok;
            if (!status.ok) {
                if (attempt == 719) {
                    res.status = 502;
                    res.set_content(err_json(status.error).dump(), "application/json");
                    return;
                }
            } else if (!status.result.is_object()) {
                res.status = 502;
                res.set_content(err_json("compute status response differs").dump(), "application/json");
                return;
            } else {
                const std::string state = status.result.value("status", "");
                if (state == "finished") {
                    std::string verification_error;
                    if (!octra::verify_resource_compute_finished(
                            status.result,
                            proof.result,
                            intent,
                            verification_error)) {
                        res.status = 502;
                        res.set_content(err_json(verification_error).dump(), "application/json");
                        return;
                    }
                    res.set_content(status.result.dump(), "application/json");
                    return;
                }
                if (state == "refused") {
                    res.status = 409;
                    res.set_content(status.result.dump(), "application/json");
                    return;
                }
                if (state != "waiting") {
                    res.status = 502;
                    res.set_content(err_json("compute status state differs").dump(), "application/json");
                    return;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
        res.status = 504;
        res.set_content(err_json("compute request deadline reached").dump(), "application/json");
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
        if (!wallet_pin_ok(body, res)) return;
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
            "define_object_policy_native",
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
        if (!wallet_pin_ok(body, res)) return;
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
            "bind_object_native",
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
        if (!wallet_pin_ok(body, res)) return;
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
            "attach_object_member_native",
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
        if (!wallet_pin_ok(body, res)) return;
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
            "detach_object_member_native",
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
        if (!wallet_pin_ok(body, res)) return;
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
            "apply_object_transition_native",
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
        auto r = octra::resolve_circle_asset(rpc, circle_id, path);
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
        std::string asset_path;
        std::string path_error;
        if (!circle_asset_path(path, asset_path, path_error)) {
            res.status = 400;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json(path_error).dump(), "application/json");
            return;
        }
        octra::RpcClient rpc(current_public_rpc_url());
        auto r = rpc.circle_asset_ciphertext_auth(
            circle_id,
            path,
            g_wallet.addr,
            g_wallet.pub_b64,
            sign_circle_read_request("octra_circle_asset_ciphertext", circle_id, "path|" + asset_path));
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
        auto r = rpc.circle_asset_ciphertext_by_resource_key_auth(
            circle_id,
            resource_key,
            g_wallet.addr,
            g_wallet.pub_b64,
            sign_circle_read_request("octra_circle_asset_ciphertext_by_resource_key", circle_id, "resource_key|" + resource_key));
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
        auto r = rpc.circle_asset_ciphertext_by_slot_ref_auth(
            circle_id,
            slot_ref,
            g_wallet.addr,
            g_wallet.pub_b64,
            sign_circle_read_request("octra_circle_asset_ciphertext_by_slot_ref", circle_id, "slot_ref|" + slot_ref));
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
        auto r = rpc.circle_asset_ciphertext_by_state_ref_auth(
            circle_id,
            state_ref,
            g_wallet.addr,
            g_wallet.pub_b64,
            sign_circle_read_request("octra_circle_asset_ciphertext_by_state_ref", circle_id, "state_ref|" + state_ref));
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
        if (!wallet_pin_ok(body, res)) return;
        auto read_string_or = [&](const char* key, const char* default_text) -> std::string {
            if (!body.contains(key) || body[key].is_null()) {
                return default_text;
            }
            if (body[key].is_string()) {
                return body[key].get<std::string>();
            }
            return default_text;
        };
        auto read_optional_string = [&](const char* key) -> std::string {
            return read_string_or(key, "");
        };
        std::string caller_circle_id = read_string_or("circle_id", "");
        std::string runtime = read_string_or("runtime", "octb");
        std::string privacy_class = read_string_or("privacy_class", "sealed");
        std::string browser_mode = read_string_or("browser_mode", "native_sealed");
        std::string resource_mode = read_string_or("resource_mode", "sealed_read");
        std::string code_b64 = read_optional_string("code_b64");
        std::string policy_hash = read_optional_string("policy_hash");
        std::string members_root = read_optional_string("members_root");
        std::string export_policy = read_optional_string("export_policy");
        auto read_limit = [&](const char* key, const char* default_text) -> std::string {
            if (!body.contains("limits") || !body["limits"].is_object()) {
                return default_text;
            }
            auto limits = body["limits"];
            if (!limits.contains(key)) {
                return default_text;
            }
            if (limits[key].is_string()) {
                return limits[key].get<std::string>();
            }
            if (limits[key].is_number_integer()) {
                return std::to_string(limits[key].get<long long>());
            }
            return default_text;
        };
        std::string max_stable_bytes = read_limit("max_stable_bytes", "33554432");
        std::string max_assets_bytes = read_limit("max_assets_bytes", "33554432");
        std::string max_inline_value = read_limit("max_inline_value", "65536");
        std::string max_wasm_bytes = read_limit("max_wasm_bytes", "33554432");
        auto json_str_of = [](const std::string& s) {
            const json value = s;
            return value.dump();
        };
        auto str_or_null = [&json_str_of](const std::string& s) {
            return s.empty() ? std::string("null") : json_str_of(s);
        };
        std::string deploy_body;
        deploy_body.reserve(512);
        deploy_body += "{";
        deploy_body += "\"runtime\":" + json_str_of(runtime) + ",";
        deploy_body += "\"privacy_class\":" + json_str_of(privacy_class) + ",";
        deploy_body += "\"browser_mode\":" + json_str_of(browser_mode) + ",";
        deploy_body += "\"resource_mode\":" + json_str_of(resource_mode) + ",";
        deploy_body += "\"code_b64\":" + str_or_null(code_b64) + ",";
        deploy_body += "\"policy_hash\":" + str_or_null(policy_hash) + ",";
        deploy_body += "\"members_root\":" + str_or_null(members_root) + ",";
        deploy_body += "\"export_policy\":" + str_or_null(export_policy) + ",";
        deploy_body += "\"limits\":{";
        deploy_body += "\"max_stable_bytes\":\"" + max_stable_bytes + "\",";
        deploy_body += "\"max_assets_bytes\":\"" + max_assets_bytes + "\",";
        deploy_body += "\"max_inline_value\":\"" + max_inline_value + "\",";
        deploy_body += "\"max_wasm_bytes\":\"" + max_wasm_bytes + "\"";
        deploy_body += "}}";
        auto bi = get_nonce_balance_for(g_wallet.addr);
        uint64_t deploy_nonce = (uint64_t)(bi.nonce + 1);
        auto h256_raw_fn = [](const std::string& tag, const std::vector<std::string>& parts) {
            std::string buf;
            buf.reserve(tag.size() + 1 + parts.size() * 4 + 256);
            buf += tag;
            buf += '\0';
            for (const auto& p : parts) {
                uint32_t n = (uint32_t)p.size();
                char b[4];
                b[0] = (char)((n >> 24) & 0xff);
                b[1] = (char)((n >> 16) & 0xff);
                b[2] = (char)((n >> 8) & 0xff);
                b[3] = (char)(n & 0xff);
                buf.append(b, 4);
                buf += p;
            }
            auto h = octra::sha256(buf);
            return std::string(reinterpret_cast<const char*>(h.data()), 32);
        };
        auto h256_hex_fn = [&h256_raw_fn](const std::string& tag, const std::vector<std::string>& parts) {
            auto raw = h256_raw_fn(tag, parts);
            static const char hc[] = "0123456789abcdef";
            std::string out;
            out.reserve(64);
            for (unsigned char c : raw) {
                out += hc[c >> 4];
                out += hc[c & 0xf];
            }
            return out;
        };
        std::string payload_hash_hex = h256_hex_fn("octra:circle_deploy_payload:v1", {deploy_body});
        std::string nonce_be(8, '\0');
        {
            uint64_t n = deploy_nonce;
            for (int i = 7; i >= 0; --i) { nonce_be[i] = (char)(n & 0xff); n >>= 8; }
        }
        std::string seed = h256_raw_fn("octra:circle_deploy_id:v1",
            {g_wallet.addr, nonce_be, payload_hash_hex});
        std::string b58 = octra::base58_encode(
            reinterpret_cast<const uint8_t*>(seed.data()), seed.size());
        std::string b58_part;
        if (b58.size() >= 44) {
            b58_part = b58.substr(0, 44);
        } else if (b58.empty()) {
            b58_part.assign(44, '1');
        } else {
            std::string ext = b58;
            size_t i = 0;
            while (ext.size() < 44) { ext += b58[i % b58.size()]; ++i; }
            b58_part = ext.substr(0, 44);
        }
        std::string derived_circle_id = "oct" + b58_part;
        if (!caller_circle_id.empty() && caller_circle_id != derived_circle_id) {
            res.status = 400;
            json err;
            err["error"] = "circle_id mismatch with derived address; omit circle_id to auto-derive";
            err["caller_circle_id"] = caller_circle_id;
            err["derived_circle_id"] = derived_circle_id;
            res.set_content(err.dump(), "application/json");
            return;
        }
        std::string circle_id = derived_circle_id;
        octra::Transaction tx;
        tx.from = g_wallet.addr;
        tx.to_ = circle_id;
        tx.amount = "0";
        tx.nonce = bi.nonce + 1;
        tx.ou = parse_ou(body, "200000");
        tx.timestamp = now_ts();
        tx.op_type = "deploy_circle";
        tx.message = deploy_body;
        sign_tx_fields(tx);
        auto result = submit_tx(tx);
        if (result.contains("error")) res.status = 500;
        else {
            result["circle_id"] = circle_id;
            result["derived_circle_id"] = derived_circle_id;
        }
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/circle/program_update", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        res.set_header("Access-Control-Allow-Origin", "*");
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        if (!wallet_pin_ok(body, res)) return;
        std::string circle_id = body.value("circle_id", "");
        std::string code_b64 = body.value("code_b64", "");
        if (circle_id.empty()) {
            res.status = 400;
            res.set_content(err_json("circle_id required").dump(), "application/json");
            return;
        }
        if (code_b64.empty()) {
            res.status = 400;
            res.set_content(err_json("code_b64 required").dump(), "application/json");
            return;
        }
        json payload;
        payload["code_b64"] = code_b64;
        auto bi = get_nonce_balance_for(g_wallet.addr);
        octra::Transaction tx;
        tx.from = g_wallet.addr;
        tx.to_ = circle_id;
        tx.amount = "0";
        tx.nonce = bi.nonce + 1;
        tx.ou = parse_ou(body, "200000");
        tx.timestamp = now_ts();
        tx.op_type = "circle_program_update";
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
        if (!wallet_pin_ok(body, res)) return;
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
        auto bi = get_nonce_balance_for(g_wallet.addr);
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
        if (!wallet_pin_ok(body, res)) return;
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
        std::string asset_path;
        std::string path_error;
        if (!circle_asset_path(path, asset_path, path_error) || asset_path == "/") {
            res.status = 400;
            res.set_content(err_json(path_error.empty() ? "invalid circle asset path" : path_error).dump(), "application/json");
            return;
        }
        if (body_b64.size() > CIRCLE_ASSET_MAX_B64_BYTES) {
            res.status = 400;
            res.set_content(err_json("circle asset body exceeds max encoded size").dump(), "application/json");
            return;
        }
        const std::string default_ou = std::to_string(circle_asset_ou_from_b64_len(body_b64.size()));
        auto bi = get_nonce_balance_for(g_wallet.addr);
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
        payload["path"] = asset_path;
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
        if (!wallet_pin_ok(body, res)) return;
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
        auto bi = get_nonce_balance_for(g_wallet.addr);
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
        if (!wallet_pin_ok(body, res)) return;
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
        auto bi = get_nonce_balance_for(g_wallet.addr);
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
        if (!wallet_pin_ok(body, res)) return;
        std::string circle_id = body.value("circle_id", "");
        std::string state_ref = body.value("state_ref", "");
        if (circle_id.empty() || state_ref.empty()) {
            res.status = 400;
            res.set_content(err_json("circle_id and state_ref required").dump(), "application/json");
            return;
        }
        auto bi = get_nonce_balance_for(g_wallet.addr);
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
        if (!wallet_pin_ok(body, res)) return;
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
        auto bi = get_nonce_balance_for(g_wallet.addr);
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
        std::string proof_error;
        if (!circle_cell_proof_payload(body, payload, proof_error)) {
            res.status = 400;
            res.set_content(err_json(proof_error).dump(), "application/json");
            return;
        }
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
        if (!wallet_pin_ok(body, res)) return;
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
        auto bi = get_nonce_balance_for(g_wallet.addr);
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
        std::string proof_error;
        if (!circle_cell_proof_payload(body, payload, proof_error)) {
            res.status = 400;
            res.set_content(err_json(proof_error).dump(), "application/json");
            return;
        }
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
        if (!wallet_pin_ok(body, res)) return;
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
        auto bi = get_nonce_balance_for(g_wallet.addr);
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
        if (!wallet_pin_ok(body, res)) return;
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
        auto bi = get_nonce_balance_for(g_wallet.addr);
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
        if (!wallet_pin_ok(body, res)) return;
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
        auto bi = get_nonce_balance_for(g_wallet.addr);
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
        if (!wallet_pin_ok(body, res)) return;
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
        auto bi = get_nonce_balance_for(g_wallet.addr);
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
        if (!wallet_pin_ok(body, res)) return;
        std::string circle_id = body.value("circle_id", "");
        std::string key_id = body.value("key_id", "");
        if (circle_id.empty() || key_id.empty()) {
            res.status = 400;
            res.set_content(err_json("circle_id and key_id required").dump(), "application/json");
            return;
        }
        json payload = json::object();
        payload["key_id"] = key_id;
        auto bi = get_nonce_balance_for(g_wallet.addr);
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
        if (!wallet_pin_ok(body, res)) return;
        std::string circle_id = body.value("circle_id", "");
        std::string key_id = body.value("key_id", "");
        if (circle_id.empty() || key_id.empty()) {
            res.status = 400;
            res.set_content(err_json("circle_id and key_id required").dump(), "application/json");
            return;
        }
        json payload = json::object();
        payload["key_id"] = key_id;
        auto bi = get_nonce_balance_for(g_wallet.addr);
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
        if (!wallet_pin_ok(body, res)) return;
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
        auto bi = get_nonce_balance_for(g_wallet.addr);
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
        if (!wallet_pin_ok(body, res)) return;
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
        auto bi = get_nonce_balance_for(g_wallet.addr);
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
        if (!wallet_pin_ok(body, res)) return;
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
        auto bi = get_nonce_balance_for(g_wallet.addr);
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
        if (!wallet_pin_ok(body, res)) return;
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
        auto bi = get_nonce_balance_for(g_wallet.addr);
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
        if (!wallet_pin_ok(body, res)) return;
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
        auto bi = get_nonce_balance_for(g_wallet.addr);
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
        auto info = rpc.circle_info(circle_id);
        if (info.ok && info.result.value("resource_mode", "") == "sealed_read") {
            const std::string uri = "oct://" + circle_id + path;
            const std::string location =
                "/circles.html?uri=" + httplib::detail::encode_query_param(uri);
            res.status = 302;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_header("Cache-Control", "no-store");
            res.set_header("Location", location);
            return;
        }
        auto r = octra::resolve_circle_asset(rpc, circle_id, path);
        if (!r.ok) {
            res.status = 404;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(err_json(r.error).dump(), "application/json");
            return;
        }
        auto content_type = r.result.value("content_type", "application/octet-stream");
        if (!octra::asset_mime_valid(content_type)) {
            res.status = 502;
            res.set_content(err_json("invalid asset media type").dump(), "application/json");
            return;
        }
        auto separator = content_type.find(';');
        auto media_type = lower_ascii(content_type.substr(0, separator));
        media_type.erase(
            std::remove_if(
                media_type.begin(),
                media_type.end(),
                [](unsigned char ch) { return std::isspace(ch); }),
            media_type.end());
        const bool active_document =
            media_type == "text/html" ||
            media_type == "application/xhtml+xml" ||
            media_type == "image/svg+xml" ||
            media_type == "text/xml" ||
            media_type == "application/xml";
        if (active_document) {
            const std::string uri = "oct://" + circle_id + path;
            const std::string location =
                "/circles.html?uri=" + httplib::detail::encode_query_param(uri);
            res.status = 302;
            res.set_header("Location", location);
            return;
        }
        auto body_b64 = r.result.value("body_b64", "");
        if (body_b64.size() > CIRCLE_ASSET_MAX_B64_BYTES) {
            res.status = 502;
            res.set_content(err_json("oversized asset from rpc").dump(), "application/json");
            return;
        }
        auto raw = octra::base64_decode(body_b64);
        std::string body(raw.begin(), raw.end());
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Cache-Control", "no-store");
        res.set_header("X-Content-Type-Options", "nosniff");
        if (serve_inline_allowed(media_type, req)) {
            res.set_content(body, content_type.c_str());
        } else {
            res.set_header("Content-Disposition", "attachment");
            res.set_content(body, "application/octet-stream");
        }
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
    static std::mutex g_token_cache_mtx;

    svr.Get("/api/tokens", [](const httplib::Request&, httplib::Response& res) {
        WALLET_GUARD
        double now = (double)time(nullptr);
        {
            std::lock_guard<std::mutex> ck(g_token_cache_mtx);
            if (!g_token_cache.empty() && g_token_cache_addr == g_wallet.addr
                && (now - g_token_cache_ts) < 30.0) {
                res.set_content(g_token_cache.dump(), "application/json");
                return;
            }
        }
        auto fast = g_rpc.tokens_by_address(g_wallet.addr);
        if (fast.ok && fast.result.contains("tokens")) {
            fast.result["tokens"] = octra::token_rows(fast.result["tokens"]);
            fast.result["count"] = fast.result["tokens"].size();
            {
                std::lock_guard<std::mutex> ck(g_token_cache_mtx);
                g_token_cache = fast.result;
                g_token_cache_ts = now;
                g_token_cache_addr = g_wallet.addr;
            }
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
                tok["name"] = sanitize_display(name, 32);
                tok["symbol"] = sanitize_display(sym, 16);
                tok["total_supply"] = supply;
                tok["balance"] = bal;
                tok["decimals"] = decimals;
                tok["owner"] = c.value("owner", "");
                tokens.push_back(tok);
            }
        }
        json j;
        j["tokens"] = octra::token_rows(tokens);
        j["count"] = j["tokens"].size();
        j["wallet_address"] = g_wallet.addr;
        {
            std::lock_guard<std::mutex> ck(g_token_cache_mtx);
            g_token_cache = j;
            g_token_cache_ts = now;
            g_token_cache_addr = g_wallet.addr;
        }
        res.set_content(j.dump(), "application/json");
    });

    svr.Post("/api/token/transfer", [](const httplib::Request& req, httplib::Response& res) {
        WALLET_GUARD
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
        if (!octra::token_units(amount_str)) {
            res.status = 400;
            res.set_content(err_json("invalid amount").dump(), "application/json");
            return;
        }

        std::string from_addr;
        std::string from_pub_b64;
        ScopedSecret64 from_sk;
        {
            std::lock_guard<std::mutex> lock(g_mtx);
            if (!g_wallet_loaded) {
                res.status = 503;
                res.set_content(err_json("no wallet loaded").dump(), "application/json");
                return;
            }
            if (!wallet_pin_ok(body, res)) return;
            from_addr = g_wallet.addr;
            from_pub_b64 = g_wallet.pub_b64;
            std::memcpy(from_sk.data(), g_wallet.sk, 64);
        }

        auto bi = get_nonce_balance_for(from_addr);
        int nonce = bi.nonce;
        octra::Transaction tx;
        tx.from = from_addr;
        tx.to_ = token;
        tx.amount = "0";
        tx.nonce = nonce + 1;
        tx.ou = parse_ou(body, "1000");
        tx.timestamp = now_ts();
        tx.op_type = "call";
        tx.encrypted_data = "transfer";
        tx.message = octra::token_params(to, amount_str);
        sign_tx_fields_for(tx, from_pub_b64, from_sk.data());
        auto result = submit_tx_for_addr(tx, from_addr);
        if (result.contains("error")) res.status = 500;
        res.set_content(result.dump(), "application/json");
    });

    svr.Post("/api/settings", [&access, &check_access](const httplib::Request& req, httplib::Response& res) {
        PVAC_LIFETIME_WRITE_GUARD
        if (!check_access(req, res)) return;
        WALLET_GUARD
        std::lock_guard<std::mutex> lock(g_mtx);
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(err_json("invalid json").dump(), "application/json");
            return;
        }
        if (!wallet_pin_ok(body, res)) return;
        std::string new_rpc = body.value("rpc_url", "");
        std::string new_explorer = body.value("explorer_url", "");
        std::string new_bridge_signer = body.value("bridge_signer_url", "");
        if (new_rpc.empty()) {
            res.status = 400;
            res.set_content(err_json("rpc_url required").dump(), "application/json");
            return;
        }
        if (!octra::endpoint_policy::secure_rpc(new_rpc)) {
            res.status = 400;
            res.set_content(err_json("invalid rpc_url: remote RPC requires https").dump(), "application/json");
            return;
        }
        if (!new_explorer.empty() && !octra::endpoint_policy::http_url(new_explorer)) {
            res.status = 400;
            res.set_content(err_json("invalid explorer_url: must be http or https with a host").dump(), "application/json");
            return;
        }
        if (!new_bridge_signer.empty() &&
            !octra::endpoint_policy::secure_rpc(new_bridge_signer)) {
            res.status = 400;
            res.set_content(err_json("invalid bridge_signer_url: remote signer requires https").dump(), "application/json");
            return;
        }
        bool cache_cleared = false;
        try {
            std::string old_rpc = g_wallet.rpc_url;
            if (!new_explorer.empty()) g_wallet.explorer_url = new_explorer;
            g_wallet.bridge_signer_url = new_bridge_signer;
            octra::save_settings(g_wallet_path, g_wallet, new_rpc, body.at("pin").get<std::string>());
            g_rpc.set_url(g_wallet.rpc_url);
            select_pvac_upgrade(g_wallet.rpc_url, g_wallet.addr);
            clear_fee_cache();
            if (old_rpc != g_wallet.rpc_url) {
                close_own_history();
                ++g_wallet_generation;
                access.renew(req, res, g_wallet.addr, g_wallet_generation);
                clear_enc_bal_cache();
                g_pvac_remote_pubkey_b64.clear();
                g_pvac_confirmed = false;
                g_pvac_foreign = false;
                clear_pvac_repair_required();
                g_txcache.ensure_identity(TXCACHE_SCHEMA, g_wallet.rpc_url);
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

    svr.Post("/api/wallet/change-pin", [&access, &check_access](const httplib::Request& req, httplib::Response& res) {
        PVAC_LIFETIME_WRITE_GUARD
        if (!check_access(req, res)) return;
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
        if (cur_pin.empty()) {
            res.status = 400;
            res.set_content(err_json("current PIN required").dump(), "application/json");
            return;
        }
        {
            std::string verr = octra::validate_pin(new_pin);
            if (!verr.empty()) {
                res.status = 400;
                res.set_content(err_json("new PIN: " + verr).dump(), "application/json");
                return;
            }
        }
        auto authorization = body;
        authorization["pin"] = cur_pin;
        if (!wallet_pin_ok(authorization, res)) return;
        try {
            octra::SessionPin next_pin;
            next_pin.set(new_pin);
            octra::save_wallet_encrypted(g_wallet_path, g_wallet, new_pin, octra::WalletWrite::replace);
            g_pin_session.exchange(next_pin);
            ++g_wallet_generation;
            access.renew(req, res, g_wallet.addr, g_wallet_generation);
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

    const char* pvac_bg_env = std::getenv("OCTRA_WALLET_PVAC_BG");
    if (pvac_bg_env && std::string(pvac_bg_env) == "1") {
        fprintf(stderr, "event = pvac_registration status = disabled reason = explicit_upgrade_required\n");
    }

    svr.new_task_queue = [] { return new httplib::ThreadPool(32); };
    if (!svr.bind_to_port("127.0.0.1", port)) {
        fprintf(stderr, "event = listen status = refused port = %d\n", port);
        return 1;
    }
    printf("octra_wallet listening on http://127.0.0.1:%d\n", port);
    printf("event = api_access code = %s\n", access.token().c_str());
    printf("API key = %s\n", access.token().c_str());
    const auto browser_url = access.browser_url(port);
    printf("Open wallet = %s\n", browser_url.c_str());
    fflush(stdout);
    if (octra::browser_requested() && !octra::open_browser(browser_url))
        fprintf(stderr, "event = browser_open status = refused reason = use_terminal_link\n");
    return svr.listen_after_bind() ? 0 : 1;
}