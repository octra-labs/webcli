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
#include <cstdint>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <iterator>
#ifdef _WIN32
#include <direct.h>
#include <io.h>
#else
#include <sys/stat.h>
#endif
#include "crypto_utils.hpp"
#include "lib/json.hpp"

extern "C" {
#include "lib/tweetnacl.h"
}

namespace octra {

constexpr const char* WALLET_DIR = "data";
constexpr const char* WALLET_FILE = "data/wallet.oct";
constexpr const char* WALLET_LEGACY = "wallet.json";

struct Wallet {
    std::string priv_b64;
    std::string addr;
    std::string rpc_url;
    std::string explorer_url = "https://devnet.octrascan.io";
    uint8_t sk[64];
    uint8_t pk[32];
    std::string pub_b64;

    ~Wallet() {
        secure_zero(sk, 64);
        secure_zero(pk, 32);
    }
};

inline std::string derive_address(const uint8_t pubkey[32]) {
    auto h = sha256(pubkey, 32);
    return "oct" + base58_encode(h.data(), 32);
}

inline void ensure_data_dir() {
#ifdef _WIN32
    _mkdir(WALLET_DIR);
#else
    struct stat st;
    if (stat(WALLET_DIR, &st) != 0) {
        mkdir(WALLET_DIR, 0700);
    }
#endif
}

inline bool has_encrypted_wallet() {
    std::ifstream f(WALLET_FILE, std::ios::binary);
    return f.good();
}

inline bool has_legacy_wallet() {
    std::ifstream f(WALLET_LEGACY);
    return f.good();
}

inline void save_wallet_encrypted(const std::string& path,
                                   const Wallet& w,
                                   const std::string& pin) {
    ensure_data_dir();
    nlohmann::json j;
    j["priv"] = w.priv_b64;
    j["addr"] = w.addr;
    j["rpc"] = w.rpc_url;
    j["explorer"] = w.explorer_url;
    std::string plaintext = j.dump();
    auto enc = wallet_encrypt(
        reinterpret_cast<const uint8_t*>(plaintext.data()),
        plaintext.size(), pin);
    secure_zero(&plaintext[0], plaintext.size());
    {
        std::ofstream f(path, std::ios::binary);
        if (!f) throw std::runtime_error("cannot write wallet file");
        f.write(reinterpret_cast<const char*>(enc.data()), enc.size());
    }
    chmod(path.c_str(), 0600);
}

inline Wallet load_wallet_encrypted(const std::string& path,
                                     const std::string& pin) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("cannot open wallet file");
    std::vector<uint8_t> data(
        (std::istreambuf_iterator<char>(f)),
        std::istreambuf_iterator<char>());
    f.close();

    auto plain = wallet_decrypt(data.data(), data.size(), pin);
    if (plain.empty()) throw std::runtime_error("wrong pin");

    std::string json_str(plain.begin(), plain.end());
    secure_zero(plain.data(), plain.size());

    nlohmann::json j = nlohmann::json::parse(json_str);
    secure_zero(&json_str[0], json_str.size());

    Wallet w;
    w.priv_b64 = j.at("priv").get<std::string>();
    w.addr = j.at("addr").get<std::string>();
    w.rpc_url = j.value("rpc", "http://165.227.225.79:8080");
    w.explorer_url = j.value("explorer", "https://devnet.octrascan.io");

    auto raw = base64_decode(w.priv_b64);
    if (raw.size() >= 64) {
        memcpy(w.sk, raw.data(), 64);
        memcpy(w.pk, w.sk + 32, 32);
    } else if (raw.size() >= 32) {
        keypair_from_seed(raw.data(), w.sk, w.pk);
    } else {
        throw std::runtime_error("invalid private key");
    }
    w.pub_b64 = base64_encode(w.pk, 32);
    chmod(path.c_str(), 0600);
    try_mlock(w.sk, 64);
    try_mlock(w.pk, 32);
    return w;
}

inline Wallet create_wallet(const std::string& path, const std::string& pin) {
    Wallet w;
    for (int i = 0; i < 100; i++) {
        crypto_sign_keypair(w.pk, w.sk);
        std::string a = derive_address(w.pk);
        if (a.size() == 47) {
            w.addr = a;
            w.priv_b64 = base64_encode(w.sk, 32);
            w.pub_b64 = base64_encode(w.pk, 32);
            w.rpc_url = "http://165.227.225.79:8080";
            save_wallet_encrypted(path, w, pin);
            try_mlock(w.sk, 64);
            try_mlock(w.pk, 32);
            return w;
        }
    }
    throw std::runtime_error("failed to generate valid address");
}

inline Wallet load_wallet_legacy(const std::string& path) {
    Wallet w;
    std::ifstream f(path);
    if (!f) throw std::runtime_error("cannot open wallet file");
    nlohmann::json j;
    f >> j;
    w.priv_b64 = j.at("priv").get<std::string>();
    w.addr = j.at("addr").get<std::string>();
    w.rpc_url = j.value("rpc", "http://165.227.225.79:8080");
    auto raw = base64_decode(w.priv_b64);
    if (raw.size() >= 64) {
        memcpy(w.sk, raw.data(), 64);
        memcpy(w.pk, w.sk + 32, 32);
    } else if (raw.size() >= 32) {
        keypair_from_seed(raw.data(), w.sk, w.pk);
    } else {
        throw std::runtime_error("invalid private key");
    }
    w.pub_b64 = base64_encode(w.pk, 32);
    try_mlock(w.sk, 64);
    try_mlock(w.pk, 32);
    return w;
}

inline Wallet migrate_wallet(const std::string& pin) {
    Wallet w = load_wallet_legacy(WALLET_LEGACY);
    save_wallet_encrypted(WALLET_FILE, w, pin);
    std::remove(WALLET_LEGACY);
    return w;
}

inline Wallet import_wallet(const std::string& path,
                             const std::string& priv_b64_raw,
                             const std::string& pin) {
    std::string clean;
    for (char c : priv_b64_raw) {
        if (c != '\n' && c != '\r' && c != ' ' && c != '\t')
            clean += c;
    }
    auto raw = base64_decode(clean);
    Wallet w;
    if (raw.size() >= 64) {
        memcpy(w.sk, raw.data(), 64);
        memcpy(w.pk, w.sk + 32, 32);
    } else if (raw.size() >= 32) {
        keypair_from_seed(raw.data(), w.sk, w.pk);
    } else {
        throw std::runtime_error("invalid private key length");
    }
    w.addr = derive_address(w.pk);
    if (w.addr.size() != 47 || w.addr.substr(0, 3) != "oct")
        throw std::runtime_error("derived address is invalid");
    w.priv_b64 = base64_encode(w.sk, 32);
    w.pub_b64 = base64_encode(w.pk, 32);
    w.rpc_url = "http://165.227.225.79:8080";
    save_wallet_encrypted(path, w, pin);
    try_mlock(w.sk, 64);
    try_mlock(w.pk, 32);
    return w;
}

inline void save_settings(const std::string& path, Wallet& w,
                           const std::string& new_rpc,
                           const std::string& pin) {
    w.rpc_url = new_rpc;
    save_wallet_encrypted(path, w, pin);
}

inline void change_pin(const std::string& path, Wallet& w,
                        const std::string& new_pin) {
    save_wallet_encrypted(path, w, new_pin);
}

// Passkey wallet support

struct PasskeyWallet {
    std::string addr;
    std::string pub_b64;
    std::string rpc_url;
    std::string explorer_url;
};

inline bool has_passkey_wallet() {
    std::ifstream f(WALLET_FILE, std::ios::binary);
    if (!f) return false;
    char c = 0;
    f.read(&c, 1);
    return c == '{';
}

inline void save_passkey_wallet(const std::string& path,
                                 const std::string& addr,
                                 const std::string& pub_b64,
                                 const std::string& rpc_url,
                                 const std::string& explorer_url) {
    ensure_data_dir();
    nlohmann::json j;
    j["type"]     = "passkey";
    j["addr"]     = addr;
    j["pub"]      = pub_b64;
    j["rpc"]      = rpc_url;
    j["explorer"] = explorer_url;
    std::ofstream f(path);
    if (!f) throw std::runtime_error("cannot write wallet file");
    f << j.dump();
    f.close();
    chmod(path.c_str(), 0600);
}

inline PasskeyWallet load_passkey_wallet_meta(const std::string& path) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("cannot open wallet file");
    nlohmann::json j;
    f >> j;
    if (j.value("type", "") != "passkey")
        throw std::runtime_error("not a passkey wallet");
    PasskeyWallet w;
    w.addr         = j.at("addr").get<std::string>();
    w.pub_b64      = j.at("pub").get<std::string>();
    w.rpc_url      = j.value("rpc",      "http://165.227.225.79:8080");
    w.explorer_url = j.value("explorer", "https://devnet.octrascan.io");
    return w;
}

inline Wallet import_wallet_from_seed(const std::string& path,
                                       const uint8_t seed[32],
                                       const std::string& rpc_url,
                                       const std::string& explorer_url) {
    Wallet w;
    keypair_from_seed(seed, w.sk, w.pk);
    w.addr = derive_address(w.pk);
    if (w.addr.size() != 47 || w.addr.substr(0, 3) != "oct")
        throw std::runtime_error("derived address is invalid");
    w.priv_b64     = base64_encode(w.sk, 32);
    w.pub_b64      = base64_encode(w.pk, 32);
    w.rpc_url      = rpc_url;
    w.explorer_url = explorer_url;
    save_passkey_wallet(path, w.addr, w.pub_b64, w.rpc_url, w.explorer_url);
    try_mlock(w.sk, 64);
    try_mlock(w.pk, 32);
    return w;
}

inline Wallet unlock_wallet_from_seed(const uint8_t seed[32],
                                       const PasskeyWallet& meta) {
    Wallet w;
    keypair_from_seed(seed, w.sk, w.pk);
    std::string derived_pub = base64_encode(w.pk, 32);
    if (derived_pub != meta.pub_b64)
        throw std::runtime_error("passkey does not match this wallet");
    w.addr         = meta.addr;
    w.pub_b64      = meta.pub_b64;
    w.priv_b64     = base64_encode(w.sk, 32);
    w.rpc_url      = meta.rpc_url;
    w.explorer_url = meta.explorer_url;
    try_mlock(w.sk, 64);
    try_mlock(w.pk, 32);
    return w;
}

inline void save_passkey_settings(const std::string& path, Wallet& w,
                                   const std::string& new_rpc,
                                   const std::string& new_explorer) {
    w.rpc_url      = new_rpc;
    w.explorer_url = new_explorer;
    save_passkey_wallet(path, w.addr, w.pub_b64, w.rpc_url, w.explorer_url);
}

// ── Account manifest ──────────────────────────────────────────────────────────

constexpr const char* ACCOUNTS_FILE = "data/accounts.json";

struct AccountEntry {
    std::string addr;
    std::string type; // "pin" or "passkey"
    std::string file;
};

inline std::string wallet_path_for(const std::string& addr) {
    return std::string(WALLET_DIR) + "/wallet_" + addr.substr(3, 8) + ".oct";
}

inline std::vector<AccountEntry> load_manifest() {
    std::vector<AccountEntry> entries;
    std::ifstream f(ACCOUNTS_FILE);
    if (!f) return entries;
    nlohmann::json j;
    try { f >> j; } catch (...) { return entries; }
    if (!j.is_array()) return entries;
    for (auto& item : j) {
        AccountEntry e;
        e.addr = item.value("addr", "");
        e.type = item.value("type", "pin");
        e.file = item.value("file", "");
        if (!e.addr.empty() && !e.file.empty())
            entries.push_back(e);
    }
    return entries;
}

inline void save_manifest(const std::vector<AccountEntry>& entries) {
    ensure_data_dir();
    nlohmann::json j = nlohmann::json::array();
    for (auto& e : entries) {
        nlohmann::json item;
        item["addr"] = e.addr;
        item["type"] = e.type;
        item["file"] = e.file;
        j.push_back(item);
    }
    std::ofstream f(ACCOUNTS_FILE);
    if (!f) throw std::runtime_error("cannot write accounts manifest");
    f << j.dump();
}

inline void manifest_upsert(const AccountEntry& entry) {
    auto entries = load_manifest();
    for (auto& e : entries) {
        if (e.addr == entry.addr) { e = entry; save_manifest(entries); return; }
    }
    entries.push_back(entry);
    save_manifest(entries);
}

inline void manifest_remove(const std::string& addr) {
    auto entries = load_manifest();
    entries.erase(
        std::remove_if(entries.begin(), entries.end(),
            [&](const AccountEntry& e) { return e.addr == addr; }),
        entries.end());
    save_manifest(entries);
}

} // namespace octra
