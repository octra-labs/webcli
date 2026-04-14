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
#include <windows.h>
#else
#include <sys/stat.h>
#include <dirent.h>
#endif
#include <set>
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
    std::string explorer_url = "https://octrascan.io";
    uint8_t sk[64];
    uint8_t pk[32];
    std::string pub_b64;
    std::string master_seed_b64;
    std::string mnemonic;
    int hd_index = 0;
    int hd_version = 1;

    bool has_master_seed() const { return !master_seed_b64.empty(); }

    ~Wallet() {
        secure_zero(sk, 64);
        secure_zero(pk, 32);
    }
};

struct ManifestEntry {
    std::string name;
    std::string file;
    std::string addr;
    bool hd = false;
    int hd_version = 1;
    int hd_index = 0;
    std::string parent_addr;
    std::string master_seed_hash;
};

constexpr const char* MANIFEST_FILE = "data/accounts.json";

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

inline std::string wallet_path_for(const std::string& addr) {
    // Require at least "oct" prefix + 8 chars for the file prefix slice
    // Also sanitize: only allow alphanumeric chars to prevent path traversal
    std::string prefix = "unknown";
    if (addr.size() > 11 && addr.substr(0, 3) == "oct") {
        std::string raw = addr.substr(3, 8);
        bool safe = true;
        for (char c : raw) {
            if (!isalnum((unsigned char)c)) { safe = false; break; }
        }
        if (safe) prefix = raw;
    }
    return std::string(WALLET_DIR) + "/wallet_" + prefix + ".oct";
}

inline std::vector<ManifestEntry> load_manifest() {
    std::vector<ManifestEntry> entries;
    std::ifstream f(MANIFEST_FILE);
    if (!f) return entries;
    try {
        nlohmann::json arr;
        f >> arr;
        for (auto& e : arr) {
            ManifestEntry m;
            m.name = e.value("name", "");
            m.file = e.value("file", "");
            m.addr = e.value("addr", "");
            m.hd = e.value("hd", false);
            m.hd_version = e.value("hd_version", 1);
            m.hd_index = e.value("hd_index", 0);
            m.parent_addr = e.value("parent_addr", "");
            m.master_seed_hash = e.value("seed_hash", "");
            entries.push_back(m);
        }
    } catch (...) {}
    return entries;
}

inline void save_manifest(const std::vector<ManifestEntry>& entries) {
    ensure_data_dir();
    nlohmann::json arr = nlohmann::json::array();
    for (auto& e : entries) {
        nlohmann::json j;
        j["name"] = e.name;
        j["file"] = e.file;
        j["addr"] = e.addr;
        j["hd"] = e.hd;
        j["hd_version"] = e.hd_version;
        j["hd_index"] = e.hd_index;
        if (!e.parent_addr.empty()) j["parent_addr"] = e.parent_addr;
        if (!e.master_seed_hash.empty()) j["seed_hash"] = e.master_seed_hash;
        arr.push_back(j);
    }
    std::ofstream f(MANIFEST_FILE);
    if (f) f << arr.dump(2);
}

inline void manifest_upsert(const ManifestEntry& entry) {
    auto entries = load_manifest();
    bool found = false;
    for (auto& e : entries) {
        if (e.addr == entry.addr) {
            if (!entry.name.empty()) e.name = entry.name;
            e.file = entry.file;
            e.hd = entry.hd;
            e.hd_version = entry.hd_version;
            e.hd_index = entry.hd_index;
            if (!entry.parent_addr.empty()) e.parent_addr = entry.parent_addr;
            if (!entry.master_seed_hash.empty()) e.master_seed_hash = entry.master_seed_hash;
            found = true;
            break;
        }
    }
    if (!found) entries.push_back(entry);
    save_manifest(entries);
}

inline void manifest_remove(const std::string& addr) {
    auto entries = load_manifest();
    entries.erase(std::remove_if(entries.begin(), entries.end(),
        [&](const ManifestEntry& e) { return e.addr == addr; }), entries.end());
    save_manifest(entries);
}

inline void manifest_rename(const std::string& addr, const std::string& name) {
    auto entries = load_manifest();
    for (auto& e : entries) {
        if (e.addr == addr) { e.name = name; break; }
    }
    save_manifest(entries);
}

inline std::string compute_seed_hash(const std::string& master_seed_b64) {
    auto raw = base64_decode(master_seed_b64);
    auto h = sha256(raw.data(), raw.size());
    char buf[17];
    for (int i = 0; i < 8; i++) snprintf(buf + i*2, 3, "%02x", h[i]);
    return std::string(buf, 16);
}

inline int manifest_next_hd_index(const std::string& master_seed_b64) {
    std::string sh = compute_seed_hash(master_seed_b64);
    auto entries = load_manifest();
    int max_idx = -1;
    for (auto& e : entries) {
        if (e.hd && e.master_seed_hash == sh && e.hd_index > max_idx)
            max_idx = e.hd_index;
    }
    return max_idx + 1;
}

inline std::string derive_address(const uint8_t pubkey[32]) {
    auto h = sha256(pubkey, 32);
    std::string b58 = base58_encode(h.data(), 32);
    while (b58.size() < 44) b58 = "1" + b58;
    return "oct" + b58;
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
    if (!w.master_seed_b64.empty()) {
        j["master_seed"] = w.master_seed_b64;
        j["hd_index"] = w.hd_index;
        j["hd_version"] = w.hd_version;
        if (!w.mnemonic.empty())
            j["mnemonic"] = w.mnemonic;
    }
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
    w.rpc_url = j.value("rpc", "http://46.101.86.250:8080");
    w.explorer_url = j.value("explorer", "https://octrascan.io");
    w.master_seed_b64 = j.value("master_seed", "");
    w.mnemonic = j.value("mnemonic", "");
    w.hd_index = j.value("hd_index", 0);
    w.hd_version = j.value("hd_version", 1);

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

inline int recover_hd_index(const std::string& master_seed_b64,
                              const std::string& target_addr, int hd_version,
                              int max_search = 64) {
    auto master_raw = base64_decode(master_seed_b64);
    if (master_raw.size() != 64) return -1;
    for (int i = 0; i < max_search; i++) {
        auto hd_seed = derive_hd_seed(master_raw.data(), (uint32_t)i, hd_version);
        uint8_t sk[64], pk[32];
        keypair_from_seed(hd_seed.data(), sk, pk);
        secure_zero(hd_seed.data(), 32);
        std::string addr = derive_address(pk);
        secure_zero(sk, 64);
        if (addr == target_addr) return i;
    }
    return -1;
}

inline void manifest_migrate_legacy(const std::string& master_seed_b64,
                                      const std::string& pin, int hd_version) {
    std::string sh = compute_seed_hash(master_seed_b64);
    auto entries = load_manifest();
    bool changed = false;
    for (auto& e : entries) {
        if (!e.hd || !e.master_seed_hash.empty()) continue;
        try {
            auto w = load_wallet_encrypted(e.file, pin);
            if (w.master_seed_b64 == master_seed_b64) {
                e.master_seed_hash = sh;
                int idx = recover_hd_index(master_seed_b64, e.addr, hd_version);
                e.hd_index = (idx >= 0) ? idx : 0;
                changed = true;
                fprintf(stderr, "manifest migrate: %s -> seed_hash=%s hd_index=%d\n",
                    e.addr.c_str(), sh.c_str(), e.hd_index);
            }
        } catch (...) {}
    }
    if (changed) save_manifest(entries);
}

inline std::pair<Wallet, std::string> create_wallet(const std::string& path,
                                                      const std::string& pin) {
    std::string mnemonic = generate_mnemonic_12();
    auto seed = mnemonic_to_seed(mnemonic);

    auto hd_seed = derive_hd_seed(seed.data(), 0, 2);

    Wallet w;
    keypair_from_seed(hd_seed.data(), w.sk, w.pk);
    secure_zero(hd_seed.data(), 32);
    w.addr = derive_address(w.pk);
    if (w.addr.size() != 47 || w.addr.substr(0, 3) != "oct")
        throw std::runtime_error("derived address is invalid");
    w.priv_b64 = base64_encode(w.sk, 32);
    w.pub_b64 = base64_encode(w.pk, 32);
    w.rpc_url = "http://46.101.86.250:8080";
    w.master_seed_b64 = base64_encode(seed.data(), 64);
    w.mnemonic = mnemonic;
    w.hd_index = 0;
    w.hd_version = 2;
    secure_zero(seed.data(), 64);
    save_wallet_encrypted(path, w, pin);
    try_mlock(w.sk, 64);
    try_mlock(w.pk, 32);
    return {w, mnemonic};
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

inline std::string addr_from_mnemonic(const std::string& mnemonic, int hd_version) {
    auto seed = mnemonic_to_seed(mnemonic);
    auto hd_seed = derive_hd_seed(seed.data(), 0, hd_version);
    uint8_t sk[64], pk[32];
    keypair_from_seed(hd_seed.data(), sk, pk);
    secure_zero(hd_seed.data(), 32);
    secure_zero(seed.data(), 64);
    auto addr = derive_address(pk);
    secure_zero(sk, 64);
    return addr;
}

inline Wallet import_wallet_mnemonic(const std::string& path,
                                      const std::string& mnemonic,
                                      const std::string& pin,
                                      int hd_version = 1) {
    if (!validate_mnemonic(mnemonic))
        throw std::runtime_error("invalid seed phrase");
    auto seed = mnemonic_to_seed(mnemonic);
    auto hd_seed = derive_hd_seed(seed.data(), 0, hd_version);
    Wallet w;
    keypair_from_seed(hd_seed.data(), w.sk, w.pk);
    secure_zero(hd_seed.data(), 32);
    w.addr = derive_address(w.pk);
    if (w.addr.size() != 47 || w.addr.substr(0, 3) != "oct")
        throw std::runtime_error("derived address is invalid");
    w.priv_b64 = base64_encode(w.sk, 32);
    w.pub_b64 = base64_encode(w.pk, 32);
    w.rpc_url = "http://46.101.86.250:8080";
    w.master_seed_b64 = base64_encode(seed.data(), 64);
    w.mnemonic = mnemonic;
    w.hd_index = 0;
    w.hd_version = hd_version;
    secure_zero(seed.data(), 64);
    save_wallet_encrypted(path, w, pin);
    try_mlock(w.sk, 64);
    try_mlock(w.pk, 32);
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
    w.rpc_url = "http://46.101.86.250:8080";
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


inline Wallet derive_hd_account(const std::string& master_seed_b64,
                                 uint32_t index,
                                 const std::string& rpc_url,
                                 const std::string& explorer_url,
                                 const std::string& pin,
                                 int hd_version = 2) {
    auto master_raw = base64_decode(master_seed_b64);
    if (master_raw.size() != 64)
        throw std::runtime_error("invalid master seed");

    auto hd_seed = derive_hd_seed(master_raw.data(), index, hd_version);

    Wallet w;
    keypair_from_seed(hd_seed.data(), w.sk, w.pk);
    secure_zero(hd_seed.data(), 32);

    w.addr = derive_address(w.pk);
    if (w.addr.size() != 47 || w.addr.substr(0, 3) != "oct")
        throw std::runtime_error("derived address is invalid");

    w.priv_b64 = base64_encode(w.sk, 32);
    w.pub_b64 = base64_encode(w.pk, 32);
    w.rpc_url = rpc_url;
    w.explorer_url = explorer_url;
    w.master_seed_b64 = master_seed_b64;
    w.hd_index = (int)index;
    w.hd_version = hd_version;

    std::string path = wallet_path_for(w.addr);
    save_wallet_encrypted(path, w, pin);
    try_mlock(w.sk, 64);
    try_mlock(w.pk, 32);

    secure_zero(master_raw.data(), master_raw.size());
    return w;
}

inline std::vector<ManifestEntry> scan_and_merge_oct_files() {
    auto entries = load_manifest();
    std::set<std::string> known_files;
    for (auto& e : entries) known_files.insert(e.file);
#ifdef _WIN32
    WIN32_FIND_DATAA fd;
    std::string pattern = std::string(WALLET_DIR) + "\\*.oct";
    HANDLE hFind = FindFirstFileA(pattern.c_str(), &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            std::string name = fd.cFileName;
            if (name.find(".tmp") != std::string::npos) continue;
            std::string path = std::string(WALLET_DIR) + "/" + name;
            if (known_files.count(path)) continue;
            ManifestEntry m;
            m.name = "";
            m.file = path;
            m.addr = "";
            m.hd = false;
            entries.push_back(m);
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
#else
    DIR* dir = opendir(WALLET_DIR);
    if (dir) {
        struct dirent* ent;
        while ((ent = readdir(dir)) != nullptr) {
            std::string name = ent->d_name;
            if (name.size() < 5) continue;
            if (name.substr(name.size() - 4) != ".oct") continue;
            if (name.find(".tmp") != std::string::npos) continue;
            std::string path = std::string(WALLET_DIR) + "/" + name;
            if (known_files.count(path)) continue;
            ManifestEntry m;
            m.name = "";
            m.file = path;
            m.addr = "";
            m.hd = false;
            entries.push_back(m);
        }
        closedir(dir);
    }
#endif
    return entries;
}
}
