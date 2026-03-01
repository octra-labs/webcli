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
#include <leveldb/db.h>
#include <leveldb/write_batch.h>
#include "json.hpp"

class TxCache {
    leveldb::DB* db_ = nullptr;
    std::string path_;
public:
    bool open(const std::string& path) {
        path_ = path;
        leveldb::Options opts;
        opts.create_if_missing = true;
        auto st = leveldb::DB::Open(opts, path, &db_);
        return st.ok();
    }

    void close() { delete db_; db_ = nullptr; path_.clear(); }
    ~TxCache() { close(); }

    void put(const std::string& key, const std::string& val) {
        if (db_) db_->Put(leveldb::WriteOptions(), key, val);
    }

    std::string get(const std::string& key) {
        std::string val;
        if (db_ && db_->Get(leveldb::ReadOptions(), key, &val).ok()) return val;
        return "";
    }

    int get_total(const std::string& addr) {
        auto v = get("total:" + addr);
        return v.empty() ? 0 : std::stoi(v);
    }

    void set_total(const std::string& addr, int total) {
        put("total:" + addr, std::to_string(total));
    }

    void store_tx(const nlohmann::json& tx) {
        std::string hash = tx.value("hash", "");
        if (hash.empty()) return;
        put("tx:" + hash, tx.dump());
        double ts = tx.value("timestamp", 0.0);
        char idx[128];
        snprintf(idx, sizeof(idx), "idx:%020.6f:%s", 9999999999.0 - ts, hash.c_str());
        put(idx, hash);
    }

    void store_txs(const nlohmann::json& txs) {
        if (!db_) return;
        leveldb::WriteBatch batch;
        for (auto& tx : txs) {
            std::string hash = tx.value("hash", "");
            if (hash.empty()) continue;
            batch.Put("tx:" + hash, tx.dump());
            double ts = tx.value("timestamp", 0.0);
            char idx[128];
            snprintf(idx, sizeof(idx), "idx:%020.6f:%s", 9999999999.0 - ts, hash.c_str());
            batch.Put(idx, hash);
        }
        db_->Write(leveldb::WriteOptions(), &batch);
    }

    nlohmann::json load_page(int limit, int offset) {
        nlohmann::json result = nlohmann::json::array();
        if (!db_) return result;
        auto it = db_->NewIterator(leveldb::ReadOptions());
        int pos = 0;
        for (it->Seek("idx:"); it->Valid(); it->Next()) {
            auto k = it->key().ToString();
            if (k.substr(0, 4) != "idx:") break;
            if (pos < offset) { pos++; continue; }
            auto hash = it->value().ToString();
            std::string val;
            if (db_->Get(leveldb::ReadOptions(), "tx:" + hash, &val).ok()) {
                try { result.push_back(nlohmann::json::parse(val)); } catch (...) {}
            }
            pos++;
            if (limit > 0 && (pos - offset) >= limit) break;
        }
        delete it;
        return result;
    }

    int count_idx() {
        if (!db_) return 0;
        int n = 0;
        auto it = db_->NewIterator(leveldb::ReadOptions());
        for (it->Seek("idx:"); it->Valid(); it->Next()) {
            if (it->key().ToString().substr(0, 4) != "idx:") break;
            n++;
        }
        delete it;
        return n;
    }

    bool has_tx(const std::string& hash) {
        std::string val;
        return db_ && db_->Get(leveldb::ReadOptions(), "tx:" + hash, &val).ok();
    }

    bool is_open() const { return db_ != nullptr; }
};
