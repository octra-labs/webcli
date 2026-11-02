// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once
#include <algorithm>
#include <array>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>
#include <leveldb/db.h>
#include <leveldb/env.h>
#include <leveldb/write_batch.h>
#include <openssl/rand.h>
#include "../crypto_utils.hpp"
#include "json.hpp"
#include "rpc_state.hpp"
#include "pvac_tx_state.hpp"
#include "tx_builder.hpp"

class TxJournal {
    using Json = nlohmann::json;
    using Cipher = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

    struct Plain {
        std::string text;
        ~Plain() { octra::secure_zero(text.data(), text.size()); }
    };

    inline static std::atomic<uint64_t> serial_{0};
    std::mutex mtx_;
    leveldb::Env* env_;
    std::unique_ptr<leveldb::DB> db_;
    std::array<uint8_t, 32> key_{};
    std::string addr_;
    std::string chain_;
    uint64_t token_ = 0;
    uint64_t count_ = 0;
    std::string active_;
    static constexpr size_t send_limit = 5'004'096;

    static void need(bool ok, const char* error) {
        if (!ok) throw std::runtime_error(error);
    }

    static void checked(const leveldb::Status& status) {
        if (!status.ok()) throw std::runtime_error("journal storage: " + status.ToString());
    }

    static bool text_ok(const std::string& text, size_t max) {
        return !text.empty() && text.size() <= max &&
            std::all_of(text.begin(), text.end(), [](unsigned char c) { return c > 32 && c < 127; });
    }

    static bool hex_ok(const std::string& text) {
        return text.size() == 64 && std::all_of(text.begin(), text.end(), [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        });
    }

    static bool digits(const std::string& text) {
        return !text.empty() && text.size() <= 20 &&
            std::all_of(text.begin(), text.end(), [](char c) { return c >= '0' && c <= '9'; });
    }

    static bool natural(const Json& value) {
        return value.is_number_unsigned() ||
            (value.is_number_integer() && value.get<int64_t>() >= 0) ||
            (value.is_string() && digits(value.get_ref<const std::string&>()));
    }

    static bool status_ok(const Json& status) {
        return status == "unknown" || status == "pending" || status == "dropped" ||
            status == "confirmed" || status == "rejected" || status == "unaccepted"
            || status == "replaced" || status == "discarded";
    }

    static bool migration_pending(const Json& row) {
        return row["op_type"] == "key_switch" && (row["status"] == "unknown"
            || row["status"] == "pending" || row["status"] == "dropped");
    }

    Json own(const Json& input) const {
        need(input.is_object(), "journal row must be an object");
        Json row = Json::object();
        for (const auto* field : {"hash", "from", "to_", "amount_raw", "op_type", "timestamp", "output_id", "request_id", "request_key", "nonce"}) {
            if (input.contains(field)) row[field] = input[field];
        }
        need(row.contains("hash") && row["hash"].is_string() &&
            hex_ok(row["hash"].get_ref<const std::string&>()), "journal hash invalid");
        need(row.contains("from") && row["from"] == addr_, "journal wallet mismatch");
        need(row.contains("to_") && row["to_"].is_string() &&
            text_ok(row["to_"].get_ref<const std::string&>(), 128), "journal recipient invalid");
        need(row.contains("amount_raw") && row["amount_raw"].is_string() &&
            digits(row["amount_raw"].get_ref<const std::string&>()), "journal amount invalid");
        need(row.contains("op_type") && row["op_type"].is_string(), "journal operation missing");
        const auto& op = row["op_type"].get_ref<const std::string&>();
        need(!op.empty() && op.size() <= 64 && std::all_of(op.begin(), op.end(), [](char c) {
            return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
        }), "journal operation invalid");
        need(row.contains("timestamp") && row["timestamp"].is_number() &&
            std::isfinite(row["timestamp"].get<double>()) && row["timestamp"].get<double>() >= 0,
            "journal timestamp invalid");
        if (row.contains("output_id")) {
            need(row["output_id"].is_string() && text_ok(row["output_id"].get_ref<const std::string&>(), 128),
                "journal output invalid");
        }
        if (row.contains("request_id") || row.contains("request_key")) {
            need(row.contains("request_id") && row["request_id"].is_string()
                && hex_ok(row["request_id"].get<std::string>())
                && row.contains("request_key") && row["request_key"].is_string()
                && hex_ok(row["request_key"].get<std::string>()), "journal request invalid");
        }
        if (row.contains("nonce")) need(octra::rpc_nonce(row["nonce"]) > 0, "journal nonce invalid");
        row["local_record"] = true;
        return row;
    }

    Json record(const Json& input) const {
        auto row = own(input);
        need(input.contains("status") && status_ok(input["status"]), "journal status invalid");
        row["status"] = input["status"];
        for (const auto* field : {"epoch", "block_height"}) {
            if (!input.contains(field)) continue;
            need(natural(input[field]), "journal evidence invalid");
            row[field] = input[field];
        }
        if (input.contains("submit_error")) {
            need(input["submit_error"].is_string() && input["submit_error"].get_ref<const std::string&>().size() <= 2048,
                "journal submit error invalid");
            row["submit_error"] = input["submit_error"];
        }
        if (input.contains("replacement_hash") || input.contains("replacement_epoch")) {
            need(input.value("status", "") == "replaced"
                && input.contains("replacement_hash") && input["replacement_hash"].is_string()
                && hex_ok(input["replacement_hash"].get<std::string>())
                && input["replacement_hash"] != row["hash"]
                && input.contains("replacement_epoch") && natural(input["replacement_epoch"]),
                "journal replacement evidence invalid");
            row["replacement_hash"] = input["replacement_hash"];
            row["replacement_epoch"] = input["replacement_epoch"];
        }
        need(row == input, "journal record fields invalid");
        return row;
    }

    std::string mac(const std::string& input) const {
        std::array<uint8_t, 32> digest{};
        unsigned int size = 0;
        need(HMAC(EVP_sha256(), key_.data(), key_.size(),
            reinterpret_cast<const uint8_t*>(input.data()), input.size(), digest.data(), &size) &&
            size == digest.size(), "journal index derivation failed");
        return octra::hex_encode(digest.data(), digest.size());
    }

    std::string row_key(const std::string& hash) const {
        need(hex_ok(hash), "journal hash invalid");
        return "r:" + mac(Json::array({"octra/own-tx-journal/index", hash}).dump());
    }

    std::string aad(const std::string& id) const {
        return Json::array({"octra/own-tx-journal/aes256gcm", addr_, chain_, id}).dump();
    }

    std::string seal(const std::string& id, const Json& row, size_t limit = 4096) const {
        Plain plain{row.dump()};
        need(plain.text.size() <= limit, "journal record too large");
        std::string out(12 + plain.text.size() + 16, '\0');
        auto* bytes = reinterpret_cast<uint8_t*>(out.data());
        need(RAND_bytes(bytes, 12) == 1, "journal nonce failed");
        Cipher ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        need(bool(ctx), "journal cipher allocation failed");
        const auto auth = aad(id);
        int size = 0;
        need(EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
            EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key_.data(), bytes) == 1 &&
            EVP_EncryptUpdate(ctx.get(), nullptr, &size,
                reinterpret_cast<const uint8_t*>(auth.data()), int(auth.size())) == 1 &&
            EVP_EncryptUpdate(ctx.get(), bytes + 12, &size,
                reinterpret_cast<const uint8_t*>(plain.text.data()), int(plain.text.size())) == 1,
            "journal encryption failed");
        int end = 0;
        need(EVP_EncryptFinal_ex(ctx.get(), bytes + 12 + size, &end) == 1 &&
            size + end == int(plain.text.size()) &&
            EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, bytes + 12 + plain.text.size()) == 1,
            "journal encryption failed");
        return out;
    }

    Json unseal(const std::string& id, const std::string& data, size_t limit = 4096) const {
        need(data.size() >= 28 && data.size() <= limit + 28, "journal ciphertext invalid");
        const auto* bytes = reinterpret_cast<const uint8_t*>(data.data());
        const auto len = data.size() - 28;
        Plain plain{std::string(len + 16, '\0')};
        Cipher ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        need(bool(ctx), "journal cipher allocation failed");
        const auto auth = aad(id);
        int size = 0;
        need(EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
            EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key_.data(), bytes) == 1 &&
            EVP_DecryptUpdate(ctx.get(), nullptr, &size,
                reinterpret_cast<const uint8_t*>(auth.data()), int(auth.size())) == 1 &&
            EVP_DecryptUpdate(ctx.get(), reinterpret_cast<uint8_t*>(plain.text.data()), &size,
                bytes + 12, int(len)) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 16,
                const_cast<uint8_t*>(bytes + 12 + len)) == 1,
            "journal decryption failed");
        int end = 0;
        need(EVP_DecryptFinal_ex(ctx.get(), reinterpret_cast<uint8_t*>(plain.text.data()) + size, &end) == 1 &&
            size + end == int(len), "journal authentication failed");
        const auto row = Json::parse(plain.text.begin(), plain.text.begin() + len, nullptr, false);
        need(!row.is_discarded(), "journal plaintext invalid");
        return row;
    }

    static leveldb::ReadOptions reads() {
        leveldb::ReadOptions opts;
        opts.verify_checksums = true;
        return opts;
    }

    Json get(const std::string& id, size_t limit = 4096) const {
        std::string data;
        const auto result = db_->Get(reads(), id, &data);
        if (result.IsNotFound()) return nullptr;
        checked(result);
        return unseal(id, data, limit);
    }

    Json sending() const {
        const auto send = get("send", send_limit);
        if (send.is_null()) return nullptr;
        need(send.is_object() && (send.size() == 2 || (send.size() == 3
            && send.contains("uncertain") && send["uncertain"].is_boolean())) && send.contains("hash")
            && send["hash"].is_string() && send.contains("tx") && send["tx"].is_object(),
            "journal send invalid");
        const auto& body = send["tx"];
        octra::Transaction tx;
        tx.from = body.at("from").get<std::string>();
        tx.to_ = body.at("to_").get<std::string>();
        tx.amount = body.at("amount").get<std::string>();
        tx.nonce = body.at("nonce").get<int>();
        tx.ou = body.at("ou").get<std::string>();
        tx.timestamp = body.at("timestamp").get<double>();
        tx.signature = body.at("signature").get<std::string>();
        tx.public_key = body.at("public_key").get<std::string>();
        tx.op_type = body.at("op_type").get<std::string>();
        tx.encrypted_data = body.value("encrypted_data", "");
        tx.message = body.value("message", "");
        need(tx.from == addr_ && tx.nonce > 0 && !tx.signature.empty()
            && !tx.public_key.empty() && (tx.op_type == "stealth" || tx.op_type == "claim")
            && octra::build_tx_json(tx) == body && octra::tx_hash(tx) == send["hash"],
            "journal send bytes mismatch");
        const auto saved = get(row_key(send["hash"].get<std::string>()));
        need(!saved.is_null() && record(saved)["hash"] == send["hash"]
            && (saved["status"] == "unknown" || saved["status"] == "dropped"
                || saved["status"] == "pending" || saved["status"] == "unaccepted"),
            "journal send state mismatch");
        return send;
    }

    static Json visible(Json row, const Json& send) {
        if (!row.is_null() && !send.is_null() && send["hash"] == row["hash"]) {
            row["retryable"] = true;
            row["nonce"] = send["tx"]["nonce"];
            if (row["status"] == "unaccepted") row["discardable"] = true;
        }
        if (row.is_object()) {
            row.erase("request_id");
            row.erase("request_key");
        }
        return row;
    }

    Json request(const std::string& id, const std::string& key) const {
        if (id.empty()) return nullptr;
        need(hex_ok(id) && hex_ok(key), "journal request invalid");
        for (const auto& row : scan()) {
            if (row.value("request_id", "") != id) continue;
            if (row.value("request_key", "") != key)
                throw std::invalid_argument("journal request parameters changed");
            return visible(row, sending());
        }
        return nullptr;
    }

    Json claim_output(const std::string& output) const {
        need(text_ok(output, 128), "journal output invalid");
        Json found = nullptr;
        int found_rank = -1;
        const auto send = sending();
        for (const auto& row : scan()) {
            if (row.value("op_type", "") != "claim" || row.value("output_id", "") != output) continue;
            const auto status = row.value("status", "");
            const int rank = status == "confirmed" ? 4 : status == "pending" ? 3
                : status == "unknown" ? 2 : status == "dropped" ? 1 : -1;
            if (rank > found_rank) {
                found = visible(row, send);
                found_rank = rank;
            }
        }
        return found;
    }

    Json scan() const {
        auto rows = Json::array();
        std::unique_ptr<leveldb::Iterator> it(db_->NewIterator(reads()));
        for (it->SeekToFirst(); it->Valid(); it->Next()) {
            const auto id = it->key().ToString();
            if (id == "meta" || id == "send") continue;
            need(id.size() == 66 && id.substr(0, 2) == "r:" && hex_ok(id.substr(2)),
                "journal index invalid");
            const auto row = record(unseal(id, it->value().ToString()));
            need(row_key(row["hash"].get<std::string>()) == id, "journal index mismatch");
            rows.push_back(row);
        }
        checked(it->status());
        need(rows.size() == count_, "journal count mismatch");
        sending();
        return rows;
    }

    void write(leveldb::WriteBatch& batch) {
        leveldb::WriteOptions opts;
        opts.sync = true;
        const auto result = db_->Write(opts, &batch);
        if (!result.ok()) {
            shut();
            checked(result);
        }
    }

    Json meta(uint64_t count) const {
        return Json::array({"octra/own-tx-journal", addr_, chain_, count});
    }

    void session(uint64_t token) const {
        need(db_ && token != 0 && token == token_, "journal session mismatch");
    }

    void shut() {
        token_ = 0;
        octra::secure_zero(key_.data(), key_.size());
        db_.reset();
        addr_.clear();
        chain_.clear();
        count_ = 0;
        active_.clear();
    }

public:
    enum class Reply { accepted, rejected, retry, unknown };

    static bool confirms_replacement(const Json& tx, const std::string& addr,
        const std::string& chain, int nonce, const std::string& hash) {
        if (!tx.is_object() || !tx.contains("status") || tx["status"] != "confirmed"
            || !tx.contains("from") || tx["from"] != addr
            || !tx.contains("nonce") || !tx.contains("epoch") || !natural(tx["epoch"])
            || (tx.contains("chain_id") && tx["chain_id"] != chain)) return false;
        const auto id = tx.contains("hash") ? tx["hash"] : tx.value("tx_hash", Json());
        if (!id.is_string() || !hex_ok(id.get<std::string>()) || id == hash
            || (tx.contains("tx_hash") && tx["tx_hash"] != id)) return false;
        try {
            return octra::rpc_nonce(tx["nonce"]) == nonce;
        } catch (const octra::RpcStateError&) { return false; }
    }

    static std::string network(const std::string& base, const std::string& addr,
        const std::string& rpc, const uint8_t* seed, const std::string& known = "") {
        need(text_ok(addr, 128) && text_ok(rpc, 4096) && seed, "journal network identity invalid");
        if (!known.empty()) need(text_ok(known, 512), "journal chain invalid");
        TxJournal pin;
        pin.addr_ = addr;
        pin.chain_ = rpc;
        const auto scope = Json::array({"octra/own-tx-network", addr, rpc}).dump();
        const auto domain = Json::array({"octra/own-tx-network/key", addr, rpc}).dump();
        unsigned int len = 0;
        need(HMAC(EVP_sha256(), seed, 32, reinterpret_cast<const uint8_t*>(domain.data()),
            domain.size(), pin.key_.data(), &len) && len == pin.key_.size(), "journal network key failed");
        const auto digest = octra::sha256(scope);
        const auto path = std::filesystem::path(base) / "networks" /
            octra::hex_encode(digest.data(), digest.size());
        const bool exists = std::filesystem::exists(path);
        if (!exists && known.empty()) return "";
        if (!exists) std::filesystem::create_directories(path.parent_path());
        leveldb::Options opts;
        opts.create_if_missing = !exists;
        opts.paranoid_checks = true;
        leveldb::DB* db = nullptr;
        const auto status = leveldb::DB::Open(opts, path.string(), &db);
        pin.db_.reset(db);
        checked(status);
        const auto saved = pin.get("network");
        if (!saved.is_null()) {
            need(saved.is_array() && saved.size() == 2 && saved[0] == scope
                && saved[1].is_string() && text_ok(saved[1].get<std::string>(), 512),
                "journal network binding invalid");
        } else need(!exists, "journal network binding missing");
        if (known.empty()) return saved[1].get<std::string>();
        leveldb::WriteBatch batch;
        batch.Put("network", pin.seal("network", Json::array({scope, known})));
        pin.write(batch);
        return known;
    }

    explicit TxJournal(leveldb::Env* env = leveldb::Env::Default()) : env_(env) {}
    TxJournal(const TxJournal&) = delete;
    TxJournal& operator=(const TxJournal&) = delete;
    ~TxJournal() { close(); }

    uint64_t open(const std::string& base, const std::string& addr, const std::string& chain,
        const uint8_t* seed, size_t size = 32) {
        std::lock_guard<std::mutex> lock(mtx_);
        shut();
        try {
            need(!base.empty() && text_ok(addr, 128) && text_ok(chain, 512), "journal identity invalid");
            need(seed && size == 32, "journal signing seed invalid");
            need(env_ != nullptr, "journal storage environment missing");
            addr_ = addr;
            chain_ = chain;
            const auto scope = Json::array({"octra/own-tx-journal", addr_, chain_}).dump();
            const auto domain = Json::array({"octra/own-tx-journal/key", addr_, chain_}).dump();
            unsigned int len = 0;
            need(HMAC(EVP_sha256(), seed, 32, reinterpret_cast<const uint8_t*>(domain.data()),
                domain.size(), key_.data(), &len) && len == key_.size(), "journal key derivation failed");
            const auto digest = octra::sha256(scope);
            const auto path = std::filesystem::path(base) / octra::hex_encode(digest.data(), digest.size());
            std::filesystem::create_directories(base);
            const bool exists = std::filesystem::exists(path);
            leveldb::Options opts;
            opts.create_if_missing = !exists;
            opts.paranoid_checks = true;
            opts.env = env_;
            leveldb::DB* db = nullptr;
            const auto result = leveldb::DB::Open(opts, path.string(), &db);
            db_.reset(db);
            checked(result);
            const auto saved = get("meta");
            if (saved.is_null()) {
                need(!exists, "journal identity missing");
                std::unique_ptr<leveldb::Iterator> it(db_->NewIterator(reads()));
                it->SeekToFirst();
                checked(it->status());
                need(!it->Valid(), "journal identity missing");
                leveldb::WriteBatch batch;
                batch.Put("meta", seal("meta", meta(0)));
                write(batch);
            } else {
                need(saved.is_array() && saved.size() == 4 && saved[3].is_number_unsigned(),
                    "journal identity invalid");
                count_ = saved[3].get<uint64_t>();
                need(saved == meta(count_), "journal identity mismatch");
            }
            scan();
            auto serial = serial_.load();
            do {
                need(serial < std::numeric_limits<uint64_t>::max(), "journal session exhausted");
            } while (!serial_.compare_exchange_weak(serial, serial + 1));
            token_ = serial + 1;
            return token_;
        } catch (...) {
            shut();
            throw;
        }
    }

    uint64_t open(const std::string& base, const std::string& addr, const std::string& chain,
        const std::array<uint8_t, 32>& seed) {
        return open(base, addr, chain, seed.data(), seed.size());
    }

    void close() {
        std::lock_guard<std::mutex> lock(mtx_);
        shut();
    }

    bool is_open(uint64_t token) {
        std::lock_guard<std::mutex> lock(mtx_);
        return db_ && token != 0 && token == token_;
    }

    void save(uint64_t token, const Json& input) {
        std::lock_guard<std::mutex> lock(mtx_);
        session(token);
        auto row = own(input);
        const auto id = row_key(row["hash"].get<std::string>());
        const auto saved = get(id);
        if (!saved.is_null()) {
            need(own(record(saved)) == row, "journal own fields mismatch");
            return;
        }
        need(count_ < std::numeric_limits<uint64_t>::max(), "journal count exhausted");
        row["status"] = "unknown";
        leveldb::WriteBatch batch;
        batch.Put(id, seal(id, row));
        batch.Put("meta", seal("meta", meta(count_ + 1)));
        write(batch);
        ++count_;
    }

    Json migration(uint64_t token) {
        std::lock_guard<std::mutex> lock(mtx_);
        session(token);
        Json selected = nullptr;
        for (const auto& row : scan()) {
            if (!migration_pending(row)) continue;
            if (selected.is_null() || row["timestamp"].get<double>() > selected["timestamp"].get<double>()
                || (row["timestamp"] == selected["timestamp"] && row["hash"] > selected["hash"])) selected = row;
        }
        return selected.is_null() ? selected : visible(selected, nullptr);
    }

    bool migration_confirmed(uint64_t token, const std::string& hash) {
        std::lock_guard<std::mutex> lock(mtx_);
        session(token);
        const auto saved = get(row_key(hash));
        if (saved.is_null()) return false;
        const auto row = record(saved);
        if (row["op_type"] != "key_switch" || !row.contains("nonce")) return false;
        if (row["status"] == "confirmed") return true;
        for (const auto& peer : scan())
            if (peer["op_type"] == "key_switch" && peer["status"] == "confirmed"
                && peer.contains("nonce") && peer["nonce"] == row["nonce"]) return true;
        return false;
    }

    void migration_used(uint64_t token, const std::string& hash, int nonce,
        bool ok, bool replied, int code, const Json& lookup) {
        std::lock_guard<std::mutex> lock(mtx_);
        session(token);
        const auto id = row_key(hash);
        auto row = record(get(id));
        need(migration_pending(row) && row.contains("nonce")
            && octra::pvac_nonce_used(nonce, octra::rpc_nonce(row["nonce"]), ok, replied, code, lookup, hash)
            && (!lookup.is_object() || !lookup.contains("chain_id") || lookup["chain_id"] == chain_)
            && (!lookup.is_object() || !lookup.contains("from") || lookup["from"] == addr_),
            "journal migration nonce not used");
        row["status"] = "replaced";
        row["submit_error"] = "account nonce used; original execution outcome unavailable; nonce = "
            + std::to_string(nonce) + "; lookup = " + (ok ? lookup.at("status").get<std::string>() : "not_found");
        leveldb::WriteBatch batch;
        batch.Put(id, seal(id, row));
        write(batch);
    }

    Json prepare_migration(uint64_t token, const Json& input, const octra::Transaction& tx,
        const std::string& retry_hash = "") {
        std::lock_guard<std::mutex> lock(mtx_);
        session(token);
        auto row = own(input);
        need(tx.from == addr_ && tx.nonce > 0 && !tx.signature.empty()
            && !tx.public_key.empty() && tx.op_type == "key_switch" && row["op_type"] == tx.op_type
            && row["hash"] == octra::tx_hash(tx), "journal migration identity mismatch");
        bool retry_found = false;
        for (const auto& prior : scan()) {
            if (!migration_pending(prior)) continue;
            if (retry_hash.empty() || prior.value("nonce", 0) != tx.nonce) return visible(prior, nullptr);
            if (prior["hash"] == retry_hash) retry_found = true;
        }
        need(retry_hash.empty() || retry_found, "journal migration retry changed");
        const auto id = row_key(row["hash"].get<std::string>());
        need(get(id).is_null(), "journal transaction already saved");
        need(count_ < std::numeric_limits<uint64_t>::max(), "journal count exhausted");
        row["status"] = "unknown";
        row["nonce"] = tx.nonce;
        leveldb::WriteBatch batch;
        batch.Put(id, seal(id, row));
        batch.Put("meta", seal("meta", meta(count_ + 1)));
        write(batch);
        ++count_;
        return nullptr;
    }

    Json prepare(uint64_t token, const Json& input, const octra::Transaction& tx) {
        std::lock_guard<std::mutex> lock(mtx_);
        session(token);
        auto row = own(input);
        const auto repeated = request(row.value("request_id", ""), row.value("request_key", ""));
        if (!repeated.is_null()) {
            auto result = repeated;
            result["reused"] = true;
            return result;
        }
        if (row.value("op_type", "") == "claim" && row.contains("output_id")) {
            auto prior = claim_output(row["output_id"].get_ref<const std::string&>());
            if (!prior.is_null()) {
                prior["reused"] = true;
                return prior;
            }
        }
        need(tx.from == addr_ && tx.nonce > 0 && !tx.signature.empty()
            && !tx.public_key.empty() && (tx.op_type == "stealth" || tx.op_type == "claim")
            && row["op_type"] == tx.op_type && row["hash"] == octra::tx_hash(tx),
            "journal send identity mismatch");
        const auto send = sending();
        if (!send.is_null()) {
            const auto prior = record(get(row_key(send["hash"].get<std::string>())));
            if (prior["status"] != "unaccepted" || !active_.empty()) return visible(prior, send);
        }
        const auto id = row_key(row["hash"].get<std::string>());
        need(get(id).is_null(), "journal transaction already saved");
        need(count_ < std::numeric_limits<uint64_t>::max(), "journal count exhausted");
        row["status"] = "unknown";
        row["nonce"] = tx.nonce;
        const Json entry = {{"hash", row["hash"]}, {"tx", octra::build_tx_json(tx)}, {"uncertain", false}};
        leveldb::WriteBatch batch;
        batch.Put(id, seal(id, row));
        batch.Put("send", seal("send", entry, send_limit));
        batch.Put("meta", seal("meta", meta(count_ + 1)));
        write(batch);
        ++count_;
        return nullptr;
    }

    Json find_request(uint64_t token, const std::string& id, const std::string& key) {
        std::lock_guard<std::mutex> lock(mtx_);
        session(token);
        return request(id, key);
    }

    Json find_claim_output(uint64_t token, const std::string& output) {
        std::lock_guard<std::mutex> lock(mtx_);
        session(token);
        return claim_output(output);
    }

    Json resend(uint64_t token, const std::string& hash) {
        std::lock_guard<std::mutex> lock(mtx_);
        session(token);
        const auto send = sending();
        need(!send.is_null() && send["hash"] == hash, "journal send not pending");
        return send["tx"];
    }

    Json waiting(uint64_t token) {
        std::lock_guard<std::mutex> lock(mtx_);
        session(token);
        const auto send = sending();
        if (send.is_null()) return nullptr;
        return visible(record(get(row_key(send["hash"].get<std::string>()))), send);
    }

    Json start(uint64_t token, const std::string& hash) {
        std::lock_guard<std::mutex> lock(mtx_);
        session(token);
        need(active_.empty(), "submission already in progress");
        auto send = sending();
        need(!send.is_null() && send["hash"] == hash, "journal send not pending");
        const auto prior = send.value("uncertain", true);
        send["uncertain"] = true;
        const auto id = row_key(hash);
        auto row = record(get(id));
        row["status"] = "unknown";
        leveldb::WriteBatch batch;
        batch.Put(id, seal(id, row));
        batch.Put("send", seal("send", send, send_limit));
        write(batch);
        active_ = hash;
        send["uncertain"] = prior;
        return send;
    }

    void finish(uint64_t token, const std::string& hash, Reply reply, bool prior,
        const std::string& error = "") {
        std::lock_guard<std::mutex> lock(mtx_);
        session(token);
        if (active_ != hash) return;
        active_.clear();
        auto send = sending();
        if (send.is_null() || send["hash"] != hash) return;
        const auto id = row_key(hash);
        auto row = record(get(id));
        const bool accepted = reply == Reply::accepted;
        const bool unknown = prior || row["status"] == "dropped";
        const bool refused = !unknown && reply == Reply::rejected;
        const bool retry = !unknown && reply == Reply::retry;
        row["status"] = accepted ? "pending" : refused ? "rejected" : retry ? "unaccepted" : "unknown";
        if (error.empty()) row.erase("submit_error");
        else row["submit_error"] = error.size() <= 2048 ? error : "RPC request refused";
        leveldb::WriteBatch batch;
        batch.Put(id, seal(id, row));
        if (accepted || refused) batch.Delete("send");
        else {
            send["uncertain"] = !retry;
            batch.Put("send", seal("send", send, send_limit));
        }
        write(batch);
    }

    void replaced(uint64_t token, const std::string& hash, const Json& evidence) {
        std::lock_guard<std::mutex> lock(mtx_);
        session(token);
        const auto send = sending();
        if (send.is_null() || send["hash"] != hash) return;
        need(confirms_replacement(evidence, addr_, chain_, send["tx"]["nonce"].get<int>(), hash),
            "journal replacement evidence invalid");
        const auto id = row_key(hash);
        auto row = record(get(id));
        row["status"] = "replaced";
        row["nonce"] = send["tx"]["nonce"];
        row["replacement_hash"] = evidence.contains("hash") ? evidence["hash"] : evidence["tx_hash"];
        row["replacement_epoch"] = evidence["epoch"];
        row["submit_error"] = "a different confirmed transaction used this nonce";
        leveldb::WriteBatch batch;
        batch.Put(id, seal(id, row));
        batch.Delete("send");
        write(batch);
        active_.clear();
    }

    void discard(uint64_t token, const std::string& hash) {
        std::lock_guard<std::mutex> lock(mtx_);
        session(token);
        const auto send = sending();
        need(!send.is_null() && send["hash"] == hash && !send.value("uncertain", true)
            && active_.empty(), "saved transaction may have been accepted");
        const auto id = row_key(hash);
        auto row = record(get(id));
        need(row["status"] == "unaccepted", "saved transaction cannot be discarded");
        row["status"] = "discarded";
        leveldb::WriteBatch batch;
        batch.Put(id, seal(id, row));
        batch.Delete("send");
        write(batch);
    }

    void sent(uint64_t token, const std::string& hash) {
        std::lock_guard<std::mutex> lock(mtx_);
        session(token);
        const auto send = sending();
        if (send.is_null() || send["hash"] != hash) return;
        const auto id = row_key(hash);
        auto row = record(get(id));
        row["status"] = "pending";
        leveldb::WriteBatch batch;
        batch.Put(id, seal(id, row));
        batch.Delete("send");
        write(batch);
    }

    Json find(uint64_t token, const std::string& hash) {
        std::lock_guard<std::mutex> lock(mtx_);
        session(token);
        const auto row = get(row_key(hash));
        if (row.is_null()) return nullptr;
        const auto result = record(row);
        need(result["hash"] == hash, "journal hash mismatch");
        return visible(result, sending());
    }

    Json list(uint64_t token, size_t limit = 50, size_t offset = 0) {
        std::lock_guard<std::mutex> lock(mtx_);
        session(token);
        auto rows = scan();
        std::sort(rows.begin(), rows.end(), [](const Json& a, const Json& b) {
            if (a["timestamp"] != b["timestamp"]) return a["timestamp"].get<double>() > b["timestamp"].get<double>();
            return a["hash"].get_ref<const std::string&>() > b["hash"].get_ref<const std::string&>();
        });
        auto page = Json::array();
        const auto send = sending();
        for (size_t i = std::min(offset, rows.size()); i < rows.size() && page.size() < limit; ++i)
            page.push_back(visible(rows[i], send));
        return page;
    }

    uint64_t count(uint64_t token) {
        std::lock_guard<std::mutex> lock(mtx_);
        session(token);
        scan();
        return count_;
    }

    void update(uint64_t token, const std::string& hash, const Json& lookup) {
        std::lock_guard<std::mutex> lock(mtx_);
        session(token);
        const auto id = row_key(hash);
        auto row = get(id);
        need(!row.is_null(), "journal transaction missing");
        row = record(row);
        need(row["hash"] == hash && lookup.is_object(), "journal lookup invalid");
        need(lookup.contains("hash") || lookup.contains("tx_hash"), "journal lookup hash missing");
        for (const auto* field : {"hash", "tx_hash"})
            if (lookup.contains(field)) need(lookup[field] == hash, "journal lookup hash mismatch");
        if (lookup.contains("chain_id")) need(lookup["chain_id"] == chain_, "journal lookup chain mismatch");
        if (row["op_type"] == "key_switch" && lookup.contains("from"))
            need(lookup["from"] == addr_, "journal migration sender mismatch");
        need(lookup.contains("status") && status_ok(lookup["status"]), "journal lookup status invalid");
        if (row["status"] == "replaced" || row["status"] == "discarded") {
            if (lookup["status"] != "confirmed" || row["op_type"] != "key_switch"
                || row.contains("replacement_hash")) return;
            row.erase("submit_error");
        }
        if (row["status"] == "confirmed" || row["status"] == "rejected")
            need(lookup["status"] == row["status"], "journal terminal status mismatch");
        row["status"] = lookup["status"];
        for (const auto* field : {"epoch", "block_height"}) {
            const char* source = field;
            if (std::string(field) == "epoch" && !lookup.contains(field)) source = "epoch_id";
            if (!lookup.contains(source) || lookup[source].is_null()) continue;
            need(natural(lookup[source]), "journal lookup evidence invalid");
            row[field] = lookup[source];
        }
        leveldb::WriteBatch batch;
        batch.Put(id, seal(id, row));
        const auto send = sending();
        if (!send.is_null() && send["hash"] == hash
            && (row["status"] == "pending" || row["status"] == "confirmed" || row["status"] == "rejected"))
            batch.Delete("send");
        else if (!send.is_null() && send["hash"] == hash && row["status"] == "dropped") {
            auto observed = send;
            observed["uncertain"] = true;
            batch.Put("send", seal("send", observed, send_limit));
        }
        write(batch);
    }
};