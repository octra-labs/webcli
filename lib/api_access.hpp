// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once

#include "httplib.h"
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <array>
#include <stdexcept>
#include <chrono>
#include <mutex>
#include <vector>
#include <functional>

namespace octra {

class ApiAccess {
    std::string token_;
    std::string browser_;
    struct Entry {
        std::string key;
        std::string api;
        std::string address;
        uint64_t generation;
        std::chrono::steady_clock::time_point expires;
    };
    mutable std::mutex mutex_;
    std::vector<Entry> entries_;
    std::function<std::chrono::steady_clock::time_point()> now_;

    static bool matches(const httplib::Request& request, const std::string& key) {
        if (request.get_header_value_count("Authorization") != 1) return false;
        const auto value = request.get_header_value("Authorization");
        return value.size() == key.size() + 7 && value.compare(0, 7, "Bearer ") == 0
            && CRYPTO_memcmp(value.data() + 7, key.data(), key.size()) == 0;
    }
    static bool refuse(httplib::Response& response) {
        response.status = 401;
        response.set_header("WWW-Authenticate", "Bearer realm=\"webcli-launch\"");
        response.set_header("Cache-Control", "no-store");
        response.set_content("{\"error\":\"wallet sign-in required\"}", "application/json");
        return false;
    }

    static std::string random_key() {
        std::array<unsigned char, 32> bytes{};
        if (RAND_bytes(bytes.data(), bytes.size()) != 1)
            throw std::runtime_error("API access entropy unavailable");
        const char* hex = "0123456789abcdef";
        std::string key;
        for (const auto byte : bytes) {
            key += hex[byte >> 4];
            key += hex[byte & 15];
        }
        OPENSSL_cleanse(bytes.data(), bytes.size());
        return key;
    }
public:
    explicit ApiAccess(std::function<std::chrono::steady_clock::time_point()> now =
        [] { return std::chrono::steady_clock::now(); })
        : token_(random_key()), browser_(random_key()), now_(std::move(now)) {}
    ~ApiAccess() {
        OPENSSL_cleanse(token_.data(), token_.size());
        OPENSSL_cleanse(browser_.data(), browser_.size());
        for (auto& value : entries_) {
            OPENSSL_cleanse(value.key.data(), value.key.size());
            OPENSSL_cleanse(value.api.data(), value.api.size());
        }
    }
    ApiAccess(const ApiAccess&) = delete;
    ApiAccess& operator=(const ApiAccess&) = delete;
    const std::string& token() const { return token_; }
    std::string browser_url(int port) const {
        return "http://127.0.0.1:" + std::to_string(port) + "/#webcli=" + browser_;
    }
    static bool entry(const httplib::Request& request) {
        return (request.method == "GET" && request.path == "/api/browser/status")
            || (request.method == "POST" && request.path == "/api/browser/login");
    }
    bool privileged(const httplib::Request& request) const {
        return matches(request, token_) || matches(request, browser_);
    }
    bool browser(const httplib::Request& request) const {
        if (matches(request, browser_)) return true;
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& value : entries_)
            if (value.expires > now_() && matches(request, value.key)) return true;
        return false;
    }
    bool scoped(const httplib::Request& request) const {
        return request.path.rfind("/api/", 0) == 0 && !entry(request) && !privileged(request);
    }
    bool allowed(const httplib::Request& request) const {
        if (privileged(request)) return true;
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& value : entries_)
            if (value.expires > now_()
                && (matches(request, value.key) || matches(request, value.api))) return true;
        return false;
    }
    bool scope(const httplib::Request& request, httplib::Response& response,
        bool loaded, const std::string& address, uint64_t generation) const {
        if (!scoped(request)) return true;
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& value : entries_)
            if (loaded && value.address == address && value.generation == generation
                && value.expires > now_()
                && (matches(request, value.key) || matches(request, value.api))) return true;
        return refuse(response);
    }
    std::string api_key(const httplib::Request& request) const {
        if (privileged(request)) return token_;
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& value : entries_)
            if (value.expires > now_()
                && (matches(request, value.key) || matches(request, value.api))) return value.api;
        throw std::runtime_error("wallet sign-in required");
    }
    std::string issue(const std::string& address, uint64_t generation) {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto now = now_();
        for (auto it = entries_.begin(); it != entries_.end();) {
            if (it->address != address || it->generation != generation || it->expires <= now) {
                OPENSSL_cleanse(it->key.data(), it->key.size());
                OPENSSL_cleanse(it->api.data(), it->api.size());
                it = entries_.erase(it);
            } else ++it;
        }
        if (entries_.size() >= 64) throw std::runtime_error("too many wallet sessions; lock and sign in again");
        auto key = random_key();
        entries_.push_back({key, random_key(), address, generation, now + std::chrono::hours(8)});
        return key;
    }
    void endpoint_change(const std::string& address, uint64_t old_generation, uint64_t new_generation) {
        if (old_generation == new_generation) return;
        std::lock_guard<std::mutex> lock(mutex_);
        const auto now = now_();
        for (auto& value : entries_) {
            if (value.address == address && value.generation == old_generation && value.expires > now)
                value.generation = new_generation;
        }
    }
    void renew(const httplib::Request& request, httplib::Response& response,
        const std::string& address, uint64_t generation) {
        if (!privileged(request)) response.set_header("X-Webcli-Session", issue(address, generation));
    }
    bool check(const httplib::Request& request, httplib::Response& response) const {
        if (request.path.rfind("/api/", 0) != 0) return true;
        if (entry(request) || allowed(request)) return true;
        return refuse(response);
    }
};

}