// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once

#include "httplib.h"
#include <functional>
#include <atomic>
#include <shared_mutex>
#include <string>

namespace octra {

inline bool session_writer(const httplib::Request& request) {
    if (request.method != "POST") return false;
    const auto& path = request.path;
    return path == "/api/wallet/unlock" || path == "/api/wallet/lock"
        || path == "/api/wallet/create" || path == "/api/wallet/import"
        || path == "/api/wallet/switch" || path == "/api/wallet/change-pin"
        || path == "/api/settings" || path == "/api/browser/login";
}

inline bool session_required(const httplib::Request& request) {
    if (request.method != "POST" && request.method != "DELETE") return false;
    const auto& path = request.path;
    return path.rfind("/api/circle/", 0) == 0 || path.rfind("/api/program/", 0) == 0
        || path.rfind("/api/fhe/", 0) == 0 || path.rfind("/api/stealth/", 0) == 0
        || path.rfind("/api/pvac/", 0) == 0 || path.rfind("/api/tx/", 0) == 0
        || path == "/api/send" || path == "/api/key_switch" || path == "/api/encrypt"
        || path == "/api/decrypt" || path == "/api/token/transfer"
        || path == "/api/contract/deploy" || path == "/api/contract/call"
        || path == "/api/keys/private";
}

class SessionServer : public httplib::Server {
    std::shared_mutex& lifetime_;
    const std::atomic<unsigned>* writers_;
    std::function<bool(const httplib::Request&, httplib::Response&)> check_;
    std::function<bool(const httplib::Request&)> scoped_;

    Handler protect(Handler handler) {
        return [this, handler = std::move(handler)](const auto& request, auto& response) {
            const auto wallets = request.get_header_value_count("X-Webcli-Wallet");
            const auto generations = request.get_header_value_count("X-Webcli-Generation");
            const bool scoped = scoped_ && scoped_(request);
            if (wallets == 0 && generations == 0) {
                if (session_required(request)) {
                    response.status = 409;
                    response.set_content("{\"error\":\"wallet session required\"}", "application/json");
                    return;
                }
                if (!scoped || session_writer(request)) {
                    handler(request, response);
                    return;
                }
            }
            if ((wallets || generations) && (wallets != 1 || generations != 1
                || (request.method != "GET" && (request.path.rfind("/api/wallet/", 0) == 0
                    || request.path == "/api/settings")))) {
                response.status = 400;
                response.set_content("{\"error\":\"invalid wallet session request\"}", "application/json");
                return;
            }
            const auto busy = [&]() {
                if (!writers_ || writers_->load() == 0) return false;
                response.status = 409;
                response.set_content("{\"error\":\"wallet change in progress\"}", "application/json");
                return true;
            };
            if (busy()) return;
            std::shared_lock<std::shared_mutex> lease(lifetime_);
            if (busy()) return;
            if (!check_(request, response)) return;
            const bool read = request.method == "GET" && (request.path.rfind("/api/relay/", 0) == 0
                || request.path == "/api/balance" || request.path == "/api/stealth/scan"
                || request.path == "/api/pvac/cipher_structure" || request.path == "/api/pvac/upgrade_status");
            if (read || (!scoped && (request.path == "/api/circle/compute" || request.path == "/api/tx/retry"
                || request.path == "/api/tx/discard"))) lease.unlock();
            handler(request, response);
            if (read) {
                std::shared_lock<std::shared_mutex> final_lease(lifetime_);
                httplib::Response checked;
                if (!check_(request, checked)) response = std::move(checked);
            }
        };
    }
public:
    SessionServer(std::shared_mutex& lifetime,
        std::function<bool(const httplib::Request&, httplib::Response&)> check,
        const std::atomic<unsigned>* writers = nullptr,
        std::function<bool(const httplib::Request&)> scoped = {})
        : lifetime_(lifetime), writers_(writers), check_(std::move(check)), scoped_(std::move(scoped)) {}
    SessionServer& Get(const std::string& path, Handler handler) {
        httplib::Server::Get(path, protect(std::move(handler)));
        return *this;
    }
    SessionServer& Post(const std::string& path, Handler handler) {
        httplib::Server::Post(path, protect(std::move(handler)));
        return *this;
    }
    SessionServer& Delete(const std::string& path, Handler handler) {
        httplib::Server::Delete(path, protect(std::move(handler)));
        return *this;
    }
};

}