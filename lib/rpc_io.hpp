// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once

#include "httplib.h"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <thread>

namespace octra {

enum class RpcLink { local, unopened, untrusted, broken, expired, answered };

struct RpcBody {
    std::string body;
    std::string error;
    int status = 0;
    RpcLink link = RpcLink::local;
    std::optional<int> retry_after;
};

inline constexpr size_t rpc_refusal_limit = 4096;

inline bool rpc_length(const std::string& text, size_t limit) {
    if (text.empty()) return false;
    size_t value = 0;
    for (char ch : text) {
        if (ch < '0' || ch > '9') return false;
        const size_t digit = static_cast<size_t>(ch - '0');
        if (digit > limit || value > (limit - digit) / 10) return false;
        value = value * 10 + digit;
    }
    return true;
}

inline std::optional<int> rpc_retry_after(const std::string& text) {
    const int seconds = rpc_length(text, 86400) ? std::stoi(text) : 0;
    return seconds > 0 ? std::optional<int>(seconds) : std::nullopt;
}

inline bool rpc_refusal(int status) {
    return status == 429 || status == 503;
}

inline RpcLink rpc_link(httplib::Error error) {
    switch (error) {
    case httplib::Error::Connection:
    case httplib::Error::ConnectionTimeout:
    case httplib::Error::BindIPAddress:
    case httplib::Error::ProxyConnection:
    case httplib::Error::SSLConnection:
        return RpcLink::unopened;
    case httplib::Error::SSLLoadingCerts:
    case httplib::Error::SSLServerVerification:
    case httplib::Error::SSLServerHostnameVerification:
        return RpcLink::untrusted;
    default:
        return RpcLink::broken;
    }
}

template <class Client>
RpcBody rpc_post(Client& client, const std::string& path, std::string body,
                 int seconds, size_t limit, const std::string& method = "POST", bool accept_errors = false) {
    if (seconds < 1 || seconds > 600 || limit == 0)
        return {{}, "invalid RPC limits"};
    client.set_connection_timeout(std::min(seconds, 5), 0);
    client.set_read_timeout(seconds, 0);
    client.set_write_timeout(seconds, 0);
    client.set_follow_location(false);
    client.set_keep_alive(false);
    client.set_decompress(false);
    RpcBody out;
    httplib::Request request;
    request.method = method;
    request.path = path;
    request.body = std::move(body);
    request.headers = {{"Content-Type", "application/json"},
        {"User-Agent", "Octra-Wallet/0.04.10"}, {"Accept-Encoding", "identity"}};
    const auto keeps_refusal = [&] { return !accept_errors && rpc_refusal(out.status); };
    const auto cap = [&] { return keeps_refusal() ? std::min(limit, rpc_refusal_limit) : limit; };
    const auto http_error = [&] { return "RPC HTTP " + std::to_string(out.status); };
    const auto oversize = [&] { return keeps_refusal() ? http_error() : std::string("rpc response too large"); };
    request.response_handler = [&](const httplib::Response& response) {
        out.status = response.status;
        out.link = RpcLink::answered;
        out.retry_after = rpc_retry_after(response.get_header_value("Retry-After"));
        if (response.status < 200 || response.status == 205 || response.status == 407
            || response.status == 408 || response.status >= 600
            || (response.status >= 300 && response.status < 400)) {
            out.error = "invalid RPC response status";
            return false;
        }
        if (!accept_errors && (response.status < 200 || response.status >= 300) && !keeps_refusal()) {
            out.error = http_error();
            return false;
        }
        const size_t lengths = response.get_header_value_count("Content-Length");
        const size_t transfers = response.get_header_value_count("Transfer-Encoding");
        auto transfer = response.get_header_value("Transfer-Encoding");
        for (auto& ch : transfer) if (ch >= 'A' && ch <= 'Z') ch += 'a' - 'A';
        if (lengths > 1 || transfers > 1 || (lengths && transfers)
            || response.get_header_value_count("Content-Encoding") != 0
            || (transfers && transfer != "chunked")) {
            out.error = "invalid RPC response headers";
            return false;
        }
        if (lengths && !rpc_length(response.get_header_value("Content-Length"), cap())) {
            out.error = oversize();
            return false;
        }
        return true;
    };
    request.content_receiver = [&](const char* data, size_t size, uint64_t, uint64_t) {
        if (size > cap() - out.body.size()) {
            out.error = oversize();
            return false;
        }
        out.body.append(data, size);
        return true;
    };
    std::mutex mutex;
    std::condition_variable condition;
    bool done = false;
    std::atomic<bool> expired{false};
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    std::thread timer([&] {
        std::unique_lock<std::mutex> lock(mutex);
        if (!condition.wait_until(lock, deadline, [&] { return done; })) {
            expired = true;
            client.request_stop();
        }
    });
    bool refused = false;
    try {
        const auto result = client.send(request);
        if (!result && out.error.empty()) {
            out.error = "connection failed";
            out.link = rpc_link(result.error());
        }
        if (result && out.status == 0) {
            out.status = result->status;
            out.link = RpcLink::answered;
            if (out.status < 200 || out.status == 205 || out.status >= 600 || (out.status >= 300 && out.status < 400))
                out.error = "invalid RPC response status";
            if (!accept_errors && (out.status < 200 || out.status >= 300))
                out.error = http_error();
        }
        refused = result && out.error.empty() && keeps_refusal();
        if (refused) out.error = http_error();
    } catch (...) {
        out.error = "RPC request failed";
        out.link = RpcLink::broken;
    }
    {
        std::lock_guard<std::mutex> lock(mutex);
        done = true;
    }
    condition.notify_one();
    timer.join();
    if (expired || std::chrono::steady_clock::now() > deadline) {
        out.error = "RPC request timed out";
        out.link = RpcLink::expired;
        refused = false;
    }
    if ((!out.error.empty() && !refused) || out.status == 204 || out.status == 205 || out.status == 304) out.body.clear();
    return out;
}

}