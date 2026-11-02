// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
// lambda0xE
// Arthur Edelstein
// Denis CMIX

#include "program_rpc.hpp"

#include <chrono>
#include <climits>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

#include "httplib.h"
#include "program_cli_detail.hpp"

namespace octra::program_rpc {

namespace {

bool method_ok(const std::string& method) {
    if (method.empty() || method.size() > 64) return false;
    for (char c : method) {
        const bool lower = c >= 'a' && c <= 'z';
        const bool upper = c >= 'A' && c <= 'Z';
        const bool digit = c >= '0' && c <= '9';
        if (!lower && !upper && !digit && c != '_') return false;
    }
    return true;
}

bool length_value(const std::string& value, size_t& result) {
    if (value.empty()) return false;
    size_t number = 0;
    for (char c : value) {
        if (c < '0' || c > '9') return false;
        const size_t digit = static_cast<size_t>(c - '0');
        if (number > (max_response_bytes - digit) / 10U) return false;
        number = number * 10U + digit;
    }
    result = number;
    return true;
}

std::string lower_ascii(std::string value) {
    for (char& c : value) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return value;
}

std::string safe_text(const std::string& value) {
    std::string out;
    out.reserve(value.size() < 512 ? value.size() : 512);
    for (unsigned char c : value) {
        if (out.size() == 512) break;
        out.push_back(c >= 0x20 && c <= 0x7e ? static_cast<char>(c) : '?');
    }
    return out;
}

bool response_headers_ok(
    const httplib::Response& response,
    size_t limit,
    bool& too_large) {
    if (response.status != 200) return false;
    if (response.get_header_value_count("Content-Encoding") != 0) return false;
    const size_t lengths = response.get_header_value_count("Content-Length");
    const size_t transfers = response.get_header_value_count("Transfer-Encoding");
    if (lengths > 1 || transfers > 1 || (lengths != 0 && transfers != 0))
        return false;
    if (transfers == 1 && lower_ascii(
            response.get_header_value("Transfer-Encoding")) != "chunked")
        return false;
    if (lengths == 1) {
        size_t length = 0;
        if (!length_value(response.get_header_value("Content-Length"), length))
            return false;
        if (length > limit) {
            too_large = true;
            return false;
        }
    }
    return true;
}

bool response_id_ok(const nlohmann::json& value, uint32_t expected) {
    if (!value.is_number_integer()) return false;
    if (value.is_number_unsigned())
        return value.get<uint64_t>() == expected;
    const int64_t number = value.get<int64_t>();
    return number >= 0 && static_cast<uint64_t>(number) == expected;
}

bool error_code(const nlohmann::json& value, int& result) {
    if (!value.is_number_integer()) return false;
    if (value.is_number_unsigned()) {
        const uint64_t number = value.get<uint64_t>();
        if (number > static_cast<uint64_t>(INT_MAX)) return false;
        result = static_cast<int>(number);
        return true;
    }
    const int64_t number = value.get<int64_t>();
    if (number < INT_MIN || number > INT_MAX) return false;
    result = static_cast<int>(number);
    return true;
}

class JsonShape : public nlohmann::json_sax<nlohmann::json> {
    struct Frame {
        bool object = false;
        std::unordered_set<std::string> keys;
    };

    size_t items_ = 0;
    std::vector<Frame> frames_;

    bool item() {
        if (items_ >= max_json_items) return false;
        ++items_;
        return true;
    }

public:
    bool null() override {
        return item();
    }

    bool boolean(bool) override {
        return item();
    }

    bool number_integer(number_integer_t) override {
        return item();
    }

    bool number_unsigned(number_unsigned_t) override {
        return item();
    }

    bool number_float(number_float_t, const string_t&) override {
        return item();
    }

    bool string(string_t&) override {
        return item();
    }

    bool binary(binary_t&) override {
        return item();
    }

    bool start_object(std::size_t) override {
        if (!item() || frames_.size() >= 64) return false;
        frames_.push_back({true, {}});
        return true;
    }

    bool key(string_t& value) override {
        if (frames_.empty() || !frames_.back().object || !item()) return false;
        return frames_.back().keys.insert(value).second;
    }

    bool end_object() override {
        if (frames_.empty() || !frames_.back().object) return false;
        frames_.pop_back();
        return true;
    }

    bool start_array(std::size_t) override {
        if (!item() || frames_.size() >= 64) return false;
        frames_.push_back({false, {}});
        return true;
    }

    bool end_array() override {
        if (frames_.empty() || frames_.back().object) return false;
        frames_.pop_back();
        return true;
    }

    bool parse_error(
        std::size_t,
        const std::string&,
        const nlohmann::detail::exception&) override {
        return false;
    }
};

Result parse_response(std::string body, uint32_t expected) {
    Result out;
    JsonShape shape;
    if (!nlohmann::json::sax_parse(body, &shape)) {
        out.error = "RPC response structure is invalid";
        return out;
    }
    auto response = nlohmann::json::parse(body, nullptr, false);
    body.clear();
    if (response.is_discarded() || !response.is_object() ||
        !response.contains("jsonrpc") ||
        !response["jsonrpc"].is_string() ||
        response["jsonrpc"] != "2.0" ||
        !response.contains("id") ||
        !response_id_ok(response["id"], expected)) {
        out.error = "RPC response is invalid";
        return out;
    }
    const bool has_result = response.contains("result");
    const bool has_error = response.contains("error");
    if (has_result == has_error) {
        out.error = "RPC response is invalid";
        return out;
    }
    if (has_result) {
        out.ok = true;
        out.value = std::move(response["result"]);
        return out;
    }
    const auto& error = response["error"];
    if (!error.is_object() || !error.contains("code") ||
        !error.contains("message") || !error["message"].is_string() ||
        !error_code(error["code"], out.code)) {
        out.error = "RPC response is invalid";
        return out;
    }
    out.remote_error = true;
    out.error = safe_text(error["message"].get_ref<const std::string&>());
    return out;
}

template <typename HttpClient>
Result perform_request(
    HttpClient& client,
    const endpoint_policy::Parsed& endpoint,
    const Settings& settings,
    std::string body,
    uint32_t expected) {
    const int io_seconds = settings.read_seconds + 1;
    client.set_connection_timeout(settings.connect_seconds, 0);
    client.set_read_timeout(io_seconds, 0);
    client.set_write_timeout(settings.connect_seconds, 0);
    client.set_keep_alive(false);

    std::string received;
    received.reserve(settings.response_bytes < 64U * 1024U
        ? settings.response_bytes
        : 64U * 1024U);
    bool too_large = false;
    bool headers_ok = true;
    httplib::Request request;
    request.method = "POST";
    request.path = endpoint.target;
    request.headers = {
        {"Accept", "application/json"},
        {"Connection", "close"},
        {"Content-Type", "application/json"},
        {"User-Agent", "Octra-Webcli/0.04.10"}
    };
    request.body = std::move(body);
    request.response_handler = [&](const httplib::Response& response) {
        headers_ok = response_headers_ok(
            response,
            settings.response_bytes,
            too_large);
        return headers_ok;
    };
    request.content_receiver = [&](
        const char* data,
        size_t size,
        uint64_t,
        uint64_t) {
        if (size > settings.response_bytes - received.size()) {
            too_large = true;
            return false;
        }
        received.append(data, size);
        return true;
    };

    const auto response = client.send(request);
    if (too_large) return {false, false, {}, 0, "RPC response exceeds limit"};
    if (!headers_ok) return {false, false, {}, 0, "RPC HTTP response is invalid"};
    if (!response) return {false, false, {}, 0, "RPC connection failed"};
    return parse_response(std::move(received), expected);
}

template <typename HttpClient>
Result send_request(
    std::shared_ptr<HttpClient> client,
    endpoint_policy::Parsed endpoint,
    Settings settings,
    std::string body,
    uint32_t expected) {
    struct State {
        std::mutex mutex;
        std::condition_variable condition;
        bool done = false;
        std::chrono::steady_clock::time_point finished;
        Result result;
    };
    auto state = std::make_shared<State>();
    const auto deadline = std::chrono::steady_clock::now() +
        std::chrono::seconds(settings.read_seconds);
    std::thread worker([state,
                        client,
                        endpoint = std::move(endpoint),
                        settings,
                        body = std::move(body),
                        expected]() mutable {
        Result result;
        try {
            result = perform_request(
                *client,
                endpoint,
                settings,
                std::move(body),
                expected);
        } catch (...) {
            result.error = "RPC request failed";
        }
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            state->result = std::move(result);
            state->finished = std::chrono::steady_clock::now();
            state->done = true;
        }
        state->condition.notify_one();
    });
    std::unique_lock<std::mutex> lock(state->mutex);
    state->condition.wait_until(
        lock,
        deadline,
        [&] { return state->done; });
    if (!state->done) {
        lock.unlock();
        client->request_stop();
        worker.detach();
        return {false, false, {}, 0, "RPC request timed out", true};
    }
    const bool late = state->finished > deadline;
    auto result = std::move(state->result);
    lock.unlock();
    worker.join();
    if (late)
        return {false, false, {}, 0, "RPC request timed out", true};
    return result;
}

}

Client::Client(const std::string& url, Settings settings)
    : endpoint_(endpoint_policy::parse(endpoint_policy::rpc_url(url))), settings_(settings) {
    if (!endpoint_.ok || (!endpoint_.tls && !endpoint_policy::loopback(endpoint_.host))) {
        error_ = "RPC endpoint must use HTTPS or exact loopback HTTP";
        return;
    }
    if (settings_.response_bytes == 0 ||
        settings_.response_bytes > max_response_bytes ||
        settings_.connect_seconds < 1 || settings_.connect_seconds > 10 ||
        settings_.read_seconds < 1 || settings_.read_seconds > 120) {
        error_ = "RPC settings are invalid";
        return;
    }
    ready_ = true;
}

bool Client::ready() const {
    return ready_;
}

const std::string& Client::error() const {
    return error_;
}

const endpoint_policy::Parsed& Client::endpoint() const {
    return endpoint_;
}

Result Client::call(const std::string& method, const nlohmann::json& params) {
    if (!ready_) return {false, false, {}, 0, error_};
    if (!method_ok(method) || next_id_ == UINT32_MAX)
        return {false, false, {}, 0, "RPC request is invalid"};
    ++next_id_;
    nlohmann::json request;
    request["jsonrpc"] = "2.0";
    request["id"] = next_id_;
    request["method"] = method;
    request["params"] = params;
    std::string body;
    try {
        body = request.dump();
    } catch (...) {
        return {false, false, {}, 0, "RPC request is invalid"};
    }
    if (body.size() > max_request_bytes ||
        !program_cli::detail::json_depth_ok(body, 16))
        return {false, false, {}, 0, "RPC request exceeds limit"};
    try {
        if (endpoint_.tls) {
            auto client = std::make_shared<httplib::SSLClient>(
                endpoint_.host,
                endpoint_.port);
            if (client->ssl_context() == nullptr ||
                SSL_CTX_set_default_verify_paths(client->ssl_context()) != 1)
                return {false, false, {}, 0, "TLS trust store is unavailable"};
            client->enable_server_certificate_verification(true);
            auto result = send_request(
                client,
                endpoint_,
                settings_,
                std::move(body),
                next_id_);
            if (result.timed_out) {
                ready_ = false;
                error_ = result.error;
            }
            return result;
        }
        auto client = std::make_shared<httplib::Client>(
            endpoint_.host,
            endpoint_.port);
        auto result = send_request(
            client,
            endpoint_,
            settings_,
            std::move(body),
            next_id_);
        if (result.timed_out) {
            ready_ = false;
            error_ = result.error;
        }
        return result;
    } catch (...) {
        return {false, false, {}, 0, "RPC request failed"};
    }
}

bool same_origin(const Client& first, const Client& second) {
    const auto& a = first.endpoint();
    const auto& b = second.endpoint();
    return a.ok && b.ok &&
        a.tls == b.tls &&
        a.host == b.host &&
        a.port == b.port;
}

}