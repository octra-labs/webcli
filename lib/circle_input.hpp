// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once

#include "httplib.h"
#include "json_shape.hpp"
#include "circle_verifier_policy.hpp"

namespace octra {

inline bool circle_body_headers(const httplib::Request& request, httplib::Response& response) {
    if (request.path.rfind("/api/", 0) != 0) return true;
    const auto refuse = [&](int status) {
        response.status = status;
        response.set_header("Connection", "close");
        response.set_content("{\"error\":\"invalid request body framing or size\"}", "application/json");
        return false;
    };
    if (request.has_header("Transfer-Encoding")) return refuse(400);
    const auto& path = request.path;
    const bool serde = path == "/api/circle/fhe/serialize_cipher"
        || path == "/api/circle/fhe/deserialize_cipher" || path == "/api/circle/fhe/commit";
    const bool verify = path == "/api/circle/fhe/verify_zero" || path == "/api/circle/fhe/verify_bound";
    if (!serde && !verify) return true;
    if (request.get_header_value_count("Content-Length") != 1) return refuse(400);
    const auto text = request.get_header_value("Content-Length");
    size_t size = 0;
    for (const auto ch : text) {
        if (ch < '0' || ch > '9') return refuse(400);
        size = size * 10 + static_cast<unsigned>(ch - '0');
        if (size > (serde ? 128U : 256U) * 1024) return refuse(413);
    }
    return text.empty() ? refuse(400) : true;
}

inline bool circle_cipher_request(const httplib::Request& request, httplib::Response& response) {
    if (request.method != "POST") return true;
    const auto& path = request.path;
    if (path != "/api/circle/fhe/serialize_cipher" && path != "/api/circle/fhe/deserialize_cipher"
        && path != "/api/circle/fhe/commit") return true;
    const auto refuse = [&](int status) {
        response.status = status;
        response.set_content("{\"error\":\"circle cipher input exceeds resource policy or is invalid\"}", "application/json");
        return false;
    };
    if (request.body.size() > 128 * 1024) return refuse(413);
    JsonShape shape(1024);
    if (!nlohmann::json::sax_parse(request.body, &shape)) return refuse(400);
    const auto body = nlohmann::json::parse(request.body);
    const auto field = path == "/api/circle/fhe/deserialize_cipher" ? "serialized_cipher" : "ciphertext";
    if (!body.is_object() || !body.contains(field) || !body[field].is_string()) return refuse(400);
    if (!circle_verifier_policy::ciphertext_size_allowed(body[field].get_ref<const std::string&>())) return refuse(413);
    return true;
}

}