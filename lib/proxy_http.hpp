// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
// lambda0xE
// Arthur Edelstein
// Denis CMIX

#pragma once

#include "endpoint_policy.hpp"
#include "rpc_io.hpp"

namespace octra {

inline RpcBody proxy_http(const std::string& url, const std::string& path,
    const std::string& body, const std::string& method) {
    const auto normalized = endpoint_policy::rpc_url(url);
    const auto endpoint = endpoint_policy::parse(normalized);
    if (!endpoint.ok || normalized.find('?') != std::string::npos)
        return {{}, "invalid service URL"};
    const auto slash = normalized.find('/', normalized.find("://") + 3);
    std::string prefix = slash == std::string::npos ? "" : endpoint.target;
    if (!prefix.empty() && prefix.back() == '/') prefix.pop_back();
    const auto target = prefix + path;
    if (endpoint.tls) {
        httplib::SSLClient client(endpoint.host, endpoint.port);
        if (client.ssl_context()) SSL_CTX_set_default_verify_paths(client.ssl_context());
        client.enable_server_certificate_verification(true);
        return rpc_post(client, target, body, 30, 8 * 1024 * 1024, method, true);
    }
    httplib::Client client(endpoint.host, endpoint.port);
    return rpc_post(client, target, body, 30, 8 * 1024 * 1024, method, true);
}

}