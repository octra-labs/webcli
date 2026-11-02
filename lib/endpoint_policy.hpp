// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once

#include <cctype>
#include <cstdint>
#include <string>

namespace octra::endpoint_policy {

struct Parsed {
    bool ok = false;
    bool tls = false;
    std::string host;
    uint16_t port = 0;
    std::string target;
};

inline bool parse_port(const std::string& value, uint16_t& result) {
    if (value.empty()) return false;
    uint32_t port = 0;
    for (char c : value) {
        if (c < '0' || c > '9') return false;
        const uint32_t digit = static_cast<uint32_t>(c - '0');
        if (port > (65535U - digit) / 10U) return false;
        port = port * 10U + digit;
    }
    if (port == 0) return false;
    result = static_cast<uint16_t>(port);
    return true;
}

inline bool valid_port(const std::string& value) {
    uint16_t port = 0;
    return parse_port(value, port);
}

inline bool valid_ipv4(const std::string& value) {
    size_t start = 0;
    unsigned parts = 0;
    while (start <= value.size()) {
        const size_t end = value.find('.', start);
        const size_t size = (end == std::string::npos ? value.size() : end) - start;
        if (size == 0 || size > 3 || (size > 1 && value[start] == '0'))
            return false;
        unsigned number = 0;
        for (size_t i = 0; i < size; ++i) {
            const char c = value[start + i];
            if (c < '0' || c > '9') return false;
            number = number * 10U + static_cast<unsigned>(c - '0');
        }
        if (number > 255U) return false;
        ++parts;
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return parts == 4;
}

inline int ipv6_units(const std::string& value, bool ipv4_last) {
    if (value.empty()) return 0;
    size_t start = 0;
    int units = 0;
    while (start <= value.size()) {
        const size_t end = value.find(':', start);
        const size_t size = (end == std::string::npos ? value.size() : end) - start;
        if (size == 0) return -1;
        const std::string part = value.substr(start, size);
        if (part.find('.') != std::string::npos) {
            if (!ipv4_last || end != std::string::npos || !valid_ipv4(part))
                return -1;
            units += 2;
        } else {
            if (size > 4) return -1;
            for (char c : part) {
                const bool digit = c >= '0' && c <= '9';
                const bool lower = c >= 'a' && c <= 'f';
                const bool upper = c >= 'A' && c <= 'F';
                if (!digit && !lower && !upper) return -1;
            }
            ++units;
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return units;
}

inline bool valid_ipv6(const std::string& value) {
    if (value.empty() || value.size() > 45) return false;
    const size_t split = value.find("::");
    if (split == std::string::npos)
        return ipv6_units(value, true) == 8;
    if (value.find("::", split + 2) != std::string::npos) return false;
    const int left = ipv6_units(value.substr(0, split), false);
    const int right = ipv6_units(value.substr(split + 2), true);
    return left >= 0 && right >= 0 && left + right < 8;
}

inline bool valid_dns(const std::string& value) {
    if (value.empty() || value.size() > 253 || value.back() == '.') return false;
    bool numeric = true;
    for (char c : value) {
        if ((c < '0' || c > '9') && c != '.') numeric = false;
    }
    if (numeric && value.find('.') != std::string::npos)
        return valid_ipv4(value);
    size_t start = 0;
    while (start <= value.size()) {
        const size_t end = value.find('.', start);
        const size_t size = (end == std::string::npos ? value.size() : end) - start;
        if (size == 0 || size > 63) return false;
        const auto alpha_num = [](char c) {
            return (c >= '0' && c <= '9') ||
                (c >= 'a' && c <= 'z') ||
                (c >= 'A' && c <= 'Z');
        };
        if (!alpha_num(value[start]) ||
            !alpha_num(value[start + size - 1]))
            return false;
        for (size_t i = 0; i < size; ++i) {
            const char c = value[start + i];
            if (!alpha_num(c) && c != '-' && c != '_') return false;
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return true;
}

inline Parsed parse(const std::string& url) {
    Parsed out;
    if (url.size() > 4096 || url.find('#') != std::string::npos) return out;
    size_t offset = 0;
    if (url.rfind("https://", 0) == 0) {
        out.tls = true;
        offset = 8;
    } else if (url.rfind("http://", 0) == 0) {
        offset = 7;
    } else {
        return out;
    }
    if (offset == url.size()) return out;
    for (unsigned char c : url) {
        if (c <= 0x20 || c == 0x7f || c == '\\') return out;
    }
    const size_t end = url.find_first_of("/?", offset);
    const std::string authority = url.substr(
        offset,
        end == std::string::npos ? std::string::npos : end - offset);
    if (authority.empty() || authority.find('@') != std::string::npos)
        return out;
    std::string host;
    if (authority.front() == '[') {
        const size_t close = authority.find(']');
        if (close == std::string::npos) return out;
        host = authority.substr(1, close - 1);
        if (!valid_ipv6(host)) return out;
        const std::string suffix = authority.substr(close + 1);
        if (!suffix.empty()) {
            if (suffix.front() != ':' || !parse_port(suffix.substr(1), out.port))
                return out;
        }
    } else {
        if (authority.find('[') != std::string::npos ||
            authority.find(']') != std::string::npos)
            return out;
        const size_t colon = authority.rfind(':');
        if (colon != std::string::npos) {
            if (authority.find(':') != colon || !parse_port(
                    authority.substr(colon + 1),
                    out.port))
                return out;
            host = authority.substr(0, colon);
        } else {
            host = authority;
        }
        if (!valid_dns(host)) return out;
    }
    if (host.empty()) return out;
    for (char& c : host)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (out.port == 0) out.port = out.tls ? 443 : 80;
    if (end == std::string::npos) {
        out.target = "/rpc";
    } else if (url[end] == '?') {
        out.target = "/rpc" + url.substr(end);
    } else {
        out.target = url.substr(end);
    }
    out.ok = true;
    out.host = host;
    return out;
}

inline bool http_url(const std::string& url) {
    return parse(url).ok;
}

inline std::string rpc_url(const std::string& input) {
    const auto start = input.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return {};
    std::string text = input.substr(start, input.find_last_not_of(" \t\r\n") - start + 1);
    if (text.find("://") == std::string::npos) text = "http://" + text;
    return text;
}

inline bool loopback(const std::string& host) {
    return host == "localhost" ||
        host == "127.0.0.1" ||
        host == "::1";
}

inline std::string rpc_identity(const std::string& url) {
    const auto endpoint = parse(rpc_url(url));
    if (!endpoint.ok) return url;
    const auto target = endpoint.target == "/rpc/" ? "/rpc" : endpoint.target;
    return std::string(endpoint.tls ? "https://" : "http://") + "[" + endpoint.host
        + "]:" + std::to_string(endpoint.port) + target;
}

inline bool secure_rpc(const std::string& url) {
    const Parsed parsed = parse(rpc_url(url));
    return parsed.ok && (parsed.tls || loopback(parsed.host));
}

inline std::string history_url(const std::string& url) {
    const auto normalized = rpc_url(url);
    const Parsed endpoint = parse(normalized);
    if (endpoint.ok && endpoint.tls && endpoint.port == 443 &&
        endpoint.host == "devnet.octrascan.io" &&
        (endpoint.target == "/rpc" || endpoint.target == "/rpc/"))
        return "https://devnet.octrascan.io/scanner/rpc";
    return normalized;
}

}