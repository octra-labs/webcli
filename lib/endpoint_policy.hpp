#pragma once

#include <cctype>
#include <cstdint>
#include <string>

namespace octra::endpoint_policy {

struct Parsed {
    bool ok = false;
    bool tls = false;
    std::string host;
};

inline bool valid_port(const std::string& value) {
    if (value.empty()) return false;
    uint32_t port = 0;
    for (char c : value) {
        if (c < '0' || c > '9') return false;
        port = port * 10 + static_cast<uint32_t>(c - '0');
        if (port > 65535) return false;
    }
    return port > 0;
}

inline Parsed parse(const std::string& url) {
    Parsed out;
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
        if (c <= 0x20 || c == 0x7f) return out;
    }
    const size_t end = url.find_first_of("/?#", offset);
    const std::string authority = url.substr(
        offset,
        end == std::string::npos ? std::string::npos : end - offset);
    if (authority.empty() || authority.find('@') != std::string::npos)
        return out;
    std::string host;
    if (authority.front() == '[') {
        const size_t close = authority.find(']');
        if (close == std::string::npos) return out;
        host = authority.substr(0, close + 1);
        const std::string tail = authority.substr(close + 1);
        if (!tail.empty() &&
            (tail.front() != ':' || !valid_port(tail.substr(1))))
            return out;
    } else {
        const size_t colon = authority.rfind(':');
        if (colon != std::string::npos) {
            if (authority.find(':') != colon ||
                !valid_port(authority.substr(colon + 1)))
                return out;
            host = authority.substr(0, colon);
        } else {
            host = authority;
        }
    }
    if (host.empty()) return out;
    for (char& c : host)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    out.ok = true;
    out.host = host;
    return out;
}

inline bool http_url(const std::string& url) {
    return parse(url).ok;
}

inline bool loopback(const std::string& host) {
    return host == "localhost" ||
        host == "127.0.0.1" ||
        host == "[::1]";
}

inline bool secure_rpc(const std::string& url) {
    const Parsed parsed = parse(url);
    return parsed.ok && (parsed.tls || loopback(parsed.host));
}

}