// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <fcntl.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#ifdef __linux__
#include <sys/syscall.h>
#include <linux/fs.h>
#endif
#endif
#include "../crypto_utils.hpp"

namespace octra {

enum class WalletWrite { create, replace };

inline std::string wallet_file_nonce() {
    uint8_t bytes[16];
    random_bytes(bytes, sizeof(bytes));
    return hex_encode(bytes, sizeof(bytes));
}

inline void write_wallet_file(const std::string& path, const uint8_t* bytes,
    size_t size, WalletWrite mode) {
    const auto staged = path + "." + wallet_file_nonce() + ".next";
#ifdef _WIN32
    int fd = _open(staged.c_str(), _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY,
        _S_IREAD | _S_IWRITE);
#else
    int fd = open(staged.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
#endif
    if (fd < 0) throw std::runtime_error("cannot create wallet staging file");
    try {
        size_t offset = 0;
        while (offset < size) {
#ifdef _WIN32
            const auto written = _write(fd, bytes + offset,
                static_cast<unsigned>(std::min<size_t>(size - offset, 1048576)));
#else
            const auto written = write(fd, bytes + offset, size - offset);
#endif
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) throw std::runtime_error("cannot write wallet file");
            offset += static_cast<size_t>(written);
        }
#ifdef _WIN32
        if (_commit(fd) != 0) throw std::runtime_error("cannot sync wallet file");
        const auto closed = _close(fd);
#else
        if (fsync(fd) != 0) throw std::runtime_error("cannot sync wallet file");
        const auto closed = close(fd);
#endif
        fd = -1;
        if (closed != 0) throw std::runtime_error("cannot close wallet file");
#ifdef _WIN32
        const auto flags = MOVEFILE_WRITE_THROUGH
            | (mode == WalletWrite::replace ? MOVEFILE_REPLACE_EXISTING : 0);
        if (!MoveFileExA(staged.c_str(), path.c_str(), flags))
            throw std::runtime_error("wallet publication refused");
#else
        bool published = false;
        if (mode == WalletWrite::replace) {
            published = rename(staged.c_str(), path.c_str()) == 0;
        } else {
#ifdef __APPLE__
            published = renamex_np(staged.c_str(), path.c_str(), RENAME_EXCL) == 0;
#elif defined(__linux__) && defined(SYS_renameat2)
            published = syscall(SYS_renameat2, AT_FDCWD, staged.c_str(),
                AT_FDCWD, path.c_str(), RENAME_NOREPLACE) == 0;
#endif
            if (!published && link(staged.c_str(), path.c_str()) == 0) {
                published = true;
                unlink(staged.c_str());
            }
        }
        if (!published) throw std::runtime_error("wallet publication refused");
#endif
    } catch (...) {
        if (fd >= 0) {
#ifdef _WIN32
            _close(fd);
#else
            close(fd);
#endif
        }
        std::remove(staged.c_str());
        throw;
    }
}

}