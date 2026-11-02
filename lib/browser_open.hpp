// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once

#include <cstdlib>
#include <string>
#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#include <io.h>
#else
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cerrno>
#include <thread>
extern char** environ;
#endif

namespace octra {

inline bool browser_requested() {
    const char* setting = std::getenv("OCTRA_OPEN_BROWSER");
    if (setting) return std::string(setting) == "1";
#ifdef _WIN32
    return _isatty(1) != 0;
#else
    return isatty(STDOUT_FILENO) != 0;
#endif
}

inline bool open_browser(const std::string& url) {
#ifdef _WIN32
    return reinterpret_cast<INT_PTR>(ShellExecuteA(nullptr, "open", url.c_str(),
        nullptr, nullptr, SW_SHOWNORMAL)) > 32;
#else
#ifdef __APPLE__
    const char* command = "/usr/bin/open";
#else
    const char* command = "xdg-open";
#endif
    char* args[] = {const_cast<char*>(command), const_cast<char*>(url.c_str()), nullptr};
    pid_t pid;
    if (posix_spawnp(&pid, command, nullptr, nullptr, args, environ) != 0) return false;
    std::thread([pid] {
        int status;
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    }).detach();
    return true;
#endif
}

}