// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
// lambda0xE
// Arthur Edelstein
// Denis CMIX

#include "program_terminal.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <utility>

#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <csignal>
#include <fcntl.h>
#include <pthread.h>
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>
#endif

namespace octra::program_cli {

namespace {

void erase_bytes(void* value, std::size_t size) noexcept {
    volatile unsigned char* cursor =
        static_cast<volatile unsigned char*>(value);
    while (size > 0) {
        *cursor = 0;
        ++cursor;
        --size;
    }
}

template <typename T>
class ScrubbedValue final {
public:
    ScrubbedValue() noexcept = default;
    ~ScrubbedValue() {
        erase_bytes(&value_, sizeof(value_));
    }
    ScrubbedValue(const ScrubbedValue&) = delete;
    ScrubbedValue& operator=(const ScrubbedValue&) = delete;

    T& get() noexcept {
        return value_;
    }

private:
    T value_{};
};

class PinBytes final {
public:
    ~PinBytes() {
        clear();
    }

    bool push(const char* value, std::size_t size) noexcept {
        if (size > TerminalPin::max_size - size_) return false;
        std::copy_n(value, size, bytes_.data() + size_);
        size_ += size;
        return true;
    }

    void pop_utf8() noexcept {
        if (size_ == 0) return;
        --size_;
        while (size_ > 0 &&
               (static_cast<unsigned char>(bytes_[size_]) & 0xc0U) == 0x80U) {
            --size_;
        }
        erase_bytes(bytes_.data() + size_, bytes_.size() - size_);
    }

    std::string_view view() const noexcept {
        return std::string_view(bytes_.data(), size_);
    }

    bool empty() const noexcept {
        return size_ == 0;
    }

    void clear() noexcept {
        erase_bytes(bytes_.data(), bytes_.size());
        size_ = 0;
    }

private:
    std::array<char, TerminalPin::max_size> bytes_{};
    std::size_t size_ = 0;
};

class ActiveInput final {
public:
    ActiveInput() noexcept : held_(!active_.test_and_set()) {}

    ~ActiveInput() {
        if (held_) active_.clear();
    }

    bool held() const noexcept {
        return held_;
    }

private:
    static std::atomic_flag active_;
    bool held_ = false;
};

std::atomic_flag ActiveInput::active_ = ATOMIC_FLAG_INIT;

TerminalPinResult failed(
    std::string error,
    bool interrupted = false,
    int delivered_signal = 0) {
    TerminalPinResult result;
    result.interrupted = interrupted;
    result.delivered_signal = delivered_signal;
    result.error = std::move(error);
    return result;
}

#ifdef _WIN32

volatile LONG console_interrupt = 0;
volatile LONG console_release = 0;
volatile LONG console_handlers = 0;
std::atomic_flag console_mode_gate = ATOMIC_FLAG_INIT;
std::atomic<HANDLE> console_mode_input{INVALID_HANDLE_VALUE};
std::atomic<DWORD> console_mode_saved{0};
std::atomic<bool> console_mode_active{false};

LONG console_interrupt_code() noexcept {
    return InterlockedCompareExchange(&console_interrupt, 0, 0);
}

bool acquire_console_mode(DWORD limit) noexcept {
    for (DWORD waited = 0; waited < limit; waited += 5) {
        if (!console_mode_gate.test_and_set(std::memory_order_acquire))
            return true;
        Sleep(5);
    }
    return false;
}

void release_console_mode() noexcept {
    console_mode_gate.clear(std::memory_order_release);
}

bool restore_console_echo(DWORD limit) noexcept {
    if (!acquire_console_mode(limit)) return false;
    bool ok = true;
    if (console_mode_active.load(std::memory_order_relaxed)) {
        const HANDLE input =
            console_mode_input.load(std::memory_order_relaxed);
        const DWORD saved =
            console_mode_saved.load(std::memory_order_relaxed);
        ok = input != nullptr && input != INVALID_HANDLE_VALUE &&
            SetConsoleMode(input, saved) != 0;
        if (ok)
            console_mode_active.store(false, std::memory_order_release);
    }
    release_console_mode();
    return ok;
}

BOOL WINAPI terminal_control(DWORD event) {
    if (event != CTRL_C_EVENT && event != CTRL_BREAK_EVENT &&
        event != CTRL_CLOSE_EVENT && event != CTRL_LOGOFF_EVENT &&
        event != CTRL_SHUTDOWN_EVENT) {
        return FALSE;
    }
    InterlockedIncrement(&console_handlers);
    InterlockedCompareExchange(
        &console_interrupt,
        static_cast<LONG>(event) + 1,
        0);
    bool mode_ok = false;
    for (DWORD waited = 0; waited < 2'000; waited += 10) {
        if (!mode_ok) mode_ok = restore_console_echo(10);
        if (mode_ok &&
            InterlockedCompareExchange(&console_release, 0, 0) != 0)
            break;
        Sleep(10);
    }
    if (!mode_ok) static_cast<void>(restore_console_echo(100));
    InterlockedDecrement(&console_handlers);
    return FALSE;
}

class ConsoleHandle final {
public:
    ConsoleHandle(const wchar_t* name, DWORD access) noexcept
        : value_(CreateFileW(name, access, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             nullptr, OPEN_EXISTING, 0, nullptr)) {}

    ~ConsoleHandle() {
        if (valid()) CloseHandle(value_);
    }

    bool valid() const noexcept {
        return value_ != INVALID_HANDLE_VALUE;
    }

    HANDLE get() const noexcept {
        return value_;
    }

private:
    HANDLE value_ = INVALID_HANDLE_VALUE;
};

class ConsoleControl final {
public:
    bool install() noexcept {
        if (InterlockedCompareExchange(&console_handlers, 0, 0) != 0 ||
            console_mode_active.load(std::memory_order_acquire))
            return false;
        InterlockedExchange(&console_release, 0);
        InterlockedExchange(&console_interrupt, 0);
        installed_ = SetConsoleCtrlHandler(terminal_control, TRUE) != 0;
        return installed_;
    }

    bool restore() noexcept {
        InterlockedExchange(&console_release, 1);
        bool ok = true;
        if (installed_) {
            ok = SetConsoleCtrlHandler(terminal_control, FALSE) != 0;
            if (ok) installed_ = false;
        }
        for (DWORD waited = 0; waited < 2'500; waited += 5) {
            if (InterlockedCompareExchange(&console_handlers, 0, 0) == 0)
                return ok;
            Sleep(5);
        }
        return false;
    }

    ~ConsoleControl() {
        restore();
    }

private:
    bool installed_ = false;
};

class ConsoleMode final {
public:
    explicit ConsoleMode(HANDLE input) noexcept : input_(input) {}

    bool disable_echo() noexcept {
        if (!GetConsoleMode(input_, &saved_)) return false;
        if (!acquire_console_mode(2'500)) return false;
        if (console_interrupt_code() != 0) {
            release_console_mode();
            return false;
        }
        console_mode_input.store(input_, std::memory_order_relaxed);
        console_mode_saved.store(saved_, std::memory_order_relaxed);
        const DWORD next = saved_ & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT);
        changed_ = SetConsoleMode(input_, next) != 0;
        console_mode_active.store(changed_, std::memory_order_release);
        release_console_mode();
        return changed_ && FlushConsoleInputBuffer(input_) != 0;
    }

    bool restore() noexcept {
        if (!changed_) return true;
        const bool mode_ok = restore_console_echo(2'500);
        const bool input_ok = FlushConsoleInputBuffer(input_) != 0;
        if (input_ok && mode_ok) changed_ = false;
        return input_ok && mode_ok;
    }

    ~ConsoleMode() {
        if (!restore()) restore();
    }

private:
    HANDLE input_ = INVALID_HANDLE_VALUE;
    DWORD saved_ = 0;
    bool changed_ = false;
};

bool write_console(HANDLE output, const wchar_t* value, DWORD size) noexcept {
    DWORD written = 0;
    return WriteConsoleW(output, value, size, &written, nullptr) != 0 &&
           written == size;
}

enum class LineState {
    ready,
    interrupted,
    too_long,
    invalid,
    read_error
};

enum class UnitState {
    accepted,
    too_long,
    invalid
};

UnitState push_console_unit(
    wchar_t unit,
    WORD repeats,
    wchar_t& high,
    PinBytes& bytes) noexcept {
    for (WORD repeat = 0; repeat < repeats; ++repeat) {
        if (unit >= 0xd800 && unit <= 0xdbff) {
            if (high != 0) return UnitState::invalid;
            high = unit;
            continue;
        }
        if (unit >= 0xdc00 && unit <= 0xdfff) {
            if (high == 0) return UnitState::invalid;
        } else if (high != 0) {
            return UnitState::invalid;
        }

        ScrubbedValue<std::array<wchar_t, 2>> units_value;
        auto& units = units_value.get();
        units = {high == 0 ? unit : high, high == 0 ? wchar_t{0} : unit};
        const int unit_count = high == 0 ? 1 : 2;
        ScrubbedValue<std::array<char, 4>> encoded_value;
        auto& encoded = encoded_value.get();
        const int encoded_size = WideCharToMultiByte(
            CP_UTF8, WC_ERR_INVALID_CHARS, units.data(), unit_count,
            encoded.data(),
            static_cast<int>(sizeof(encoded)), nullptr, nullptr);
        high = 0;
        if (encoded_size <= 0) return UnitState::invalid;
        if (!bytes.push(encoded.data(), static_cast<std::size_t>(encoded_size)))
            return UnitState::too_long;
    }
    return UnitState::accepted;
}

LineState read_console_line(HANDLE input, PinBytes& bytes) noexcept {
    ScrubbedValue<wchar_t> high_value;
    wchar_t& high = high_value.get();
    while (console_interrupt_code() == 0) {
        const DWORD wait = WaitForSingleObject(input, 100);
        if (wait == WAIT_TIMEOUT) continue;
        if (wait != WAIT_OBJECT_0) return LineState::read_error;

        ScrubbedValue<INPUT_RECORD> record_value;
        INPUT_RECORD& record = record_value.get();
        DWORD read = 0;
        if (!ReadConsoleInputW(input, &record, 1, &read) || read != 1)
            return LineState::read_error;
        if (record.EventType != KEY_EVENT ||
            !record.Event.KeyEvent.bKeyDown)
            continue;

        const KEY_EVENT_RECORD& key = record.Event.KeyEvent;
        if (key.wVirtualKeyCode == VK_RETURN) {
            if (high != 0) return LineState::invalid;
            return LineState::ready;
        }
        if (key.wVirtualKeyCode == VK_BACK) {
            const WORD repeats = key.wRepeatCount == 0 ? 1 : key.wRepeatCount;
            for (WORD repeat = 0; repeat < repeats; ++repeat) {
                if (high != 0) high = 0;
                else bytes.pop_utf8();
            }
            continue;
        }

        const wchar_t& unit = key.uChar.UnicodeChar;
        if (unit == 0) continue;
        const WORD repeats = key.wRepeatCount == 0 ? 1 : key.wRepeatCount;
        const UnitState state = push_console_unit(unit, repeats, high, bytes);
        if (state == UnitState::invalid) return LineState::invalid;
        if (state == UnitState::too_long) return LineState::too_long;
    }
    return LineState::interrupted;
}

#else

std::atomic<int> terminal_signal_number{0};
static_assert(std::atomic<int>::is_always_lock_free);

int caught_signal() noexcept {
    return terminal_signal_number.load(std::memory_order_relaxed);
}

void terminal_signal(int signal_number) {
    int empty = 0;
    terminal_signal_number.compare_exchange_strong(
        empty,
        signal_number,
        std::memory_order_relaxed,
        std::memory_order_relaxed);
}

class TerminalFd final {
public:
    TerminalFd() noexcept {
        int flags = O_RDWR | O_NOCTTY | O_NONBLOCK;
#ifdef O_CLOEXEC
        flags |= O_CLOEXEC;
#endif
        value_ = open("/dev/tty", flags);
        if (value_ < 0) return;
        const int current = fcntl(value_, F_GETFD);
        if (current < 0 || fcntl(value_, F_SETFD, current | FD_CLOEXEC) < 0) {
            close(value_);
            value_ = -1;
        }
    }

    ~TerminalFd() {
        if (value_ >= 0) close(value_);
    }

    bool valid() const noexcept {
        return value_ >= 0 && isatty(value_) == 1;
    }

    int get() const noexcept {
        return value_;
    }

private:
    int value_ = -1;
};

constexpr std::array<int, 7> terminal_signals = {
    SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGTSTP, SIGTTIN, SIGTTOU
};

class SignalState final {
public:
    bool install() noexcept {
        terminal_signal_number.store(0, std::memory_order_relaxed);
        struct sigaction next{};
        next.sa_handler = terminal_signal;
        sigemptyset(&next.sa_mask);
        next.sa_flags = 0;
        for (std::size_t i = 0; i < terminal_signals.size(); ++i) {
            if (sigaction(terminal_signals[i], &next, &saved_[i]) != 0) {
                restore();
                return false;
            }
            installed_[i] = true;
        }
        return true;
    }

    bool restore() noexcept {
        bool ok = true;
        for (std::size_t i = terminal_signals.size(); i > 0; --i) {
            const std::size_t index = i - 1;
            if (!installed_[index]) continue;
            if (sigaction(terminal_signals[index], &saved_[index], nullptr) !=
                0) {
                ok = false;
            } else {
                installed_[index] = false;
            }
        }
        return ok;
    }

    bool deliver(int signal_number) noexcept {
        if (signal_number == 0 || delivered_) return true;
        if (kill(getpid(), signal_number) != 0) return false;
        delivered_ = true;
        return true;
    }

    ~SignalState() {
        bool restored = restore();
        if (!restored) restored = restore();
        if (restored && !delivered_ && caught_signal() != 0)
            static_cast<void>(deliver(caught_signal()));
    }

private:
    std::array<struct sigaction, terminal_signals.size()> saved_{};
    std::array<bool, terminal_signals.size()> installed_{};
    bool delivered_ = false;
};

bool set_terminal_mode(
    int fd,
    int action,
    const struct termios& value,
    bool& applied) noexcept {
    sigset_t set{};
    sigset_t saved{};
    sigemptyset(&set);
    sigaddset(&set, SIGTTOU);
    if (pthread_sigmask(SIG_BLOCK, &set, &saved) != 0) {
        applied = false;
        return false;
    }

    int status = 0;
    do {
        status = tcsetattr(fd, action, &value);
    } while (status != 0 && errno == EINTR && caught_signal() == 0);
    applied = status == 0;

    const bool mask_ok =
        pthread_sigmask(SIG_SETMASK, &saved, nullptr) == 0;
    return applied && mask_ok;
}

bool clear_terminal_input(int fd) noexcept {
    sigset_t set{};
    sigset_t saved{};
    sigemptyset(&set);
    sigaddset(&set, SIGTTOU);
    if (pthread_sigmask(SIG_BLOCK, &set, &saved) != 0) return false;

    int status = 0;
    do {
        status = tcflush(fd, TCIFLUSH);
    } while (status != 0 && errno == EINTR && caught_signal() == 0);

    const bool mask_ok =
        pthread_sigmask(SIG_SETMASK, &saved, nullptr) == 0;
    return status == 0 && mask_ok;
}

class TerminalMode final {
public:
    explicit TerminalMode(int fd) noexcept : fd_(fd) {}

    bool disable_echo() noexcept {
        if (tcgetattr(fd_, &saved_) != 0) return false;
        struct termios next = saved_;
        next.c_lflag &= static_cast<tcflag_t>(~(ECHO | ECHONL));
        bool applied = false;
        const bool mode_ok =
            set_terminal_mode(fd_, TCSANOW, next, applied);
        changed_ = applied;
        if (!mode_ok) return false;
        return clear_terminal_input(fd_);
    }

    bool restore() noexcept {
        if (!changed_) return true;
        const bool input_ok = clear_terminal_input(fd_);
        bool applied = false;
        const bool mode_ok =
            set_terminal_mode(fd_, TCSANOW, saved_, applied);
        if (applied) changed_ = false;
        return input_ok && mode_ok;
    }

    ~TerminalMode() {
        if (!restore()) restore();
    }

private:
    int fd_ = -1;
    struct termios saved_{};
    bool changed_ = false;
};

bool write_all(int fd, std::string_view value) noexcept {
    std::size_t offset = 0;
    while (offset < value.size()) {
        const ssize_t written = write(fd, value.data() + offset,
                                      value.size() - offset);
        if (written > 0) {
            offset += static_cast<std::size_t>(written);
            continue;
        }
        if (written < 0 && errno == EINTR && caught_signal() == 0)
            continue;
        return false;
    }
    return true;
}

enum class LineState {
    ready,
    interrupted,
    eof,
    too_long,
    read_error
};

LineState read_terminal_line(int fd, PinBytes& bytes) noexcept {
    if (fd < 0 || fd >= FD_SETSIZE) return LineState::read_error;
    for (;;) {
        if (caught_signal() != 0) return LineState::interrupted;
        fd_set watched;
        FD_ZERO(&watched);
        FD_SET(fd, &watched);
        struct timeval wait{0, 100'000};
        int ready = 0;
        do {
            ready = select(fd + 1, &watched, nullptr, nullptr, &wait);
        } while (ready < 0 && errno == EINTR && caught_signal() == 0);
        if (caught_signal() != 0) return LineState::interrupted;
        if (ready == 0) continue;
        if (ready < 0 || !FD_ISSET(fd, &watched)) return LineState::read_error;
        char value = 0;
        const ssize_t read_size = read(fd, &value, 1);
        if (read_size == 1) {
            if (value == '\n') {
                erase_bytes(&value, sizeof(value));
                return LineState::ready;
            }
            if (!bytes.push(&value, 1)) {
                erase_bytes(&value, sizeof(value));
                return LineState::too_long;
            }
            erase_bytes(&value, sizeof(value));
            continue;
        }
        erase_bytes(&value, sizeof(value));
        if (read_size == 0) return LineState::eof;
        if (errno == EINTR) {
            if (caught_signal() != 0) return LineState::interrupted;
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
        return LineState::read_error;
    }
}

#endif

}

TerminalPin::~TerminalPin() {
    clear();
}

TerminalPin::TerminalPin(TerminalPin&& source) noexcept {
    assign(source.view());
    source.clear();
}

TerminalPin& TerminalPin::operator=(TerminalPin&& source) noexcept {
    if (this == &source) return *this;
    clear();
    assign(source.view());
    source.clear();
    return *this;
}

std::string_view TerminalPin::view() const noexcept {
    return std::string_view(bytes_.data(), size_);
}

std::size_t TerminalPin::size() const noexcept {
    return size_;
}

bool TerminalPin::empty() const noexcept {
    return size_ == 0;
}

void TerminalPin::clear() noexcept {
    erase_bytes(bytes_.data(), bytes_.size());
    size_ = 0;
}

void TerminalPin::assign(std::string_view value) noexcept {
    clear();
    if (value.size() > max_size) return;
    std::copy(value.begin(), value.end(), bytes_.begin());
    size_ = value.size();
}

TerminalPin program_terminal::detail::make_pin(
    std::string_view value) noexcept {
    TerminalPin pin;
    pin.assign(value);
    return pin;
}

TerminalPinResult read_terminal_pin() {
    ActiveInput active;
    if (!active.held()) return failed("terminal PIN entry already active");

#ifdef _WIN32
    ConsoleHandle input(L"CONIN$", GENERIC_READ | GENERIC_WRITE);
    ConsoleHandle output(L"CONOUT$", GENERIC_WRITE);
    if (!input.valid() || !output.valid())
        return failed("controlling terminal unavailable");

    ConsoleControl control;
    if (!control.install()) return failed("terminal signal setup failed");

    ConsoleMode mode(input.get());
    if (!mode.disable_echo()) return failed("terminal PIN setup failed");
    if (!write_console(output.get(), L"PIN: ", 5))
        return failed("terminal output failed");

    PinBytes bytes;
    LineState state = read_console_line(input.get(), bytes);
    const LONG interrupt = console_interrupt_code();
    if (interrupt != 0) {
        state = LineState::interrupted;
        bytes.clear();
    }
    const bool newline_ok = interrupt != 0 ||
        write_console(output.get(), L"\r\n", 2);
    bool mode_ok = mode.restore();
    if (!mode_ok) mode_ok = mode.restore();
    if (console_interrupt_code() != 0) {
        state = LineState::interrupted;
        bytes.clear();
    }
    if (!mode_ok)
        return failed(
            "terminal mode restore failed",
            console_interrupt_code() != 0);
    const bool control_ok = control.restore();
    if (console_interrupt_code() != 0) {
        state = LineState::interrupted;
        bytes.clear();
    }
    if (!control_ok)
        return failed(
            "terminal signal restore failed",
            console_interrupt_code() != 0);
    if (state == LineState::interrupted)
        return failed("terminal PIN entry interrupted", true);
    if (state == LineState::too_long)
        return failed("terminal PIN exceeds 64 bytes");
    if (state == LineState::invalid)
        return failed("terminal PIN encoding is invalid");
    if (state == LineState::read_error)
        return failed("terminal PIN read failed");
    if (!newline_ok) return failed("terminal output failed");
#else
    TerminalFd terminal;
    if (!terminal.valid()) return failed("controlling terminal unavailable");

    SignalState signals;
    if (!signals.install())
        return failed(
            "terminal signal setup failed",
            caught_signal() != 0,
            caught_signal());

    TerminalMode mode(terminal.get());
    if (!mode.disable_echo())
        return failed(
            "terminal PIN setup failed",
            caught_signal() != 0,
            caught_signal());
    if (!write_all(terminal.get(), "PIN: "))
        return failed(
            "terminal output failed",
            caught_signal() != 0,
            caught_signal());

    PinBytes bytes;
    LineState state = read_terminal_line(terminal.get(), bytes);
    int signal_number = caught_signal();
    if (signal_number != 0) {
        state = LineState::interrupted;
        bytes.clear();
    }
    const bool newline_ok = signal_number != 0 ||
        write_all(terminal.get(), "\n");
    bool mode_ok = mode.restore();
    if (!mode_ok) mode_ok = mode.restore();
    signal_number = caught_signal();
    if (signal_number != 0) {
        state = LineState::interrupted;
        bytes.clear();
    }
    bool signals_ok = signals.restore();
    if (!signals_ok) signals_ok = signals.restore();
    signal_number = caught_signal();
    if (signal_number != 0) {
        state = LineState::interrupted;
        bytes.clear();
    }
    if (!mode_ok)
        return failed(
            "terminal mode restore failed",
            signal_number != 0,
            signal_number);
    if (!signals_ok)
        return failed(
            "terminal signal restore failed",
            signal_number != 0,
            signal_number);
    if (state == LineState::interrupted) {
        if (!signals.deliver(signal_number))
            return failed(
                "terminal signal delivery failed",
                true,
                signal_number);
        return failed(
            "terminal PIN entry interrupted",
            true,
            signal_number);
    }
    if (state == LineState::eof)
        return failed("terminal PIN input closed");
    if (state == LineState::too_long)
        return failed("terminal PIN exceeds 64 bytes");
    if (state == LineState::read_error)
        return failed("terminal PIN read failed");
    if (!newline_ok) return failed("terminal output failed");
#endif

    if (bytes.empty()) return failed("terminal PIN is required");
    TerminalPinResult result;
    result.ok = true;
    result.pin = program_terminal::detail::make_pin(bytes.view());
    return result;
}

}