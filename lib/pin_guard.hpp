// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once

#include <array>
#include <algorithm>
#include <chrono>
#include <mutex>
#include <string>
#include <stdexcept>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace octra {

class PinRefused : public std::runtime_error {
public:
    PinRefused() : std::runtime_error("PIN refused") {}
};

class SessionPin {
    std::array<unsigned char, 16> salt_{};
    std::array<unsigned char, 32> hash_{};
    bool ready_ = false;

    bool derive(const std::string& pin, unsigned char* out) const {
        return !pin.empty() && pin.size() <= 1024
            && PKCS5_PBKDF2_HMAC(pin.data(), static_cast<int>(pin.size()),
                salt_.data(), salt_.size(), 600000, EVP_sha256(), hash_.size(), out) == 1;
    }
public:
    SessionPin() = default;
    SessionPin(const SessionPin&) = delete;
    SessionPin& operator=(const SessionPin&) = delete;
    void exchange(SessionPin& other) noexcept {
        salt_.swap(other.salt_);
        hash_.swap(other.hash_);
        std::swap(ready_, other.ready_);
    }
    ~SessionPin() { clear(); }
    bool is_set() const { return ready_; }
    void clear() {
        OPENSSL_cleanse(hash_.data(), hash_.size());
        OPENSSL_cleanse(salt_.data(), salt_.size());
        ready_ = false;
    }
    void set(const std::string& pin) {
        clear();
        if (RAND_bytes(salt_.data(), salt_.size()) != 1 || !derive(pin, hash_.data())) {
            clear();
            throw std::runtime_error("PIN verifier unavailable");
        }
        ready_ = true;
    }
    bool matches(const std::string& pin) const {
        std::array<unsigned char, 32> hash{};
        const bool ok = ready_ && derive(pin, hash.data())
            && CRYPTO_memcmp(hash.data(), hash_.data(), hash.size()) == 0;
        OPENSSL_cleanse(hash.data(), hash.size());
        return ok;
    }
};

enum class PinResult { accepted, refused, wait };

struct PinWait {
    unsigned seconds;
    bool checking;
};

template<class Clock> class PinBudget {
    std::mutex mutex_;
    unsigned failures_ = 0;
    unsigned rounds_ = 0;
    bool active_ = false;
    typename Clock::time_point next_{};

    void finish(bool accepted) {
        std::lock_guard<std::mutex> lock(mutex_);
        active_ = false;
        if (accepted) return;
        if (++failures_ >= 5) {
            failures_ = 0;
            const unsigned seconds = std::min(900U, 30U << std::min(rounds_, 5U));
            next_ = Clock::now() + std::chrono::seconds(seconds);
            if (rounds_ < 5) ++rounds_;
        }
    }
public:
    PinWait wait_state() {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto now = Clock::now();
        const auto seconds = now < next_
            ? std::chrono::ceil<std::chrono::seconds>(next_ - now).count() : 0;
        return {static_cast<unsigned>(seconds), active_};
    }

    template<class Check> PinResult verify(Check check) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (active_ || Clock::now() < next_) return PinResult::wait;
            active_ = true;
        }
        try {
            const bool accepted = check();
            finish(accepted);
            return accepted ? PinResult::accepted : PinResult::refused;
        } catch (const PinRefused&) {
            finish(false);
            return PinResult::refused;
        } catch (...) {
            finish(true);
            throw;
        }
    }
};

using PinAttempts = PinBudget<std::chrono::steady_clock>;

}