// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
// lambda0xE
// Arthur Edelstein
// Denis CMIX

#include "program_wallet.hpp"

#include <climits>
#include <cstring>
#include <memory>
#include <set>
#include <string_view>
#include <utility>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "../crypto_utils.hpp"
#include "limited_file.hpp"
#include "program_cli_detail.hpp"

namespace octra::program_cli {

namespace {

inline constexpr size_t max_wallet_bytes = 65'536;
inline constexpr size_t max_wallet_depth = 8;
inline constexpr size_t max_wallet_items = 4'096;

template <typename Value>
class WipeValue {
    Value& value_;

public:
    explicit WipeValue(Value& value) : value_(value) {}
    ~WipeValue() {
        if (!value_.empty()) secure_zero(value_.data(), value_.size());
    }
    WipeValue(const WipeValue&) = delete;
    WipeValue& operator=(const WipeValue&) = delete;
};

class WipeKey {
    std::array<uint8_t, 64>& value_;

public:
    explicit WipeKey(std::array<uint8_t, 64>& value) : value_(value) {}
    ~WipeKey() {
        secure_zero(value_.data(), value_.size());
    }
    WipeKey(const WipeKey&) = delete;
    WipeKey& operator=(const WipeKey&) = delete;
};

void wipe_json(nlohmann::json& value) {
    if (value.is_string()) {
        auto& text = value.get_ref<std::string&>();
        if (!text.empty()) secure_zero(text.data(), text.size());
        return;
    }
    if (value.is_array()) {
        for (auto& item : value) wipe_json(item);
        return;
    }
    if (value.is_object()) {
        for (auto& item : value.items()) wipe_json(item.value());
    }
}

class WipeJson {
    nlohmann::json& value_;

public:
    explicit WipeJson(nlohmann::json& value) : value_(value) {}
    ~WipeJson() {
        wipe_json(value_);
    }
    WipeJson(const WipeJson&) = delete;
    WipeJson& operator=(const WipeJson&) = delete;
};

class WalletJsonShape final : public nlohmann::json_sax<nlohmann::json> {
    struct Frame final {
        bool object = false;
        std::set<std::array<uint8_t, 32>> keys;
    };

    size_t items_ = 0;
    std::vector<Frame> frames_;

    bool item() {
        if (items_ >= max_wallet_items) return false;
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

    bool string(string_t& value) override {
        WipeValue<string_t> wipe(value);
        return item();
    }

    bool binary(binary_t& value) override {
        WipeValue<binary_t> wipe(value);
        return item();
    }

    bool start_object(std::size_t) override {
        if (!item() || frames_.size() >= max_wallet_depth) return false;
        frames_.push_back({true, {}});
        return true;
    }

    bool key(string_t& value) override {
        WipeValue<string_t> wipe(value);
        if (frames_.empty() || !frames_.back().object || !item()) return false;
        const auto digest = sha256(
            reinterpret_cast<const uint8_t*>(value.data()),
            value.size());
        return frames_.back().keys.insert(digest).second;
    }

    bool end_object() override {
        if (frames_.empty() || !frames_.back().object) return false;
        frames_.pop_back();
        return true;
    }

    bool start_array(std::size_t) override {
        if (!item() || frames_.size() >= max_wallet_depth) return false;
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

bool wallet_json_ok(std::vector<uint8_t>& value) {
    try {
        WalletJsonShape shape;
        return nlohmann::json::sax_parse(value.begin(), value.end(), &shape);
    } catch (...) {
        return false;
    }
}

int base64_digit(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

bool decode_private_key(
    const std::string& text,
    std::array<uint8_t, 64>& output,
    size_t& output_size) {
    if (text.size() != 44 && text.size() != 88) return false;
    const size_t expected = text.size() == 44 ? 32 : 64;
    const size_t expected_padding = expected == 32 ? 1 : 2;
    if (text[text.size() - 1] != '=' ||
        (expected_padding == 2 && text[text.size() - 2] != '=') ||
        (expected_padding == 1 && text[text.size() - 2] == '='))
        return false;
    size_t offset = 0;
    for (size_t index = 0; index < text.size(); index += 4) {
        const bool last = index + 4 == text.size();
        const int a = base64_digit(text[index]);
        const int b = base64_digit(text[index + 1]);
        const bool c_pad = text[index + 2] == '=';
        const bool d_pad = text[index + 3] == '=';
        const int c = c_pad ? 0 : base64_digit(text[index + 2]);
        const int d = d_pad ? 0 : base64_digit(text[index + 3]);
        if (a < 0 || b < 0 || c < 0 || d < 0 ||
            (!last && (c_pad || d_pad)) || (c_pad && !d_pad))
            return false;
        const uint32_t word =
            (static_cast<uint32_t>(a) << 18) |
            (static_cast<uint32_t>(b) << 12) |
            (static_cast<uint32_t>(c) << 6) |
            static_cast<uint32_t>(d);
        if (offset >= output.size()) return false;
        output[offset++] = static_cast<uint8_t>(word >> 16);
        if (!c_pad) {
            if (offset >= output.size()) return false;
            output[offset++] = static_cast<uint8_t>(word >> 8);
        }
        if (!d_pad) {
            if (offset >= output.size()) return false;
            output[offset++] = static_cast<uint8_t>(word);
        }
    }
    if (offset != expected) return false;
    std::string encoded = base64_encode(output.data(), offset);
    WipeValue<std::string> wipe(encoded);
    if (encoded.size() != text.size() ||
        CRYPTO_memcmp(encoded.data(), text.data(), text.size()) != 0)
        return false;
    output_size = offset;
    return true;
}

bool decrypt_wallet(
    const std::string& input,
    std::string_view pin,
    std::vector<uint8_t>& output) {
    if (pin.empty() || input.size() <= 60 || input.size() - 60 > INT_MAX)
        return false;
    const auto* bytes = reinterpret_cast<const uint8_t*>(input.data());
    const auto* salt = bytes;
    const auto* nonce = bytes + 32;
    const auto* ciphertext = bytes + 44;
    const size_t ciphertext_size = input.size() - 60;
    const auto* tag = ciphertext + ciphertext_size;
    std::array<uint8_t, 32> key{};
    WipeValue<std::array<uint8_t, 32>> wipe_key(key);
    if (PKCS5_PBKDF2_HMAC(
            pin.data(),
            static_cast<int>(pin.size()),
            salt,
            32,
            600'000,
            EVP_sha256(),
            static_cast<int>(key.size()),
            key.data()) != 1)
        return false;
    using Cipher = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
    Cipher context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!context) return false;
    output.assign(ciphertext_size + 16, 0);
    int first = 0;
    int last = 0;
    if (EVP_DecryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
        EVP_DecryptInit_ex(context.get(), nullptr, nullptr, key.data(), nonce) != 1 ||
        EVP_DecryptUpdate(
            context.get(),
            output.data(),
            &first,
            ciphertext,
            static_cast<int>(ciphertext_size)) != 1 ||
        EVP_CIPHER_CTX_ctrl(
            context.get(),
            EVP_CTRL_GCM_SET_TAG,
            16,
            const_cast<uint8_t*>(tag)) != 1 ||
        EVP_DecryptFinal_ex(context.get(), output.data() + first, &last) != 1 ||
        first < 0 || last < 0 ||
        static_cast<size_t>(first + last) != ciphertext_size)
        return false;
    output.resize(ciphertext_size);
    return true;
}

void unlock_secret(void* address, size_t size) {
#if defined(__unix__) || defined(__APPLE__)
    munlock(address, size);
#elif defined(_WIN32)
    VirtualUnlock(address, size);
#else
    static_cast<void>(address);
    static_cast<void>(size);
#endif
}

bool address_text_ok(const std::string& value) {
    static const std::string alphabet =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    return value.size() == 47 &&
        value.rfind("oct", 0) == 0 &&
        value.find_first_not_of(alphabet, 3) == std::string::npos;
}

}

ProgramWallet::ProgramWallet(
    std::string address,
    std::string rpc_url,
    std::string public_key_b64,
    const std::array<uint8_t, 64>& secret_key)
    : address_(std::move(address)),
      rpc_url_(std::move(rpc_url)),
      public_key_b64_(std::move(public_key_b64)) {
    locked_ = try_mlock(secret_key_.data(), secret_key_.size());
    std::memcpy(secret_key_.data(), secret_key.data(), secret_key_.size());
}

ProgramWallet::ProgramWallet(ProgramWallet&& other) noexcept
    : address_(std::move(other.address_)),
      rpc_url_(std::move(other.rpc_url_)),
      public_key_b64_(std::move(other.public_key_b64_)) {
    locked_ = try_mlock(secret_key_.data(), secret_key_.size());
    std::memcpy(secret_key_.data(), other.secret_key_.data(), secret_key_.size());
    other.clear();
}

ProgramWallet& ProgramWallet::operator=(ProgramWallet&& other) noexcept {
    if (this == &other) return *this;
    clear();
    address_ = std::move(other.address_);
    rpc_url_ = std::move(other.rpc_url_);
    public_key_b64_ = std::move(other.public_key_b64_);
    locked_ = try_mlock(secret_key_.data(), secret_key_.size());
    std::memcpy(secret_key_.data(), other.secret_key_.data(), secret_key_.size());
    other.clear();
    return *this;
}

ProgramWallet::~ProgramWallet() {
    clear();
}

const std::string& ProgramWallet::address() const {
    return address_;
}

const std::string& ProgramWallet::rpc_url() const {
    return rpc_url_;
}

const std::string& ProgramWallet::public_key_b64() const {
    return public_key_b64_;
}

const uint8_t* ProgramWallet::secret_key() const {
    return secret_key_.data();
}

void ProgramWallet::clear() {
    secure_zero(secret_key_.data(), secret_key_.size());
    if (locked_) unlock_secret(secret_key_.data(), secret_key_.size());
    locked_ = false;
    address_.clear();
    if (!rpc_url_.empty()) secure_zero(rpc_url_.data(), rpc_url_.size());
    rpc_url_.clear();
    public_key_b64_.clear();
}

bool WalletRead::ok() const {
    return wallet.has_value();
}

WalletRead read_program_wallet(
    const std::filesystem::path& path,
    const TerminalPin& pin) {
    WalletRead out;
    if (pin.empty()) {
        out.error = "Program PIN is empty";
        return out;
    }
    std::string encrypted;
    WipeValue<std::string> wipe_encrypted(encrypted);
    if (!detail::read_limited_file(
            path,
            max_wallet_bytes,
            "Program wallet",
            encrypted,
            out.error))
        return out;
    std::vector<uint8_t> plain;
    WipeValue<std::vector<uint8_t>> wipe_plain(plain);
    if (!decrypt_wallet(encrypted, pin.view(), plain) ||
        !wallet_json_ok(plain)) {
        out.error = "Program wallet PIN or data is invalid";
        return out;
    }
    auto document = nlohmann::json::parse(plain.begin(), plain.end(), nullptr, false);
    WipeJson wipe_document(document);
    if (document.is_discarded() || !document.is_object() ||
        !document.contains("priv") || !document["priv"].is_string() ||
        !document.contains("addr") || !document["addr"].is_string() ||
        (document.contains("rpc") && !document["rpc"].is_string())) {
        out.error = "Program wallet data is invalid";
        return out;
    }
    auto& private_text = document["priv"].get_ref<std::string&>();
    const auto& address = document["addr"].get_ref<const std::string&>();
    const std::string rpc_url = document.contains("rpc")
        ? document["rpc"].get<std::string>()
        : "https://devnet.octrascan.io/rpc";
    if (!address_text_ok(address) || rpc_url.empty() ||
        rpc_url.size() > detail::max_path_bytes) {
        out.error = "Program wallet data is invalid";
        return out;
    }
    std::array<uint8_t, 64> decoded{};
    WipeKey wipe_decoded(decoded);
    size_t decoded_size = 0;
    if (!decode_private_key(private_text, decoded, decoded_size)) {
        out.error = "Program wallet data is invalid";
        return out;
    }
    std::array<uint8_t, 64> secret{};
    WipeKey wipe_secret(secret);
    std::array<uint8_t, 32> public_key{};
    WipeValue<std::array<uint8_t, 32>> wipe_public(public_key);
    if (crypto_sign_seed_keypair(
            public_key.data(),
            secret.data(),
            decoded.data()) != 0 ||
        (decoded_size == 64 && CRYPTO_memcmp(
            decoded.data() + 32,
            public_key.data(),
            public_key.size()) != 0)) {
        out.error = "Program wallet data is invalid";
        return out;
    }
    std::string derived_address;
    try {
        derived_address = derive_address_from_pubkey(public_key.data());
    } catch (...) {
        out.error = "Program wallet data is invalid";
        return out;
    }
    if (derived_address.size() != address.size() ||
        CRYPTO_memcmp(
            derived_address.data(),
            address.data(),
            address.size()) != 0) {
        out.error = "Program wallet data is invalid";
        return out;
    }
    try {
        ProgramWallet wallet(
            address,
            rpc_url,
            base64_encode(public_key.data(), public_key.size()),
            secret);
        out.wallet.emplace(std::move(wallet));
    } catch (...) {
        out.error = "Program wallet data is invalid";
    }
    return out;
}

}