// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
// lambda0xE
// Arthur Edelstein
// Denis CMIX

#include "program_cli_plan.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>

#include "../crypto_utils.hpp"
#include "program_cli_detail.hpp"

namespace octra::program_cli {

namespace {

bool base64_text(const std::string& value) {
    if (value.empty() || value.size() % 4 != 0) return false;
    size_t padding = 0;
    if (value.back() == '=') ++padding;
    if (value.size() > 1 && value[value.size() - 2] == '=') ++padding;
    for (size_t index = 0; index < value.size(); ++index) {
        const auto c = static_cast<unsigned char>(value[index]);
        const bool data = detail::ascii_alnum(c) || c == '+' || c == '/';
        const bool pad = c == '=' && index >= value.size() - padding;
        if (!data && !pad) return false;
    }
    return true;
}

bool decode_base64(
    const std::string& encoded,
    size_t limit,
    std::string& raw,
    std::string& error) {
    if (encoded.size() > ((limit + 2) / 3) * 4 || !base64_text(encoded)) {
        error = "Program package encoding is invalid";
        return false;
    }
    const auto bytes = octra::base64_decode(encoded);
    if (bytes.size() > limit
        || octra::base64_encode(bytes.data(), bytes.size()) != encoded) {
        error = "Program package encoding is invalid";
        return false;
    }
    raw.assign(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    return true;
}

std::string digest_hex(const std::string& value) {
    const auto hash = octra::sha256(
        reinterpret_cast<const uint8_t*>(value.data()),
        value.size());
    return octra::hex_encode(hash.data(), hash.size());
}

bool digest_text(const nlohmann::json& value) {
    if (!value.is_string()) return false;
    const auto& text = value.get_ref<const std::string&>();
    if (text.size() != 64) return false;
    return std::all_of(text.begin(), text.end(), [](unsigned char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}

std::string source_digest(const SourceBundle& sources) {
    auto rows = nlohmann::json::array();
    for (const auto& source : sources.files) {
        rows.push_back({
            {"path", source.path},
            {"source_hash", digest_hex(source.body)}
        });
    }
    return digest_hex(rows.dump());
}

class WireReader {
    const std::string& raw_;
    size_t offset_ = 0;

public:
    explicit WireReader(const std::string& raw) : raw_(raw) {}

    bool bytes(size_t count, std::string& value) {
        if (count > raw_.size() - offset_) return false;
        value.assign(raw_.data() + offset_, count);
        offset_ += count;
        return true;
    }

    bool u16(uint16_t& value) {
        std::string raw;
        if (!bytes(2, raw)) return false;
        value = static_cast<uint16_t>(
            static_cast<uint8_t>(raw[0])
            | static_cast<uint16_t>(static_cast<uint8_t>(raw[1])) << 8);
        return true;
    }

    bool u32(uint32_t& value) {
        std::string raw;
        if (!bytes(4, raw)) return false;
        value = static_cast<uint8_t>(raw[0])
            | static_cast<uint32_t>(static_cast<uint8_t>(raw[1])) << 8
            | static_cast<uint32_t>(static_cast<uint8_t>(raw[2])) << 16
            | static_cast<uint32_t>(static_cast<uint8_t>(raw[3])) << 24;
        return true;
    }

    bool done() const {
        return offset_ == raw_.size();
    }
};

bool inspect_code(const std::string& code, std::string& error) {
    WireReader reader(code);
    std::string magic;
    uint16_t version = 0;
    uint16_t constants = 0;
    uint32_t instructions = 0;
    if (!reader.bytes(4, magic)
        || !reader.u16(version)
        || !reader.u16(constants)
        || !reader.u32(instructions)
        || magic != "OCTB"
        || version != 1
        || constants > 32'768
        || instructions == 0
        || instructions > 65'536
        || static_cast<uint64_t>(constants) * 5 + instructions + 12 > code.size()) {
        error = "Program bytecode header is invalid";
        return false;
    }
    return true;
}

bool inspect_certificate(
    const std::string& certificate,
    const std::string& code,
    const SourceBundle& sources,
    std::string& error) {
    try {
        if (certificate.empty()
            || !detail::json_shape_ok(
                certificate,
                64,
                detail::max_certificate_json_items,
                detail::JsonRoot::object)) {
            error = "Program certificate is invalid";
            return false;
        }
        const auto value = nlohmann::json::parse(certificate);
        if (!value.is_object()
            || value.value("schema", "") != "aml_bytecode_certificate_v2"
            || value.value("compiler", "") != "octra_aml"
            || value.value("declaration", "") != "program"
            || value.value("source_mode", "") != "multi"
            || !value.contains("compiler_version")
            || !value["compiler_version"].is_string()
            || value["compiler_version"].get_ref<const std::string&>().empty()
            || value["compiler_version"].get_ref<const std::string&>().size()
                > detail::max_version_bytes
            || !value.contains("verification_schema")
            || !value["verification_schema"].is_string()
            || value["verification_schema"].get_ref<const std::string&>().empty()
            || value["verification_schema"].get_ref<const std::string&>().size()
                > detail::max_version_bytes
            || !value.contains("source_hash")
            || !digest_text(value["source_hash"])
            || value["source_hash"].get_ref<const std::string&>() != source_digest(sources)
            || !value.contains("bytecode_hash")
            || !digest_text(value["bytecode_hash"])
            || value["bytecode_hash"].get_ref<const std::string&>() != digest_hex(code)
            || !value.contains("verification_hash")
            || !digest_text(value["verification_hash"])
            || !value.contains("facts_hash")
            || !digest_text(value["facts_hash"])
            || !value.contains("effects")
            || !value["effects"].is_array()
            || !std::all_of(
                value["effects"].begin(),
                value["effects"].end(),
                [](const nlohmann::json& item) { return item.is_string(); })
            || !value.contains("facts")
            || !value["facts"].is_object()) {
            error = "Program certificate is invalid";
            return false;
        }
        const auto& facts = value["facts"];
        for (const char* field : {"root", "entries", "calls", "xcalls"}) {
            if (!facts.contains(field) || !facts[field].is_array()) {
                error = "Program certificate is invalid";
                return false;
            }
        }
        if (facts.contains("storage") && !facts["storage"].is_array()) {
            error = "Program certificate is invalid";
            return false;
        }
    } catch (...) {
        error = "Program certificate is invalid";
        return false;
    }
    return true;
}

bool inspect_envelope(
    const std::string& raw,
    const SourceBundle& sources,
    std::string& error) {
    WireReader reader(raw);
    std::string magic;
    uint16_t version = 0;
    uint16_t flags = 0;
    uint32_t code_size = 0;
    uint32_t certificate_size = 0;
    std::string code;
    std::string certificate;
    if (!reader.bytes(4, magic)
        || !reader.u16(version)
        || !reader.u16(flags)
        || !reader.u32(code_size)
        || !reader.u32(certificate_size)
        || magic != "OCPG"
        || version != 2
        || flags != 0
        || code_size == 0
        || code_size > detail::max_envelope_bytes
        || certificate_size > detail::max_certificate_bytes
        || static_cast<uint64_t>(code_size) + certificate_size + 16 != raw.size()
        || !reader.bytes(code_size, code)
        || !reader.bytes(certificate_size, certificate)
        || !reader.done()) {
        error = "Program envelope is invalid";
        return false;
    }
    return inspect_code(code, error)
        && inspect_certificate(certificate, code, sources, error);
}

bool inspect_sources(const SourceBundle& sources, std::string& error) {
    if (sources.files.empty() || sources.files.size() > detail::max_source_files) {
        error = "Local Program sources are invalid";
        return false;
    }
    size_t total = 0;
    std::string previous;
    bool has_main = false;
    for (const auto& file : sources.files) {
        if (!valid_source_path(file.path)
            || file.body.size() > detail::max_source_bytes
            || (!previous.empty() && previous >= file.path)
            || file.path.size() > detail::max_sources_bytes - total) {
            error = "Local Program sources are invalid";
            return false;
        }
        previous = file.path;
        total += file.path.size();
        if (file.body.size() > detail::max_sources_bytes - total) {
            error = "Local Program sources are invalid";
            return false;
        }
        total += file.body.size();
        if (file.path == "main.aml") {
            if (file.body != sources.main_source) {
                error = "Local Program sources are invalid";
                return false;
            }
            has_main = true;
        }
    }
    if (!has_main) {
        error = "Local Program sources are invalid";
        return false;
    }
    return true;
}

bool inspect_package(
    const std::string& raw,
    const SourceBundle& expected,
    std::string& envelope,
    std::string& error) {
    WireReader reader(raw);
    std::string magic;
    uint16_t version = 0;
    uint16_t profile = 0;
    uint16_t main_size = 0;
    std::string main_path;
    uint16_t count = 0;
    if (!reader.bytes(4, magic)
        || !reader.u16(version)
        || !reader.u16(profile)
        || !reader.u16(main_size)
        || !reader.bytes(main_size, main_path)
        || !reader.u16(count)
        || magic != "OCPS"
        || version != 1
        || profile != 1
        || main_path != "main.aml"
        || count == 0
        || count > detail::max_source_files
        || count != expected.files.size()) {
        error = "Program package header is invalid";
        return false;
    }
    size_t source_total = 0;
    for (size_t index = 0; index < count; ++index) {
        uint16_t path_size = 0;
        uint32_t body_size = 0;
        std::string path;
        std::string body;
        if (!reader.u16(path_size)
            || !reader.bytes(path_size, path)
            || !reader.u32(body_size)
            || body_size > detail::max_source_bytes
            || !reader.bytes(body_size, body)
            || !valid_source_path(path)
            || path != expected.files[index].path
            || body != expected.files[index].body) {
            error = "Program package sources do not match local files";
            return false;
        }
        source_total += path.size() + body.size();
        if (source_total > detail::max_sources_bytes) {
            error = "Program package sources exceed limit";
            return false;
        }
    }
    uint32_t envelope_size = 0;
    if (!reader.u32(envelope_size)
        || envelope_size > detail::max_envelope_bytes
        || !reader.bytes(envelope_size, envelope)
        || !reader.done()) {
        error = "Program package length is invalid";
        return false;
    }
    return inspect_envelope(envelope, expected, error);
}

}

ArtifactResult inspect_compile_package(
    const nlohmann::json& result,
    const SourceBundle& sources) {
    ArtifactResult out;
    if (!inspect_sources(sources, out.error)) return out;
    if (!result.is_object()
        || !result.contains("bytecode")
        || !result["bytecode"].is_string()
        || !result.contains("program_envelope")
        || !result["program_envelope"].is_string()
        || !result.contains("deploy_payload")
        || !result["deploy_payload"].is_string()) {
        out.error = "Node did not return a complete Program package";
        return out;
    }
    const auto& bytecode = result["bytecode"].get_ref<const std::string&>();
    const auto& envelope_b64 = result["program_envelope"].get_ref<const std::string&>();
    const auto& package_b64 = result["deploy_payload"].get_ref<const std::string&>();
    if (bytecode.size() > detail::max_envelope_b64_bytes
        || envelope_b64.size() > detail::max_envelope_b64_bytes
        || package_b64.size() > detail::max_package_b64_bytes
        || bytecode != envelope_b64) {
        out.error = "Node returned inconsistent Program data";
        return out;
    }
    std::string envelope;
    if (!decode_base64(envelope_b64, detail::max_envelope_bytes, envelope, out.error)) {
        return out;
    }
    if (!inspect_envelope(envelope, sources, out.error)) return out;
    std::string package;
    if (!decode_base64(package_b64, detail::max_package_bytes, package, out.error)) {
        return out;
    }
    std::string embedded;
    if (!inspect_package(package, sources, embedded, out.error)) return out;
    if (embedded != envelope) {
        out.error = "Program package envelope does not match compiler output";
        return out;
    }
    out.artifact.envelope_b64 = envelope_b64;
    out.artifact.package_b64 = package_b64;
    if (result.contains("version")) {
        if (!result["version"].is_string()
            || result["version"].get_ref<const std::string&>().size()
                > detail::max_version_bytes) {
            out.error = "Node returned invalid Program version";
            return out;
        }
        out.artifact.version = result["version"].get_ref<const std::string&>();
    }
    if (result.contains("instructions")) {
        if (!result["instructions"].is_number_integer()) {
            out.error = "Node returned invalid Program instruction count";
            return out;
        }
        if (result["instructions"].is_number_unsigned()) {
            const auto instructions = result["instructions"].get<uint64_t>();
            if (instructions > static_cast<uint64_t>(std::numeric_limits<int>::max())) {
                out.error = "Node returned invalid Program instruction count";
                return out;
            }
            out.artifact.instructions = static_cast<int>(instructions);
        } else {
            const auto instructions = result["instructions"].get<int64_t>();
            if (instructions < 0 || instructions > std::numeric_limits<int>::max()) {
                out.error = "Node returned invalid Program instruction count";
                return out;
            }
            out.artifact.instructions = static_cast<int>(instructions);
        }
    }
    out.ok = true;
    return out;
}

}