// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
// lambda0xE
// Arthur Edelstein
// Denis CMIX

#include "program_cli_plan.hpp"

#include <algorithm>
#include <filesystem>
#include <sstream>
#include <system_error>

#include "limited_file.hpp"
#include "program_cli_detail.hpp"

namespace octra::program_cli {

namespace {

bool source_limit(
    const std::vector<SourceFile>& files,
    const std::string& path,
    size_t& limit,
    std::string& error) {
    if (!valid_source_path(path)) {
        error = "Program source path is invalid";
        return false;
    }
    if (files.size() >= detail::max_source_files) {
        error = "Program source file count exceeds limit";
        return false;
    }
    size_t total = 0;
    for (const auto& file : files) {
        if (file.path == path) {
            error = "Program source path is duplicated";
            return false;
        }
        if (file.path.size() > detail::max_sources_bytes - total) {
            error = "Program sources exceed limit";
            return false;
        }
        total += file.path.size();
        if (file.body.size() > detail::max_sources_bytes - total) {
            error = "Program sources exceed limit";
            return false;
        }
        total += file.body.size();
    }
    if (path.size() > detail::max_sources_bytes - total) {
        error = "Program sources exceed limit";
        return false;
    }
    limit = std::min(
        detail::max_source_bytes,
        detail::max_sources_bytes - total - path.size());
    return true;
}

bool add_source(
    std::vector<SourceFile>& files,
    const std::string& path,
    std::string body,
    std::string& error) {
    size_t limit = 0;
    if (!source_limit(files, path, limit, error)) return false;
    if (body.size() > limit) {
        error = "Program sources exceed limit";
        return false;
    }
    files.push_back({path, std::move(body)});
    return true;
}

bool finish_sources(std::vector<SourceFile>& files, std::string& error) {
    if (files.empty() || files.size() > detail::max_source_files) {
        error = "Program source file count exceeds limit";
        return false;
    }
    std::sort(files.begin(), files.end(), [](const SourceFile& left, const SourceFile& right) {
        return left.path < right.path;
    });
    size_t total = 0;
    std::string previous;
    bool has_main = false;
    for (const auto& file : files) {
        if (!previous.empty() && previous == file.path) {
            error = "Program source path is duplicated";
            return false;
        }
        previous = file.path;
        has_main = has_main || file.path == "main.aml";
        if (file.path.size() > detail::max_sources_bytes - total) {
            error = "Program sources exceed limit";
            return false;
        }
        total += file.path.size();
        if (file.body.size() > detail::max_sources_bytes - total) {
            error = "Program sources exceed limit";
            return false;
        }
        total += file.body.size();
    }
    if (!has_main) {
        error = "Program main.aml is missing";
        return false;
    }
    return true;
}

bool load_project_json(
    const std::filesystem::path& path,
    std::vector<SourceFile>& files,
    std::string& error) {
    std::string raw;
    if (!detail::read_limited_file(
        path,
        detail::max_project_bytes,
        "Program project",
        raw,
        error)) return false;
    try {
        if (!detail::json_shape_ok(
                raw,
                8,
                detail::max_project_json_items,
                detail::JsonRoot::object)) {
            error = "Program project structure exceeds limit";
            return false;
        }
        const auto project = nlohmann::json::parse(raw);
        if (!project.is_object()
            || !project.contains("files")
            || !project["files"].is_object()) {
            error = "Program project must contain a files object";
            return false;
        }
        for (auto item = project["files"].begin(); item != project["files"].end(); ++item) {
            if (!item.value().is_string()) {
                error = "Program project source must be text";
                return false;
            }
            if (!add_source(files, item.key(), item.value().get<std::string>(), error)) {
                return false;
            }
        }
    } catch (...) {
        error = "Program project is invalid JSON";
        return false;
    }
    return true;
}

bool load_directory_once(
    const std::filesystem::path& root,
    std::vector<SourceFile>& files,
    std::string& error) {
    std::error_code ec;
    const auto root_status = std::filesystem::symlink_status(root, ec);
    if (ec || !std::filesystem::is_directory(root_status)) {
        error = "Program project directory is unavailable";
        return false;
    }
    if (std::filesystem::is_symlink(root_status)) {
        error = "Program project symlinks are refused";
        return false;
    }
    std::filesystem::recursive_directory_iterator item(root, ec);
    const std::filesystem::recursive_directory_iterator end;
    size_t entries = 0;
    while (!ec && item != end) {
        if (++entries > detail::max_directory_entries) {
            error = "Program project entry count exceeds limit";
            return false;
        }
        const auto status = item->symlink_status(ec);
        if (ec) break;
        if (std::filesystem::is_symlink(status)) {
            error = "Program project symlinks are refused";
            return false;
        }
        if (std::filesystem::is_regular_file(status) && item->path().extension() == ".aml") {
            const std::string logical = item->path().lexically_relative(root).generic_string();
            size_t limit = 0;
            if (!source_limit(files, logical, limit, error)) return false;
            std::string body;
            if (!detail::read_limited_file(
                item->path(),
                limit,
                "Program source file",
                body,
                error)) return false;
            if (!add_source(files, logical, std::move(body), error)) return false;
        }
        item.increment(ec);
    }
    if (ec) {
        error = "Program project directory cannot be read";
        return false;
    }
    return true;
}

bool same_sources(
    const std::vector<SourceFile>& left,
    const std::vector<SourceFile>& right) {
    if (left.size() != right.size()) return false;
    for (size_t index = 0; index < left.size(); ++index) {
        if (left[index].path != right[index].path
            || left[index].body != right[index].body) return false;
    }
    return true;
}

bool load_directory(
    const std::filesystem::path& root,
    std::vector<SourceFile>& files,
    std::string& error) {
    std::vector<SourceFile> first;
    std::vector<SourceFile> second;
    if (!load_directory_once(root, first, error)
        || !load_directory_once(root, second, error)) return false;
    const auto order = [](const SourceFile& left, const SourceFile& right) {
        return left.path < right.path;
    };
    std::sort(first.begin(), first.end(), order);
    std::sort(second.begin(), second.end(), order);
    if (!same_sources(first, second)) {
        error = "Program project changed while reading";
        return false;
    }
    files = std::move(first);
    return true;
}

bool load_extra_files(
    const std::vector<std::string>& paths,
    const std::filesystem::path& source_base,
    std::vector<SourceFile>& files,
    std::string& error) {
    for (const auto& value : paths) {
        if (value.size() > detail::max_path_bytes) {
            error = "Program source path exceeds local limit";
            return false;
        }
        const std::filesystem::path file_path(value);
        if (file_path.is_absolute()) {
            error = "Program dependency path must be relative";
            return false;
        }
        const std::string logical = file_path.generic_string();
        size_t limit = 0;
        if (!source_limit(files, logical, limit, error)) return false;
        std::string body;
        if (!detail::read_limited_file(
            source_base / file_path,
            limit,
            "Program source file",
            body,
            error)) return false;
        if (!add_source(files, logical, std::move(body), error)) return false;
    }
    return true;
}

bool project_file(const std::string& path) {
    const std::string suffix = ".aml-project.json";
    return path.size() >= suffix.size()
        && path.compare(path.size() - suffix.size(), suffix.size(), suffix) == 0;
}

}

bool valid_source_path(const std::string& path) {
    if (path.empty()
        || path.size() > detail::max_source_path_bytes
        || path.front() == '/') return false;
    for (char value : path) {
        const auto c = static_cast<unsigned char>(value);
        if (!(detail::ascii_alnum(c) || c == '.' || c == '_' || c == '-' || c == '/')) {
            return false;
        }
    }
    std::istringstream parts(path);
    std::string part;
    while (std::getline(parts, part, '/')) {
        if (part.empty() || part == "." || part == "..") return false;
    }
    return path.back() != '/';
}

SourceResult load_sources(const Options& options) {
    SourceResult out;
    if (options.source_path.empty() || options.source_path.size() > detail::max_path_bytes) {
        out.error = "Program source path is invalid";
        return out;
    }
    const std::filesystem::path path(options.source_path);
    std::error_code ec;
    const auto status = std::filesystem::symlink_status(path, ec);
    if (ec || !std::filesystem::exists(status)) {
        out.error = "Program source path does not exist";
        return out;
    }
    if (std::filesystem::is_symlink(status)) {
        out.error = "Program source symlinks are refused";
        return out;
    }
    std::vector<SourceFile> files;
    if (std::filesystem::is_directory(status)) {
        if (!load_directory(path, files, out.error)) return out;
    } else if (project_file(options.source_path)) {
        if (!load_project_json(path, files, out.error)) return out;
    } else if (path.extension() == ".aml") {
        std::string body;
        if (!detail::read_limited_file(
            path,
            detail::max_source_bytes,
            "Program source file",
            body,
            out.error)) return out;
        if (!add_source(files, "main.aml", std::move(body), out.error)) return out;
    } else {
        out.error = "Program source type is not supported";
        return out;
    }
    const auto source_base = std::filesystem::is_directory(status)
        ? path
        : path.parent_path();
    if (!load_extra_files(options.file_paths, source_base, files, out.error)) return out;
    if (!finish_sources(files, out.error)) return out;
    out.bundle.files = std::move(files);
    const auto main = std::find_if(
        out.bundle.files.begin(),
        out.bundle.files.end(),
        [](const SourceFile& file) { return file.path == "main.aml"; });
    out.bundle.main_source = main->body;
    out.ok = true;
    return out;
}

nlohmann::json compile_files_json(const SourceBundle& sources) {
    auto files = nlohmann::json::array();
    for (const auto& file : sources.files) {
        files.push_back({{"path", file.path}, {"source", file.body}});
    }
    return files;
}

nlohmann::json verify_files_json(const SourceBundle& sources) {
    auto files = nlohmann::json::array();
    for (const auto& file : sources.files) {
        if (file.path != "main.aml") {
            files.push_back({{"path", file.path}, {"source", file.body}});
        }
    }
    return files;
}

std::string deploy_params(const Options& options, std::string& error) {
    std::string raw = options.params_json;
    if (!options.params_path.empty()) {
        if (!detail::read_limited_file(
            options.params_path,
            detail::max_params_bytes,
            "Program parameters file",
            raw,
            error)) return "";
    }
    if (raw.empty()) raw = "[]";
    if (!detail::params_json_ok(raw, error)) return "";
    return raw;
}

}