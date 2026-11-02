// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#include "limited_file.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace octra::program_cli::detail {

namespace {

bool path_parts(
    const std::filesystem::path& path,
    std::vector<std::filesystem::path>& parts) {
    if (path.empty()) return false;
    for (const auto& part : path.relative_path()) {
        if (part.empty() || part == ".") continue;
        if (part == "..") return false;
        parts.push_back(part);
    }
    return !parts.empty();
}

#ifdef _WIN32

class FileHandle {
    HANDLE value_ = INVALID_HANDLE_VALUE;

public:
    explicit FileHandle(HANDLE value = INVALID_HANDLE_VALUE) : value_(value) {}
    ~FileHandle() {
        if (value_ != INVALID_HANDLE_VALUE) CloseHandle(value_);
    }
    FileHandle(const FileHandle&) = delete;
    FileHandle& operator=(const FileHandle&) = delete;
    FileHandle(FileHandle&& other) noexcept : value_(other.value_) {
        other.value_ = INVALID_HANDLE_VALUE;
    }
    FileHandle& operator=(FileHandle&& other) noexcept {
        if (this == &other) return *this;
        if (value_ != INVALID_HANDLE_VALUE) CloseHandle(value_);
        value_ = other.value_;
        other.value_ = INVALID_HANDLE_VALUE;
        return *this;
    }
    HANDLE get() const {
        return value_;
    }
    bool valid() const {
        return value_ != INVALID_HANDLE_VALUE;
    }
};

using NtCreateFileCall = NTSTATUS (NTAPI *)(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    PIO_STATUS_BLOCK,
    PLARGE_INTEGER,
    ULONG,
    ULONG,
    ULONG,
    ULONG,
    PVOID,
    ULONG);

FileHandle open_child(
    NtCreateFileCall create_file,
    HANDLE parent,
    const std::filesystem::path& part,
    bool final) {
    const std::wstring name = part.native();
    const auto max_chars = static_cast<size_t>(
        std::numeric_limits<USHORT>::max() / sizeof(wchar_t));
    if (name.empty()
        || name.size() > max_chars
        || name.find(L'\0') != std::wstring::npos
        || name.find(L'\\') != std::wstring::npos
        || name.find(L'/') != std::wstring::npos
        || name.find(L':') != std::wstring::npos) {
        return FileHandle();
    }
    UNICODE_STRING object_name{};
    object_name.Length = static_cast<USHORT>(name.size() * sizeof(wchar_t));
    object_name.MaximumLength = object_name.Length;
    object_name.Buffer = const_cast<PWSTR>(name.data());
    OBJECT_ATTRIBUTES attributes{};
    attributes.Length = sizeof(attributes);
    attributes.RootDirectory = parent;
    attributes.ObjectName = &object_name;
    attributes.Attributes = OBJ_CASE_INSENSITIVE;
    attributes.SecurityDescriptor = nullptr;
    attributes.SecurityQualityOfService = nullptr;
    IO_STATUS_BLOCK status_block{};
    HANDLE value = INVALID_HANDLE_VALUE;
    const ACCESS_MASK access = final
        ? GENERIC_READ | SYNCHRONIZE
        : FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
    const ULONG options = FILE_OPEN_REPARSE_POINT
        | FILE_SYNCHRONOUS_IO_NONALERT
        | (final ? FILE_NON_DIRECTORY_FILE | FILE_SEQUENTIAL_ONLY
                 : FILE_DIRECTORY_FILE);
    const NTSTATUS status = create_file(
        &value,
        access,
        &attributes,
        &status_block,
        nullptr,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        options,
        nullptr,
        0);
    if (!NT_SUCCESS(status)) return FileHandle();
    return FileHandle(value);
}

bool file_identity_equal(
    const BY_HANDLE_FILE_INFORMATION& left,
    const BY_HANDLE_FILE_INFORMATION& right) {
    return left.dwVolumeSerialNumber == right.dwVolumeSerialNumber
        && left.nFileIndexHigh == right.nFileIndexHigh
        && left.nFileIndexLow == right.nFileIndexLow
        && left.nFileSizeHigh == right.nFileSizeHigh
        && left.nFileSizeLow == right.nFileSizeLow
        && left.ftLastWriteTime.dwHighDateTime == right.ftLastWriteTime.dwHighDateTime
        && left.ftLastWriteTime.dwLowDateTime == right.ftLastWriteTime.dwLowDateTime;
}

bool read_snapshot(HANDLE file, size_t size, std::string& body) {
    LARGE_INTEGER zero;
    zero.QuadPart = 0;
    if (!SetFilePointerEx(file, zero, nullptr, FILE_BEGIN)) return false;
    body.assign(size, '\0');
    size_t offset = 0;
    while (offset < size) {
        DWORD read = 0;
        const auto count = static_cast<DWORD>(std::min(
            size - offset,
            static_cast<size_t>(std::numeric_limits<DWORD>::max())));
        if (!ReadFile(file, body.data() + offset, count, &read, nullptr) || read == 0) {
            return false;
        }
        offset += read;
    }
    char extra = 0;
    DWORD read = 0;
    return ReadFile(file, &extra, 1, &read, nullptr) && read == 0;
}

bool read_platform_file(
    const std::filesystem::path& path,
    const std::vector<std::filesystem::path>& parts,
    size_t limit,
    const std::string& label,
    std::string& body,
    std::string& error) {
    const bool absolute = path.is_absolute();
    if (!absolute && (path.has_root_name() || path.has_root_directory())) {
        error = label + " path is invalid";
        return false;
    }
    const HMODULE module = GetModuleHandleW(L"ntdll.dll");
    const auto create_file = module == nullptr
        ? nullptr
        : reinterpret_cast<NtCreateFileCall>(GetProcAddress(module, "NtCreateFile"));
    if (create_file == nullptr) {
        error = label + " cannot be opened";
        return false;
    }
    std::vector<FileHandle> handles;
    handles.reserve(parts.size() + 1);
    const std::filesystem::path root_path = absolute
        ? path.root_path()
        : std::filesystem::path(L".");
    FileHandle root(CreateFileW(
        root_path.c_str(),
        FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
        nullptr));
    if (!root.valid()) {
        error = label + " cannot be opened";
        return false;
    }
    FILE_ATTRIBUTE_TAG_INFO root_attributes;
    if (!GetFileInformationByHandleEx(
            root.get(),
            FileAttributeTagInfo,
            &root_attributes,
            sizeof(root_attributes))
        || (root_attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || (root_attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        error = label + " path is invalid";
        return false;
    }
    handles.push_back(std::move(root));
    for (size_t index = 0; index < parts.size(); ++index) {
        const bool final = index + 1 == parts.size();
        FileHandle handle(open_child(
            create_file,
            handles.back().get(),
            parts[index],
            final));
        if (!handle.valid()) {
            error = label + " cannot be opened";
            return false;
        }
        FILE_ATTRIBUTE_TAG_INFO attributes;
        if (!GetFileInformationByHandleEx(
                handle.get(),
                FileAttributeTagInfo,
                &attributes,
                sizeof(attributes))
            || (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
            error = label + " links are refused";
            return false;
        }
        const bool directory = (attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        if (final ? directory : !directory) {
            error = label + " is not a regular file";
            return false;
        }
        handles.push_back(std::move(handle));
    }
    auto& file = handles.back();
    LARGE_INTEGER size;
    BY_HANDLE_FILE_INFORMATION before;
    if (!GetFileSizeEx(file.get(), &size)
        || size.QuadPart < 0
        || static_cast<uint64_t>(size.QuadPart) > limit
        || !GetFileInformationByHandle(file.get(), &before)) {
        error = label + " exceeds limit";
        return false;
    }
    std::string first;
    std::string second;
    const auto expected = static_cast<size_t>(size.QuadPart);
    BY_HANDLE_FILE_INFORMATION after;
    if (!read_snapshot(file.get(), expected, first)
        || !read_snapshot(file.get(), expected, second)
        || first != second
        || !GetFileInformationByHandle(file.get(), &after)
        || !file_identity_equal(before, after)) {
        error = label + " changed while reading";
        return false;
    }
    body = std::move(first);
    return true;
}

#else

class FileDescriptor {
    int value_ = -1;

public:
    explicit FileDescriptor(int value = -1) : value_(value) {}
    ~FileDescriptor() {
        if (value_ >= 0) close(value_);
    }
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
    int get() const {
        return value_;
    }
    bool valid() const {
        return value_ >= 0;
    }
    void reset(int value) {
        if (value_ >= 0) close(value_);
        value_ = value;
    }
};

bool read_snapshot(int file, size_t size, std::string& body) {
    if (lseek(file, 0, SEEK_SET) < 0) return false;
    body.assign(size, '\0');
    size_t offset = 0;
    while (offset < size) {
        const auto count = read(file, body.data() + offset, size - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        offset += static_cast<size_t>(count);
    }
    char extra = 0;
    while (true) {
        const auto count = read(file, &extra, 1);
        if (count < 0 && errno == EINTR) continue;
        return count == 0;
    }
}

bool file_identity_equal(const struct stat& left, const struct stat& right) {
    const bool identity = left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && left.st_mode == right.st_mode
        && left.st_size == right.st_size;
#if defined(__APPLE__)
    return identity
        && left.st_mtimespec.tv_sec == right.st_mtimespec.tv_sec
        && left.st_mtimespec.tv_nsec == right.st_mtimespec.tv_nsec
        && left.st_ctimespec.tv_sec == right.st_ctimespec.tv_sec
        && left.st_ctimespec.tv_nsec == right.st_ctimespec.tv_nsec;
#else
    return identity
        && left.st_mtim.tv_sec == right.st_mtim.tv_sec
        && left.st_mtim.tv_nsec == right.st_mtim.tv_nsec
        && left.st_ctim.tv_sec == right.st_ctim.tv_sec
        && left.st_ctim.tv_nsec == right.st_ctim.tv_nsec;
#endif
}

bool read_platform_file(
    const std::filesystem::path& path,
    const std::vector<std::filesystem::path>& parts,
    size_t limit,
    const std::string& label,
    std::string& body,
    std::string& error) {
    FileDescriptor directory(open(
        path.is_absolute() ? "/" : ".",
        O_RDONLY | O_CLOEXEC | O_DIRECTORY));
    if (!directory.valid()) {
        error = label + " cannot be opened";
        return false;
    }
    for (size_t index = 0; index + 1 < parts.size(); ++index) {
        const std::string name = parts[index].string();
        const int next = openat(
            directory.get(),
            name.c_str(),
            O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
        if (next < 0) {
            error = label + " cannot be opened";
            return false;
        }
        directory.reset(next);
    }
    const std::string name = parts.back().string();
    FileDescriptor file(openat(
        directory.get(),
        name.c_str(),
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    if (!file.valid()) {
        error = errno == ELOOP
            ? label + " links are refused"
            : label + " cannot be opened";
        return false;
    }
    struct stat before;
    if (fstat(file.get(), &before) != 0 || !S_ISREG(before.st_mode)) {
        error = label + " is not a regular file";
        return false;
    }
    if (before.st_size < 0 || static_cast<uint64_t>(before.st_size) > limit) {
        error = label + " exceeds limit";
        return false;
    }
    const auto expected = static_cast<size_t>(before.st_size);
    std::string first;
    std::string second;
    struct stat after;
    if (!read_snapshot(file.get(), expected, first)
        || !read_snapshot(file.get(), expected, second)
        || first != second
        || fstat(file.get(), &after) != 0
        || !file_identity_equal(before, after)) {
        error = label + " changed while reading";
        return false;
    }
    body = std::move(first);
    return true;
}

#endif

}

bool read_limited_file(
    const std::filesystem::path& path,
    size_t limit,
    const std::string& label,
    std::string& body,
    std::string& error) {
    body.clear();
    std::vector<std::filesystem::path> parts;
    try {
        if (!path_parts(path, parts)) {
            error = label + " path is invalid";
            return false;
        }
        return read_platform_file(path, parts, limit, label, body, error);
    } catch (...) {
        error = label + " cannot be opened";
        return false;
    }
}

}