// Adapted from Microsoft BuildXL StringOperations.cpp at the revision recorded
// in native/third_party/buildxl/provenance.json. Licensed under the MIT License.
#include "StringOperations.h"

#include <cstdlib>
#include <cassert>
#include <cwctype>
#include <cwchar>
#include <memory>
#include <utility>

#define BOLT_MAX_EXTENDED_PATH_LENGTH 32768
#define BOLT_MAX_EXTENDED_DIR_LENGTH \
    (BOLT_MAX_EXTENDED_PATH_LENGTH - _MAX_DRIVE - _MAX_FNAME - _MAX_EXT - 4)

bool IsPathCharEqual(const PathChar left, const PathChar right) noexcept {
    return left == right || std::towupper(left) == std::towupper(right);
}

bool HasPrefix(const PCPathChar value, const PCPathChar prefix) noexcept {
    assert(value != nullptr);
    assert(prefix != nullptr);
    for (std::size_t index = 0;; ++index) {
        if (value[index] == L'\0') {
            return prefix[index] == L'\0';
        }
        if (prefix[index] == L'\0') {
            return true;
        }
        if (!IsPathCharEqual(value[index], prefix[index])) {
            return false;
        }
    }
}

bool IsWin32NtPathName(const PCPathChar path) noexcept {
    assert(path != nullptr);
    return path[0] == L'\\' && (path[1] == L'\\' || path[1] == L'?') &&
           path[2] == L'?' && path[3] == L'\\';
}

bool IsLocalDevicePathName(const PCPathChar path) noexcept {
    assert(path != nullptr);
    return path[0] == L'\\' && path[1] == L'\\' && path[2] == L'.' &&
           path[3] == L'\\';
}

std::size_t FindFinalPathSeparator(const PCPathChar path) noexcept {
    assert(path != nullptr);
    std::size_t final_separator = 0;
    for (std::size_t index = 0; path[index] != L'\0'; ++index) {
        if (IsDirectorySeparator(path[index])) {
            final_separator = index;
        }
    }
    return final_separator;
}

std::size_t GetRootLength(const PCPathChar path) noexcept {
    if (path == nullptr) {
        return 0;
    }

    std::size_t root_length = 0;
    std::size_t volume_separator_length = 2;
    std::size_t unc_root_length = 2;
    const bool extended_syntax = HasPrefix(path, NT_LONG_PATH_PREFIX) || HasPrefix(path, NT_PATH_PREFIX);
    const bool extended_unc_syntax = HasPrefix(path, LONG_UNC_PATH_PREFIX);
    const std::size_t path_length = std::wcslen(path);

    if (extended_syntax) {
        if (extended_unc_syntax) {
            unc_root_length = std::wcslen(LONG_UNC_PATH_PREFIX);
        } else {
            volume_separator_length += std::wcslen(NT_LONG_PATH_PREFIX);
        }
    }

    if ((!extended_syntax || extended_unc_syntax) && path_length > 0 && IsDirectorySeparator(path[0])) {
        root_length = 1;
        if (extended_unc_syntax || (path_length > 1 && IsDirectorySeparator(path[1]))) {
            root_length = unc_root_length;
            int separators_remaining = 2;
            while (root_length < path_length &&
                   (!IsDirectorySeparator(path[root_length]) || --separators_remaining > 0)) {
                ++root_length;
            }
        }
    } else if (path_length >= volume_separator_length && path[volume_separator_length - 1] == L':') {
        root_length = volume_separator_length;
        if (path_length >= volume_separator_length + 1 && IsDirectorySeparator(path[volume_separator_length])) {
            ++root_length;
        }
    }
    return root_length;
}

int TryDecomposePath(const std::wstring& path, std::vector<std::wstring>& elements) {
    auto drive = std::make_unique<wchar_t[]>(_MAX_DRIVE);
    auto directory = std::make_unique<wchar_t[]>(BOLT_MAX_EXTENDED_DIR_LENGTH);
    auto file_name = std::make_unique<wchar_t[]>(_MAX_FNAME);
    auto extension = std::make_unique<wchar_t[]>(_MAX_EXT);

    const errno_t error = _wsplitpath_s(
        path.c_str(), drive.get(), _MAX_DRIVE, directory.get(),
        BOLT_MAX_EXTENDED_DIR_LENGTH, file_name.get(), _MAX_FNAME,
        extension.get(), _MAX_EXT);
    if (error != 0) {
        return error;
    }

    std::wstring drive_element = drive.get();
    if (!drive_element.empty()) {
        elements.push_back(std::move(drive_element));
    }

    wchar_t* context = nullptr;
    wchar_t* next = wcstok_s(directory.get(), L"\\/", &context);
    while (next != nullptr) {
        std::wstring directory_element = next;
        if (!directory_element.empty()) {
            elements.push_back(std::move(directory_element));
        }
        next = wcstok_s(nullptr, L"\\/", &context);
    }

    std::wstring filename_and_extension = file_name.get();
    filename_and_extension.append(extension.get());
    if (!filename_and_extension.empty()) {
        elements.push_back(std::move(filename_and_extension));
    }
    return 0;
}
