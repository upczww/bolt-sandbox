#include "hook/filesystem/final_path_resolver.h"

#include "hook/filesystem/path_cache.h"
#include "hook/filesystem/safe_device.h"

#include <cstddef>
#include <filesystem>
#include <utility>
#include <vector>

namespace bolt::filesystem {

bool ResolveFinalPathForPolicy(
    const wchar_t* path,
    const OpenPathFunction open_path,
    std::wstring& resolved_path) noexcept {
    if (TryGetResolvedPathForPolicy(path, resolved_path)) {
        return true;
    }
    if (path == nullptr || path[0] == L'\0' || open_path == nullptr) {
        return false;
    }
    if (IsNullDevicePath(path)) {
        resolved_path = L"NUL";
        return true;
    }
    try {
        std::filesystem::path candidate{path};
        std::vector<std::filesystem::path> suffix;
        if (candidate.filename().empty()) {
            const auto parent = candidate.parent_path();
            if (!parent.empty() && parent != candidate) {
                candidate = parent;
            }
        }
        constexpr std::size_t maximum_ancestors = 256;
        for (std::size_t depth = 0; depth < maximum_ancestors; ++depth) {
            const HANDLE handle = open_path(
                candidate.c_str(), FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS, nullptr);
            if (handle != INVALID_HANDLE_VALUE) {
                const DWORD required = GetFinalPathNameByHandleW(
                    handle, nullptr, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
                if (required == 0) {
                    CloseHandle(handle);
                    return false;
                }
                std::wstring final_path(static_cast<std::size_t>(required) + 1, L'\0');
                const DWORD copied = GetFinalPathNameByHandleW(
                    handle, final_path.data(), static_cast<DWORD>(final_path.size()),
                    FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
                CloseHandle(handle);
                if (copied == 0 || copied >= final_path.size()) {
                    return false;
                }
                final_path.resize(copied);
                std::filesystem::path combined{std::move(final_path)};
                for (auto iterator = suffix.rbegin(); iterator != suffix.rend(); ++iterator) {
                    combined /= *iterator;
                }
                resolved_path = combined.lexically_normal().wstring();
                CacheResolvedPathForPolicy(path, resolved_path);
                return true;
            }
            const DWORD error = GetLastError();
            if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
                return false;
            }
            const auto parent = candidate.parent_path();
            if (parent.empty() || parent == candidate || candidate.filename().empty()) {
                return false;
            }
            suffix.push_back(candidate.filename());
            candidate = parent;
        }
    } catch (...) {
        resolved_path.clear();
    }
    return false;
}

}  // namespace bolt::filesystem
