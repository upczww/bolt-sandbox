#pragma once

#include <string>

namespace bolt::filesystem {

void InvalidateResolvedPathForMutation(const wchar_t* path, bool is_directory) noexcept;

bool TryGetResolvedPathForPolicy(
    const wchar_t* path,
    std::wstring& resolved_path) noexcept;

void CacheResolvedPathForPolicy(
    const wchar_t* path,
    const std::wstring& resolved_path) noexcept;

}  // namespace bolt::filesystem
