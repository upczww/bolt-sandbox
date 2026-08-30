// Narrow Bolt-facing declaration for the BuildXL path decomposition adapter.
#pragma once

#include <string>
#include <vector>

using PathChar = wchar_t;
using PCPathChar = const PathChar*;

constexpr PathChar NT_DIRECTORY_SEPARATOR = L'\\';
constexpr PathChar UNIX_DIRECTORY_SEPARATOR = L'/';
constexpr PCPathChar NT_LONG_PATH_PREFIX = L"\\\\?\\";
constexpr PCPathChar NT_PATH_PREFIX = L"\\??\\";
constexpr PCPathChar LONG_UNC_PATH_PREFIX = L"\\\\?\\UNC\\";

constexpr bool IsDirectorySeparator(const PathChar character) noexcept {
    return character == NT_DIRECTORY_SEPARATOR || character == UNIX_DIRECTORY_SEPARATOR;
}

bool IsPathCharEqual(PathChar left, PathChar right) noexcept;
bool HasPrefix(PCPathChar value, PCPathChar prefix) noexcept;
bool IsWin32NtPathName(PCPathChar path) noexcept;
bool IsLocalDevicePathName(PCPathChar path) noexcept;
std::size_t FindFinalPathSeparator(PCPathChar path) noexcept;
std::size_t GetRootLength(PCPathChar path) noexcept;
int TryDecomposePath(const std::wstring& path, std::vector<std::wstring>& elements);
