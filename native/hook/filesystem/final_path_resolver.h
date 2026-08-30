#pragma once

#include <string>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace bolt::filesystem {

using OpenPathFunction = HANDLE(WINAPI*)(
    LPCWSTR,
    DWORD,
    DWORD,
    LPSECURITY_ATTRIBUTES,
    DWORD,
    DWORD,
    HANDLE);

bool ResolveFinalPathForPolicy(
    const wchar_t* path,
    OpenPathFunction open_path,
    std::wstring& resolved_path) noexcept;

}  // namespace bolt::filesystem
