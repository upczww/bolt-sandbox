#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace bolt::filesystem {

bool IsNullDevicePath(const wchar_t* path) noexcept;
bool IsNullDeviceHandle(HANDLE handle) noexcept;
bool IsConsoleDevicePath(const wchar_t* path) noexcept;
bool IsKernelSecurityDevicePath(const wchar_t* path) noexcept;
bool IsNetworkDevicePath(const wchar_t* path) noexcept;

}  // namespace bolt::filesystem
