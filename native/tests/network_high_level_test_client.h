#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdint>

namespace bolt::tests {

struct HighLevelConnectResult {
    bool connection_denied = false;
    DWORD error = ERROR_SUCCESS;
};

HighLevelConnectResult TryWinHttpConnect(
    const wchar_t* server,
    std::uint16_t port) noexcept;

HighLevelConnectResult TryWinInetConnectW(
    const wchar_t* server,
    std::uint16_t port) noexcept;

HighLevelConnectResult TryWinInetConnectA(
    const char* server,
    std::uint16_t port) noexcept;

std::uint32_t TryWinHttpGet(const wchar_t* server, std::uint16_t port) noexcept;
std::uint32_t TryWinInetGetW(const wchar_t* server, std::uint16_t port) noexcept;

}  // namespace bolt::tests
