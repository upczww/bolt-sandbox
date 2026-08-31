#pragma once

#include <cstdint>

namespace bolt::network {

bool DenyHighLevelConnection(
    const char* server,
    std::uint16_t port,
    bool resolve_target) noexcept;
bool DenyHighLevelConnection(
    const wchar_t* server,
    std::uint16_t port,
    bool resolve_target) noexcept;

bool AttachWinHttpHooks() noexcept;
bool AttachWinInetHooks() noexcept;

}  // namespace bolt::network
