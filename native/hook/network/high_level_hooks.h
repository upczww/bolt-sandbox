#pragma once

namespace bolt::network {

bool DenyHighLevelConnection(const char* server) noexcept;
bool DenyHighLevelConnection(const wchar_t* server) noexcept;

bool AttachWinHttpHooks() noexcept;
bool AttachWinInetHooks() noexcept;

}  // namespace bolt::network
