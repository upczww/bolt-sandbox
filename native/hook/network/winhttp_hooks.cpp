#include "hook/network/high_level_hooks.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>

#include <detours.h>

namespace bolt::network {
namespace {

using WinHttpConnectFunction = decltype(&WinHttpConnect);

WinHttpConnectFunction g_win_http_connect = WinHttpConnect;

HINTERNET WINAPI DetouredWinHttpConnect(
    const HINTERNET session,
    const LPCWSTR server,
    const INTERNET_PORT port,
    const DWORD reserved) noexcept {
    if (DenyHighLevelConnection(server)) {
        return nullptr;
    }
    return g_win_http_connect(session, server, port, reserved);
}

}  // namespace

bool AttachWinHttpHooks() noexcept {
    return DetourAttach(
               reinterpret_cast<PVOID*>(&g_win_http_connect),
               reinterpret_cast<PVOID>(DetouredWinHttpConnect)) == NO_ERROR;
}

}  // namespace bolt::network
