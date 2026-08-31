#include "hook/network/high_level_hooks.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>

#include <detours.h>

namespace bolt::network {
namespace {

using WinHttpConnectFunction = decltype(&WinHttpConnect);

WinHttpConnectFunction g_win_http_connect = WinHttpConnect;

bool UsesExplicitProxy(const HINTERNET session) noexcept {
    if (session == nullptr) {
        return false;
    }
    WINHTTP_PROXY_INFO proxy{};
    DWORD proxy_length = sizeof(proxy);
    return WinHttpQueryOption(
               session, WINHTTP_OPTION_PROXY, &proxy, &proxy_length) != FALSE &&
           proxy.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY;
}

HINTERNET WINAPI DetouredWinHttpConnect(
    const HINTERNET session,
    const LPCWSTR server,
    const INTERNET_PORT port,
    const DWORD reserved) noexcept {
    if (DenyHighLevelConnection(server, port, !UsesExplicitProxy(session))) {
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
