#include "hook/network/high_level_hooks.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wininet.h>

#include <detours.h>

namespace bolt::network {
namespace {

using InternetConnectAFunction = decltype(&InternetConnectA);
using InternetConnectWFunction = decltype(&InternetConnectW);

InternetConnectAFunction g_internet_connect_a = InternetConnectA;
InternetConnectWFunction g_internet_connect_w = InternetConnectW;

HINTERNET WINAPI DetouredInternetConnectA(
    const HINTERNET internet,
    const LPCSTR server,
    const INTERNET_PORT port,
    const LPCSTR user_name,
    const LPCSTR password,
    const DWORD service,
    const DWORD flags,
    const DWORD_PTR context) noexcept {
    if (DenyHighLevelConnection(server)) {
        return nullptr;
    }
    return g_internet_connect_a(
        internet, server, port, user_name, password, service, flags, context);
}

HINTERNET WINAPI DetouredInternetConnectW(
    const HINTERNET internet,
    const LPCWSTR server,
    const INTERNET_PORT port,
    const LPCWSTR user_name,
    const LPCWSTR password,
    const DWORD service,
    const DWORD flags,
    const DWORD_PTR context) noexcept {
    if (DenyHighLevelConnection(server)) {
        return nullptr;
    }
    return g_internet_connect_w(
        internet, server, port, user_name, password, service, flags, context);
}

}  // namespace

bool AttachWinInetHooks() noexcept {
    return DetourAttach(
               reinterpret_cast<PVOID*>(&g_internet_connect_a),
               reinterpret_cast<PVOID>(DetouredInternetConnectA)) == NO_ERROR &&
           DetourAttach(
               reinterpret_cast<PVOID*>(&g_internet_connect_w),
               reinterpret_cast<PVOID>(DetouredInternetConnectW)) == NO_ERROR;
}

}  // namespace bolt::network
