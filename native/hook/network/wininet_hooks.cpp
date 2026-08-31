#include "hook/network/high_level_hooks.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wininet.h>

#include <array>

#include <detours.h>

namespace bolt::network {
namespace {

using InternetConnectAFunction = decltype(&InternetConnectA);
using InternetConnectWFunction = decltype(&InternetConnectW);

InternetConnectAFunction g_internet_connect_a = InternetConnectA;
InternetConnectWFunction g_internet_connect_w = InternetConnectW;

bool UsesExplicitProxy(const HINTERNET internet) noexcept {
    if (internet == nullptr) {
        return false;
    }
    alignas(INTERNET_PROXY_INFO) std::array<std::uint8_t, 4'096> buffer{};
    DWORD proxy_length = static_cast<DWORD>(buffer.size());
    auto* const proxy =
        reinterpret_cast<INTERNET_PROXY_INFO*>(buffer.data());
    return InternetQueryOptionW(
               internet, INTERNET_OPTION_PROXY, buffer.data(),
               &proxy_length) != FALSE &&
           proxy->dwAccessType == INTERNET_OPEN_TYPE_PROXY;
}

HINTERNET WINAPI DetouredInternetConnectA(
    const HINTERNET internet,
    const LPCSTR server,
    const INTERNET_PORT port,
    const LPCSTR user_name,
    const LPCSTR password,
    const DWORD service,
    const DWORD flags,
    const DWORD_PTR context) noexcept {
    if (DenyHighLevelConnection(server, port, !UsesExplicitProxy(internet))) {
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
    if (DenyHighLevelConnection(server, port, !UsesExplicitProxy(internet))) {
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
