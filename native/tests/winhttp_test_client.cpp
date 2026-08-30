#include "tests/network_high_level_test_client.h"

#include <winhttp.h>

namespace bolt::tests {

HighLevelConnectResult TryWinHttpConnect(
    const wchar_t* server,
    const std::uint16_t port) noexcept {
    SetLastError(ERROR_SUCCESS);
    const HINTERNET connection = WinHttpConnect(nullptr, server, port, 0);
    const DWORD error = GetLastError();
    if (connection != nullptr) {
        WinHttpCloseHandle(connection);
    }
    return {connection == nullptr, error};
}

bool TryWinHttpGet(
    const wchar_t* const server,
    const std::uint16_t port) noexcept {
    const HINTERNET session = WinHttpOpen(
        L"bolt-sandbox-network-test/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    const HINTERNET connection =
        session == nullptr ? nullptr : WinHttpConnect(session, server, port, 0);
    const HINTERNET request = connection == nullptr
                                  ? nullptr
                                  : WinHttpOpenRequest(
                                        connection, L"GET", L"/", nullptr,
                                        WINHTTP_NO_REFERER,
                                        WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    const bool sent = request != nullptr &&
        WinHttpSendRequest(
            request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) != FALSE;
    const bool received = sent && WinHttpReceiveResponse(request, nullptr) != FALSE;
    char body[2]{};
    DWORD bytes_read = 0;
    const bool read = received &&
        WinHttpReadData(request, body, sizeof(body), &bytes_read) != FALSE &&
        bytes_read == sizeof(body) && body[0] == 'o' && body[1] == 'k';
    if (request != nullptr) {
        WinHttpCloseHandle(request);
    }
    if (connection != nullptr) {
        WinHttpCloseHandle(connection);
    }
    if (session != nullptr) {
        WinHttpCloseHandle(session);
    }
    return read;
}

}  // namespace bolt::tests
