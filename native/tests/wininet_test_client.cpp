#include "tests/network_high_level_test_client.h"

#include <wininet.h>

namespace bolt::tests {

HighLevelConnectResult TryWinInetConnectW(
    const wchar_t* server,
    const std::uint16_t port) noexcept {
    SetLastError(ERROR_SUCCESS);
    const HINTERNET connection = InternetConnectW(
        nullptr, server, port, nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0);
    const DWORD error = GetLastError();
    if (connection != nullptr) {
        InternetCloseHandle(connection);
    }
    return {connection == nullptr, error};
}

HighLevelConnectResult TryWinInetConnectA(
    const char* server,
    const std::uint16_t port) noexcept {
    SetLastError(ERROR_SUCCESS);
    const HINTERNET connection = InternetConnectA(
        nullptr, server, port, nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0);
    const DWORD error = GetLastError();
    if (connection != nullptr) {
        InternetCloseHandle(connection);
    }
    return {connection == nullptr, error};
}

std::uint32_t TryWinInetGetW(
    const wchar_t* const server,
    const std::uint16_t port) noexcept {
    const HINTERNET session = InternetOpenW(
        L"bolt-sandbox-network-test/1.0", INTERNET_OPEN_TYPE_DIRECT, nullptr,
        nullptr, 0);
    const HINTERNET connection = session == nullptr
                                     ? nullptr
                                     : InternetConnectW(
                                           session, server, port, nullptr,
                                           nullptr, INTERNET_SERVICE_HTTP, 0,
                                           0);
    const wchar_t* accept_types[] = {L"*/*", nullptr};
    const HINTERNET request = connection == nullptr
                                  ? nullptr
                                  : HttpOpenRequestW(
                                        connection, L"GET", L"/", nullptr,
                                        nullptr, accept_types,
                                        INTERNET_FLAG_NO_CACHE_WRITE |
                                            INTERNET_FLAG_RELOAD,
                                        0);
    const bool sent = request != nullptr &&
        HttpSendRequestW(request, nullptr, 0, nullptr, 0) != FALSE;
    char body[2]{};
    DWORD bytes_read = 0;
    const bool read = sent &&
        InternetReadFile(request, body, sizeof(body), &bytes_read) != FALSE &&
        bytes_read == sizeof(body) && body[0] == 'o' && body[1] == 'k';
    if (request != nullptr) {
        InternetCloseHandle(request);
    }
    if (connection != nullptr) {
        InternetCloseHandle(connection);
    }
    if (session != nullptr) {
        InternetCloseHandle(session);
    }
    if (session == nullptr) {
        return 1;
    }
    if (connection == nullptr) {
        return 2;
    }
    if (request == nullptr) {
        return 3;
    }
    if (!sent) {
        return 4;
    }
    return read ? 0U : 5U;
}

}  // namespace bolt::tests
