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

}  // namespace bolt::tests
