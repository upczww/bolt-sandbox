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

}  // namespace bolt::tests
