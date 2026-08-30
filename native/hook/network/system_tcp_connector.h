#pragma once

#include "hook/network/tcp_proxy_server.h"

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>

namespace bolt::network {

class SystemTcpConnector final : public TcpConnector {
  public:
    SystemTcpConnector() noexcept = default;
    ~SystemTcpConnector() noexcept override;

    SystemTcpConnector(const SystemTcpConnector&) = delete;
    SystemTcpConnector& operator=(const SystemTcpConnector&) = delete;
    SystemTcpConnector(SystemTcpConnector&&) = delete;
    SystemTcpConnector& operator=(SystemTcpConnector&&) = delete;

    bool Connect(
        AddressFamily family,
        const std::uint8_t* address,
        std::size_t address_length,
        std::uint16_t port,
        std::uint32_t& network_error) noexcept override;

    [[nodiscard]] SOCKET ReleaseSocket() noexcept;

  private:
    SOCKET socket_ = INVALID_SOCKET;
};

}  // namespace bolt::network
