#pragma once

#include "hook/network/network_policy.h"
#include "protocol/tcp_proxy_protocol.h"

#include <cstddef>
#include <cstdint>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>

namespace bolt::network {

using TcpConnectFunction = int(WSAAPI*)(SOCKET, const sockaddr*, int);

enum class TcpProxyClientStatus : std::uint8_t {
    kConnected,
    kDenied,
    kConnectFailed,
    kProxyFailure,
    kInvalidArgument,
    kProxyConnectFailed,
    kWriteFailed,
    kReadFailed,
    kProtocolFailed,
    kAllocationFailed,
};

TcpProxyClientStatus ConnectTcpSocketThroughProxy(
    SOCKET socket,
    TcpConnectFunction original_connect,
    std::uint16_t proxy_port,
    const protocol::DnsProxySession& session,
    std::uint64_t sequence,
    std::uint32_t process_id,
    AddressFamily family,
    const std::uint8_t* address,
    std::size_t address_length,
    std::uint16_t target_port,
    const char* ascii_domain,
    std::uint32_t& network_error) noexcept;

}  // namespace bolt::network
