#pragma once

#include <cstdint>

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>

namespace bolt::network {

class NetworkPolicy;

enum class TcpRelayStatus : std::uint8_t {
    kCompleted,
    kInvalidSocket,
    kSelectFailed,
    kReadFailed,
    kWriteFailed,
    kShutdownFailed,
    kPolicyDenied,
};

TcpRelayStatus RelayTcpSockets(SOCKET client, SOCKET upstream) noexcept;
TcpRelayStatus RelayTcpSocketsWithPolicy(
    SOCKET client,
    SOCKET upstream,
    const NetworkPolicy& policy) noexcept;

}  // namespace bolt::network
