#pragma once

#include <cstdint>

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>

namespace bolt::network {

enum class TcpRelayStatus : std::uint8_t {
    kCompleted,
    kInvalidSocket,
    kSelectFailed,
    kReadFailed,
    kWriteFailed,
    kShutdownFailed,
};

TcpRelayStatus RelayTcpSockets(SOCKET client, SOCKET upstream) noexcept;

}  // namespace bolt::network
