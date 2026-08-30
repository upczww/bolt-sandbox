#pragma once

#include "hook/network/dns_binding_table.h"
#include "hook/network/network_policy.h"
#include "protocol/tcp_proxy_protocol.h"

#include <cstdint>

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>

namespace bolt::network {

enum class TcpProxyConnectionStatus : std::uint8_t {
    kRelayed,
    kRejected,
    kInvalidSocket,
    kReadFailed,
    kInvalidFrameLength,
    kAllocationFailed,
    kProtocolFailed,
    kWriteFailed,
    kRelayFailed,
};

TcpProxyConnectionStatus RunTcpProxyConnection(
    SOCKET client,
    const protocol::DnsProxySession& session,
    const NetworkPolicy& policy,
    const DnsBindingTable& bindings,
    std::uint64_t expected_sequence,
    std::uint64_t now) noexcept;

}  // namespace bolt::network
