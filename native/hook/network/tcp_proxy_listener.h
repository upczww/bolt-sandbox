#pragma once

#include "hook/network/dns_binding_table.h"
#include "hook/network/network_policy.h"
#include "protocol/dns_proxy_protocol.h"

#include <cstddef>
#include <cstdint>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>

namespace bolt::network {

enum class TcpProxyListenerStatus : std::uint8_t {
    kStopped,
    kInvalidArgument,
    kAcceptFailed,
    kLimitReached,
};

TcpProxyListenerStatus RunTcpProxyListener(
    SOCKET listener,
    const protocol::DnsProxySession& session,
    const NetworkPolicy& policy,
    const DnsBindingTable& bindings,
    std::size_t maximum_connections) noexcept;

}  // namespace bolt::network
