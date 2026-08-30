#pragma once

#include "hook/network/dns_proxy_server.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace bolt::network {

enum class TransportReadStatus : std::uint8_t {
    kFrame,
    kEof,
    kFailure,
};

class DnsProxyTransport {
  public:
    virtual ~DnsProxyTransport() = default;
    virtual TransportReadStatus ReadFrame(
        std::vector<std::uint8_t>& frame) noexcept = 0;
    virtual bool WriteFrame(const std::vector<std::uint8_t>& frame) noexcept = 0;
};

enum class DnsProxySessionStatus : std::uint8_t {
    kCompleted,
    kTransportFailed,
    kProtocolFailed,
    kLimitReached,
};

DnsProxySessionStatus RunDnsProxySession(
    const protocol::DnsProxySession& session,
    const NetworkPolicy& policy,
    DnsResolver& resolver,
    DnsBindingTable& bindings,
    DnsProxyTransport& transport,
    std::size_t maximum_requests) noexcept;

}  // namespace bolt::network
