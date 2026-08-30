#pragma once

#include "hook/network/dns_binding_table.h"
#include "hook/network/network_policy.h"
#include "protocol/tcp_proxy_protocol.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace bolt::network {

class TcpConnector {
  public:
    virtual ~TcpConnector() = default;

    virtual bool Connect(
        AddressFamily family,
        const std::uint8_t* address,
        std::size_t address_length,
        std::uint16_t port,
        std::uint32_t& network_error) noexcept = 0;
};

protocol::TcpProxyStatus ProcessTcpProxyRequest(
    const protocol::DnsProxySession& session,
    const NetworkPolicy& policy,
    const DnsBindingTable& bindings,
    std::uint64_t expected_sequence,
    const std::uint8_t* encoded_request,
    std::size_t request_length,
    std::uint64_t now,
    TcpConnector& connector,
    std::vector<std::uint8_t>& encoded_response) noexcept;

}  // namespace bolt::network
