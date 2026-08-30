#pragma once

#include "hook/network/dns_binding_table.h"
#include "protocol/dns_proxy_protocol.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace bolt::network {

enum class DnsProxyClientStatus : std::uint8_t {
    kSuccess,
    kDenied,
    kNotFound,
    kResolverFailed,
    kProtocolFailed,
    kBindingFailed,
    kInvalidArgument,
};

DnsProxyClientStatus ConsumeDnsProxyResponse(
    const protocol::DnsProxySession& session,
    std::uint64_t expected_sequence,
    const std::uint8_t* encoded_response,
    std::size_t response_length,
    const std::array<std::uint8_t, 16>& session_id,
    std::uint32_t process_id,
    const char* ascii_domain,
    std::uint16_t port,
    std::uint64_t now,
    DnsBindingTable& bindings,
    std::vector<protocol::DnsProxyAddress>* resolved_addresses = nullptr) noexcept;

}  // namespace bolt::network
