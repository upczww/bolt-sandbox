#pragma once

#include "hook/network/network_policy.h"
#include "protocol/dns_proxy_protocol.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace bolt::network {

class DnsResolver {
  public:
    virtual ~DnsResolver() = default;

    virtual protocol::DnsProxyResult Resolve(
        const char* ascii_domain,
        protocol::DnsProxyQueryFamily family,
        std::vector<protocol::DnsProxyAddress>& addresses) noexcept = 0;
};

protocol::DnsProxyStatus ProcessDnsProxyRequest(
    const protocol::DnsProxySession& session,
    const NetworkPolicy& policy,
    std::uint64_t expected_sequence,
    const std::uint8_t* encoded_request,
    std::size_t request_length,
    DnsResolver& resolver,
    std::vector<std::uint8_t>& encoded_response) noexcept;

}  // namespace bolt::network
