#pragma once

#include "hook/network/dns_proxy_server.h"

namespace bolt::network {

class SystemDnsResolver final : public DnsResolver {
  public:
    protocol::DnsProxyResult Resolve(
        const char* ascii_domain,
        protocol::DnsProxyQueryFamily family,
        std::vector<protocol::DnsProxyAddress>& addresses) noexcept override;
};

}  // namespace bolt::network
