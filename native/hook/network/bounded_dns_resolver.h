#pragma once

#include "hook/network/dns_proxy_server.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>

namespace bolt::network {

class BoundedDnsResolver final : public DnsResolver {
  public:
    BoundedDnsResolver(
        std::shared_ptr<DnsResolver> resolver,
        std::uint32_t timeout_milliseconds) noexcept;

    protocol::DnsProxyResult Resolve(
        const char* ascii_domain,
        protocol::DnsProxyQueryFamily family,
        std::vector<protocol::DnsProxyAddress>& addresses) noexcept override;

  private:
    std::shared_ptr<DnsResolver> resolver_;
    std::uint32_t timeout_milliseconds_ = 0;
    std::atomic<bool> poisoned_ = false;
    std::mutex resolve_lock_;
};

}  // namespace bolt::network
