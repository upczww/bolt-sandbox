#pragma once

#include "hook/network/dns_proxy_client.h"
#include "hook/network/dns_proxy_session.h"

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

namespace bolt::network {

enum class DnsProxyChannelStatus : std::uint8_t {
    kSuccess,
    kDenied,
    kNotFound,
    kResolverFailed,
    kTransportFailed,
    kProtocolFailed,
    kBindingFailed,
    kInvalidArgument,
    kClosed,
};

class DnsProxyClientChannel final {
  public:
    ~DnsProxyClientChannel();
    DnsProxyClientChannel(const DnsProxyClientChannel&) = delete;
    DnsProxyClientChannel& operator=(const DnsProxyClientChannel&) = delete;

    static DnsProxyChannelStatus Create(
        const protocol::DnsProxySession& session,
        const std::array<std::uint8_t, 16>& session_id,
        std::uint32_t process_id,
        std::unique_ptr<DnsProxyTransport> transport,
        DnsBindingTable& bindings,
        std::unique_ptr<DnsProxyClientChannel>& channel) noexcept;

    DnsProxyChannelStatus Resolve(
        const char* ascii_domain,
        std::uint16_t port,
        std::uint64_t now,
        std::vector<protocol::DnsProxyAddress>* resolved_addresses = nullptr,
        protocol::DnsProxyQueryFamily family =
            protocol::DnsProxyQueryFamily::kAny) noexcept;

  private:
    struct Impl;
    explicit DnsProxyClientChannel(std::unique_ptr<Impl> implementation) noexcept;
    std::unique_ptr<Impl> implementation_;
};

}  // namespace bolt::network
