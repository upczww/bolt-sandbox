#pragma once

#include "protocol/dns_proxy_protocol.h"

#include <array>
#include <cstddef>
#include <cstdint>

namespace bolt::protocol {

inline constexpr std::size_t kDnsProxyStartupLength = 96;

struct DnsProxyStartup {
    std::uint32_t policy_length = 0;
    std::uint64_t policy_handle = 0;
    std::uint64_t read_handle = 0;
    std::uint64_t write_handle = 0;
    std::uint32_t maximum_frame_length = 0;
    std::uint32_t maximum_requests = 0;
    DnsProxySession session{};

    bool operator==(const DnsProxyStartup& other) const noexcept {
        return policy_length == other.policy_length &&
               policy_handle == other.policy_handle && read_handle == other.read_handle &&
               write_handle == other.write_handle &&
               maximum_frame_length == other.maximum_frame_length &&
               maximum_requests == other.maximum_requests &&
               session.nonce == other.session.nonce &&
               session.authentication_key == other.session.authentication_key;
    }
    bool operator!=(const DnsProxyStartup& other) const noexcept { return !(*this == other); }
};

enum class DnsProxyStartupStatus : std::uint8_t {
    kSuccess,
    kInvalidArgument,
    kInvalidLength,
    kInvalidMagic,
    kUnsupportedVersion,
    kInvalidHeaderLength,
    kInvalidPolicy,
    kInvalidHandle,
    kInvalidLimits,
    kInvalidSession,
};

std::array<std::uint8_t, kDnsProxyStartupLength> EncodeDnsProxyStartup(
    const DnsProxyStartup& startup) noexcept;

DnsProxyStartupStatus DecodeDnsProxyStartup(
    const std::uint8_t* encoded,
    std::size_t length,
    DnsProxyStartup& startup) noexcept;

}  // namespace bolt::protocol
