#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace bolt::protocol {

inline constexpr std::size_t kDnsProxyNonceLength = 16;
inline constexpr std::size_t kDnsProxyAuthenticationKeyLength = 32;
inline constexpr std::size_t kDnsProxyMacLength = 32;
inline constexpr std::size_t kDnsProxyHeaderLength = 68;
inline constexpr std::size_t kDnsProxyMaximumDomainLength = 253;
inline constexpr std::size_t kDnsProxyMaximumAddressRecords = 16;

struct DnsProxySession {
    std::array<std::uint8_t, kDnsProxyNonceLength> nonce{};
    std::array<std::uint8_t, kDnsProxyAuthenticationKeyLength> authentication_key{};
};

enum class DnsProxyQueryFamily : std::uint8_t {
    kAny = 0,
    kIpv4 = 4,
    kIpv6 = 6,
};

struct DnsProxyRequest {
    std::uint64_t sequence = 0;
    std::string ascii_domain;
    std::uint16_t port = 0;
    DnsProxyQueryFamily family = DnsProxyQueryFamily::kAny;
};

enum class DnsProxyAddressFamily : std::uint8_t {
    kIpv4 = 4,
    kIpv6 = 6,
};

struct DnsProxyAddress {
    DnsProxyAddressFamily family = DnsProxyAddressFamily::kIpv4;
    std::array<std::uint8_t, 16> address{};
    std::uint32_t ttl_seconds = 0;

    bool operator==(const DnsProxyAddress& other) const noexcept {
        return family == other.family && address == other.address &&
               ttl_seconds == other.ttl_seconds;
    }
};

enum class DnsProxyResult : std::uint8_t {
    kSuccess = 0,
    kDenied = 1,
    kNotFound = 2,
    kFailure = 3,
};

struct DnsProxyResponse {
    std::uint64_t sequence = 0;
    DnsProxyResult result = DnsProxyResult::kFailure;
    std::vector<DnsProxyAddress> addresses;
};

enum class DnsProxyStatus : std::uint8_t {
    kSuccess,
    kInvalidArgument,
    kInvalidLength,
    kInvalidMagic,
    kUnsupportedVersion,
    kUnexpectedKind,
    kSessionMismatch,
    kAuthenticationFailed,
    kUnexpectedSequence,
    kInvalidDomain,
    kInvalidPort,
    kAllocationFailed,
    kCryptoFailed,
};

std::size_t DnsProxyRequestFrameLength(const char* ascii_domain) noexcept;

DnsProxyStatus EncodeDnsProxyRequest(
    const DnsProxySession& session,
    std::uint64_t sequence,
    const char* ascii_domain,
    std::uint16_t port,
    std::vector<std::uint8_t>& encoded,
    DnsProxyQueryFamily family = DnsProxyQueryFamily::kAny) noexcept;

DnsProxyStatus DecodeDnsProxyRequest(
    const DnsProxySession& session,
    const std::uint8_t* encoded,
    std::size_t length,
    std::uint64_t expected_sequence,
    DnsProxyRequest& request) noexcept;

DnsProxyStatus EncodeDnsProxyResponse(
    const DnsProxySession& session,
    std::uint64_t sequence,
    DnsProxyResult result,
    const std::vector<DnsProxyAddress>& addresses,
    std::vector<std::uint8_t>& encoded) noexcept;

DnsProxyStatus DecodeDnsProxyResponse(
    const DnsProxySession& session,
    const std::uint8_t* encoded,
    std::size_t length,
    std::uint64_t expected_sequence,
    DnsProxyResponse& response) noexcept;

}  // namespace bolt::protocol
