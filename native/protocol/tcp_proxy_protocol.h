#pragma once

#include "protocol/dns_proxy_protocol.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace bolt::protocol {

inline constexpr std::size_t kTcpProxyMaximumDomainLength = 253;

struct TcpProxyRequest {
    std::uint64_t sequence = 0;
    std::uint32_t process_id = 0;
    DnsProxyAddressFamily family = DnsProxyAddressFamily::kIpv4;
    std::array<std::uint8_t, 16> address{};
    std::uint16_t port = 0;
    std::string ascii_domain;
};

enum class TcpProxyResult : std::uint8_t {
    kConnected = 0,
    kDenied = 1,
    kConnectFailed = 2,
    kFailure = 3,
};

struct TcpProxyResponse {
    std::uint64_t sequence = 0;
    TcpProxyResult result = TcpProxyResult::kFailure;
    std::uint32_t network_error = 0;
};

enum class TcpProxyStatus : std::uint8_t {
    kSuccess,
    kInvalidArgument,
    kInvalidLength,
    kInvalidMagic,
    kUnsupportedVersion,
    kUnexpectedKind,
    kSessionMismatch,
    kAuthenticationFailed,
    kUnexpectedSequence,
    kInvalidProcess,
    kInvalidAddress,
    kInvalidPort,
    kInvalidDomain,
    kAllocationFailed,
    kCryptoFailed,
};

std::size_t TcpProxyRequestFrameLength(const char* ascii_domain) noexcept;

TcpProxyStatus EncodeTcpProxyRequest(
    const DnsProxySession& session,
    std::uint64_t sequence,
    std::uint32_t process_id,
    DnsProxyAddressFamily family,
    const std::array<std::uint8_t, 16>& address,
    std::uint16_t port,
    const char* ascii_domain,
    std::vector<std::uint8_t>& encoded) noexcept;

TcpProxyStatus DecodeTcpProxyRequest(
    const DnsProxySession& session,
    const std::uint8_t* encoded,
    std::size_t length,
    std::uint64_t expected_sequence,
    TcpProxyRequest& request) noexcept;

TcpProxyStatus EncodeTcpProxyResponse(
    const DnsProxySession& session,
    std::uint64_t sequence,
    TcpProxyResult result,
    std::uint32_t network_error,
    std::vector<std::uint8_t>& encoded) noexcept;

TcpProxyStatus DecodeTcpProxyResponse(
    const DnsProxySession& session,
    const std::uint8_t* encoded,
    std::size_t length,
    std::uint64_t expected_sequence,
    TcpProxyResponse& response) noexcept;

}  // namespace bolt::protocol
