#include "protocol/tcp_proxy_protocol.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace {

bolt::protocol::DnsProxySession TestSession() {
    bolt::protocol::DnsProxySession session{};
    for (std::size_t index = 0; index < session.nonce.size(); ++index) {
        session.nonce[index] = static_cast<std::uint8_t>(index + 1U);
    }
    for (std::size_t index = 0;
         index < session.authentication_key.size(); ++index) {
        session.authentication_key[index] =
            static_cast<std::uint8_t>(0xA0U + index);
    }
    return session;
}

}  // namespace

bool RunTcpProxyProtocolTests() {
    const auto session = TestSession();
    std::array<std::uint8_t, 16> ipv4{};
    ipv4[0] = 192;
    ipv4[1] = 0;
    ipv4[2] = 2;
    ipv4[3] = 44;

    std::vector<std::uint8_t> encoded;
    if (bolt::protocol::EncodeTcpProxyRequest(
            session, 9, 1'234,
            bolt::protocol::DnsProxyAddressFamily::kIpv4, ipv4, 443,
            "api.example", encoded) !=
            bolt::protocol::TcpProxyStatus::kSuccess ||
        encoded.size() !=
            bolt::protocol::TcpProxyRequestFrameLength("api.example")) {
        return false;
    }
    bolt::protocol::TcpProxyRequest request{};
    if (bolt::protocol::DecodeTcpProxyRequest(
            session, encoded.data(), encoded.size(), 9, request) !=
            bolt::protocol::TcpProxyStatus::kSuccess ||
        request.sequence != 9 || request.process_id != 1'234 ||
        request.family != bolt::protocol::DnsProxyAddressFamily::kIpv4 ||
        request.address != ipv4 || request.port != 443 ||
        request.ascii_domain != "api.example") {
        return false;
    }

    auto tampered = encoded;
    tampered[tampered.size() - 1] ^= 0x01;
    if (bolt::protocol::DecodeTcpProxyRequest(
            session, tampered.data(), tampered.size(), 9, request) !=
            bolt::protocol::TcpProxyStatus::kAuthenticationFailed ||
        bolt::protocol::DecodeTcpProxyRequest(
            session, encoded.data(), encoded.size(), 10, request) !=
            bolt::protocol::TcpProxyStatus::kUnexpectedSequence ||
        bolt::protocol::DecodeTcpProxyRequest(
            session, encoded.data(), encoded.size() - 1, 9, request) !=
            bolt::protocol::TcpProxyStatus::kInvalidLength) {
        return false;
    }
    auto wrong_session = session;
    wrong_session.nonce[0] ^= 0xFF;
    if (bolt::protocol::DecodeTcpProxyRequest(
            wrong_session, encoded.data(), encoded.size(), 9, request) !=
        bolt::protocol::TcpProxyStatus::kSessionMismatch) {
        return false;
    }

    std::array<std::uint8_t, 16> ipv6{};
    ipv6[0] = 0x20;
    ipv6[1] = 0x01;
    ipv6[2] = 0x0D;
    ipv6[3] = 0xB8;
    ipv6[15] = 1;
    if (bolt::protocol::EncodeTcpProxyRequest(
            session, 10, 5'678,
            bolt::protocol::DnsProxyAddressFamily::kIpv6, ipv6, 8'080,
            nullptr, encoded) != bolt::protocol::TcpProxyStatus::kSuccess ||
        bolt::protocol::DecodeTcpProxyRequest(
            session, encoded.data(), encoded.size(), 10, request) !=
            bolt::protocol::TcpProxyStatus::kSuccess ||
        !request.ascii_domain.empty() || request.address != ipv6) {
        return false;
    }

    std::array<std::uint8_t, 16> invalid_ipv4 = ipv4;
    invalid_ipv4[4] = 1;
    std::string maximum_domain(
        bolt::protocol::kTcpProxyMaximumDomainLength, 'a');
    std::string oversized_domain(
        bolt::protocol::kTcpProxyMaximumDomainLength + 1, 'a');
    bolt::protocol::DnsProxySession invalid_session{};
    if (bolt::protocol::EncodeTcpProxyRequest(
            session, 11, 1,
            bolt::protocol::DnsProxyAddressFamily::kIpv4, invalid_ipv4, 443,
            nullptr, encoded) != bolt::protocol::TcpProxyStatus::kInvalidAddress ||
        bolt::protocol::EncodeTcpProxyRequest(
            session, 11, 0,
            bolt::protocol::DnsProxyAddressFamily::kIpv4, ipv4, 443, nullptr,
            encoded) != bolt::protocol::TcpProxyStatus::kInvalidProcess ||
        bolt::protocol::EncodeTcpProxyRequest(
            session, 11, 1,
            bolt::protocol::DnsProxyAddressFamily::kIpv4, ipv4, 0, nullptr,
            encoded) != bolt::protocol::TcpProxyStatus::kInvalidPort ||
        bolt::protocol::EncodeTcpProxyRequest(
            session, 11, 1,
            bolt::protocol::DnsProxyAddressFamily::kIpv4, ipv4, 443,
            oversized_domain.c_str(), encoded) !=
            bolt::protocol::TcpProxyStatus::kInvalidDomain ||
        bolt::protocol::EncodeTcpProxyRequest(
            invalid_session, 11, 1,
            bolt::protocol::DnsProxyAddressFamily::kIpv4, ipv4, 443, nullptr,
            encoded) != bolt::protocol::TcpProxyStatus::kInvalidArgument ||
        bolt::protocol::EncodeTcpProxyRequest(
            session, 0, 1,
            bolt::protocol::DnsProxyAddressFamily::kIpv4, ipv4, 443, nullptr,
            encoded) != bolt::protocol::TcpProxyStatus::kInvalidArgument ||
        bolt::protocol::EncodeTcpProxyRequest(
            session, 12, 1,
            bolt::protocol::DnsProxyAddressFamily::kIpv4, ipv4, 443,
            maximum_domain.c_str(), encoded) !=
            bolt::protocol::TcpProxyStatus::kSuccess) {
        return false;
    }

    if (bolt::protocol::EncodeTcpProxyResponse(
            session, 12, bolt::protocol::TcpProxyResult::kConnected, 0,
            encoded) != bolt::protocol::TcpProxyStatus::kSuccess) {
        return false;
    }
    bolt::protocol::TcpProxyResponse response{};
    if (bolt::protocol::DecodeTcpProxyResponse(
            session, encoded.data(), encoded.size(), 12, response) !=
            bolt::protocol::TcpProxyStatus::kSuccess ||
        response.sequence != 12 ||
        response.result != bolt::protocol::TcpProxyResult::kConnected ||
        response.network_error != 0) {
        return false;
    }
    tampered = encoded;
    tampered.back() ^= 1;
    if (bolt::protocol::DecodeTcpProxyResponse(
            session, tampered.data(), tampered.size(), 12, response) !=
            bolt::protocol::TcpProxyStatus::kAuthenticationFailed ||
        bolt::protocol::EncodeTcpProxyResponse(
            session, 13, bolt::protocol::TcpProxyResult::kConnectFailed,
            10'061, encoded) != bolt::protocol::TcpProxyStatus::kSuccess ||
        bolt::protocol::DecodeTcpProxyResponse(
            session, encoded.data(), encoded.size(), 13, response) !=
            bolt::protocol::TcpProxyStatus::kSuccess ||
        response.network_error != 10'061 ||
        bolt::protocol::EncodeTcpProxyResponse(
            session, 14, bolt::protocol::TcpProxyResult::kConnected, 5,
            encoded) != bolt::protocol::TcpProxyStatus::kInvalidArgument ||
        bolt::protocol::EncodeTcpProxyResponse(
            session, 14, bolt::protocol::TcpProxyResult::kConnectFailed, 0,
            encoded) != bolt::protocol::TcpProxyStatus::kInvalidArgument ||
        bolt::protocol::EncodeTcpProxyResponse(
            session, 14, bolt::protocol::TcpProxyResult::kDenied, 5,
            encoded) != bolt::protocol::TcpProxyStatus::kInvalidArgument) {
        return false;
    }
    return true;
}
