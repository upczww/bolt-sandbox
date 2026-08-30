#include "protocol/dns_proxy_protocol.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

bool RunDnsProxyProtocolTests() {
    bolt::protocol::DnsProxySession session{};
    for (std::size_t index = 0; index < session.nonce.size(); ++index) {
        session.nonce[index] = static_cast<std::uint8_t>(index + 1U);
    }
    for (std::size_t index = 0; index < session.authentication_key.size(); ++index) {
        session.authentication_key[index] = static_cast<std::uint8_t>(0x80U + index);
    }

    std::vector<std::uint8_t> encoded;
    if (bolt::protocol::EncodeDnsProxyRequest(
            session, 7, 1'234, "api.example", 443, encoded) !=
            bolt::protocol::DnsProxyStatus::kSuccess ||
        encoded.size() != bolt::protocol::DnsProxyRequestFrameLength("api.example")) {
        return false;
    }
    bolt::protocol::DnsProxyRequest decoded{};
    if (bolt::protocol::DecodeDnsProxyRequest(
            session, encoded.data(), encoded.size(), 7, decoded) !=
            bolt::protocol::DnsProxyStatus::kSuccess ||
        decoded.sequence != 7 || decoded.process_id != 1'234 ||
        decoded.port != 443 ||
        decoded.ascii_domain != "api.example") {
        return false;
    }

    auto tampered = encoded;
    tampered.back() ^= 0x01;
    if (bolt::protocol::DecodeDnsProxyRequest(
            session, tampered.data(), tampered.size(), 7, decoded) !=
            bolt::protocol::DnsProxyStatus::kAuthenticationFailed ||
        bolt::protocol::DecodeDnsProxyRequest(
            session, encoded.data(), encoded.size(), 8, decoded) !=
            bolt::protocol::DnsProxyStatus::kUnexpectedSequence ||
        bolt::protocol::DecodeDnsProxyRequest(
            session, encoded.data(), encoded.size() - 1, 7, decoded) !=
            bolt::protocol::DnsProxyStatus::kInvalidLength) {
        return false;
    }

    auto wrong_session = session;
    wrong_session.nonce[0] ^= 0xff;
    if (bolt::protocol::DecodeDnsProxyRequest(
            wrong_session, encoded.data(), encoded.size(), 7, decoded) !=
        bolt::protocol::DnsProxyStatus::kSessionMismatch) {
        return false;
    }

    bolt::protocol::DnsProxyAddress ipv4{};
    ipv4.family = bolt::protocol::DnsProxyAddressFamily::kIpv4;
    ipv4.address[0] = 192;
    ipv4.address[1] = 0;
    ipv4.address[2] = 2;
    ipv4.address[3] = 10;
    ipv4.ttl_seconds = 60;
    bolt::protocol::DnsProxyAddress ipv6{};
    ipv6.family = bolt::protocol::DnsProxyAddressFamily::kIpv6;
    ipv6.address[0] = 0x20;
    ipv6.address[1] = 0x01;
    ipv6.address[2] = 0x0d;
    ipv6.address[3] = 0xb8;
    ipv6.address[15] = 1;
    ipv6.ttl_seconds = 120;
    const std::vector<bolt::protocol::DnsProxyAddress> addresses = {ipv4, ipv6};
    if (bolt::protocol::EncodeDnsProxyResponse(
            session, 7, bolt::protocol::DnsProxyResult::kSuccess, addresses,
            encoded) != bolt::protocol::DnsProxyStatus::kSuccess) {
        return false;
    }
    bolt::protocol::DnsProxyResponse response{};
    if (bolt::protocol::DecodeDnsProxyResponse(
            session, encoded.data(), encoded.size(), 7, response) !=
            bolt::protocol::DnsProxyStatus::kSuccess ||
        response.result != bolt::protocol::DnsProxyResult::kSuccess ||
        response.addresses != addresses) {
        return false;
    }
    tampered = encoded;
    tampered.back() ^= 1;
    if (bolt::protocol::DecodeDnsProxyResponse(
            session, tampered.data(), tampered.size(), 7, response) !=
        bolt::protocol::DnsProxyStatus::kAuthenticationFailed) {
        return false;
    }
    auto invalid_ttl = addresses;
    invalid_ttl[0].ttl_seconds = 0;
    std::vector<bolt::protocol::DnsProxyAddress> too_many(17, ipv4);
    if (bolt::protocol::EncodeDnsProxyResponse(
            session, 8, bolt::protocol::DnsProxyResult::kSuccess, {}, encoded) !=
            bolt::protocol::DnsProxyStatus::kInvalidArgument ||
        bolt::protocol::EncodeDnsProxyResponse(
            session, 8, bolt::protocol::DnsProxyResult::kDenied, addresses,
            encoded) != bolt::protocol::DnsProxyStatus::kInvalidArgument ||
        bolt::protocol::EncodeDnsProxyResponse(
            session, 8, bolt::protocol::DnsProxyResult::kSuccess, invalid_ttl,
            encoded) != bolt::protocol::DnsProxyStatus::kInvalidArgument ||
        bolt::protocol::EncodeDnsProxyResponse(
            session, 8, bolt::protocol::DnsProxyResult::kSuccess, too_many,
            encoded) != bolt::protocol::DnsProxyStatus::kInvalidArgument) {
        return false;
    }

    std::string maximum_domain(253, 'a');
    std::string oversized_domain(254, 'a');
    bolt::protocol::DnsProxySession invalid_session{};
    return bolt::protocol::EncodeDnsProxyRequest(
               session, 8, 1'234, maximum_domain.c_str(), 65'535, encoded) ==
               bolt::protocol::DnsProxyStatus::kSuccess &&
           bolt::protocol::EncodeDnsProxyRequest(
               session, 9, 1'234, oversized_domain.c_str(), 443, encoded) ==
               bolt::protocol::DnsProxyStatus::kInvalidDomain &&
           bolt::protocol::EncodeDnsProxyRequest(
               session, 9, 1'234, "api.example", 0, encoded,
               bolt::protocol::DnsProxyQueryFamily::kIpv4) ==
               bolt::protocol::DnsProxyStatus::kSuccess &&
           bolt::protocol::EncodeDnsProxyRequest(
               invalid_session, 1, 1'234, "api.example", 443, encoded) ==
               bolt::protocol::DnsProxyStatus::kInvalidArgument &&
           bolt::protocol::EncodeDnsProxyRequest(
               session, 0, 1'234, "api.example", 443, encoded) ==
               bolt::protocol::DnsProxyStatus::kInvalidArgument;
}
