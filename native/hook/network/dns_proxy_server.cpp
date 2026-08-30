#include "hook/network/dns_proxy_server.h"

namespace bolt::network {

protocol::DnsProxyStatus ProcessDnsProxyRequest(
    const protocol::DnsProxySession& session,
    const NetworkPolicy& policy,
    const std::uint64_t expected_sequence,
    const std::uint8_t* const encoded_request,
    const std::size_t request_length,
    DnsResolver& resolver,
    std::vector<std::uint8_t>& encoded_response) noexcept {
    encoded_response.clear();
    protocol::DnsProxyRequest request{};
    const auto decode_status = protocol::DecodeDnsProxyRequest(
        session, encoded_request, request_length, expected_sequence, request);
    if (decode_status != protocol::DnsProxyStatus::kSuccess) {
        return decode_status;
    }

    if (policy.mode() != Mode::kAllowList ||
        policy.DecideDomain(request.ascii_domain.c_str()) != Decision::kAllow ||
        (request.port != 0 &&
         policy.DecidePort(request.port) != Decision::kAllow)) {
        return protocol::EncodeDnsProxyResponse(
            session, expected_sequence, protocol::DnsProxyResult::kDenied, {},
            encoded_response);
    }

    try {
        std::vector<protocol::DnsProxyAddress> addresses;
        addresses.reserve(protocol::kDnsProxyMaximumAddressRecords);
        protocol::DnsProxyResult result =
            resolver.Resolve(
                request.ascii_domain.c_str(), request.family, addresses);
        if (result != protocol::DnsProxyResult::kSuccess) {
            addresses.clear();
        } else if (addresses.empty() ||
                   addresses.size() > protocol::kDnsProxyMaximumAddressRecords) {
            result = protocol::DnsProxyResult::kFailure;
            addresses.clear();
        }
        return protocol::EncodeDnsProxyResponse(
            session, expected_sequence, result, addresses, encoded_response);
    } catch (...) {
        encoded_response.clear();
        return protocol::DnsProxyStatus::kAllocationFailed;
    }
}

}  // namespace bolt::network
