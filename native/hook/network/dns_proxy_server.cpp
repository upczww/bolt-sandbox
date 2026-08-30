#include "hook/network/dns_proxy_server.h"

namespace bolt::network {

protocol::DnsProxyStatus ProcessDnsProxyRequest(
    const protocol::DnsProxySession& session,
    const NetworkPolicy& policy,
    const std::uint64_t expected_sequence,
    const std::uint8_t* const encoded_request,
    const std::size_t request_length,
    DnsResolver& resolver,
    DnsBindingTable& bindings,
    const std::uint64_t now,
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
        } else {
            for (const auto& address : addresses) {
                const AddressFamily family =
                    address.family == protocol::DnsProxyAddressFamily::kIpv4
                        ? AddressFamily::kIpv4
                        : AddressFamily::kIpv6;
                const std::size_t address_length =
                    family == AddressFamily::kIpv4 ? 4 : 16;
                const BindingKey key{
                    session.nonce, request.process_id,
                    request.ascii_domain.c_str(), family,
                    address.address.data(), address_length, request.port};
                const std::uint64_t ttl_milliseconds =
                    static_cast<std::uint64_t>(address.ttl_seconds) * 1'000U;
                if (bindings.Upsert(key, now, ttl_milliseconds) !=
                    BindingStatus::kSuccess) {
                    result = protocol::DnsProxyResult::kFailure;
                    addresses.clear();
                    break;
                }
            }
        }
        return protocol::EncodeDnsProxyResponse(
            session, expected_sequence, result, addresses, encoded_response);
    } catch (...) {
        encoded_response.clear();
        return protocol::DnsProxyStatus::kAllocationFailed;
    }
}

}  // namespace bolt::network
