#include "hook/network/dns_proxy_client.h"

namespace bolt::network {

DnsProxyClientStatus ConsumeDnsProxyResponse(
    const protocol::DnsProxySession& session,
    const std::uint64_t expected_sequence,
    const std::uint8_t* const encoded_response,
    const std::size_t response_length,
    const std::array<std::uint8_t, 16>& session_id,
    const std::uint32_t process_id,
    const char* const ascii_domain,
    const std::uint16_t port,
    const std::uint64_t now,
    DnsBindingTable& bindings,
    std::vector<protocol::DnsProxyAddress>* const resolved_addresses) noexcept {
    if (resolved_addresses != nullptr) {
        resolved_addresses->clear();
    }
    if (ascii_domain == nullptr || process_id == 0) {
        return DnsProxyClientStatus::kInvalidArgument;
    }
    protocol::DnsProxyResponse response{};
    if (protocol::DecodeDnsProxyResponse(
            session, encoded_response, response_length, expected_sequence,
            response) != protocol::DnsProxyStatus::kSuccess) {
        return DnsProxyClientStatus::kProtocolFailed;
    }
    if (response.result == protocol::DnsProxyResult::kDenied) {
        return DnsProxyClientStatus::kDenied;
    }
    if (response.result == protocol::DnsProxyResult::kNotFound) {
        return DnsProxyClientStatus::kNotFound;
    }
    if (response.result == protocol::DnsProxyResult::kFailure) {
        return DnsProxyClientStatus::kResolverFailed;
    }
    for (const auto& address : response.addresses) {
        const AddressFamily family =
            address.family == protocol::DnsProxyAddressFamily::kIpv4
                ? AddressFamily::kIpv4
                : AddressFamily::kIpv6;
        const std::size_t address_length = family == AddressFamily::kIpv4 ? 4 : 16;
        const BindingKey key{
            session_id, process_id, ascii_domain, family, address.address.data(),
            address_length, port};
        const std::uint64_t ttl_milliseconds =
            static_cast<std::uint64_t>(address.ttl_seconds) * 1'000U;
        const auto status = bindings.Upsert(key, now, ttl_milliseconds);
        if (status != BindingStatus::kSuccess) {
            return DnsProxyClientStatus::kBindingFailed;
        }
    }
    if (resolved_addresses != nullptr) {
        try {
            *resolved_addresses = response.addresses;
        } catch (...) {
            resolved_addresses->clear();
            return DnsProxyClientStatus::kBindingFailed;
        }
    }
    return DnsProxyClientStatus::kSuccess;
}

}  // namespace bolt::network
