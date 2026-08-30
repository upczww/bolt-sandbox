#include "hook/network/dns_proxy_client.h"

#include <memory>
#include <vector>

bool RunDnsProxyClientTests() {
    bolt::protocol::DnsProxySession session{};
    session.nonce[0] = 1;
    session.authentication_key[0] = 2;
    bolt::protocol::DnsProxyAddress address{};
    address.address[0] = 192;
    address.address[1] = 0;
    address.address[2] = 2;
    address.address[3] = 44;
    address.ttl_seconds = 2;
    std::vector<std::uint8_t> encoded;
    if (bolt::protocol::EncodeDnsProxyResponse(
            session, 1, bolt::protocol::DnsProxyResult::kSuccess, {address},
            encoded) != bolt::protocol::DnsProxyStatus::kSuccess) {
        return false;
    }
    std::unique_ptr<bolt::network::DnsBindingTable> table;
    if (bolt::network::DnsBindingTable::Create(4, table) !=
        bolt::network::BindingStatus::kSuccess) {
        return false;
    }
    const std::array<std::uint8_t, 16> session_id = {1};
    if (bolt::network::ConsumeDnsProxyResponse(
            session, 1, encoded.data(), encoded.size(), session_id, 77,
            "api.example", 443, 1'000, *table) !=
            bolt::network::DnsProxyClientStatus::kSuccess) {
        return false;
    }
    const std::array<std::uint8_t, 4> ip = {192, 0, 2, 44};
    const bolt::network::BindingKey key{
        session_id, 77, "api.example", bolt::network::AddressFamily::kIpv4,
        ip.data(), ip.size(), 443};
    if (!table->IsAuthorized(key, 2'999) || table->IsAuthorized(key, 3'000)) {
        return false;
    }
    encoded.back() ^= 1;
    std::unique_ptr<bolt::network::DnsBindingTable> clean_table;
    bolt::network::DnsBindingTable::Create(4, clean_table);
    return bolt::network::ConsumeDnsProxyResponse(
               session, 1, encoded.data(), encoded.size(), session_id, 77,
               "api.example", 443, 1'000, *clean_table) ==
               bolt::network::DnsProxyClientStatus::kProtocolFailed &&
           clean_table->ActiveCount(1'000) == 0;
}
