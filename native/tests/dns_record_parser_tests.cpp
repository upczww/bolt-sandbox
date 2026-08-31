#include "hook/network/dns_record_parser.h"

#include <array>
#include <cstring>
#include <vector>

bool RunDnsRecordParserTests() {
    char query[] = "api.example";
    char edge[] = "edge.example";
    char final_name[] = "final.example";
    char unrelated[] = "unrelated.example";
    std::array<DNS_RECORD, 5> records{};
    records[0].pName = query;
    records[0].wType = DNS_TYPE_CNAME;
    records[0].Data.CNAME.pNameHost = edge;
    records[0].pNext = &records[1];
    records[1].pName = edge;
    records[1].wType = DNS_TYPE_CNAME;
    records[1].Data.CNAME.pNameHost = final_name;
    records[1].pNext = &records[2];
    records[2].pName = unrelated;
    records[2].wType = DNS_TYPE_A;
    records[2].dwTtl = 300;
    records[2].Data.A.IpAddress = 0x0100000AU;
    records[2].pNext = &records[3];
    records[3].pName = final_name;
    records[3].wType = DNS_TYPE_A;
    records[3].dwTtl = 30;
    records[3].Data.A.IpAddress = 0x140200C0U;
    records[3].pNext = &records[4];
    records[4].pName = final_name;
    records[4].wType = DNS_TYPE_A;
    records[4].dwTtl = 20;
    records[4].Data.A.IpAddress = 0x016433C6U;

    std::vector<bolt::protocol::DnsProxyAddress> addresses;
    const auto valid = bolt::network::CollectValidatedDnsAddresses(
        "API.EXAMPLE.", DNS_TYPE_A, records.data(), addresses);
    if (valid != bolt::network::DnsRecordParseStatus::kSuccess ||
        addresses.size() != 2 || addresses[0].ttl_seconds != 30 ||
        addresses[0].address[0] != 192 || addresses[0].address[1] != 0 ||
        addresses[0].address[2] != 2 || addresses[0].address[3] != 20 ||
        addresses[1].ttl_seconds != 20 ||
        addresses[1].address[0] != 198 || addresses[1].address[1] != 51 ||
        addresses[1].address[2] != 100 || addresses[1].address[3] != 1) {
        return false;
    }

    records[1].Data.CNAME.pNameHost = query;
    addresses.assign(1, {});
    if (bolt::network::CollectValidatedDnsAddresses(
            query, DNS_TYPE_A, records.data(), addresses) !=
            bolt::network::DnsRecordParseStatus::kInvalid ||
        !addresses.empty()) {
        return false;
    }

    records[1].Data.CNAME.pNameHost = final_name;
    records[3].dwTtl = 0;
    records[4].dwTtl = 0;
    if (bolt::network::CollectValidatedDnsAddresses(
            query, DNS_TYPE_A, records.data(), addresses) !=
            bolt::network::DnsRecordParseStatus::kNotFound ||
        !addresses.empty()) {
        return false;
    }

    DNS_RECORD ipv6_record{};
    ipv6_record.pName = query;
    ipv6_record.wType = DNS_TYPE_AAAA;
    ipv6_record.dwTtl = 60;
    ipv6_record.Data.AAAA.Ip6Address.IP6Byte[0] = 0x20;
    ipv6_record.Data.AAAA.Ip6Address.IP6Byte[1] = 0x01;
    ipv6_record.Data.AAAA.Ip6Address.IP6Byte[2] = 0x0d;
    ipv6_record.Data.AAAA.Ip6Address.IP6Byte[3] = 0xb8;
    ipv6_record.Data.AAAA.Ip6Address.IP6Byte[15] = 1;
    if (bolt::network::CollectValidatedDnsAddresses(
            query, DNS_TYPE_AAAA, &ipv6_record, addresses) !=
            bolt::network::DnsRecordParseStatus::kSuccess ||
        addresses.size() != 1 ||
        addresses[0].family !=
            bolt::protocol::DnsProxyAddressFamily::kIpv6 ||
        addresses[0].address[0] != 0x20 ||
        addresses[0].address[1] != 0x01 ||
        addresses[0].address[15] != 1) {
        return false;
    }

    std::array<DNS_RECORD, bolt::protocol::kDnsProxyMaximumAddressRecords + 1>
        oversized{};
    for (std::size_t index = 0; index < oversized.size(); ++index) {
        oversized[index].pName = query;
        oversized[index].wType = DNS_TYPE_A;
        oversized[index].dwTtl = 1;
        oversized[index].Data.A.IpAddress =
            static_cast<DWORD>(index + 1);
        oversized[index].pNext =
            index + 1 < oversized.size() ? &oversized[index + 1] : nullptr;
    }
    return bolt::network::CollectValidatedDnsAddresses(
               query, DNS_TYPE_A, oversized.data(), addresses) ==
               bolt::network::DnsRecordParseStatus::kInvalid &&
           addresses.empty();
}
