#include "hook/network/system_dns_resolver.h"

#include <algorithm>
#include <cstring>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <windns.h>

namespace bolt::network {
namespace {

void AppendRecords(
    const DNS_RECORD* records,
    std::vector<protocol::DnsProxyAddress>& addresses) {
    for (const DNS_RECORD* record = records;
         record != nullptr && addresses.size() < protocol::kDnsProxyMaximumAddressRecords;
         record = record->pNext) {
        protocol::DnsProxyAddress address{};
        if (record->wType == DNS_TYPE_A) {
            address.family = protocol::DnsProxyAddressFamily::kIpv4;
            std::memcpy(address.address.data(), &record->Data.A.IpAddress, 4);
        } else if (record->wType == DNS_TYPE_AAAA) {
            address.family = protocol::DnsProxyAddressFamily::kIpv6;
            std::copy_n(
                record->Data.AAAA.Ip6Address.IP6Byte, 16,
                address.address.begin());
        } else {
            continue;
        }
        if (record->dwTtl == 0) {
            continue;
        }
        address.ttl_seconds = record->dwTtl;
        if (std::find(addresses.begin(), addresses.end(), address) == addresses.end()) {
            addresses.push_back(address);
        }
    }
}

DNS_STATUS Query(
    const char* domain,
    const WORD type,
    std::vector<protocol::DnsProxyAddress>& addresses) {
    DNS_RECORD* records = nullptr;
    const DNS_STATUS status = DnsQuery_A(
        domain, type, DNS_QUERY_STANDARD, nullptr, &records, nullptr);
    if (status == ERROR_SUCCESS) {
        AppendRecords(records, addresses);
    }
    if (records != nullptr) {
        DnsRecordListFree(records, DnsFreeRecordList);
    }
    return status;
}

}  // namespace

protocol::DnsProxyResult SystemDnsResolver::Resolve(
    const char* const ascii_domain,
    const protocol::DnsProxyQueryFamily family,
    std::vector<protocol::DnsProxyAddress>& addresses) noexcept {
    addresses.clear();
    if (ascii_domain == nullptr || ascii_domain[0] == '\0') {
        return protocol::DnsProxyResult::kFailure;
    }
    try {
        DNS_STATUS ipv4 = DNS_INFO_NO_RECORDS;
        DNS_STATUS ipv6 = DNS_INFO_NO_RECORDS;
        if (family == protocol::DnsProxyQueryFamily::kAny ||
            family == protocol::DnsProxyQueryFamily::kIpv4) {
            ipv4 = Query(ascii_domain, DNS_TYPE_A, addresses);
        }
        if (family == protocol::DnsProxyQueryFamily::kAny ||
            family == protocol::DnsProxyQueryFamily::kIpv6) {
            ipv6 = Query(ascii_domain, DNS_TYPE_AAAA, addresses);
        }
        if (!addresses.empty()) {
            return protocol::DnsProxyResult::kSuccess;
        }
        if (ipv4 == DNS_ERROR_RCODE_NAME_ERROR || ipv6 == DNS_ERROR_RCODE_NAME_ERROR ||
            ipv4 == DNS_INFO_NO_RECORDS || ipv6 == DNS_INFO_NO_RECORDS) {
            return protocol::DnsProxyResult::kNotFound;
        }
        return protocol::DnsProxyResult::kFailure;
    } catch (...) {
        addresses.clear();
        return protocol::DnsProxyResult::kFailure;
    }
}

}  // namespace bolt::network
