#include "hook/network/system_dns_resolver.h"

#include "hook/network/dns_record_parser.h"

#include <algorithm>
#include <cstring>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <windns.h>

namespace bolt::network {
namespace {

struct QueryResult {
    DNS_STATUS status = DNS_INFO_NO_RECORDS;
    DnsRecordParseStatus parse_status = DnsRecordParseStatus::kNotFound;
};

QueryResult Query(
    const char* domain,
    const WORD type,
    std::vector<protocol::DnsProxyAddress>& addresses) {
    DNS_RECORD* records = nullptr;
    const DNS_STATUS status = DnsQuery_A(
        domain, type, DNS_QUERY_STANDARD, nullptr, &records, nullptr);
    DnsRecordParseStatus parse_status = DnsRecordParseStatus::kNotFound;
    if (status == ERROR_SUCCESS) {
        std::vector<protocol::DnsProxyAddress> parsed;
        parse_status =
            CollectValidatedDnsAddresses(domain, type, records, parsed);
        if (parse_status == DnsRecordParseStatus::kSuccess) {
            for (const auto& address : parsed) {
                if (std::find(addresses.begin(), addresses.end(), address) ==
                    addresses.end()) {
                    if (addresses.size() ==
                        protocol::kDnsProxyMaximumAddressRecords) {
                        addresses.clear();
                        parse_status = DnsRecordParseStatus::kInvalid;
                        break;
                    }
                    addresses.push_back(address);
                }
            }
        }
    }
    if (records != nullptr) {
        DnsRecordListFree(records, DnsFreeRecordList);
    }
    return {status, parse_status};
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
        QueryResult ipv4{};
        QueryResult ipv6{};
        if (family == protocol::DnsProxyQueryFamily::kAny ||
            family == protocol::DnsProxyQueryFamily::kIpv4) {
            ipv4 = Query(ascii_domain, DNS_TYPE_A, addresses);
        }
        if (family == protocol::DnsProxyQueryFamily::kAny ||
            family == protocol::DnsProxyQueryFamily::kIpv6) {
            ipv6 = Query(ascii_domain, DNS_TYPE_AAAA, addresses);
        }
        if (ipv4.parse_status == DnsRecordParseStatus::kInvalid ||
            ipv6.parse_status == DnsRecordParseStatus::kInvalid) {
            addresses.clear();
            return protocol::DnsProxyResult::kFailure;
        }
        if (!addresses.empty()) {
            return protocol::DnsProxyResult::kSuccess;
        }
        if (ipv4.status == DNS_ERROR_RCODE_NAME_ERROR ||
            ipv6.status == DNS_ERROR_RCODE_NAME_ERROR ||
            ipv4.status == DNS_INFO_NO_RECORDS ||
            ipv6.status == DNS_INFO_NO_RECORDS) {
            return protocol::DnsProxyResult::kNotFound;
        }
        return protocol::DnsProxyResult::kFailure;
    } catch (...) {
        addresses.clear();
        return protocol::DnsProxyResult::kFailure;
    }
}

}  // namespace bolt::network
