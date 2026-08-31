#include "hook/network/dns_record_parser.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <string>

namespace bolt::network {
namespace {

constexpr std::size_t kMaximumCnameDepth = 16;
constexpr std::size_t kMaximumRecords = 1'024;

bool CanonicalizeName(const char* const name, std::string& canonical) {
    canonical.clear();
    if (name == nullptr) {
        return false;
    }
    std::size_t length = 0;
    while (length <= 254 && name[length] != '\0') {
        ++length;
    }
    if (length == 0 || length > 254) {
        return false;
    }
    if (name[length - 1] == '.') {
        --length;
    }
    if (length == 0 || length > 253 || name[length - 1] == '.') {
        return false;
    }
    canonical.reserve(length);
    std::size_t label_length = 0;
    for (std::size_t index = 0; index < length; ++index) {
        const auto byte = static_cast<unsigned char>(name[index]);
        if (byte == '.') {
            if (label_length == 0 || label_length > 63 ||
                canonical.back() == '-') {
                return false;
            }
            canonical.push_back('.');
            label_length = 0;
            continue;
        }
        const char lowered = static_cast<char>(std::tolower(byte));
        if (!((lowered >= 'a' && lowered <= 'z') ||
              (lowered >= '0' && lowered <= '9') || lowered == '-') ||
            (label_length == 0 && lowered == '-')) {
            return false;
        }
        canonical.push_back(lowered);
        ++label_length;
    }
    return label_length != 0 && label_length <= 63 &&
           canonical.back() != '-';
}

bool RecordListIsBoundedAndAcyclic(const DNS_RECORD* records) noexcept {
    const DNS_RECORD* slow = records;
    const DNS_RECORD* fast = records;
    std::size_t count = 0;
    while (slow != nullptr) {
        if (++count > kMaximumRecords) {
            return false;
        }
        slow = slow->pNext;
        if (fast != nullptr) {
            fast = fast->pNext;
        }
        if (fast != nullptr) {
            fast = fast->pNext;
        }
        if (slow != nullptr && slow == fast) {
            return false;
        }
    }
    return true;
}

}  // namespace

DnsRecordParseStatus CollectValidatedDnsAddresses(
    const char* const query_domain,
    const WORD query_type,
    const DNS_RECORD* const records,
    std::vector<protocol::DnsProxyAddress>& addresses) noexcept {
    addresses.clear();
    if ((query_type != DNS_TYPE_A && query_type != DNS_TYPE_AAAA) ||
        !RecordListIsBoundedAndAcyclic(records)) {
        return DnsRecordParseStatus::kInvalid;
    }
    try {
        std::string current;
        if (!CanonicalizeName(query_domain, current)) {
            return DnsRecordParseStatus::kInvalid;
        }
        std::array<std::string, kMaximumCnameDepth + 1> visited{};
        visited[0] = current;
        for (std::size_t depth = 0; depth <= kMaximumCnameDepth; ++depth) {
            std::string cname_target;
            bool cname_present = false;
            for (const DNS_RECORD* record = records; record != nullptr;
                 record = record->pNext) {
                std::string owner;
                if (!CanonicalizeName(record->pName, owner) ||
                    owner != current) {
                    continue;
                }
                if (record->wType == DNS_TYPE_CNAME) {
                    std::string target;
                    if (!CanonicalizeName(
                            record->Data.CNAME.pNameHost, target) ||
                        (cname_present && target != cname_target)) {
                        addresses.clear();
                        return DnsRecordParseStatus::kInvalid;
                    }
                    cname_target = std::move(target);
                    cname_present = true;
                    continue;
                }
                if (record->wType != query_type || record->dwTtl == 0) {
                    continue;
                }
                protocol::DnsProxyAddress address{};
                if (query_type == DNS_TYPE_A) {
                    address.family = protocol::DnsProxyAddressFamily::kIpv4;
                    std::memcpy(
                        address.address.data(), &record->Data.A.IpAddress, 4);
                } else {
                    address.family = protocol::DnsProxyAddressFamily::kIpv6;
                    std::copy_n(
                        record->Data.AAAA.Ip6Address.IP6Byte, 16,
                        address.address.begin());
                }
                address.ttl_seconds = record->dwTtl;
                if (std::find(addresses.begin(), addresses.end(), address) ==
                    addresses.end()) {
                    if (addresses.size() ==
                        protocol::kDnsProxyMaximumAddressRecords) {
                        addresses.clear();
                        return DnsRecordParseStatus::kInvalid;
                    }
                    addresses.push_back(address);
                }
            }
            if (!addresses.empty()) {
                if (cname_present) {
                    addresses.clear();
                    return DnsRecordParseStatus::kInvalid;
                }
                return DnsRecordParseStatus::kSuccess;
            }
            if (!cname_present) {
                return DnsRecordParseStatus::kNotFound;
            }
            if (depth == kMaximumCnameDepth ||
                std::find(
                    visited.begin(), visited.begin() + depth + 1,
                    cname_target) != visited.begin() + depth + 1) {
                return DnsRecordParseStatus::kInvalid;
            }
            current = std::move(cname_target);
            visited[depth + 1] = current;
        }
    } catch (...) {
        addresses.clear();
        return DnsRecordParseStatus::kInvalid;
    }
    addresses.clear();
    return DnsRecordParseStatus::kInvalid;
}

}  // namespace bolt::network
