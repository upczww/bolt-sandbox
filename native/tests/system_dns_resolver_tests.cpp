#include "hook/network/system_dns_resolver.h"

#include <vector>

bool RunSystemDnsResolverTests() {
    bolt::network::SystemDnsResolver resolver;
    std::vector<bolt::protocol::DnsProxyAddress> addresses;
    const auto result = resolver.Resolve(
        "localhost", bolt::protocol::DnsProxyQueryFamily::kAny, addresses);
    if (result != bolt::protocol::DnsProxyResult::kSuccess || addresses.empty() ||
        addresses.size() > bolt::protocol::kDnsProxyMaximumAddressRecords) {
        return false;
    }
    for (const auto& address : addresses) {
        if (address.ttl_seconds == 0) {
            return false;
        }
    }
    addresses.push_back({});
    const auto invalid = resolver.Resolve(
        "bad domain", bolt::protocol::DnsProxyQueryFamily::kAny, addresses);
    return invalid != bolt::protocol::DnsProxyResult::kSuccess && addresses.empty();
}
