#include "protocol/dns_proxy_startup.h"

bool RunDnsProxyStartupTests() {
    bolt::protocol::DnsProxyStartup startup{};
    startup.policy_length = 128;
    startup.policy_handle = 10;
    startup.read_handle = 11;
    startup.write_handle = 12;
    startup.maximum_frame_length = 1'024;
    startup.maximum_requests = 64;
    startup.session.nonce[0] = 1;
    startup.session.authentication_key[0] = 2;
    const auto encoded = bolt::protocol::EncodeDnsProxyStartup(startup);
    bolt::protocol::DnsProxyStartup decoded{};
    if (bolt::protocol::DecodeDnsProxyStartup(
            encoded.data(), encoded.size(), decoded) !=
            bolt::protocol::DnsProxyStartupStatus::kSuccess ||
        decoded != startup) {
        return false;
    }
    auto tampered = encoded;
    tampered[0] ^= 1;
    if (bolt::protocol::DecodeDnsProxyStartup(
            tampered.data(), tampered.size(), decoded) !=
            bolt::protocol::DnsProxyStartupStatus::kInvalidMagic ||
        bolt::protocol::DecodeDnsProxyStartup(
            encoded.data(), encoded.size() - 1, decoded) !=
            bolt::protocol::DnsProxyStartupStatus::kInvalidLength) {
        return false;
    }
    startup.maximum_frame_length = 0;
    return bolt::protocol::EncodeDnsProxyStartup(startup) ==
           std::array<std::uint8_t, bolt::protocol::kDnsProxyStartupLength>{};
}
