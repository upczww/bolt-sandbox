#include "hook/network/http_connect_policy.h"

#include "tests/policy_fixture.h"

#include <cstring>
#include <memory>

bool RunHttpConnectPolicyTests() {
    bolt::tests::NetworkAddressRule loopback{};
    loopback.family = 4;
    loopback.prefix_length = 32;
    loopback.address[0] = 127;
    loopback.address[3] = 1;
    const bolt::tests::NetworkAllowListRules rules{
        {{false, "allowed.example"}}, {loopback}, {{443, 443}}};
    const auto payload = bolt::tests::SealPolicy(
        {}, bolt::tests::ChildProcessPolicyKind::kInherit,
        bolt::tests::NetworkPolicyKind::kAllowList, rules);
    std::unique_ptr<bolt::network::NetworkPolicy> policy;
    if (bolt::network::NetworkPolicy::Load(
            payload.data(), payload.size(), policy) !=
        bolt::network::PolicyLoadStatus::kValid) {
        return false;
    }

    const char allowed[] =
        "CONNECT allowed.example:443 HTTP/1.1\r\nHost: allowed.example\r\n\r\n";
    const char denied_domain[] =
        "CONNECT denied.example:443 HTTP/1.1\r\n\r\n";
    const char denied_port[] =
        "CONNECT allowed.example:444 HTTP/1.1\r\n\r\n";
    const char allowed_ipv4[] =
        "CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n";
    const char malformed[] = "CONNECT allowed.example HTTP/1.1\r\n\r\n";
    const char ordinary[] = "GET / HTTP/1.1\r\n\r\n";
    return bolt::network::InspectHttpConnectPreface(
               allowed, std::strlen(allowed), false, *policy) ==
               bolt::network::HttpConnectInspection::kAllow &&
           bolt::network::InspectHttpConnectPreface(
               denied_domain, std::strlen(denied_domain), false, *policy) ==
               bolt::network::HttpConnectInspection::kDeny &&
           bolt::network::InspectHttpConnectPreface(
               denied_port, std::strlen(denied_port), false, *policy) ==
               bolt::network::HttpConnectInspection::kDeny &&
           bolt::network::InspectHttpConnectPreface(
               allowed_ipv4, std::strlen(allowed_ipv4), false, *policy) ==
               bolt::network::HttpConnectInspection::kAllow &&
           bolt::network::InspectHttpConnectPreface(
               malformed, std::strlen(malformed), false, *policy) ==
               bolt::network::HttpConnectInspection::kDeny &&
           bolt::network::InspectHttpConnectPreface(
               ordinary, std::strlen(ordinary), false, *policy) ==
               bolt::network::HttpConnectInspection::kNotConnect &&
           bolt::network::InspectHttpConnectPreface(
               allowed, 4, false, *policy) ==
               bolt::network::HttpConnectInspection::kNeedMore &&
           bolt::network::InspectHttpConnectPreface(
               allowed, 4, true, *policy) ==
               bolt::network::HttpConnectInspection::kNotConnect;
}
