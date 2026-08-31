#include "hook/network/network_policy.h"
#include "tests/policy_fixture.h"

#include <array>
#include <memory>

namespace {

bool LoadsMode(
    const bolt::tests::NetworkPolicyKind encoded_mode,
    const bolt::network::Mode expected_mode,
    const bolt::network::Decision expected_decision) {
    const auto payload = bolt::tests::SealPolicy(
        {}, bolt::tests::ChildProcessPolicyKind::kInherit, encoded_mode);
    std::unique_ptr<bolt::network::NetworkPolicy> policy;
    return !payload.empty() &&
           bolt::network::NetworkPolicy::Load(payload.data(), payload.size(), policy) ==
               bolt::network::PolicyLoadStatus::kValid &&
           policy != nullptr && policy->mode() == expected_mode &&
           policy->DecideConnect() == expected_decision;
}

}  // namespace

bool RunNetworkPolicyTests() {
    if (!LoadsMode(
            bolt::tests::NetworkPolicyKind::kUnrestricted,
            bolt::network::Mode::kUnrestricted,
            bolt::network::Decision::kAllow) ||
        !LoadsMode(
            bolt::tests::NetworkPolicyKind::kDenied,
            bolt::network::Mode::kDenied,
            bolt::network::Decision::kDeny)) {
        return false;
    }

    bolt::tests::NetworkAddressRule ipv4_rule{};
    ipv4_rule.family = 4;
    ipv4_rule.prefix_length = 24;
    ipv4_rule.address[0] = 192;
    ipv4_rule.address[1] = 0;
    ipv4_rule.address[2] = 2;
    bolt::tests::NetworkAddressRule ipv6_rule{};
    ipv6_rule.family = 6;
    ipv6_rule.prefix_length = 32;
    ipv6_rule.address[0] = 0x20;
    ipv6_rule.address[1] = 0x01;
    ipv6_rule.address[2] = 0x0d;
    ipv6_rule.address[3] = 0xb8;
    bolt::tests::NetworkAddressRule ipv4_prefix_rule{};
    ipv4_prefix_rule.family = 4;
    ipv4_prefix_rule.prefix_length = 25;
    ipv4_prefix_rule.address[0] = 198;
    ipv4_prefix_rule.address[1] = 51;
    ipv4_prefix_rule.address[2] = 100;
    ipv4_prefix_rule.address[3] = 128;
    const bolt::tests::NetworkAllowListRules allow_list{
        {{false, "example.com"}, {true, "example.org"}},
        {ipv4_rule, ipv4_prefix_rule, ipv6_rule},
        {{443, 443}, {8'000, 8'080}},
    };
    const auto allow_list_payload = bolt::tests::SealPolicy(
        {}, bolt::tests::ChildProcessPolicyKind::kInherit,
        bolt::tests::NetworkPolicyKind::kAllowList, allow_list);
    std::unique_ptr<bolt::network::NetworkPolicy> policy;
    if (allow_list_payload.empty() ||
        bolt::network::NetworkPolicy::Load(
            allow_list_payload.data(), allow_list_payload.size(), policy) !=
            bolt::network::PolicyLoadStatus::kValid ||
        policy == nullptr || policy->mode() != bolt::network::Mode::kAllowList ||
        policy->DecideConnect() != bolt::network::Decision::kDeny ||
        policy->DecideDomain("example.com") != bolt::network::Decision::kAllow ||
        policy->DecideDomain("EXAMPLE.COM") != bolt::network::Decision::kAllow ||
        policy->DecideDomain("www.example.com") != bolt::network::Decision::kDeny ||
        policy->DecideDomain("example.org") != bolt::network::Decision::kDeny ||
        policy->DecideDomain("a.example.org") != bolt::network::Decision::kAllow ||
        policy->DecideDomain("evil-example.org") != bolt::network::Decision::kDeny ||
        policy->DecideDomain("example.com.") != bolt::network::Decision::kDeny ||
        policy->DecidePort(443) != bolt::network::Decision::kAllow ||
        policy->DecidePort(8'050) != bolt::network::Decision::kAllow ||
        policy->DecidePort(0) != bolt::network::Decision::kDeny ||
        policy->DecidePort(8'081) != bolt::network::Decision::kDeny) {
        return false;
    }

    const std::array<std::uint8_t, 4> allowed_ipv4 = {192, 0, 2, 255};
    const std::array<std::uint8_t, 4> denied_ipv4 = {192, 0, 3, 0};
    std::array<std::uint8_t, 16> allowed_ipv6{};
    allowed_ipv6[0] = 0x20;
    allowed_ipv6[1] = 0x01;
    allowed_ipv6[2] = 0x0d;
    allowed_ipv6[3] = 0xb8;
    allowed_ipv6[15] = 1;
    std::array<std::uint8_t, 16> denied_ipv6 = allowed_ipv6;
    denied_ipv6[3] = 0xb9;
    std::array<std::uint8_t, 16> ipv4_mapped_ipv6{};
    ipv4_mapped_ipv6[10] = 0xff;
    ipv4_mapped_ipv6[11] = 0xff;
    ipv4_mapped_ipv6[12] = 192;
    ipv4_mapped_ipv6[13] = 0;
    ipv4_mapped_ipv6[14] = 2;
    ipv4_mapped_ipv6[15] = 1;
    const std::array<std::uint8_t, 4> allowed_prefix_ipv4 = {198, 51, 100, 255};
    const std::array<std::uint8_t, 4> denied_prefix_ipv4 = {198, 51, 100, 127};
    if (policy->DecideAddress(
            bolt::network::AddressFamily::kIpv4, allowed_ipv4.data(),
            allowed_ipv4.size()) != bolt::network::Decision::kAllow ||
        policy->DecideAddress(
            bolt::network::AddressFamily::kIpv4, denied_ipv4.data(),
            denied_ipv4.size()) != bolt::network::Decision::kDeny ||
        policy->DecideAddress(
            bolt::network::AddressFamily::kIpv6, allowed_ipv6.data(),
            allowed_ipv6.size()) != bolt::network::Decision::kAllow ||
        policy->DecideAddress(
            bolt::network::AddressFamily::kIpv6, denied_ipv6.data(),
            denied_ipv6.size()) != bolt::network::Decision::kDeny ||
        policy->DecideAddress(
            bolt::network::AddressFamily::kIpv6, ipv4_mapped_ipv6.data(),
            ipv4_mapped_ipv6.size()) != bolt::network::Decision::kDeny ||
        policy->DecideAddress(
            bolt::network::AddressFamily::kIpv4, allowed_prefix_ipv4.data(),
            allowed_prefix_ipv4.size()) != bolt::network::Decision::kAllow ||
        policy->DecideAddress(
            bolt::network::AddressFamily::kIpv4, denied_prefix_ipv4.data(),
            denied_prefix_ipv4.size()) != bolt::network::Decision::kDeny) {
        return false;
    }

    const bolt::tests::NetworkAllowListRules localhost_allow_list{
        {{false, "localhost"}}, {}, {{80, 80}}};
    const auto localhost_payload = bolt::tests::SealPolicy(
        {}, bolt::tests::ChildProcessPolicyKind::kInherit,
        bolt::tests::NetworkPolicyKind::kAllowList, localhost_allow_list);
    if (localhost_payload.empty() ||
        bolt::network::NetworkPolicy::Load(
            localhost_payload.data(), localhost_payload.size(), policy) !=
            bolt::network::PolicyLoadStatus::kValid ||
        policy->DecideDomain("localhost") !=
            bolt::network::Decision::kAllow ||
        policy->DecideDomain("LOCALHOST") !=
            bolt::network::Decision::kAllow ||
        policy->DecideDomain("localhost.") !=
            bolt::network::Decision::kDeny ||
        policy->DecideDomain("localhost.localdomain") !=
            bolt::network::Decision::kDeny) {
        return false;
    }

    const auto empty_allow_list_payload = bolt::tests::SealPolicy(
        {}, bolt::tests::ChildProcessPolicyKind::kInherit,
        bolt::tests::NetworkPolicyKind::kAllowList);
    if (empty_allow_list_payload.empty() ||
        bolt::network::NetworkPolicy::Load(
            empty_allow_list_payload.data(), empty_allow_list_payload.size(),
            policy) != bolt::network::PolicyLoadStatus::kValid ||
        policy == nullptr || policy->DecideConnect() != bolt::network::Decision::kDeny ||
        policy->DecideDomain("example.com") != bolt::network::Decision::kDeny ||
        policy->DecidePort(443) != bolt::network::Decision::kDeny) {
        return false;
    }

    const bolt::tests::NetworkAllowListRules invalid_domain{
        {{false, "bad..example"}}, {}, {}};
    auto invalid_payload = bolt::tests::SealPolicy(
        {}, bolt::tests::ChildProcessPolicyKind::kInherit,
        bolt::tests::NetworkPolicyKind::kAllowList, invalid_domain);
    if (invalid_payload.empty() ||
        bolt::network::NetworkPolicy::Load(
            invalid_payload.data(), invalid_payload.size(), policy) !=
            bolt::network::PolicyLoadStatus::kInvalidNetworkPolicy ||
        policy != nullptr) {
        return false;
    }

    const bolt::tests::NetworkAllowListRules ip_literal_domain{
        {{false, "127.0.0.1"}}, {}, {}};
    invalid_payload = bolt::tests::SealPolicy(
        {}, bolt::tests::ChildProcessPolicyKind::kInherit,
        bolt::tests::NetworkPolicyKind::kAllowList, ip_literal_domain);
    if (invalid_payload.empty() ||
        bolt::network::NetworkPolicy::Load(
            invalid_payload.data(), invalid_payload.size(), policy) !=
            bolt::network::PolicyLoadStatus::kInvalidNetworkPolicy) {
        return false;
    }

    auto noncanonical_ipv4 = ipv4_rule;
    noncanonical_ipv4.address[3] = 1;
    const bolt::tests::NetworkAllowListRules invalid_cidr{
        {}, {noncanonical_ipv4}, {}};
    invalid_payload = bolt::tests::SealPolicy(
        {}, bolt::tests::ChildProcessPolicyKind::kInherit,
        bolt::tests::NetworkPolicyKind::kAllowList, invalid_cidr);
    if (invalid_payload.empty() ||
        bolt::network::NetworkPolicy::Load(
            invalid_payload.data(), invalid_payload.size(), policy) !=
            bolt::network::PolicyLoadStatus::kInvalidNetworkPolicy) {
        return false;
    }

    const bolt::tests::NetworkAllowListRules overlapping_ports{
        {}, {}, {{100, 200}, {200, 300}}};
    invalid_payload = bolt::tests::SealPolicy(
        {}, bolt::tests::ChildProcessPolicyKind::kInherit,
        bolt::tests::NetworkPolicyKind::kAllowList, overlapping_ports);
    if (invalid_payload.empty() ||
        bolt::network::NetworkPolicy::Load(
            invalid_payload.data(), invalid_payload.size(), policy) !=
            bolt::network::PolicyLoadStatus::kInvalidNetworkPolicy) {
        return false;
    }

    auto corrupted = bolt::tests::SealPolicy(
        {}, bolt::tests::ChildProcessPolicyKind::kInherit,
        bolt::tests::NetworkPolicyKind::kDenied);
    corrupted.back() ^= 0xFF;
    return bolt::network::NetworkPolicy::Load(
               corrupted.data(), corrupted.size(), policy) ==
               bolt::network::PolicyLoadStatus::kInvalidPayload &&
           policy == nullptr;
}
