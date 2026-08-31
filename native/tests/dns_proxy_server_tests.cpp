#include "hook/network/dns_proxy_server.h"
#include "hook/network/dns_binding_table.h"
#include "hook/network/network_policy.h"
#include "protocol/dns_proxy_protocol.h"
#include "tests/policy_fixture.h"

#include <memory>
#include <string>
#include <vector>

namespace {

class FakeResolver final : public bolt::network::DnsResolver {
  public:
    bolt::protocol::DnsProxyResult Resolve(
        const char* domain,
        bolt::protocol::DnsProxyQueryFamily,
        std::vector<bolt::protocol::DnsProxyAddress>& addresses) noexcept override {
        ++calls;
        last_domain = domain;
        bolt::protocol::DnsProxyAddress address{};
        address.address[0] = 192;
        address.address[1] = 0;
        address.address[2] = 2;
        address.address[3] = 20;
        address.ttl_seconds = 30;
        addresses.push_back(address);
        bolt::protocol::DnsProxyAddress ipv6{};
        ipv6.family = bolt::protocol::DnsProxyAddressFamily::kIpv6;
        ipv6.address[0] = 0x20;
        ipv6.address[1] = 0x01;
        ipv6.address[2] = 0x0d;
        ipv6.address[3] = 0xb8;
        ipv6.address[15] = 1;
        ipv6.ttl_seconds = 20;
        addresses.push_back(ipv6);
        return bolt::protocol::DnsProxyResult::kSuccess;
    }

    int calls = 0;
    std::string last_domain;
};

class ResultResolver final : public bolt::network::DnsResolver {
  public:
    bolt::protocol::DnsProxyResult Resolve(
        const char*,
        bolt::protocol::DnsProxyQueryFamily,
        std::vector<bolt::protocol::DnsProxyAddress>& addresses) noexcept override {
        for (std::size_t index = 0; index < address_count; ++index) {
            bolt::protocol::DnsProxyAddress address{};
            address.address[0] = 198;
            address.address[1] = 51;
            address.address[2] = 100;
            address.address[3] = static_cast<std::uint8_t>(index + 1);
            address.ttl_seconds = 10;
            addresses.push_back(address);
        }
        return result;
    }

    bolt::protocol::DnsProxyResult result =
        bolt::protocol::DnsProxyResult::kNotFound;
    std::size_t address_count = 1;
};

}  // namespace

bool RunDnsProxyServerTests() {
    bolt::protocol::DnsProxySession session{};
    session.nonce[0] = 1;
    session.authentication_key[0] = 2;
    const bolt::tests::NetworkAllowListRules rules{
        {{false, "api.example"}}, {}, {{443, 443}}};
    const auto payload = bolt::tests::SealPolicy(
        {}, bolt::tests::ChildProcessPolicyKind::kInherit,
        bolt::tests::NetworkPolicyKind::kAllowList, rules);
    std::unique_ptr<bolt::network::NetworkPolicy> policy;
    if (bolt::network::NetworkPolicy::Load(payload.data(), payload.size(), policy) !=
        bolt::network::PolicyLoadStatus::kValid) {
        return false;
    }
    std::vector<std::uint8_t> request;
    std::vector<std::uint8_t> response;
    FakeResolver resolver;
    std::unique_ptr<bolt::network::DnsBindingTable> bindings;
    if (bolt::network::DnsBindingTable::Create(4, bindings) !=
        bolt::network::BindingStatus::kSuccess) {
        return false;
    }
    if (bolt::protocol::EncodeDnsProxyRequest(
            session, 1, 1'234, "api.example", 443, request) !=
            bolt::protocol::DnsProxyStatus::kSuccess ||
        bolt::network::ProcessDnsProxyRequest(
            session, *policy, 1, request.data(), request.size(), resolver,
            *bindings, 1'000, response) !=
            bolt::protocol::DnsProxyStatus::kSuccess) {
        return false;
    }
    bolt::protocol::DnsProxyResponse decoded{};
    if (resolver.calls != 1 || resolver.last_domain != "api.example" ||
        bolt::protocol::DecodeDnsProxyResponse(
            session, response.data(), response.size(), 1, decoded) !=
            bolt::protocol::DnsProxyStatus::kSuccess ||
        decoded.result != bolt::protocol::DnsProxyResult::kSuccess ||
        decoded.addresses.size() != 2) {
        return false;
    }
    const std::array<std::uint8_t, 4> bound_address = {192, 0, 2, 20};
    const bolt::network::BindingKey bound_key{
        session.nonce, 1'234, "api.example",
        bolt::network::AddressFamily::kIpv4, bound_address.data(),
        bound_address.size(), 443};
    auto wrong_process = bound_key;
    wrong_process.process_id = 1'235;
    std::array<std::uint8_t, 16> bound_ipv6{};
    bound_ipv6[0] = 0x20;
    bound_ipv6[1] = 0x01;
    bound_ipv6[2] = 0x0d;
    bound_ipv6[3] = 0xb8;
    bound_ipv6[15] = 1;
    const bolt::network::BindingKey bound_ipv6_key{
        session.nonce, 1'234, "api.example",
        bolt::network::AddressFamily::kIpv6, bound_ipv6.data(),
        bound_ipv6.size(), 443};
    if (!bindings->IsAuthorized(bound_key, 30'999) ||
        bindings->IsAuthorized(bound_key, 31'000) ||
        bindings->IsAuthorized(wrong_process, 2'000) ||
        !bindings->IsAuthorized(bound_ipv6_key, 20'999) ||
        bindings->IsAuthorized(bound_ipv6_key, 21'000)) {
        return false;
    }
    if (bolt::protocol::EncodeDnsProxyRequest(
            session, 2, 1'234, "denied.example", 443, request) !=
            bolt::protocol::DnsProxyStatus::kSuccess ||
        bolt::network::ProcessDnsProxyRequest(
            session, *policy, 2, request.data(), request.size(), resolver,
            *bindings, 2'000, response) !=
            bolt::protocol::DnsProxyStatus::kSuccess ||
        resolver.calls != 1 ||
        bolt::protocol::DecodeDnsProxyResponse(
            session, response.data(), response.size(), 2, decoded) !=
            bolt::protocol::DnsProxyStatus::kSuccess ||
        decoded.result != bolt::protocol::DnsProxyResult::kDenied ||
        !decoded.addresses.empty()) {
        return false;
    }
    ResultResolver result_resolver;
    if (bolt::protocol::EncodeDnsProxyRequest(
            session, 3, 5'678, "api.example", 443, request) !=
            bolt::protocol::DnsProxyStatus::kSuccess ||
        bolt::network::ProcessDnsProxyRequest(
            session, *policy, 3, request.data(), request.size(),
            result_resolver, *bindings, 3'000, response) !=
            bolt::protocol::DnsProxyStatus::kSuccess ||
        bolt::protocol::DecodeDnsProxyResponse(
            session, response.data(), response.size(), 3, decoded) !=
            bolt::protocol::DnsProxyStatus::kSuccess ||
        decoded.result != bolt::protocol::DnsProxyResult::kNotFound ||
        !decoded.addresses.empty()) {
        return false;
    }
    const std::array<std::uint8_t, 4> discarded_address = {198, 51, 100, 1};
    const bolt::network::BindingKey discarded_key{
        session.nonce, 5'678, "api.example",
        bolt::network::AddressFamily::kIpv4, discarded_address.data(),
        discarded_address.size(), 443};
    if (bindings->IsAuthorized(discarded_key, 3'001)) {
        return false;
    }
    result_resolver.result = bolt::protocol::DnsProxyResult::kSuccess;
    result_resolver.address_count =
        bolt::protocol::kDnsProxyMaximumAddressRecords + 1;
    if (bolt::protocol::EncodeDnsProxyRequest(
            session, 4, 5'679, "api.example", 443, request) !=
            bolt::protocol::DnsProxyStatus::kSuccess ||
        bolt::network::ProcessDnsProxyRequest(
            session, *policy, 4, request.data(), request.size(),
            result_resolver, *bindings, 4'000, response) !=
            bolt::protocol::DnsProxyStatus::kSuccess ||
        bolt::protocol::DecodeDnsProxyResponse(
            session, response.data(), response.size(), 4, decoded) !=
            bolt::protocol::DnsProxyStatus::kSuccess ||
        decoded.result != bolt::protocol::DnsProxyResult::kFailure ||
        !decoded.addresses.empty()) {
        return false;
    }
    result_resolver.result = bolt::protocol::DnsProxyResult::kFailure;
    result_resolver.address_count = 1;
    if (bolt::protocol::EncodeDnsProxyRequest(
            session, 5, 5'680, "api.example", 443, request) !=
            bolt::protocol::DnsProxyStatus::kSuccess ||
        bolt::network::ProcessDnsProxyRequest(
            session, *policy, 5, request.data(), request.size(),
            result_resolver, *bindings, 5'000, response) !=
            bolt::protocol::DnsProxyStatus::kSuccess ||
        bolt::protocol::DecodeDnsProxyResponse(
            session, response.data(), response.size(), 5, decoded) !=
            bolt::protocol::DnsProxyStatus::kSuccess ||
        decoded.result != bolt::protocol::DnsProxyResult::kFailure ||
        !decoded.addresses.empty()) {
        return false;
    }
    request.back() ^= 1;
    response.assign(1, 0xff);
    return bolt::network::ProcessDnsProxyRequest(
               session, *policy, 2, request.data(), request.size(), resolver,
               *bindings, 2'000, response) ==
               bolt::protocol::DnsProxyStatus::kAuthenticationFailed &&
           response.empty() && resolver.calls == 1;
}
