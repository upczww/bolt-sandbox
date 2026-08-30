#include "hook/network/dns_proxy_server.h"
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
        return bolt::protocol::DnsProxyResult::kSuccess;
    }

    int calls = 0;
    std::string last_domain;
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
    if (bolt::protocol::EncodeDnsProxyRequest(
            session, 1, "api.example", 443, request) !=
            bolt::protocol::DnsProxyStatus::kSuccess ||
        bolt::network::ProcessDnsProxyRequest(
            session, *policy, 1, request.data(), request.size(), resolver,
            response) != bolt::protocol::DnsProxyStatus::kSuccess) {
        return false;
    }
    bolt::protocol::DnsProxyResponse decoded{};
    if (resolver.calls != 1 || resolver.last_domain != "api.example" ||
        bolt::protocol::DecodeDnsProxyResponse(
            session, response.data(), response.size(), 1, decoded) !=
            bolt::protocol::DnsProxyStatus::kSuccess ||
        decoded.result != bolt::protocol::DnsProxyResult::kSuccess ||
        decoded.addresses.size() != 1) {
        return false;
    }
    if (bolt::protocol::EncodeDnsProxyRequest(
            session, 2, "denied.example", 443, request) !=
            bolt::protocol::DnsProxyStatus::kSuccess ||
        bolt::network::ProcessDnsProxyRequest(
            session, *policy, 2, request.data(), request.size(), resolver,
            response) != bolt::protocol::DnsProxyStatus::kSuccess ||
        resolver.calls != 1 ||
        bolt::protocol::DecodeDnsProxyResponse(
            session, response.data(), response.size(), 2, decoded) !=
            bolt::protocol::DnsProxyStatus::kSuccess ||
        decoded.result != bolt::protocol::DnsProxyResult::kDenied ||
        !decoded.addresses.empty()) {
        return false;
    }
    request.back() ^= 1;
    response.assign(1, 0xff);
    return bolt::network::ProcessDnsProxyRequest(
               session, *policy, 2, request.data(), request.size(), resolver,
               response) == bolt::protocol::DnsProxyStatus::kAuthenticationFailed &&
           response.empty() && resolver.calls == 1;
}
