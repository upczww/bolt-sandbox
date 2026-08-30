#include "hook/network/dns_proxy_session.h"
#include "tests/policy_fixture.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

namespace {

class FakeResolver final : public bolt::network::DnsResolver {
  public:
    bolt::protocol::DnsProxyResult Resolve(
        const char*, bolt::protocol::DnsProxyQueryFamily,
        std::vector<bolt::protocol::DnsProxyAddress>& addresses) noexcept override {
        ++calls;
        bolt::protocol::DnsProxyAddress address{};
        address.address[0] = 192;
        address.address[1] = 0;
        address.address[2] = 2;
        address.address[3] = 30;
        address.ttl_seconds = 20;
        addresses.push_back(address);
        return bolt::protocol::DnsProxyResult::kSuccess;
    }
    int calls = 0;
};

class FakeTransport final : public bolt::network::DnsProxyTransport {
  public:
    bolt::network::TransportReadStatus ReadFrame(
        std::vector<std::uint8_t>& frame) noexcept override {
        if (read_index == frames.size()) {
            return bolt::network::TransportReadStatus::kEof;
        }
        frame = frames[read_index++];
        return bolt::network::TransportReadStatus::kFrame;
    }
    bool WriteFrame(const std::vector<std::uint8_t>& frame) noexcept override {
        writes.push_back(frame);
        return true;
    }
    std::vector<std::vector<std::uint8_t>> frames;
    std::vector<std::vector<std::uint8_t>> writes;
    std::size_t read_index = 0;
};

}  // namespace

bool RunDnsProxySessionTests() {
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
    FakeTransport transport;
    transport.frames.resize(2);
    if (bolt::protocol::EncodeDnsProxyRequest(
            session, 1, 1'234, "api.example", 443, transport.frames[0]) !=
            bolt::protocol::DnsProxyStatus::kSuccess ||
        bolt::protocol::EncodeDnsProxyRequest(
            session, 2, 1'234, "denied.example", 443, transport.frames[1]) !=
            bolt::protocol::DnsProxyStatus::kSuccess) {
        return false;
    }
    FakeResolver resolver;
    std::unique_ptr<bolt::network::DnsBindingTable> bindings;
    if (bolt::network::DnsBindingTable::Create(4, bindings) !=
        bolt::network::BindingStatus::kSuccess) {
        return false;
    }
    if (bolt::network::RunDnsProxySession(
            session, *policy, resolver, *bindings, transport, 8) !=
            bolt::network::DnsProxySessionStatus::kCompleted ||
        resolver.calls != 1 || transport.writes.size() != 2) {
        return false;
    }
    bolt::protocol::DnsProxyResponse response{};
    if (bolt::protocol::DecodeDnsProxyResponse(
            session, transport.writes[0].data(), transport.writes[0].size(), 1,
            response) != bolt::protocol::DnsProxyStatus::kSuccess ||
        response.result != bolt::protocol::DnsProxyResult::kSuccess ||
        bolt::protocol::DecodeDnsProxyResponse(
            session, transport.writes[1].data(), transport.writes[1].size(), 2,
            response) != bolt::protocol::DnsProxyStatus::kSuccess ||
        response.result != bolt::protocol::DnsProxyResult::kDenied) {
        return false;
    }
    FakeTransport tampered;
    tampered.frames.push_back(transport.frames[0]);
    tampered.frames[0].back() ^= 1;
    return bolt::network::RunDnsProxySession(
               session, *policy, resolver, *bindings, tampered, 8) ==
               bolt::network::DnsProxySessionStatus::kProtocolFailed &&
           tampered.writes.empty();
}
