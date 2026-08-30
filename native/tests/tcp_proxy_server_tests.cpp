#include "hook/network/tcp_proxy_server.h"

#include "hook/network/dns_binding_table.h"
#include "hook/network/network_policy.h"
#include "protocol/tcp_proxy_protocol.h"
#include "tests/policy_fixture.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <vector>

namespace {

class FakeConnector final : public bolt::network::TcpConnector {
  public:
    bool Connect(
        bolt::network::AddressFamily family,
        const std::uint8_t* address,
        std::size_t address_length,
        std::uint16_t port,
        std::uint32_t& network_error) noexcept override {
        ++calls;
        last_family = family;
        last_address.fill(0);
        if (address != nullptr && address_length <= last_address.size()) {
            std::copy_n(address, address_length, last_address.begin());
        }
        last_port = port;
        network_error = next_error;
        return next_connected;
    }

    int calls = 0;
    bool next_connected = true;
    std::uint32_t next_error = 0;
    bolt::network::AddressFamily last_family =
        bolt::network::AddressFamily::kIpv4;
    std::array<std::uint8_t, 16> last_address{};
    std::uint16_t last_port = 0;
};

bolt::protocol::DnsProxySession TestSession() {
    bolt::protocol::DnsProxySession session{};
    session.nonce[0] = 1;
    session.authentication_key[0] = 2;
    return session;
}

}  // namespace

bool RunTcpProxyServerTests() {
    const auto session = TestSession();
    bolt::tests::NetworkAddressRule cidr{};
    cidr.family = 4;
    cidr.prefix_length = 24;
    cidr.address[0] = 198;
    cidr.address[1] = 51;
    cidr.address[2] = 100;
    const bolt::tests::NetworkAllowListRules rules{
        {{false, "api.example"}}, {cidr}, {{443, 443}}};
    const auto payload = bolt::tests::SealPolicy(
        {}, bolt::tests::ChildProcessPolicyKind::kInherit,
        bolt::tests::NetworkPolicyKind::kAllowList, rules);
    std::unique_ptr<bolt::network::NetworkPolicy> policy;
    std::unique_ptr<bolt::network::DnsBindingTable> bindings;
    if (bolt::network::NetworkPolicy::Load(
            payload.data(), payload.size(), policy) !=
            bolt::network::PolicyLoadStatus::kValid ||
        bolt::network::DnsBindingTable::Create(4, bindings) !=
            bolt::network::BindingStatus::kSuccess) {
        return false;
    }

    std::array<std::uint8_t, 16> resolved{};
    resolved[0] = 192;
    resolved[1] = 0;
    resolved[2] = 2;
    resolved[3] = 20;
    const bolt::network::BindingKey bound_key{
        session.nonce, 1'234, "api.example",
        bolt::network::AddressFamily::kIpv4, resolved.data(), 4, 443};
    if (bindings->Upsert(bound_key, 1'000, 30'000) !=
        bolt::network::BindingStatus::kSuccess) {
        return false;
    }

    std::vector<std::uint8_t> request;
    std::vector<std::uint8_t> response;
    FakeConnector connector;
    if (bolt::protocol::EncodeTcpProxyRequest(
            session, 1, 1'234,
            bolt::protocol::DnsProxyAddressFamily::kIpv4, resolved, 443,
            "api.example", request) !=
            bolt::protocol::TcpProxyStatus::kSuccess ||
        bolt::network::ProcessTcpProxyRequest(
            session, *policy, *bindings, 1, request.data(), request.size(),
            2'000, connector, response) !=
            bolt::protocol::TcpProxyStatus::kSuccess) {
        return false;
    }
    bolt::protocol::TcpProxyResponse decoded{};
    if (connector.calls != 1 || connector.last_port != 443 ||
        connector.last_address != resolved ||
        bolt::protocol::DecodeTcpProxyResponse(
            session, response.data(), response.size(), 1, decoded) !=
            bolt::protocol::TcpProxyStatus::kSuccess ||
        decoded.result != bolt::protocol::TcpProxyResult::kConnected) {
        return false;
    }

    if (bolt::protocol::EncodeTcpProxyRequest(
            session, 2, 1'235,
            bolt::protocol::DnsProxyAddressFamily::kIpv4, resolved, 443,
            "api.example", request) !=
            bolt::protocol::TcpProxyStatus::kSuccess ||
        bolt::network::ProcessTcpProxyRequest(
            session, *policy, *bindings, 2, request.data(), request.size(),
            2'000, connector, response) !=
            bolt::protocol::TcpProxyStatus::kSuccess ||
        connector.calls != 1 ||
        bolt::protocol::DecodeTcpProxyResponse(
            session, response.data(), response.size(), 2, decoded) !=
            bolt::protocol::TcpProxyStatus::kSuccess ||
        decoded.result != bolt::protocol::TcpProxyResult::kDenied) {
        return false;
    }
    if (bolt::protocol::EncodeTcpProxyRequest(
            session, 3, 1'234,
            bolt::protocol::DnsProxyAddressFamily::kIpv4, resolved, 443,
            "api.example", request) !=
            bolt::protocol::TcpProxyStatus::kSuccess ||
        bolt::network::ProcessTcpProxyRequest(
            session, *policy, *bindings, 3, request.data(), request.size(),
            31'000, connector, response) !=
            bolt::protocol::TcpProxyStatus::kSuccess ||
        connector.calls != 1 ||
        bolt::protocol::DecodeTcpProxyResponse(
            session, response.data(), response.size(), 3, decoded) !=
            bolt::protocol::TcpProxyStatus::kSuccess ||
        decoded.result != bolt::protocol::TcpProxyResult::kDenied) {
        return false;
    }

    std::array<std::uint8_t, 16> direct{};
    direct[0] = 198;
    direct[1] = 51;
    direct[2] = 100;
    direct[3] = 7;
    if (bolt::protocol::EncodeTcpProxyRequest(
            session, 4, 1'234,
            bolt::protocol::DnsProxyAddressFamily::kIpv4, direct, 443,
            nullptr, request) != bolt::protocol::TcpProxyStatus::kSuccess ||
        bolt::network::ProcessTcpProxyRequest(
            session, *policy, *bindings, 4, request.data(), request.size(),
            2'000, connector, response) !=
            bolt::protocol::TcpProxyStatus::kSuccess ||
        connector.calls != 2 || connector.last_address != direct) {
        return false;
    }

    connector.next_connected = false;
    connector.next_error = 10'061;
    if (bolt::protocol::EncodeTcpProxyRequest(
            session, 5, 1'234,
            bolt::protocol::DnsProxyAddressFamily::kIpv4, direct, 443,
            nullptr, request) != bolt::protocol::TcpProxyStatus::kSuccess ||
        bolt::network::ProcessTcpProxyRequest(
            session, *policy, *bindings, 5, request.data(), request.size(),
            2'000, connector, response) !=
            bolt::protocol::TcpProxyStatus::kSuccess ||
        bolt::protocol::DecodeTcpProxyResponse(
            session, response.data(), response.size(), 5, decoded) !=
            bolt::protocol::TcpProxyStatus::kSuccess ||
        decoded.result != bolt::protocol::TcpProxyResult::kConnectFailed ||
        decoded.network_error != 10'061) {
        return false;
    }

    request.back() ^= 1;
    response.assign(1, 0xFF);
    return bolt::network::ProcessTcpProxyRequest(
               session, *policy, *bindings, 5, request.data(), request.size(),
               2'000, connector, response) ==
               bolt::protocol::TcpProxyStatus::kAuthenticationFailed &&
           response.empty() && connector.calls == 3;
}
