#include "hook/network/dns_proxy_client_channel.h"

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

namespace {

class ScriptedTransport final : public bolt::network::DnsProxyTransport {
  public:
    bool WriteFrame(const std::vector<std::uint8_t>& frame) noexcept override {
        writes.push_back(frame);
        return !fail_write;
    }
    bolt::network::TransportReadStatus ReadFrame(
        std::vector<std::uint8_t>& frame) noexcept override {
        if (fail_read || responses.empty()) {
            return bolt::network::TransportReadStatus::kFailure;
        }
        frame = responses.front();
        responses.erase(responses.begin());
        return bolt::network::TransportReadStatus::kFrame;
    }
    bool fail_write = false;
    bool fail_read = false;
    std::vector<std::vector<std::uint8_t>> writes;
    std::vector<std::vector<std::uint8_t>> responses;
};

}  // namespace

bool RunDnsProxyClientChannelTests() {
    bolt::protocol::DnsProxySession session{};
    session.nonce[0] = 1;
    session.authentication_key[0] = 2;
    bolt::protocol::DnsProxyAddress address{};
    address.address[0] = 192;
    address.address[1] = 0;
    address.address[2] = 2;
    address.address[3] = 55;
    address.ttl_seconds = 3;
    auto transport = std::make_unique<ScriptedTransport>();
    auto* scripted = transport.get();
    std::vector<std::uint8_t> response;
    bolt::protocol::EncodeDnsProxyResponse(
        session, 1, bolt::protocol::DnsProxyResult::kSuccess, {address}, response);
    scripted->responses.push_back(response);
    std::unique_ptr<bolt::network::DnsBindingTable> bindings;
    bolt::network::DnsBindingTable::Create(4, bindings);
    const std::array<std::uint8_t, 16> session_id = {9};
    std::unique_ptr<bolt::network::DnsProxyClientChannel> channel;
    if (bolt::network::DnsProxyClientChannel::Create(
            session, session_id, 88, std::move(transport), *bindings, channel) !=
        bolt::network::DnsProxyChannelStatus::kSuccess) {
        return false;
    }
    if (channel->Resolve("api.example", 443, 1'000) !=
            bolt::network::DnsProxyChannelStatus::kSuccess ||
        scripted->writes.size() != 1) {
        return false;
    }
    bolt::protocol::DnsProxyRequest request{};
    if (bolt::protocol::DecodeDnsProxyRequest(
            session, scripted->writes[0].data(), scripted->writes[0].size(), 1,
            request) != bolt::protocol::DnsProxyStatus::kSuccess ||
        request.ascii_domain != "api.example" || request.port != 443) {
        return false;
    }
    const std::array<std::uint8_t, 4> ip = {192, 0, 2, 55};
    if (!bindings->IsEndpointAuthorized(
            session_id, 88, bolt::network::AddressFamily::kIpv4, ip.data(),
            ip.size(), 443, 3'999)) {
        return false;
    }
    return channel->Resolve("api.example", 443, 2'000) ==
               bolt::network::DnsProxyChannelStatus::kTransportFailed &&
           channel->Resolve("api.example", 443, 2'000) ==
               bolt::network::DnsProxyChannelStatus::kClosed;
}
