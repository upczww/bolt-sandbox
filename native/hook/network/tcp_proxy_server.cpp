#include "hook/network/tcp_proxy_server.h"

namespace bolt::network {
namespace {

bool IsAuthorized(
    const protocol::DnsProxySession& session,
    const NetworkPolicy& policy,
    const DnsBindingTable& bindings,
    const protocol::TcpProxyRequest& request,
    const std::uint64_t now) noexcept {
    if (policy.mode() != Mode::kAllowList ||
        policy.DecidePort(request.port) != Decision::kAllow) {
        return false;
    }
    const AddressFamily family =
        request.family == protocol::DnsProxyAddressFamily::kIpv4
            ? AddressFamily::kIpv4
            : AddressFamily::kIpv6;
    const std::size_t address_length =
        family == AddressFamily::kIpv4 ? 4 : 16;
    if (policy.DecideAddress(
            family, request.address.data(), address_length) ==
        Decision::kAllow) {
        return true;
    }
    if (request.ascii_domain.empty() ||
        policy.DecideDomain(request.ascii_domain.c_str()) != Decision::kAllow) {
        return false;
    }
    const BindingKey key{
        session.nonce, request.process_id, request.ascii_domain.c_str(), family,
        request.address.data(), address_length, request.port};
    if (bindings.IsAuthorized(key, now)) {
        return true;
    }
    const BindingKey service_agnostic_key{
        session.nonce, request.process_id, request.ascii_domain.c_str(), family,
        request.address.data(), address_length, 0};
    return bindings.IsAuthorized(service_agnostic_key, now);
}

}  // namespace

protocol::TcpProxyStatus ProcessTcpProxyRequest(
    const protocol::DnsProxySession& session,
    const NetworkPolicy& policy,
    const DnsBindingTable& bindings,
    const std::uint64_t expected_sequence,
    const std::uint8_t* const encoded_request,
    const std::size_t request_length,
    const std::uint64_t now,
    TcpConnector& connector,
    std::vector<std::uint8_t>& encoded_response) noexcept {
    encoded_response.clear();
    protocol::TcpProxyRequest request{};
    const auto decode_status = protocol::DecodeTcpProxyRequest(
        session, encoded_request, request_length, expected_sequence, request);
    if (decode_status != protocol::TcpProxyStatus::kSuccess) {
        return decode_status;
    }
    if (!IsAuthorized(session, policy, bindings, request, now)) {
        return protocol::EncodeTcpProxyResponse(
            session, expected_sequence, protocol::TcpProxyResult::kDenied, 0,
            encoded_response);
    }

    const AddressFamily family =
        request.family == protocol::DnsProxyAddressFamily::kIpv4
            ? AddressFamily::kIpv4
            : AddressFamily::kIpv6;
    const std::size_t address_length =
        family == AddressFamily::kIpv4 ? 4 : 16;
    std::uint32_t network_error = 0;
    const bool connected = connector.Connect(
        family, request.address.data(), address_length, request.port,
        network_error);
    if (connected && network_error == 0) {
        return protocol::EncodeTcpProxyResponse(
            session, expected_sequence, protocol::TcpProxyResult::kConnected,
            0, encoded_response);
    }
    if (!connected && network_error != 0) {
        return protocol::EncodeTcpProxyResponse(
            session, expected_sequence,
            protocol::TcpProxyResult::kConnectFailed, network_error,
            encoded_response);
    }
    return protocol::EncodeTcpProxyResponse(
        session, expected_sequence, protocol::TcpProxyResult::kFailure, 0,
        encoded_response);
}

}  // namespace bolt::network
