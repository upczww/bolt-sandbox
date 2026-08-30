#include "hook/network/tcp_proxy_connection.h"

#include "hook/network/dns_binding_table.h"
#include "hook/network/network_policy.h"
#include "protocol/tcp_proxy_protocol.h"
#include "tests/policy_fixture.h"

#include <array>
#include <cstdint>
#include <memory>
#include <thread>
#include <vector>

namespace {

bool CreateConnectedPair(SOCKET& client, SOCKET& server) {
    client = INVALID_SOCKET;
    server = INVALID_SOCKET;
    const SOCKET listener = WSASocketW(
        AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
        WSA_FLAG_NO_HANDLE_INHERIT);
    sockaddr_in endpoint{};
    endpoint.sin_family = AF_INET;
    endpoint.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    endpoint.sin_port = 0;
    int length = sizeof(endpoint);
    if (listener == INVALID_SOCKET ||
        bind(
            listener, reinterpret_cast<const sockaddr*>(&endpoint),
            sizeof(endpoint)) != 0 ||
        listen(listener, 1) != 0 ||
        getsockname(listener, reinterpret_cast<sockaddr*>(&endpoint), &length) !=
            0) {
        if (listener != INVALID_SOCKET) {
            closesocket(listener);
        }
        return false;
    }
    client = WSASocketW(
        AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
        WSA_FLAG_NO_HANDLE_INHERIT);
    if (client == INVALID_SOCKET ||
        connect(
            client, reinterpret_cast<const sockaddr*>(&endpoint),
            sizeof(endpoint)) != 0) {
        if (client != INVALID_SOCKET) {
            closesocket(client);
            client = INVALID_SOCKET;
        }
        closesocket(listener);
        return false;
    }
    server = accept(listener, nullptr, nullptr);
    closesocket(listener);
    return server != INVALID_SOCKET;
}

bool SendExact(const SOCKET socket, const std::uint8_t* bytes, std::size_t length) {
    std::size_t offset = 0;
    while (offset < length) {
        const int sent = send(
            socket, reinterpret_cast<const char*>(bytes + offset),
            static_cast<int>(length - offset), 0);
        if (sent <= 0) {
            return false;
        }
        offset += static_cast<std::size_t>(sent);
    }
    return true;
}

bool ReceiveExact(SOCKET socket, std::uint8_t* bytes, std::size_t length) {
    std::size_t offset = 0;
    while (offset < length) {
        const int received = recv(
            socket, reinterpret_cast<char*>(bytes + offset),
            static_cast<int>(length - offset), 0);
        if (received <= 0) {
            return false;
        }
        offset += static_cast<std::size_t>(received);
    }
    return true;
}

std::array<std::uint8_t, 4> LengthPrefix(std::size_t length) {
    const auto value = static_cast<std::uint32_t>(length);
    return {
        static_cast<std::uint8_t>(value),
        static_cast<std::uint8_t>(value >> 8U),
        static_cast<std::uint8_t>(value >> 16U),
        static_cast<std::uint8_t>(value >> 24U)};
}

std::uint32_t ReadLength(const std::array<std::uint8_t, 4>& bytes) {
    return static_cast<std::uint32_t>(bytes[0]) |
           (static_cast<std::uint32_t>(bytes[1]) << 8U) |
           (static_cast<std::uint32_t>(bytes[2]) << 16U) |
           (static_cast<std::uint32_t>(bytes[3]) << 24U);
}

}  // namespace

bool RunTcpProxyConnectionTests() {
    WSADATA winsock{};
    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) {
        return false;
    }
    const SOCKET upstream_listener = WSASocketW(
        AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
        WSA_FLAG_NO_HANDLE_INHERIT);
    sockaddr_in upstream_endpoint{};
    upstream_endpoint.sin_family = AF_INET;
    upstream_endpoint.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    upstream_endpoint.sin_port = 0;
    int upstream_length = sizeof(upstream_endpoint);
    if (upstream_listener == INVALID_SOCKET ||
        bind(
            upstream_listener,
            reinterpret_cast<const sockaddr*>(&upstream_endpoint),
            sizeof(upstream_endpoint)) != 0 ||
        listen(upstream_listener, 1) != 0 ||
        getsockname(
            upstream_listener,
            reinterpret_cast<sockaddr*>(&upstream_endpoint),
            &upstream_length) != 0) {
        if (upstream_listener != INVALID_SOCKET) {
            closesocket(upstream_listener);
        }
        WSACleanup();
        return false;
    }
    const std::uint16_t upstream_port = ntohs(upstream_endpoint.sin_port);
    bolt::tests::NetworkAddressRule loopback_rule{};
    loopback_rule.family = 4;
    loopback_rule.prefix_length = 32;
    loopback_rule.address[0] = 127;
    loopback_rule.address[3] = 1;
    const bolt::tests::NetworkAllowListRules rules{
        {}, {loopback_rule}, {{upstream_port, upstream_port}}};
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
        closesocket(upstream_listener);
        WSACleanup();
        return false;
    }
    bolt::protocol::DnsProxySession session{};
    session.nonce[0] = 1;
    session.authentication_key[0] = 2;
    std::array<std::uint8_t, 16> loopback{};
    loopback[0] = 127;
    loopback[3] = 1;
    std::vector<std::uint8_t> request;
    if (bolt::protocol::EncodeTcpProxyRequest(
            session, 1, 1'234,
            bolt::protocol::DnsProxyAddressFamily::kIpv4, loopback,
            upstream_port, nullptr, request) !=
        bolt::protocol::TcpProxyStatus::kSuccess) {
        closesocket(upstream_listener);
        WSACleanup();
        return false;
    }

    SOCKET hook_socket = INVALID_SOCKET;
    SOCKET proxy_socket = INVALID_SOCKET;
    if (!CreateConnectedPair(hook_socket, proxy_socket)) {
        closesocket(upstream_listener);
        WSACleanup();
        return false;
    }
    auto connection_status =
        bolt::network::TcpProxyConnectionStatus::kInvalidSocket;
    std::thread connection([&] {
        connection_status = bolt::network::RunTcpProxyConnection(
            proxy_socket, session, *policy, *bindings, 1, 1'000);
    });
    const auto request_prefix = LengthPrefix(request.size());
    bool passed = SendExact(
        hook_socket, request_prefix.data(), request_prefix.size());
    passed = passed && SendExact(hook_socket, request.data(), request.size());
    std::array<std::uint8_t, 4> response_prefix{};
    passed = passed && ReceiveExact(
        hook_socket, response_prefix.data(), response_prefix.size());
    std::vector<std::uint8_t> response(ReadLength(response_prefix));
    passed = passed && !response.empty() &&
             ReceiveExact(hook_socket, response.data(), response.size());
    bolt::protocol::TcpProxyResponse decoded{};
    passed = passed &&
        bolt::protocol::DecodeTcpProxyResponse(
            session, response.data(), response.size(), 1, decoded) ==
            bolt::protocol::TcpProxyStatus::kSuccess &&
        decoded.result == bolt::protocol::TcpProxyResult::kConnected;

    const SOCKET upstream = passed ? accept(upstream_listener, nullptr, nullptr)
                                   : INVALID_SOCKET;
    constexpr std::array<std::uint8_t, 5> message = {'h', 'e', 'l', 'l', 'o'};
    std::array<std::uint8_t, message.size()> received{};
    passed = passed && upstream != INVALID_SOCKET &&
        SendExact(hook_socket, message.data(), message.size()) &&
        ReceiveExact(upstream, received.data(), received.size()) &&
        received == message &&
        SendExact(upstream, message.data(), message.size()) &&
        ReceiveExact(hook_socket, received.data(), received.size());
    if (hook_socket != INVALID_SOCKET) {
        shutdown(hook_socket, SD_SEND);
    }
    if (upstream != INVALID_SOCKET) {
        shutdown(upstream, SD_SEND);
    }
    connection.join();
    passed = passed &&
        connection_status == bolt::network::TcpProxyConnectionStatus::kRelayed;

    closesocket(hook_socket);
    closesocket(proxy_socket);
    if (upstream != INVALID_SOCKET) {
        closesocket(upstream);
    }
    closesocket(upstream_listener);
    WSACleanup();
    return passed;
}
