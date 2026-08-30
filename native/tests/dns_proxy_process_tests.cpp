#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>

#include "hook/network/dns_proxy_process.h"
#include "hook/network/dns_proxy_client_channel.h"
#include "hook/network/dns_proxy_handle_transport.h"
#include "protocol/tcp_proxy_protocol.h"
#include "tests/policy_fixture.h"

#include <array>
#include <filesystem>
#include <memory>
#include <vector>

namespace {

bool SendExact(
    const SOCKET socket,
    const std::uint8_t* bytes,
    const std::size_t length) {
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

bool ReadExact(
    const SOCKET socket,
    std::uint8_t* bytes,
    const std::size_t length) {
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

std::array<std::uint8_t, 4> Prefix(const std::size_t length) {
    const auto value = static_cast<std::uint32_t>(length);
    return {
        static_cast<std::uint8_t>(value),
        static_cast<std::uint8_t>(value >> 8U),
        static_cast<std::uint8_t>(value >> 16U),
        static_cast<std::uint8_t>(value >> 24U)};
}

std::uint32_t PrefixLength(const std::array<std::uint8_t, 4>& prefix) {
    return static_cast<std::uint32_t>(prefix[0]) |
           (static_cast<std::uint32_t>(prefix[1]) << 8U) |
           (static_cast<std::uint32_t>(prefix[2]) << 16U) |
           (static_cast<std::uint32_t>(prefix[3]) << 24U);
}

}  // namespace

bool RunDnsProxyProcessTests() {
#if defined(_WIN64)
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

    std::wstring executable(32'768, L'\0');
    const DWORD length = GetModuleFileNameW(
        nullptr, executable.data(), static_cast<DWORD>(executable.size()));
    if (length == 0 || length == executable.size()) {
        closesocket(upstream_listener);
        WSACleanup();
        return false;
    }
    executable.resize(length);
    const auto proxy = std::filesystem::path(executable).parent_path() /
                       L"bolt-sandbox-dns-proxy.exe";
    const bolt::tests::NetworkAllowListRules rules{
        {{false, "localhost"}}, {}, {{upstream_port, upstream_port}}};
    const auto policy = bolt::tests::SealPolicy(
        {}, bolt::tests::ChildProcessPolicyKind::kInherit,
        bolt::tests::NetworkPolicyKind::kAllowList, rules);
    bolt::protocol::DnsProxySession session{};
    session.nonce[0] = 1;
    session.authentication_key[0] = 2;
    std::unique_ptr<bolt::network::DnsProxyProcess> process;
    if (bolt::network::DnsProxyProcess::Start(
            proxy, policy.data(), policy.size(), session, 1'024, 8, process) !=
        bolt::network::DnsProxyProcessStatus::kSuccess ||
        process == nullptr || process->tcp_proxy_port() == 0 ||
        process->tcp_proxy_ipv6_port() == 0) {
        closesocket(upstream_listener);
        WSACleanup();
        return false;
    }
    std::unique_ptr<bolt::network::DnsProxyHandleTransport> transport;
    if (bolt::network::DnsProxyHandleTransport::Create(
            process->response_read_handle(), process->request_write_handle(),
            1'024, transport) != bolt::network::HandleTransportStatus::kSuccess) {
        closesocket(upstream_listener);
        WSACleanup();
        return false;
    }
    std::unique_ptr<bolt::network::DnsBindingTable> bindings;
    bolt::network::DnsBindingTable::Create(8, bindings);
    std::unique_ptr<bolt::network::DnsProxyClientChannel> channel;
    const std::array<std::uint8_t, 16> session_id = {3};
    std::vector<bolt::protocol::DnsProxyAddress> addresses;
    if (bolt::network::DnsProxyClientChannel::Create(
            session, session_id, 99, std::move(transport), *bindings, channel) !=
            bolt::network::DnsProxyChannelStatus::kSuccess ||
        channel->Resolve(
            "localhost", upstream_port, 1'000, &addresses,
            bolt::protocol::DnsProxyQueryFamily::kIpv4) !=
            bolt::network::DnsProxyChannelStatus::kSuccess ||
        addresses.empty() ||
        addresses[0].family !=
            bolt::protocol::DnsProxyAddressFamily::kIpv4) {
        closesocket(upstream_listener);
        WSACleanup();
        return false;
    }

    const SOCKET client = WSASocketW(
        AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
        WSA_FLAG_NO_HANDLE_INHERIT);
    sockaddr_in proxy_endpoint{};
    proxy_endpoint.sin_family = AF_INET;
    proxy_endpoint.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    proxy_endpoint.sin_port = htons(process->tcp_proxy_port());
    std::vector<std::uint8_t> request;
    const bool request_ready =
        client != INVALID_SOCKET &&
        bolt::protocol::EncodeTcpProxyRequest(
            session, 1, 99,
            bolt::protocol::DnsProxyAddressFamily::kIpv4,
            addresses[0].address, upstream_port, "localhost", request) ==
            bolt::protocol::TcpProxyStatus::kSuccess &&
        connect(
            client, reinterpret_cast<const sockaddr*>(&proxy_endpoint),
            sizeof(proxy_endpoint)) == 0;
    const auto request_prefix = Prefix(request.size());
    std::array<std::uint8_t, 4> response_prefix{};
    bool relayed = request_ready &&
        SendExact(client, request_prefix.data(), request_prefix.size()) &&
        SendExact(client, request.data(), request.size()) &&
        ReadExact(client, response_prefix.data(), response_prefix.size());
    std::vector<std::uint8_t> response(PrefixLength(response_prefix));
    relayed = relayed && !response.empty() &&
        ReadExact(client, response.data(), response.size());
    bolt::protocol::TcpProxyResponse decoded{};
    relayed = relayed &&
        bolt::protocol::DecodeTcpProxyResponse(
            session, response.data(), response.size(), 1, decoded) ==
            bolt::protocol::TcpProxyStatus::kSuccess &&
        decoded.result == bolt::protocol::TcpProxyResult::kConnected;
    const SOCKET upstream = relayed
                                ? accept(upstream_listener, nullptr, nullptr)
                                : INVALID_SOCKET;
    std::uint8_t byte = 0x5A;
    std::uint8_t received = 0;
    relayed = relayed && upstream != INVALID_SOCKET &&
        SendExact(client, &byte, 1) && ReadExact(upstream, &received, 1) &&
        received == byte;
    byte = 0xA5;
    relayed = relayed && SendExact(upstream, &byte, 1) &&
        ReadExact(client, &received, 1) && received == byte;
    if (client != INVALID_SOCKET) {
        shutdown(client, SD_SEND);
    }
    if (upstream != INVALID_SOCKET) {
        shutdown(upstream, SD_SEND);
    }
    if (client != INVALID_SOCKET) {
        closesocket(client);
    }
    if (upstream != INVALID_SOCKET) {
        closesocket(upstream);
    }
    closesocket(upstream_listener);
    channel.reset();
    process->CloseClientHandles();
    const bool stopped = process->Wait(5'000) ==
                         bolt::network::DnsProxyProcessStatus::kSuccess;
    WSACleanup();
    return relayed && stopped;
#else
    return true;
#endif
}
