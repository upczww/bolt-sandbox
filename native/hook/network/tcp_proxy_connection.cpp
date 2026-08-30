#include "hook/network/tcp_proxy_connection.h"

#include "hook/network/system_tcp_connector.h"
#include "hook/network/tcp_proxy_server.h"
#include "hook/network/tcp_relay.h"

#include <array>
#include <new>
#include <vector>

namespace bolt::network {
namespace {

constexpr std::size_t kLengthPrefixSize = 4;

bool ReadExact(
    const SOCKET socket,
    std::uint8_t* const bytes,
    const std::size_t length) noexcept {
    std::size_t offset = 0;
    while (offset < length) {
        const int received = recv(
            socket, reinterpret_cast<char*>(bytes + offset),
            static_cast<int>(length - offset), 0);
        if (received > 0) {
            offset += static_cast<std::size_t>(received);
            continue;
        }
        if (received == SOCKET_ERROR && WSAGetLastError() == WSAEINTR) {
            continue;
        }
        return false;
    }
    return true;
}

bool WriteExact(
    const SOCKET socket,
    const std::uint8_t* const bytes,
    const std::size_t length) noexcept {
    std::size_t offset = 0;
    while (offset < length) {
        const int sent = send(
            socket, reinterpret_cast<const char*>(bytes + offset),
            static_cast<int>(length - offset), 0);
        if (sent > 0) {
            offset += static_cast<std::size_t>(sent);
            continue;
        }
        if (sent == SOCKET_ERROR && WSAGetLastError() == WSAEINTR) {
            continue;
        }
        return false;
    }
    return true;
}

std::uint32_t ReadU32(
    const std::array<std::uint8_t, kLengthPrefixSize>& bytes) noexcept {
    return static_cast<std::uint32_t>(bytes[0]) |
           (static_cast<std::uint32_t>(bytes[1]) << 8U) |
           (static_cast<std::uint32_t>(bytes[2]) << 16U) |
           (static_cast<std::uint32_t>(bytes[3]) << 24U);
}

std::array<std::uint8_t, kLengthPrefixSize> LengthPrefix(
    const std::size_t length) noexcept {
    const auto value = static_cast<std::uint32_t>(length);
    return {
        static_cast<std::uint8_t>(value),
        static_cast<std::uint8_t>(value >> 8U),
        static_cast<std::uint8_t>(value >> 16U),
        static_cast<std::uint8_t>(value >> 24U)};
}

}  // namespace

TcpProxyConnectionStatus RunTcpProxyConnection(
    const SOCKET client,
    const protocol::DnsProxySession& session,
    const NetworkPolicy& policy,
    const DnsBindingTable& bindings,
    const std::uint64_t expected_sequence,
    const std::uint64_t now) noexcept {
    if (client == INVALID_SOCKET || expected_sequence == 0) {
        return TcpProxyConnectionStatus::kInvalidSocket;
    }
    std::array<std::uint8_t, kLengthPrefixSize> request_prefix{};
    if (!ReadExact(client, request_prefix.data(), request_prefix.size())) {
        return TcpProxyConnectionStatus::kReadFailed;
    }
    const std::size_t request_length = ReadU32(request_prefix);
    const std::size_t minimum_length =
        protocol::TcpProxyRequestFrameLength(nullptr);
    const std::size_t maximum_length =
        minimum_length + protocol::kTcpProxyMaximumDomainLength;
    if (request_length < minimum_length || request_length > maximum_length) {
        return TcpProxyConnectionStatus::kInvalidFrameLength;
    }
    try {
        std::vector<std::uint8_t> request(request_length);
        if (!ReadExact(client, request.data(), request.size())) {
            return TcpProxyConnectionStatus::kReadFailed;
        }
        SystemTcpConnector connector;
        std::vector<std::uint8_t> response;
        if (ProcessTcpProxyRequest(
                session, policy, bindings, expected_sequence, request.data(),
                request.size(), now, connector, response) !=
                protocol::TcpProxyStatus::kSuccess ||
            response.empty()) {
            return TcpProxyConnectionStatus::kProtocolFailed;
        }
        const auto response_prefix = LengthPrefix(response.size());
        if (!WriteExact(
                client, response_prefix.data(), response_prefix.size()) ||
            !WriteExact(client, response.data(), response.size())) {
            return TcpProxyConnectionStatus::kWriteFailed;
        }
        const SOCKET upstream = connector.ReleaseSocket();
        if (upstream == INVALID_SOCKET) {
            return TcpProxyConnectionStatus::kRejected;
        }
        const auto relay_status = RelayTcpSockets(client, upstream);
        closesocket(upstream);
        return relay_status == TcpRelayStatus::kCompleted
                   ? TcpProxyConnectionStatus::kRelayed
                   : TcpProxyConnectionStatus::kRelayFailed;
    } catch (const std::bad_alloc&) {
        return TcpProxyConnectionStatus::kAllocationFailed;
    } catch (...) {
        return TcpProxyConnectionStatus::kProtocolFailed;
    }
}

}  // namespace bolt::network
