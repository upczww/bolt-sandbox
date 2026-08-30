#include "hook/network/tcp_proxy_client.h"

#include <algorithm>
#include <array>
#include <new>
#include <vector>

#include <ws2tcpip.h>

namespace bolt::network {
namespace {

constexpr std::size_t kPrefixLength = 4;
constexpr std::size_t kMaximumResponseLength = 1'024;

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

std::array<std::uint8_t, kPrefixLength> Prefix(
    const std::size_t length) noexcept {
    const auto value = static_cast<std::uint32_t>(length);
    return {
        static_cast<std::uint8_t>(value),
        static_cast<std::uint8_t>(value >> 8U),
        static_cast<std::uint8_t>(value >> 16U),
        static_cast<std::uint8_t>(value >> 24U)};
}

std::uint32_t ReadLength(
    const std::array<std::uint8_t, kPrefixLength>& bytes) noexcept {
    return static_cast<std::uint32_t>(bytes[0]) |
           (static_cast<std::uint32_t>(bytes[1]) << 8U) |
           (static_cast<std::uint32_t>(bytes[2]) << 16U) |
           (static_cast<std::uint32_t>(bytes[3]) << 24U);
}

void DisableSocket(const SOCKET socket) noexcept {
    shutdown(socket, SD_BOTH);
}

}  // namespace

TcpProxyClientStatus ConnectTcpSocketThroughProxy(
    const SOCKET socket,
    const TcpConnectFunction original_connect,
    const std::uint16_t proxy_port,
    const protocol::DnsProxySession& session,
    const std::uint64_t sequence,
    const std::uint32_t process_id,
    const AddressFamily family,
    const std::uint8_t* const address,
    const std::size_t address_length,
    const std::uint16_t target_port,
    const char* const ascii_domain,
    std::uint32_t& network_error) noexcept {
    network_error = 0;
    if (socket == INVALID_SOCKET || original_connect == nullptr ||
        proxy_port == 0 || sequence == 0 || process_id == 0 ||
        target_port == 0 || address == nullptr) {
        network_error = WSAEINVAL;
        return TcpProxyClientStatus::kInvalidArgument;
    }
    WSAPROTOCOL_INFOW socket_protocol{};
    int protocol_length = sizeof(socket_protocol);
    if (getsockopt(
            socket, SOL_SOCKET, SO_PROTOCOL_INFOW,
            reinterpret_cast<char*>(&socket_protocol), &protocol_length) ==
            SOCKET_ERROR ||
        socket_protocol.iAddressFamily != AF_INET) {
        network_error = WSAEAFNOSUPPORT;
        return TcpProxyClientStatus::kInvalidArgument;
    }
    try {
        std::array<std::uint8_t, 16> target_address{};
        const std::size_t expected_length =
            family == AddressFamily::kIpv4
                ? 4
                : family == AddressFamily::kIpv6 ? 16 : 0;
        if (address_length != expected_length) {
            network_error = WSAEINVAL;
            return TcpProxyClientStatus::kInvalidArgument;
        }
        std::copy_n(address, address_length, target_address.begin());
        const auto protocol_family =
            family == AddressFamily::kIpv4
                ? protocol::DnsProxyAddressFamily::kIpv4
                : protocol::DnsProxyAddressFamily::kIpv6;
        std::vector<std::uint8_t> request;
        if (protocol::EncodeTcpProxyRequest(
                session, sequence, process_id, protocol_family,
                target_address, target_port, ascii_domain, request) !=
            protocol::TcpProxyStatus::kSuccess) {
            network_error = WSAEINVAL;
            return TcpProxyClientStatus::kInvalidArgument;
        }
        sockaddr_in proxy{};
        proxy.sin_family = AF_INET;
        proxy.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        proxy.sin_port = htons(proxy_port);
        if (original_connect(
                socket, reinterpret_cast<const sockaddr*>(&proxy),
                sizeof(proxy)) == SOCKET_ERROR) {
            network_error = static_cast<std::uint32_t>(WSAGetLastError());
            return TcpProxyClientStatus::kProxyConnectFailed;
        }
        const auto request_prefix = Prefix(request.size());
        if (!WriteExact(
                socket, request_prefix.data(), request_prefix.size()) ||
            !WriteExact(socket, request.data(), request.size())) {
            DisableSocket(socket);
            network_error = WSAECONNABORTED;
            return TcpProxyClientStatus::kWriteFailed;
        }
        std::array<std::uint8_t, kPrefixLength> response_prefix{};
        if (!ReadExact(
                socket, response_prefix.data(), response_prefix.size())) {
            DisableSocket(socket);
            network_error = WSAECONNABORTED;
            return TcpProxyClientStatus::kReadFailed;
        }
        const std::size_t response_length = ReadLength(response_prefix);
        if (response_length < protocol::kDnsProxyHeaderLength ||
            response_length > kMaximumResponseLength) {
            DisableSocket(socket);
            network_error = WSAEPROTONOSUPPORT;
            return TcpProxyClientStatus::kProtocolFailed;
        }
        std::vector<std::uint8_t> response(response_length);
        if (!ReadExact(socket, response.data(), response.size())) {
            DisableSocket(socket);
            network_error = WSAECONNABORTED;
            return TcpProxyClientStatus::kReadFailed;
        }
        protocol::TcpProxyResponse decoded{};
        if (protocol::DecodeTcpProxyResponse(
                session, response.data(), response.size(), sequence,
                decoded) != protocol::TcpProxyStatus::kSuccess) {
            DisableSocket(socket);
            network_error = WSAEPROTONOSUPPORT;
            return TcpProxyClientStatus::kProtocolFailed;
        }
        if (decoded.result == protocol::TcpProxyResult::kConnected) {
            return TcpProxyClientStatus::kConnected;
        }
        DisableSocket(socket);
        if (decoded.result == protocol::TcpProxyResult::kDenied) {
            network_error = WSAEACCES;
            return TcpProxyClientStatus::kDenied;
        }
        if (decoded.result == protocol::TcpProxyResult::kConnectFailed) {
            network_error = decoded.network_error;
            return TcpProxyClientStatus::kConnectFailed;
        }
        network_error = WSAECONNABORTED;
        return TcpProxyClientStatus::kProxyFailure;
    } catch (const std::bad_alloc&) {
        network_error = WSAENOBUFS;
        return TcpProxyClientStatus::kAllocationFailed;
    } catch (...) {
        network_error = WSAEINVAL;
        return TcpProxyClientStatus::kInvalidArgument;
    }
}

}  // namespace bolt::network
