#include "hook/network/system_tcp_connector.h"

#include <cstring>

#include <ws2tcpip.h>

namespace bolt::network {

SystemTcpConnector::~SystemTcpConnector() noexcept {
    if (socket_ != INVALID_SOCKET) {
        closesocket(socket_);
    }
}

bool SystemTcpConnector::Connect(
    const AddressFamily family,
    const std::uint8_t* const address,
    const std::size_t address_length,
    const std::uint16_t port,
    std::uint32_t& network_error) noexcept {
    network_error = 0;
    if (socket_ != INVALID_SOCKET) {
        network_error = WSAEISCONN;
        return false;
    }
    const bool ipv4 = family == AddressFamily::kIpv4;
    const bool ipv6 = family == AddressFamily::kIpv6;
    const std::size_t expected_length = ipv4 ? 4 : ipv6 ? 16 : 0;
    if (address == nullptr || address_length != expected_length || port == 0) {
        network_error = expected_length == 0 ? WSAEAFNOSUPPORT : WSAEINVAL;
        return false;
    }
    const int native_family = ipv4 ? AF_INET : AF_INET6;
    const SOCKET candidate = WSASocketW(
        native_family, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
        WSA_FLAG_NO_HANDLE_INHERIT);
    if (candidate == INVALID_SOCKET) {
        network_error = static_cast<std::uint32_t>(WSAGetLastError());
        return false;
    }

    sockaddr_storage storage{};
    int storage_length = 0;
    if (ipv4) {
        auto* endpoint = reinterpret_cast<sockaddr_in*>(&storage);
        endpoint->sin_family = AF_INET;
        endpoint->sin_port = htons(port);
        std::memcpy(&endpoint->sin_addr, address, 4);
        storage_length = sizeof(*endpoint);
    } else {
        auto* endpoint = reinterpret_cast<sockaddr_in6*>(&storage);
        endpoint->sin6_family = AF_INET6;
        endpoint->sin6_port = htons(port);
        std::memcpy(&endpoint->sin6_addr, address, 16);
        storage_length = sizeof(*endpoint);
    }
    if (connect(
            candidate, reinterpret_cast<const sockaddr*>(&storage),
            storage_length) == SOCKET_ERROR) {
        network_error = static_cast<std::uint32_t>(WSAGetLastError());
        closesocket(candidate);
        return false;
    }
    socket_ = candidate;
    return true;
}

SOCKET SystemTcpConnector::ReleaseSocket() noexcept {
    const SOCKET released = socket_;
    socket_ = INVALID_SOCKET;
    return released;
}

}  // namespace bolt::network
