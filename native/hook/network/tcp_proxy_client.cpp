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
constexpr DWORD kProxyHandshakeTimeoutMilliseconds = 2'000;

class NonblockingHandshakeScope final {
  public:
    explicit NonblockingHandshakeScope(const SOCKET socket) noexcept
        : socket_(socket) {}

    ~NonblockingHandshakeScope() noexcept {
        if (!active_) {
            return;
        }
        setsockopt(
            socket_, SOL_SOCKET, SO_RCVTIMEO,
            reinterpret_cast<const char*>(&receive_timeout_),
            sizeof(receive_timeout_));
        setsockopt(
            socket_, SOL_SOCKET, SO_SNDTIMEO,
            reinterpret_cast<const char*>(&send_timeout_),
            sizeof(send_timeout_));
        RestoreNonblocking();
    }

    NonblockingHandshakeScope(const NonblockingHandshakeScope&) = delete;
    NonblockingHandshakeScope& operator=(
        const NonblockingHandshakeScope&) = delete;

    bool CompletePendingConnect(std::uint32_t& network_error) noexcept {
        fd_set writable{};
        fd_set failed{};
        FD_ZERO(&writable);
        FD_ZERO(&failed);
        FD_SET(socket_, &writable);
        FD_SET(socket_, &failed);
        timeval timeout{};
        timeout.tv_sec =
            static_cast<long>(kProxyHandshakeTimeoutMilliseconds / 1'000);
        timeout.tv_usec = static_cast<long>(
            (kProxyHandshakeTimeoutMilliseconds % 1'000) * 1'000);
        const int selected =
            select(0, nullptr, &writable, &failed, &timeout);
        if (selected <= 0) {
            network_error = selected == 0
                                ? WSAETIMEDOUT
                                : static_cast<std::uint32_t>(WSAGetLastError());
            return false;
        }
        int socket_error = 0;
        int error_length = sizeof(socket_error);
        if (getsockopt(
                socket_, SOL_SOCKET, SO_ERROR,
                reinterpret_cast<char*>(&socket_error), &error_length) ==
                SOCKET_ERROR ||
            socket_error != 0) {
            network_error = socket_error == 0
                                ? static_cast<std::uint32_t>(WSAGetLastError())
                                : static_cast<std::uint32_t>(socket_error);
            return false;
        }
        int option_length = sizeof(receive_timeout_);
        if (getsockopt(
                socket_, SOL_SOCKET, SO_RCVTIMEO,
                reinterpret_cast<char*>(&receive_timeout_), &option_length) ==
                SOCKET_ERROR) {
            network_error = static_cast<std::uint32_t>(WSAGetLastError());
            return false;
        }
        option_length = sizeof(send_timeout_);
        if (getsockopt(
                socket_, SOL_SOCKET, SO_SNDTIMEO,
                reinterpret_cast<char*>(&send_timeout_), &option_length) ==
                SOCKET_ERROR) {
            network_error = static_cast<std::uint32_t>(WSAGetLastError());
            return false;
        }
        u_long disabled = 0;
        const DWORD timeout_value = kProxyHandshakeTimeoutMilliseconds;
        if (ioctlsocket(socket_, FIONBIO, &disabled) == SOCKET_ERROR) {
            network_error = static_cast<std::uint32_t>(WSAGetLastError());
            return false;
        }
        if (setsockopt(
                socket_, SOL_SOCKET, SO_RCVTIMEO,
                reinterpret_cast<const char*>(&timeout_value),
                sizeof(timeout_value)) == SOCKET_ERROR) {
            network_error = static_cast<std::uint32_t>(WSAGetLastError());
            RestoreNonblocking();
            return false;
        }
        if (setsockopt(
                socket_, SOL_SOCKET, SO_SNDTIMEO,
                reinterpret_cast<const char*>(&timeout_value),
                sizeof(timeout_value)) == SOCKET_ERROR) {
            network_error = static_cast<std::uint32_t>(WSAGetLastError());
            setsockopt(
                socket_, SOL_SOCKET, SO_RCVTIMEO,
                reinterpret_cast<const char*>(&receive_timeout_),
                sizeof(receive_timeout_));
            RestoreNonblocking();
            return false;
        }
        active_ = true;
        network_error = 0;
        return true;
    }

  private:
    void RestoreNonblocking() const noexcept {
        u_long enabled = 1;
        ioctlsocket(socket_, FIONBIO, &enabled);
    }

    SOCKET socket_ = INVALID_SOCKET;
    DWORD receive_timeout_ = 0;
    DWORD send_timeout_ = 0;
    bool active_ = false;
};

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
    const int expected_socket_family =
        family == AddressFamily::kIpv4
            ? AF_INET
            : family == AddressFamily::kIpv6 ? AF_INET6 : AF_UNSPEC;
    if (getsockopt(
            socket, SOL_SOCKET, SO_PROTOCOL_INFOW,
            reinterpret_cast<char*>(&socket_protocol), &protocol_length) ==
            SOCKET_ERROR ||
        expected_socket_family == AF_UNSPEC ||
        socket_protocol.iAddressFamily != expected_socket_family) {
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
        sockaddr_storage proxy{};
        int proxy_length = 0;
        if (family == AddressFamily::kIpv4) {
            auto* endpoint = reinterpret_cast<sockaddr_in*>(&proxy);
            endpoint->sin_family = AF_INET;
            endpoint->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            endpoint->sin_port = htons(proxy_port);
            proxy_length = sizeof(*endpoint);
        } else {
            auto* endpoint = reinterpret_cast<sockaddr_in6*>(&proxy);
            endpoint->sin6_family = AF_INET6;
            endpoint->sin6_addr = in6addr_loopback;
            endpoint->sin6_port = htons(proxy_port);
            proxy_length = sizeof(*endpoint);
        }
        NonblockingHandshakeScope nonblocking_handshake(socket);
        if (original_connect(
                socket, reinterpret_cast<const sockaddr*>(&proxy),
                proxy_length) == SOCKET_ERROR) {
            network_error = static_cast<std::uint32_t>(WSAGetLastError());
            if (network_error != WSAEWOULDBLOCK ||
                !nonblocking_handshake.CompletePendingConnect(network_error)) {
                return TcpProxyClientStatus::kProxyConnectFailed;
            }
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
