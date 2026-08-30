#include "hook/network/tcp_relay.h"

#include <array>

namespace bolt::network {
namespace {

constexpr std::size_t kRelayBufferLength = 16U * 1'024U;

bool SendAll(
    const SOCKET destination,
    const char* const bytes,
    const int length) noexcept {
    int offset = 0;
    while (offset < length) {
        const int sent = send(destination, bytes + offset, length - offset, 0);
        if (sent > 0) {
            offset += sent;
            continue;
        }
        if (sent == SOCKET_ERROR && WSAGetLastError() == WSAEINTR) {
            continue;
        }
        return false;
    }
    return true;
}

TcpRelayStatus ForwardReadable(
    const SOCKET source,
    const SOCKET destination,
    bool& source_open,
    std::array<char, kRelayBufferLength>& buffer) noexcept {
    const int received =
        recv(source, buffer.data(), static_cast<int>(buffer.size()), 0);
    if (received > 0) {
        return SendAll(destination, buffer.data(), received)
                   ? TcpRelayStatus::kCompleted
                   : TcpRelayStatus::kWriteFailed;
    }
    if (received == 0) {
        source_open = false;
        if (shutdown(destination, SD_SEND) == SOCKET_ERROR) {
            const int error = WSAGetLastError();
            if (error != WSAENOTCONN && error != WSAESHUTDOWN) {
                return TcpRelayStatus::kShutdownFailed;
            }
        }
        return TcpRelayStatus::kCompleted;
    }
    return WSAGetLastError() == WSAEINTR
               ? TcpRelayStatus::kCompleted
               : TcpRelayStatus::kReadFailed;
}

}  // namespace

TcpRelayStatus RelayTcpSockets(
    const SOCKET client,
    const SOCKET upstream) noexcept {
    if (client == INVALID_SOCKET || upstream == INVALID_SOCKET ||
        client == upstream) {
        return TcpRelayStatus::kInvalidSocket;
    }
    bool client_open = true;
    bool upstream_open = true;
    std::array<char, kRelayBufferLength> client_buffer{};
    std::array<char, kRelayBufferLength> upstream_buffer{};
    while (client_open || upstream_open) {
        fd_set readable{};
        FD_ZERO(&readable);
        if (client_open) {
            FD_SET(client, &readable);
        }
        if (upstream_open) {
            FD_SET(upstream, &readable);
        }
        const int selected = select(0, &readable, nullptr, nullptr, nullptr);
        if (selected == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEINTR) {
                continue;
            }
            return TcpRelayStatus::kSelectFailed;
        }
        if (selected == 0) {
            continue;
        }
        if (client_open && FD_ISSET(client, &readable)) {
            const auto status = ForwardReadable(
                client, upstream, client_open, client_buffer);
            if (status != TcpRelayStatus::kCompleted) {
                return status;
            }
        }
        if (upstream_open && FD_ISSET(upstream, &readable)) {
            const auto status = ForwardReadable(
                upstream, client, upstream_open, upstream_buffer);
            if (status != TcpRelayStatus::kCompleted) {
                return status;
            }
        }
    }
    return TcpRelayStatus::kCompleted;
}

}  // namespace bolt::network
