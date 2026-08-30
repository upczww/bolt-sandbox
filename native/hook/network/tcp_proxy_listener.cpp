#include "hook/network/tcp_proxy_listener.h"

#include "hook/network/tcp_proxy_connection.h"
#include "hook/network/tcp_relay.h"

#include <limits>
#include <thread>
#include <vector>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace bolt::network {

TcpProxyListenerStatus RunTcpProxyListener(
    const SOCKET listener,
    const protocol::DnsProxySession& session,
    const NetworkPolicy& policy,
    const DnsBindingTable& bindings,
    const std::atomic<bool>& stop_requested,
    const std::size_t maximum_connections) noexcept {
    if (listener == INVALID_SOCKET || maximum_connections == 0 ||
        maximum_connections > 4'096) {
        return TcpProxyListenerStatus::kInvalidArgument;
    }
    std::vector<std::thread> workers;
    try {
        workers.reserve(maximum_connections);
    } catch (...) {
        return TcpProxyListenerStatus::kInvalidArgument;
    }
    std::uint64_t sequence = 1;
    std::size_t completed = 0;
    TcpProxyListenerStatus result = TcpProxyListenerStatus::kLimitReached;
    while (completed < maximum_connections) {
        if (stop_requested.load(std::memory_order_acquire)) {
            result = TcpProxyListenerStatus::kStopped;
            break;
        }
        fd_set readable{};
        FD_ZERO(&readable);
        FD_SET(listener, &readable);
        timeval timeout{};
        timeout.tv_usec = 100'000;
        const int selected =
            select(0, &readable, nullptr, nullptr, &timeout);
        if (selected == 0) {
            continue;
        }
        if (selected == SOCKET_ERROR) {
            const int error = WSAGetLastError();
            if (error == WSAEINTR) {
                continue;
            }
            result = TcpProxyListenerStatus::kAcceptFailed;
            break;
        }
        const SOCKET client = accept(listener, nullptr, nullptr);
        if (client == INVALID_SOCKET) {
            const int error = WSAGetLastError();
            if (error == WSAENOTSOCK || error == WSAEINVAL ||
                error == WSAESHUTDOWN) {
                result = TcpProxyListenerStatus::kStopped;
                break;
            }
            if (error == WSAEINTR) {
                continue;
            }
            result = TcpProxyListenerStatus::kAcceptFailed;
            break;
        }
        SetHandleInformation(
            reinterpret_cast<HANDLE>(client), HANDLE_FLAG_INHERIT, 0);
        constexpr DWORD handshake_timeout = 5'000;
        setsockopt(
            client, SOL_SOCKET, SO_RCVTIMEO,
            reinterpret_cast<const char*>(&handshake_timeout),
            sizeof(handshake_timeout));
        SOCKET upstream = INVALID_SOCKET;
        const auto status = PrepareTcpProxyConnection(
            client, session, policy, bindings, sequence, GetTickCount64(),
            upstream);
        if (status == TcpProxyHandshakeStatus::kReady) {
            try {
                workers.emplace_back([client, upstream] {
                    RelayTcpSockets(client, upstream);
                    closesocket(upstream);
                    closesocket(client);
                });
            } catch (...) {
                closesocket(upstream);
                closesocket(client);
                result = TcpProxyListenerStatus::kAcceptFailed;
                break;
            }
        } else {
            closesocket(client);
        }
        if (status == TcpProxyHandshakeStatus::kReady ||
            status == TcpProxyHandshakeStatus::kRejected) {
            ++completed;
            if (sequence == std::numeric_limits<std::uint64_t>::max()) {
                result = TcpProxyListenerStatus::kLimitReached;
                break;
            }
            ++sequence;
        }
    }
    for (auto& worker : workers) {
        worker.join();
    }
    return result;
}

}  // namespace bolt::network
