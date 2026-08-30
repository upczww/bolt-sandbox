#include "hook/network/tcp_relay.h"

#include <array>
#include <cstdint>
#include <thread>

namespace {

bool CreateConnectedPair(SOCKET& first, SOCKET& second) {
    first = INVALID_SOCKET;
    second = INVALID_SOCKET;
    const SOCKET listener = WSASocketW(
        AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
        WSA_FLAG_NO_HANDLE_INHERIT);
    sockaddr_in endpoint{};
    endpoint.sin_family = AF_INET;
    endpoint.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    endpoint.sin_port = 0;
    int endpoint_length = sizeof(endpoint);
    if (listener == INVALID_SOCKET ||
        bind(
            listener, reinterpret_cast<const sockaddr*>(&endpoint),
            sizeof(endpoint)) != 0 ||
        listen(listener, 1) != 0 ||
        getsockname(
            listener, reinterpret_cast<sockaddr*>(&endpoint),
            &endpoint_length) != 0) {
        if (listener != INVALID_SOCKET) {
            closesocket(listener);
        }
        return false;
    }
    first = WSASocketW(
        AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
        WSA_FLAG_NO_HANDLE_INHERIT);
    if (first == INVALID_SOCKET ||
        connect(
            first, reinterpret_cast<const sockaddr*>(&endpoint),
            sizeof(endpoint)) != 0) {
        if (first != INVALID_SOCKET) {
            closesocket(first);
            first = INVALID_SOCKET;
        }
        closesocket(listener);
        return false;
    }
    second = accept(listener, nullptr, nullptr);
    closesocket(listener);
    return second != INVALID_SOCKET;
}

bool SendExact(const SOCKET socket, const char* bytes, const int length) {
    int offset = 0;
    while (offset < length) {
        const int sent = send(socket, bytes + offset, length - offset, 0);
        if (sent <= 0) {
            return false;
        }
        offset += sent;
    }
    return true;
}

bool ReceiveExact(const SOCKET socket, char* bytes, const int length) {
    int offset = 0;
    while (offset < length) {
        const int received = recv(socket, bytes + offset, length - offset, 0);
        if (received <= 0) {
            return false;
        }
        offset += received;
    }
    return true;
}

void CloseSocket(SOCKET& socket) {
    if (socket != INVALID_SOCKET) {
        closesocket(socket);
        socket = INVALID_SOCKET;
    }
}

}  // namespace

bool RunTcpRelayTests() {
    if (bolt::network::RelayTcpSockets(INVALID_SOCKET, INVALID_SOCKET) !=
        bolt::network::TcpRelayStatus::kInvalidSocket) {
        return false;
    }
    WSADATA winsock{};
    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) {
        return false;
    }
    SOCKET client_application = INVALID_SOCKET;
    SOCKET proxy_client = INVALID_SOCKET;
    SOCKET proxy_upstream = INVALID_SOCKET;
    SOCKET upstream_server = INVALID_SOCKET;
    if (!CreateConnectedPair(client_application, proxy_client) ||
        !CreateConnectedPair(proxy_upstream, upstream_server)) {
        CloseSocket(client_application);
        CloseSocket(proxy_client);
        CloseSocket(proxy_upstream);
        CloseSocket(upstream_server);
        WSACleanup();
        return false;
    }
    constexpr DWORD timeout = 3'000;
    setsockopt(
        client_application, SOL_SOCKET, SO_RCVTIMEO,
        reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    setsockopt(
        upstream_server, SOL_SOCKET, SO_RCVTIMEO,
        reinterpret_cast<const char*>(&timeout), sizeof(timeout));

    auto relay_status = bolt::network::TcpRelayStatus::kInvalidSocket;
    std::thread relay([&] {
        relay_status =
            bolt::network::RelayTcpSockets(proxy_client, proxy_upstream);
    });

    constexpr std::array<char, 7> request = {'r', 'e', 'q', 'u', 'e', 's', 't'};
    std::array<char, request.size()> request_received{};
    const bool request_forwarded =
        SendExact(
            client_application, request.data(),
            static_cast<int>(request.size())) &&
        ReceiveExact(
            upstream_server, request_received.data(),
            static_cast<int>(request_received.size())) &&
        request_received == request;

    constexpr std::array<char, 8> response = {
        'r', 'e', 's', 'p', 'o', 'n', 's', 'e'};
    std::array<char, response.size()> response_received{};
    const bool response_forwarded =
        request_forwarded &&
        SendExact(
            upstream_server, response.data(),
            static_cast<int>(response.size())) &&
        ReceiveExact(
            client_application, response_received.data(),
            static_cast<int>(response_received.size())) &&
        response_received == response;

    char probe = 0;
    const bool client_half_close_forwarded =
        response_forwarded && shutdown(client_application, SD_SEND) == 0 &&
        recv(upstream_server, &probe, 1, 0) == 0;
    const bool server_half_close_forwarded =
        client_half_close_forwarded && shutdown(upstream_server, SD_SEND) == 0 &&
        recv(client_application, &probe, 1, 0) == 0;

    if (!server_half_close_forwarded) {
        shutdown(proxy_client, SD_BOTH);
        shutdown(proxy_upstream, SD_BOTH);
    }
    relay.join();
    CloseSocket(client_application);
    CloseSocket(proxy_client);
    CloseSocket(proxy_upstream);
    CloseSocket(upstream_server);
    WSACleanup();
    return server_half_close_forwarded &&
           relay_status == bolt::network::TcpRelayStatus::kCompleted;
}
