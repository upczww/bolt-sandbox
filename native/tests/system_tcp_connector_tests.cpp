#include "hook/network/system_tcp_connector.h"

#include <array>
#include <cstdint>
#include <cstring>

bool RunSystemTcpConnectorTests() {
    WSADATA winsock{};
    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) {
        return false;
    }
    const SOCKET listener = WSASocketW(
        AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
        WSA_FLAG_NO_HANDLE_INHERIT);
    sockaddr_in endpoint{};
    endpoint.sin_family = AF_INET;
    endpoint.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    endpoint.sin_port = 0;
    int endpoint_length = sizeof(endpoint);
    const bool listening = listener != INVALID_SOCKET &&
        bind(
            listener, reinterpret_cast<const sockaddr*>(&endpoint),
            sizeof(endpoint)) == 0 &&
        listen(listener, 1) == 0 &&
        getsockname(
            listener, reinterpret_cast<sockaddr*>(&endpoint),
            &endpoint_length) == 0;
    if (!listening) {
        if (listener != INVALID_SOCKET) {
            closesocket(listener);
        }
        WSACleanup();
        return false;
    }

    std::array<std::uint8_t, 4> loopback = {127, 0, 0, 1};
    bolt::network::SystemTcpConnector connector;
    std::uint32_t network_error = 99;
    const bool connected = connector.Connect(
        bolt::network::AddressFamily::kIpv4, loopback.data(), loopback.size(),
        ntohs(endpoint.sin_port), network_error);
    const SOCKET upstream = connected ? accept(listener, nullptr, nullptr)
                                      : INVALID_SOCKET;
    const SOCKET client = connector.ReleaseSocket();
    const char request[] = "ping";
    std::array<char, 4> received{};
    const bool request_round_trip =
        connected && network_error == 0 && upstream != INVALID_SOCKET &&
        client != INVALID_SOCKET &&
        send(client, request, static_cast<int>(sizeof(request) - 1), 0) == 4 &&
        recv(upstream, received.data(), static_cast<int>(received.size()), 0) ==
            4 &&
        std::memcmp(received.data(), request, received.size()) == 0;
    const char response[] = "pong";
    received.fill(0);
    const bool response_round_trip =
        request_round_trip &&
        send(upstream, response, static_cast<int>(sizeof(response) - 1), 0) ==
            4 &&
        recv(client, received.data(), static_cast<int>(received.size()), 0) ==
            4 &&
        std::memcmp(received.data(), response, received.size()) == 0;

    if (client != INVALID_SOCKET) {
        closesocket(client);
    }
    if (upstream != INVALID_SOCKET) {
        closesocket(upstream);
    }
    closesocket(listener);

    bolt::network::SystemTcpConnector invalid;
    network_error = 0;
    const bool invalid_rejected =
        !invalid.Connect(
            bolt::network::AddressFamily::kIpv4, loopback.data(), 3, 443,
            network_error) &&
        network_error == WSAEINVAL;

    bolt::network::SystemTcpConnector refused;
    network_error = 0;
    const bool refusal_preserved =
        !refused.Connect(
            bolt::network::AddressFamily::kIpv4, loopback.data(),
            loopback.size(), ntohs(endpoint.sin_port), network_error) &&
        network_error != 0 && network_error != WSAEACCES;
    WSACleanup();
    return response_round_trip && invalid_rejected && refusal_preserved;
}
