#include "hook/network/tcp_proxy_client.h"

#include <array>
#include <cstdint>
#include <thread>
#include <vector>

#include <ws2tcpip.h>

namespace {

bool ReadExact(SOCKET socket, std::uint8_t* bytes, std::size_t length) {
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

bool WriteExact(SOCKET socket, const std::uint8_t* bytes, std::size_t length) {
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

std::uint32_t ReadLength(const std::array<std::uint8_t, 4>& bytes) {
    return static_cast<std::uint32_t>(bytes[0]) |
           (static_cast<std::uint32_t>(bytes[1]) << 8U) |
           (static_cast<std::uint32_t>(bytes[2]) << 16U) |
           (static_cast<std::uint32_t>(bytes[3]) << 24U);
}

std::array<std::uint8_t, 4> Prefix(std::size_t length) {
    const auto value = static_cast<std::uint32_t>(length);
    return {
        static_cast<std::uint8_t>(value),
        static_cast<std::uint8_t>(value >> 8U),
        static_cast<std::uint8_t>(value >> 16U),
        static_cast<std::uint8_t>(value >> 24U)};
}

bool RunCase(
    const bolt::protocol::TcpProxyResult result,
    const std::uint32_t response_error,
    const bool tamper_response,
    const bolt::network::TcpProxyClientStatus expected_status,
    const std::uint32_t expected_error) {
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
    bolt::protocol::DnsProxySession session{};
    session.nonce[0] = 1;
    session.authentication_key[0] = 2;
    bool server_valid = false;
    std::thread server([&] {
        const SOCKET accepted = accept(listener, nullptr, nullptr);
        std::array<std::uint8_t, 4> prefix{};
        std::vector<std::uint8_t> request;
        if (accepted != INVALID_SOCKET &&
            ReadExact(accepted, prefix.data(), prefix.size())) {
            request.resize(ReadLength(prefix));
        }
        bolt::protocol::TcpProxyRequest decoded{};
        server_valid = !request.empty() &&
            ReadExact(accepted, request.data(), request.size()) &&
            bolt::protocol::DecodeTcpProxyRequest(
                session, request.data(), request.size(), 7, decoded) ==
                bolt::protocol::TcpProxyStatus::kSuccess &&
            decoded.process_id == 99 && decoded.port == 443 &&
            decoded.ascii_domain == "api.example";
        std::vector<std::uint8_t> response;
        if (server_valid) {
            server_valid = bolt::protocol::EncodeTcpProxyResponse(
                session, 7, result, response_error, response) ==
                bolt::protocol::TcpProxyStatus::kSuccess;
        }
        if (server_valid && tamper_response) {
            response.back() ^= 1;
        }
        if (server_valid) {
            const auto response_prefix = Prefix(response.size());
            server_valid =
                WriteExact(
                    accepted, response_prefix.data(), response_prefix.size()) &&
                WriteExact(accepted, response.data(), response.size());
        }
        if (accepted != INVALID_SOCKET) {
            closesocket(accepted);
        }
    });

    const SOCKET client = WSASocketW(
        AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
        WSA_FLAG_NO_HANDLE_INHERIT);
    std::array<std::uint8_t, 16> target{};
    target[0] = 192;
    target[1] = 0;
    target[2] = 2;
    target[3] = 20;
    std::uint32_t network_error = 0;
    const auto status = bolt::network::ConnectTcpSocketThroughProxy(
        client, connect, ntohs(endpoint.sin_port), session, 7, 99,
        bolt::network::AddressFamily::kIpv4, target.data(), 4, 443,
        "api.example", network_error);
    server.join();
    closesocket(client);
    closesocket(listener);
    return server_valid && status == expected_status &&
           network_error == expected_error;
}

bool RunIpv6Case() {
    const SOCKET listener = WSASocketW(
        AF_INET6, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
        WSA_FLAG_NO_HANDLE_INHERIT);
    sockaddr_in6 endpoint{};
    endpoint.sin6_family = AF_INET6;
    endpoint.sin6_addr = in6addr_loopback;
    endpoint.sin6_port = 0;
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
    bolt::protocol::DnsProxySession session{};
    session.nonce[0] = 1;
    session.authentication_key[0] = 2;
    bool server_valid = false;
    std::thread server([&] {
        fd_set readable{};
        FD_ZERO(&readable);
        FD_SET(listener, &readable);
        timeval wait{};
        wait.tv_sec = 2;
        if (select(0, &readable, nullptr, nullptr, &wait) != 1) {
            return;
        }
        const SOCKET accepted = accept(listener, nullptr, nullptr);
        std::array<std::uint8_t, 4> prefix{};
        std::vector<std::uint8_t> request;
        if (accepted != INVALID_SOCKET &&
            ReadExact(accepted, prefix.data(), prefix.size())) {
            request.resize(ReadLength(prefix));
        }
        bolt::protocol::TcpProxyRequest decoded{};
        server_valid = !request.empty() &&
            ReadExact(accepted, request.data(), request.size()) &&
            bolt::protocol::DecodeTcpProxyRequest(
                session, request.data(), request.size(), 1, decoded) ==
                bolt::protocol::TcpProxyStatus::kSuccess &&
            decoded.family ==
                bolt::protocol::DnsProxyAddressFamily::kIpv6;
        std::vector<std::uint8_t> response;
        if (server_valid) {
            server_valid = bolt::protocol::EncodeTcpProxyResponse(
                session, 1, bolt::protocol::TcpProxyResult::kConnected, 0,
                response) == bolt::protocol::TcpProxyStatus::kSuccess;
        }
        if (server_valid) {
            const auto response_prefix = Prefix(response.size());
            server_valid = WriteExact(
                               accepted, response_prefix.data(),
                               response_prefix.size()) &&
                           WriteExact(
                               accepted, response.data(), response.size());
        }
        if (accepted != INVALID_SOCKET) {
            closesocket(accepted);
        }
    });
    const SOCKET client = WSASocketW(
        AF_INET6, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
        WSA_FLAG_NO_HANDLE_INHERIT);
    std::array<std::uint8_t, 16> target{};
    target[0] = 0x20;
    target[1] = 0x01;
    target[2] = 0x0D;
    target[3] = 0xB8;
    target[15] = 0x20;
    std::uint32_t network_error = 0;
    const auto status = bolt::network::ConnectTcpSocketThroughProxy(
        client, connect, ntohs(endpoint.sin6_port), session, 1, 99,
        bolt::network::AddressFamily::kIpv6, target.data(), target.size(), 443,
        "ipv6.example", network_error);
    server.join();
    closesocket(client);
    closesocket(listener);
    return server_valid &&
        status == bolt::network::TcpProxyClientStatus::kConnected &&
        network_error == 0;
}

}  // namespace

bool RunTcpProxyClientTests() {
    WSADATA winsock{};
    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) {
        return false;
    }
    const bool passed =
        RunCase(
            bolt::protocol::TcpProxyResult::kConnected, 0, false,
            bolt::network::TcpProxyClientStatus::kConnected, 0) &&
        RunCase(
            bolt::protocol::TcpProxyResult::kDenied, 0, false,
            bolt::network::TcpProxyClientStatus::kDenied, WSAEACCES) &&
        RunCase(
            bolt::protocol::TcpProxyResult::kConnectFailed, WSAECONNREFUSED,
            false, bolt::network::TcpProxyClientStatus::kConnectFailed,
            WSAECONNREFUSED) &&
        RunCase(
            bolt::protocol::TcpProxyResult::kConnected, 0, true,
            bolt::network::TcpProxyClientStatus::kProtocolFailed,
            WSAEPROTONOSUPPORT) &&
        RunIpv6Case();
    WSACleanup();
    return passed;
}
