#include "hook/network/tcp_proxy_listener.h"
#include "hook/network/bounded_dns_resolver.h"
#include "hook/network/dns_proxy_handle_transport.h"
#include "hook/network/dns_proxy_server.h"
#include "hook/network/dns_proxy_session.h"
#include "hook/network/network_policy.h"
#include "hook/network/system_dns_resolver.h"
#include "protocol/dns_proxy_startup.h"

#include <cstdint>
#include <atomic>
#include <cstring>
#include <memory>
#include <thread>
#include <vector>

#include <ws2tcpip.h>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace {

HANDLE HandleFromWire(const std::uint64_t value) noexcept {
    return reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(value));
}

bool ValidateListener(
    const SOCKET listener,
    const int expected_family,
    const std::uint16_t expected_port) noexcept {
    if (listener == INVALID_SOCKET || expected_port == 0) {
        return false;
    }
    sockaddr_storage storage{};
    int storage_length = sizeof(storage);
    BOOL accepting = FALSE;
    int accepting_length = sizeof(accepting);
    if (getsockname(
            listener, reinterpret_cast<sockaddr*>(&storage),
            &storage_length) == SOCKET_ERROR ||
        storage.ss_family != expected_family ||
        getsockopt(
            listener, SOL_SOCKET, SO_ACCEPTCONN,
            reinterpret_cast<char*>(&accepting), &accepting_length) ==
            SOCKET_ERROR ||
        accepting == FALSE) {
        return false;
    }
    if (expected_family == AF_INET) {
        const auto* endpoint = reinterpret_cast<const sockaddr_in*>(&storage);
        if (endpoint->sin_addr.s_addr != htonl(INADDR_LOOPBACK) ||
            ntohs(endpoint->sin_port) != expected_port) {
            return false;
        }
    } else {
        const auto* endpoint = reinterpret_cast<const sockaddr_in6*>(&storage);
        if (std::memcmp(
                &endpoint->sin6_addr, &in6addr_loopback,
                sizeof(in6addr_loopback)) != 0 ||
            ntohs(endpoint->sin6_port) != expected_port) {
            return false;
        }
    }
    return SetHandleInformation(
               reinterpret_cast<HANDLE>(listener), HANDLE_FLAG_INHERIT, 0) !=
           FALSE;
}

void CloseListeners(
    const SOCKET ipv4_listener,
    const SOCKET ipv6_listener) noexcept {
    if (ipv4_listener != INVALID_SOCKET) {
        closesocket(ipv4_listener);
    }
    if (ipv6_listener != INVALID_SOCKET) {
        closesocket(ipv6_listener);
    }
}

int RunProxy() noexcept {
    STARTUPINFOW startup_info{};
    startup_info.cb = sizeof(startup_info);
    GetStartupInfoW(&startup_info);
    if ((startup_info.dwFlags & STARTF_USESTDHANDLES) == 0) {
        return 10;
    }
    const HANDLE startup_mapping = GetStdHandle(STD_INPUT_HANDLE);
    const auto* startup_bytes = static_cast<const std::uint8_t*>(
        MapViewOfFile(
            startup_mapping, FILE_MAP_READ, 0, 0,
            bolt::protocol::kDnsProxyStartupLength));
    if (startup_bytes == nullptr) {
        return 10;
    }
    bolt::protocol::DnsProxyStartup startup{};
    const auto startup_status = bolt::protocol::DecodeDnsProxyStartup(
        startup_bytes, bolt::protocol::kDnsProxyStartupLength, startup);
    UnmapViewOfFile(startup_bytes);
    if (startup_status !=
        bolt::protocol::DnsProxyStartupStatus::kSuccess) {
        return 11;
    }
    if (HandleFromWire(startup.read_handle) != GetStdHandle(STD_OUTPUT_HANDLE) ||
        HandleFromWire(startup.write_handle) != GetStdHandle(STD_ERROR_HANDLE)) {
        SecureZeroMemory(
            startup.session.authentication_key.data(),
            startup.session.authentication_key.size());
        return 11;
    }
    WSADATA winsock{};
    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) {
        SecureZeroMemory(
            startup.session.authentication_key.data(),
            startup.session.authentication_key.size());
        return 16;
    }
    const SOCKET tcp_listener =
        static_cast<SOCKET>(startup.tcp_listener_handle);
    const SOCKET tcp_ipv6_listener =
        static_cast<SOCKET>(startup.tcp_ipv6_listener_handle);
    if (!ValidateListener(
            tcp_listener, AF_INET, startup.tcp_listener_port) ||
        !ValidateListener(
            tcp_ipv6_listener, AF_INET6,
            startup.tcp_ipv6_listener_port)) {
        CloseListeners(tcp_listener, tcp_ipv6_listener);
        WSACleanup();
        SecureZeroMemory(
            startup.session.authentication_key.data(),
            startup.session.authentication_key.size());
        return 16;
    }

    const HANDLE policy_handle = HandleFromWire(startup.policy_handle);
    const auto* policy_bytes = static_cast<const std::uint8_t*>(
        MapViewOfFile(
            policy_handle, FILE_MAP_READ, 0, 0,
            static_cast<SIZE_T>(startup.policy_length)));
    if (policy_bytes == nullptr) {
        CloseListeners(tcp_listener, tcp_ipv6_listener);
        WSACleanup();
        SecureZeroMemory(
            startup.session.authentication_key.data(),
            startup.session.authentication_key.size());
        return 12;
    }
    std::unique_ptr<bolt::network::NetworkPolicy> policy;
    const auto policy_status = bolt::network::NetworkPolicy::Load(
        policy_bytes, startup.policy_length, policy);
    UnmapViewOfFile(policy_bytes);
    if (policy_status != bolt::network::PolicyLoadStatus::kValid ||
        policy == nullptr || policy->mode() != bolt::network::Mode::kAllowList) {
        CloseListeners(tcp_listener, tcp_ipv6_listener);
        WSACleanup();
        SecureZeroMemory(
            startup.session.authentication_key.data(),
            startup.session.authentication_key.size());
        return 13;
    }

    std::unique_ptr<bolt::network::DnsProxyHandleTransport> transport;
    if (bolt::network::DnsProxyHandleTransport::Create(
            HandleFromWire(startup.read_handle),
            HandleFromWire(startup.write_handle), startup.maximum_frame_length,
            transport) != bolt::network::HandleTransportStatus::kSuccess) {
        CloseListeners(tcp_listener, tcp_ipv6_listener);
        WSACleanup();
        SecureZeroMemory(
            startup.session.authentication_key.data(),
            startup.session.authentication_key.size());
        return 14;
    }
    auto system_resolver =
        std::make_shared<bolt::network::SystemDnsResolver>();
    constexpr std::uint32_t dns_timeout_milliseconds = 2'000;
    bolt::network::BoundedDnsResolver resolver(
        system_resolver, dns_timeout_milliseconds);
    std::unique_ptr<bolt::network::DnsBindingTable> bindings;
    if (bolt::network::DnsBindingTable::Create(4'096, bindings) !=
        bolt::network::BindingStatus::kSuccess) {
        CloseListeners(tcp_listener, tcp_ipv6_listener);
        WSACleanup();
        SecureZeroMemory(
            startup.session.authentication_key.data(),
            startup.session.authentication_key.size());
        return 14;
    }
    auto listener_status =
        bolt::network::TcpProxyListenerStatus::kInvalidArgument;
    auto ipv6_listener_status =
        bolt::network::TcpProxyListenerStatus::kInvalidArgument;
    std::atomic<bool> stop_listener = false;
    std::atomic<bool> stop_ipv6_listener = false;
    std::thread listener_thread;
    std::thread ipv6_listener_thread;
    try {
        listener_thread = std::thread([&] {
            listener_status = bolt::network::RunTcpProxyListener(
                tcp_listener, startup.session, *policy, *bindings,
                stop_listener,
                startup.maximum_tcp_connections);
        });
        ipv6_listener_thread = std::thread([&] {
            ipv6_listener_status = bolt::network::RunTcpProxyListener(
                tcp_ipv6_listener, startup.session, *policy, *bindings,
                stop_ipv6_listener, startup.maximum_tcp_connections);
        });
    } catch (...) {
        stop_listener.store(true, std::memory_order_release);
        stop_ipv6_listener.store(true, std::memory_order_release);
        if (listener_thread.joinable()) {
            listener_thread.join();
        }
        if (ipv6_listener_thread.joinable()) {
            ipv6_listener_thread.join();
        }
        CloseListeners(tcp_listener, tcp_ipv6_listener);
        WSACleanup();
        SecureZeroMemory(
            startup.session.authentication_key.data(),
            startup.session.authentication_key.size());
        return 16;
    }
    const auto session_status = bolt::network::RunDnsProxySession(
        startup.session, *policy, resolver, *bindings, *transport,
        startup.maximum_requests);
    stop_listener.store(true, std::memory_order_release);
    stop_ipv6_listener.store(true, std::memory_order_release);
    listener_thread.join();
    ipv6_listener_thread.join();
    CloseListeners(tcp_listener, tcp_ipv6_listener);
    WSACleanup();
    SecureZeroMemory(
        startup.session.authentication_key.data(),
        startup.session.authentication_key.size());
    return session_status == bolt::network::DnsProxySessionStatus::kCompleted &&
                   listener_status ==
                       bolt::network::TcpProxyListenerStatus::kStopped &&
                   ipv6_listener_status ==
                       bolt::network::TcpProxyListenerStatus::kStopped
               ? 0
               : 15;
}

}  // namespace

int wmain() {
    return RunProxy();
}
