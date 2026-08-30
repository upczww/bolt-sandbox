#include "hook/network/tcp_proxy_listener.h"
#include "hook/network/dns_proxy_handle_transport.h"
#include "hook/network/dns_proxy_server.h"
#include "hook/network/dns_proxy_session.h"
#include "hook/network/network_policy.h"
#include "hook/network/system_dns_resolver.h"
#include "protocol/dns_proxy_startup.h"

#include <cstdint>
#include <memory>
#include <thread>
#include <vector>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace {

HANDLE HandleFromWire(const std::uint64_t value) noexcept {
    return reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(value));
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
    sockaddr_in listener_endpoint{};
    int listener_endpoint_length = sizeof(listener_endpoint);
    BOOL accepting = FALSE;
    int accepting_length = sizeof(accepting);
    if (tcp_listener == INVALID_SOCKET ||
        getsockname(
            tcp_listener, reinterpret_cast<sockaddr*>(&listener_endpoint),
            &listener_endpoint_length) == SOCKET_ERROR ||
        listener_endpoint.sin_family != AF_INET ||
        listener_endpoint.sin_addr.s_addr != htonl(INADDR_LOOPBACK) ||
        ntohs(listener_endpoint.sin_port) != startup.tcp_listener_port ||
        getsockopt(
            tcp_listener, SOL_SOCKET, SO_ACCEPTCONN,
            reinterpret_cast<char*>(&accepting), &accepting_length) ==
            SOCKET_ERROR ||
        accepting == FALSE ||
        !SetHandleInformation(
            reinterpret_cast<HANDLE>(tcp_listener), HANDLE_FLAG_INHERIT, 0)) {
        closesocket(tcp_listener);
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
        closesocket(tcp_listener);
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
        closesocket(tcp_listener);
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
        closesocket(tcp_listener);
        WSACleanup();
        SecureZeroMemory(
            startup.session.authentication_key.data(),
            startup.session.authentication_key.size());
        return 14;
    }
    bolt::network::SystemDnsResolver resolver;
    std::unique_ptr<bolt::network::DnsBindingTable> bindings;
    if (bolt::network::DnsBindingTable::Create(4'096, bindings) !=
        bolt::network::BindingStatus::kSuccess) {
        closesocket(tcp_listener);
        WSACleanup();
        SecureZeroMemory(
            startup.session.authentication_key.data(),
            startup.session.authentication_key.size());
        return 14;
    }
    auto listener_status =
        bolt::network::TcpProxyListenerStatus::kInvalidArgument;
    std::thread listener_thread;
    try {
        listener_thread = std::thread([&] {
            listener_status = bolt::network::RunTcpProxyListener(
                tcp_listener, startup.session, *policy, *bindings,
                startup.maximum_tcp_connections);
        });
    } catch (...) {
        closesocket(tcp_listener);
        WSACleanup();
        SecureZeroMemory(
            startup.session.authentication_key.data(),
            startup.session.authentication_key.size());
        return 16;
    }
    const auto session_status = bolt::network::RunDnsProxySession(
        startup.session, *policy, resolver, *bindings, *transport,
        startup.maximum_requests);
    closesocket(tcp_listener);
    listener_thread.join();
    WSACleanup();
    SecureZeroMemory(
        startup.session.authentication_key.data(),
        startup.session.authentication_key.size());
    return session_status == bolt::network::DnsProxySessionStatus::kCompleted &&
                   listener_status ==
                       bolt::network::TcpProxyListenerStatus::kStopped
               ? 0
               : 15;
}

}  // namespace

int wmain() {
    return RunProxy();
}
