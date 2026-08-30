#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <windns.h>
#include <ws2tcpip.h>

#include "common/execution_job.h"
#include "common/immutable_policy_mapping.h"
#include "common/private_pipe.h"
#include "common/suspended_process.h"
#include "hook/network/dns_proxy_process.h"
#include "hook/network/network_policy.h"
#include "protocol/event_frame.h"
#include "tests/network_high_level_test_client.h"
#include "tests/policy_fixture.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace {

volatile LONG g_lookup_completion_count = 0;
volatile LONG g_dns_query_completion_count = 0;

void CALLBACK LookupCompletion(
    const DWORD error,
    const DWORD bytes,
    LPOVERLAPPED overlapped) {
    static_cast<void>(error);
    static_cast<void>(bytes);
    static_cast<void>(overlapped);
    InterlockedIncrement(&g_lookup_completion_count);
}

void WINAPI DnsQueryCompletion(
    PVOID context,
    PDNS_QUERY_RESULT results) {
    static_cast<void>(results);
    InterlockedIncrement(&g_dns_query_completion_count);
    if (context != nullptr) {
        SetEvent(static_cast<HANDLE>(context));
    }
}

std::wstring CurrentExecutable() {
    std::wstring path(32'768, L'\0');
    const DWORD length = GetModuleFileNameW(
        nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (length == 0 || length == path.size()) {
        return {};
    }
    path.resize(length);
    return path;
}

std::wstring PipeName(const DWORD process_id) {
    std::wostringstream suffix;
    suffix << std::hex << std::nouppercase << std::setfill(L'0')
           << std::setw(32) << static_cast<std::uint64_t>(process_id);
    return L"\\\\.\\pipe\\bolt-sandbox-" + suffix.str();
}

bool ReadExact(
    const HANDLE handle,
    std::uint8_t* bytes,
    const std::size_t length) {
    std::size_t offset = 0;
    while (offset < length) {
        DWORD bytes_read = 0;
        if (!ReadFile(
                handle, bytes + offset, static_cast<DWORD>(length - offset),
                &bytes_read, nullptr) ||
            bytes_read == 0) {
            return false;
        }
        offset += bytes_read;
    }
    return true;
}

bool ReadNetworkViolation(
    const HANDLE event_pipe,
    const std::uint32_t process_id,
    const std::uint64_t sequence,
    const bolt::protocol::NetworkAddressFamily family,
    const bolt::protocol::NetworkOperation operation =
        bolt::protocol::NetworkOperation::kConnect) {
    bolt::protocol::NetworkEndpoint endpoint{};
    endpoint.family = family;
    if (family == bolt::protocol::NetworkAddressFamily::kIpv4) {
        endpoint.address[0] = 127;
        endpoint.address[3] = 1;
    } else {
        endpoint.address[15] = 1;
    }
    endpoint.port = 9;

    const std::size_t frame_length =
        family == bolt::protocol::NetworkAddressFamily::kIpv4
            ? bolt::protocol::kIpv4NetworkViolationFrameLength
            : bolt::protocol::kIpv6NetworkViolationFrameLength;
    std::vector<std::uint8_t> actual(frame_length);
    std::vector<std::uint8_t> expected(frame_length);
    std::size_t written = 0;
    const bool read = ReadExact(event_pipe, actual.data(), actual.size());
    const bool encoded =
           bolt::protocol::EncodeNetworkViolationFrame(
               process_id, operation,
               endpoint, sequence, expected.data(), expected.size(), written) ==
        bolt::protocol::FrameEncodeStatus::kSuccess;
    if (!read || !encoded || written != expected.size() || actual != expected) {
        std::fprintf(stderr, "network frame mismatch at sequence %llu\nactual: ",
                     static_cast<unsigned long long>(sequence));
        for (const auto byte : actual) {
            std::fprintf(stderr, "%02X", static_cast<unsigned int>(byte));
        }
        std::fprintf(stderr, "\nexpected: ");
        for (const auto byte : expected) {
            std::fprintf(stderr, "%02X", static_cast<unsigned int>(byte));
        }
        std::fprintf(stderr, "\n");
        return false;
    }
    return true;
}

bool ReadDomainNetworkViolation(
    const HANDLE event_pipe,
    const std::uint32_t process_id,
    const std::uint64_t sequence,
    const char* domain,
    const bolt::protocol::NetworkOperation operation =
        bolt::protocol::NetworkOperation::kResolve) {
    const std::size_t frame_length =
        bolt::protocol::DomainNetworkViolationFrameLength(domain);
    std::vector<std::uint8_t> actual(frame_length);
    std::vector<std::uint8_t> expected(frame_length);
    std::size_t written = 0;
    return frame_length != 0 &&
           ReadExact(event_pipe, actual.data(), actual.size()) &&
           bolt::protocol::EncodeDomainNetworkViolationFrame(
               process_id, operation, domain, sequence, expected.data(),
               expected.size(), written) ==
               bolt::protocol::FrameEncodeStatus::kSuccess &&
           written == expected.size() && actual == expected;
}

SOCKET AcceptWithTimeout(
    const SOCKET listener,
    const long timeout_milliseconds) {
    fd_set readable{};
    FD_ZERO(&readable);
    FD_SET(listener, &readable);
    timeval timeout{};
    timeout.tv_sec = timeout_milliseconds / 1'000;
    timeout.tv_usec = (timeout_milliseconds % 1'000) * 1'000;
    return select(0, &readable, nullptr, nullptr, &timeout) == 1
               ? accept(listener, nullptr, nullptr)
               : INVALID_SOCKET;
}

}  // namespace

int RunNetworkHookChild(const int argument_count, wchar_t** arguments) {
    static_cast<void>(arguments);
    if (argument_count != 2) {
        return 200;
    }
    WSADATA winsock{};
    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) {
        return 201;
    }

    sockaddr_in endpoint{};
    endpoint.sin_family = AF_INET;
    endpoint.sin_port = htons(9);
    endpoint.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    const SOCKET connect_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    const int connect_result =
        connect(connect_socket, reinterpret_cast<const sockaddr*>(&endpoint), sizeof(endpoint));
    const int connect_error = WSAGetLastError();
    closesocket(connect_socket);

    sockaddr_in6 ipv6_endpoint{};
    ipv6_endpoint.sin6_family = AF_INET6;
    ipv6_endpoint.sin6_port = htons(9);
    ipv6_endpoint.sin6_addr = in6addr_loopback;
    const SOCKET wsa_connect_socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    const int wsa_connect_result = WSAConnect(
        wsa_connect_socket, reinterpret_cast<const sockaddr*>(&ipv6_endpoint),
        sizeof(ipv6_endpoint), nullptr, nullptr, nullptr, nullptr);
    const int wsa_connect_error = WSAGetLastError();
    closesocket(wsa_connect_socket);

    const SOCKET invalid_address_socket =
        socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    const auto* invalid_address = reinterpret_cast<const sockaddr*>(
        static_cast<std::uintptr_t>(1));
    const int invalid_address_result =
        connect(invalid_address_socket, invalid_address, sizeof(sockaddr_in));
    const int invalid_address_error = WSAGetLastError();
    closesocket(invalid_address_socket);

    const SOCKET connect_ex_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    const int connect_ex_socket_error =
        connect_ex_socket == INVALID_SOCKET ? WSAGetLastError() : 0;
    sockaddr_in local_endpoint{};
    local_endpoint.sin_family = AF_INET;
    local_endpoint.sin_addr.s_addr = htonl(INADDR_ANY);
    local_endpoint.sin_port = 0;
    GUID connect_ex_guid = WSAID_CONNECTEX;
    LPFN_CONNECTEX connect_ex = nullptr;
    DWORD extension_bytes = 0;
    const int extension_status = WSAIoctl(
        connect_ex_socket, SIO_GET_EXTENSION_FUNCTION_POINTER,
        &connect_ex_guid, sizeof(connect_ex_guid), &connect_ex,
        sizeof(connect_ex), &extension_bytes, nullptr, nullptr);
    auto sentinel_connect_ex = reinterpret_cast<LPFN_CONNECTEX>(
        static_cast<std::uintptr_t>(1));
    DWORD short_extension_bytes = 0;
    const int short_extension_status = WSAIoctl(
        connect_ex_socket, SIO_GET_EXTENSION_FUNCTION_POINTER,
        &connect_ex_guid, sizeof(connect_ex_guid), &sentinel_connect_ex,
        sizeof(sentinel_connect_ex) - 1, &short_extension_bytes, nullptr,
        nullptr);
    const int short_extension_error = WSAGetLastError();
    const HANDLE completion_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    OVERLAPPED overlapped{};
    overlapped.hEvent = completion_event;
    DWORD sent = 0;
    const int connect_ex_bind_status =
        connect_ex_socket == INVALID_SOCKET
            ? SOCKET_ERROR
            : bind(
                  connect_ex_socket,
                  reinterpret_cast<const sockaddr*>(&local_endpoint),
                  sizeof(local_endpoint));
    const bool connect_ex_ready =
        connect_ex_socket != INVALID_SOCKET && connect_ex_bind_status == 0 &&
        extension_status == 0 && extension_bytes == sizeof(connect_ex) &&
        connect_ex != nullptr && completion_event != nullptr;
    const BOOL connect_ex_result =
        connect_ex_ready
            ? connect_ex(
                  connect_ex_socket,
                  reinterpret_cast<const sockaddr*>(&endpoint), sizeof(endpoint),
                  nullptr, 0, &sent, &overlapped)
            : TRUE;
    const int connect_ex_error = WSAGetLastError();
    const bool connect_ex_not_completed =
        completion_event != nullptr &&
        WaitForSingleObject(completion_event, 0) == WAIT_TIMEOUT;
    closesocket(connect_ex_socket);
    if (completion_event != nullptr) {
        CloseHandle(completion_event);
    }

    ADDRINFOA* ansi_results = nullptr;
    const int ansi_resolve_status =
        getaddrinfo("localhost", "80", nullptr, &ansi_results);
    const int ansi_resolve_error = WSAGetLastError();
    const bool ansi_results_absent = ansi_results == nullptr;
    if (ansi_results != nullptr) {
        freeaddrinfo(ansi_results);
    }
    ADDRINFOW* wide_results = nullptr;
    const int wide_resolve_status =
        GetAddrInfoW(L"localhost", L"80", nullptr, &wide_results);
    const int wide_resolve_error = WSAGetLastError();
    const bool wide_results_absent = wide_results == nullptr;
    if (wide_results != nullptr) {
        FreeAddrInfoW(wide_results);
    }
    DNS_RECORD* ansi_dns_records = nullptr;
    const DNS_STATUS ansi_dns_status = DnsQuery_A(
        "localhost", DNS_TYPE_A, DNS_QUERY_STANDARD, nullptr,
        &ansi_dns_records, nullptr);
    const bool ansi_dns_records_absent = ansi_dns_records == nullptr;
    if (ansi_dns_records != nullptr) {
        DnsRecordListFree(ansi_dns_records, DnsFreeRecordList);
    }
    DNS_RECORD* wide_dns_records = nullptr;
    const DNS_STATUS wide_dns_status = DnsQuery_W(
        L"localhost", DNS_TYPE_AAAA, DNS_QUERY_STANDARD, nullptr,
        &wide_dns_records, nullptr);
    const bool wide_dns_records_absent = wide_dns_records == nullptr;
    if (wide_dns_records != nullptr) {
        DnsRecordListFree(wide_dns_records, DnsFreeRecordList);
    }
    DNS_RECORD* utf8_dns_records = nullptr;
    const DNS_STATUS utf8_dns_status = DnsQuery_UTF8(
        "localhost", DNS_TYPE_A, DNS_QUERY_STANDARD, nullptr,
        &utf8_dns_records, nullptr);
    const bool utf8_dns_records_absent = utf8_dns_records == nullptr;
    if (utf8_dns_records != nullptr) {
        DnsRecordListFree(utf8_dns_records, DnsFreeRecordList);
    }

    ADDRINFOEXW* asynchronous_results = nullptr;
    const HANDLE lookup_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    OVERLAPPED lookup_overlapped{};
    lookup_overlapped.hEvent = lookup_event;
    HANDLE lookup_handle = reinterpret_cast<HANDLE>(
        static_cast<std::uintptr_t>(1));
    const int asynchronous_resolve_status = GetAddrInfoExW(
        L"localhost", L"80", NS_DNS, nullptr, nullptr, &asynchronous_results,
        nullptr, &lookup_overlapped, LookupCompletion, &lookup_handle);
    const int asynchronous_resolve_error = WSAGetLastError();
    const bool asynchronous_results_absent = asynchronous_results == nullptr;
    const bool lookup_handle_absent = lookup_handle == nullptr;
    const bool lookup_not_completed =
        lookup_event != nullptr &&
        WaitForSingleObject(lookup_event, 0) == WAIT_TIMEOUT &&
        InterlockedCompareExchange(&g_lookup_completion_count, 0, 0) == 0;
    if (asynchronous_resolve_status == WSA_IO_PENDING &&
        lookup_handle != nullptr) {
        GetAddrInfoExCancel(&lookup_handle);
    }
    if (asynchronous_results != nullptr) {
        FreeAddrInfoExW(asynchronous_results);
    }
    if (lookup_event != nullptr) {
        CloseHandle(lookup_event);
    }

    ADDRINFOEXA* asynchronous_ansi_results = nullptr;
    const HANDLE ansi_lookup_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    OVERLAPPED ansi_lookup_overlapped{};
    ansi_lookup_overlapped.hEvent = ansi_lookup_event;
    HANDLE ansi_lookup_handle = reinterpret_cast<HANDLE>(
        static_cast<std::uintptr_t>(1));
#pragma warning(push)
#pragma warning(disable : 4996)
    const int asynchronous_ansi_status = GetAddrInfoExA(
        "localhost", "80", NS_DNS, nullptr, nullptr, &asynchronous_ansi_results,
        nullptr, &ansi_lookup_overlapped, LookupCompletion, &ansi_lookup_handle);
#pragma warning(pop)
    const int asynchronous_ansi_error = WSAGetLastError();
    const bool asynchronous_ansi_results_absent =
        asynchronous_ansi_results == nullptr;
    const bool ansi_lookup_handle_absent = ansi_lookup_handle == nullptr;
    const bool ansi_lookup_not_completed =
        ansi_lookup_event != nullptr &&
        WaitForSingleObject(ansi_lookup_event, 0) == WAIT_TIMEOUT &&
        InterlockedCompareExchange(&g_lookup_completion_count, 0, 0) == 0;
    if (asynchronous_ansi_status == WSA_IO_PENDING &&
        ansi_lookup_handle != nullptr) {
        GetAddrInfoExCancel(&ansi_lookup_handle);
    }
    if (asynchronous_ansi_results != nullptr) {
#pragma warning(push)
#pragma warning(disable : 4996)
        FreeAddrInfoExA(asynchronous_ansi_results);
#pragma warning(pop)
    }
    if (ansi_lookup_event != nullptr) {
        CloseHandle(ansi_lookup_event);
    }

    const HANDLE dns_query_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    DNS_QUERY_REQUEST dns_query_request{};
    dns_query_request.Version = DNS_QUERY_REQUEST_VERSION1;
    dns_query_request.QueryName = L"localhost";
    dns_query_request.QueryType = DNS_TYPE_A;
    dns_query_request.QueryOptions = DNS_QUERY_STANDARD;
    dns_query_request.pQueryCompletionCallback = DnsQueryCompletion;
    dns_query_request.pQueryContext = dns_query_event;
    DNS_QUERY_RESULT dns_query_result{};
    dns_query_result.Version = DNS_QUERY_REQUEST_VERSION1;
    dns_query_result.QueryStatus = ERROR_INVALID_DATA;
    dns_query_result.QueryOptions = 1;
    dns_query_result.pQueryRecords = reinterpret_cast<PDNS_RECORD>(
        static_cast<std::uintptr_t>(1));
    dns_query_result.Reserved = reinterpret_cast<PVOID>(
        static_cast<std::uintptr_t>(1));
    DNS_QUERY_CANCEL dns_query_cancel{};
    std::fill(
        std::begin(dns_query_cancel.Reserved),
        std::end(dns_query_cancel.Reserved), static_cast<char>(0x5A));
    const DNS_STATUS dns_query_ex_status = DnsQueryEx(
        &dns_query_request, &dns_query_result, &dns_query_cancel);
    const bool dns_query_ex_not_completed =
        dns_query_event != nullptr &&
        WaitForSingleObject(dns_query_event, 0) == WAIT_TIMEOUT &&
        InterlockedCompareExchange(&g_dns_query_completion_count, 0, 0) == 0;
    const DNS_QUERY_CANCEL denied_cancel_state = dns_query_cancel;
    DNS_QUERY_CANCEL cancellation_probe = denied_cancel_state;
    const DNS_STATUS denied_cancel_status =
        dns_query_ex_status == ERROR_ACCESS_DENIED
            ? DnsCancelQuery(&cancellation_probe)
            : ERROR_SUCCESS;
    if (dns_query_ex_status == DNS_REQUEST_PENDING) {
        DnsCancelQuery(&dns_query_cancel);
        if (dns_query_event != nullptr) {
            WaitForSingleObject(dns_query_event, 5'000);
        }
    }
    if (dns_query_ex_status == ERROR_SUCCESS &&
        dns_query_result.pQueryRecords != nullptr &&
        dns_query_result.pQueryRecords != reinterpret_cast<PDNS_RECORD>(
                                                static_cast<std::uintptr_t>(1))) {
        DnsRecordListFree(dns_query_result.pQueryRecords, DnsFreeRecordList);
    }
    if (dns_query_event != nullptr) {
        CloseHandle(dns_query_event);
    }

    char datagram[] = "x";
    const SOCKET send_to_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    const int send_to_status = sendto(
        send_to_socket, datagram, 1, 0,
        reinterpret_cast<const sockaddr*>(&endpoint), sizeof(endpoint));
    const int send_to_error = WSAGetLastError();
    closesocket(send_to_socket);

    const SOCKET wsa_send_to_socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    WSABUF datagram_buffer{};
    datagram_buffer.buf = datagram;
    datagram_buffer.len = 1;
    DWORD datagram_bytes_sent = 99;
    const int wsa_send_to_status = WSASendTo(
        wsa_send_to_socket, &datagram_buffer, 1, &datagram_bytes_sent, 0,
        reinterpret_cast<const sockaddr*>(&ipv6_endpoint), sizeof(ipv6_endpoint),
        nullptr, nullptr);
    const int wsa_send_to_error = WSAGetLastError();
    closesocket(wsa_send_to_socket);

    const auto win_http_connect =
        bolt::tests::TryWinHttpConnect(L"LOCALHOST", 443);
    const auto win_inet_wide_connect =
        bolt::tests::TryWinInetConnectW(L"LOCALHOST", 443);
    const auto win_inet_ansi_connect =
        bolt::tests::TryWinInetConnectA("LOCALHOST", 443);

    const HMODULE hook = GetModuleHandleW(
#if defined(_WIN64)
        L"bolt-sandbox-x64.dll"
#else
        L"bolt-sandbox-x86.dll"
#endif
    );
    const auto flush_events = hook == nullptr
                                  ? nullptr
                                  : reinterpret_cast<BOOL (*)(DWORD)>(
                                        GetProcAddress(hook, "BoltSandboxFlushEvents"));
    const bool connect_passed =
        connect_result == SOCKET_ERROR && connect_error == WSAEACCES &&
        wsa_connect_result == SOCKET_ERROR && wsa_connect_error == WSAEACCES &&
        invalid_address_result == SOCKET_ERROR &&
        invalid_address_error == WSAEACCES && connect_ex_ready &&
        connect_ex_result == FALSE && connect_ex_error == WSAEACCES &&
        connect_ex_not_completed && short_extension_status == SOCKET_ERROR &&
        short_extension_error == WSAEFAULT &&
        sentinel_connect_ex == reinterpret_cast<LPFN_CONNECTEX>(
                                   static_cast<std::uintptr_t>(1));
    const bool address_resolution_passed =
        ansi_resolve_status == WSAEACCES && ansi_resolve_error == WSAEACCES &&
        ansi_results_absent && wide_resolve_status == WSAEACCES &&
        wide_resolve_error == WSAEACCES && wide_results_absent;
    const bool dns_query_passed =
        ansi_dns_status == ERROR_ACCESS_DENIED && ansi_dns_records_absent &&
        wide_dns_status == ERROR_ACCESS_DENIED && wide_dns_records_absent &&
        utf8_dns_status == ERROR_ACCESS_DENIED && utf8_dns_records_absent;
    const bool datagram_passed =
        send_to_status == SOCKET_ERROR && send_to_error == WSAEACCES &&
        wsa_send_to_status == SOCKET_ERROR && wsa_send_to_error == WSAEACCES &&
        datagram_bytes_sent == 99;
    const bool asynchronous_resolution_passed =
        asynchronous_resolve_status == WSAEACCES &&
        asynchronous_resolve_error == WSAEACCES && asynchronous_results_absent &&
        lookup_handle_absent && lookup_not_completed;
    const bool asynchronous_ansi_resolution_passed =
        asynchronous_ansi_status == WSAEACCES &&
        asynchronous_ansi_error == WSAEACCES &&
        asynchronous_ansi_results_absent && ansi_lookup_handle_absent &&
        ansi_lookup_not_completed;
    const bool dns_query_ex_passed =
        dns_query_ex_status == ERROR_ACCESS_DENIED &&
        dns_query_result.QueryStatus == ERROR_ACCESS_DENIED &&
        dns_query_result.QueryOptions == 0 &&
        dns_query_result.pQueryRecords == nullptr &&
        dns_query_result.Reserved == nullptr && dns_query_ex_not_completed &&
        denied_cancel_status != ERROR_SUCCESS &&
        std::all_of(
            std::begin(denied_cancel_state.Reserved),
            std::end(denied_cancel_state.Reserved),
            [](const char byte) { return byte == 0; });
    const bool high_level_network_passed =
        win_http_connect.connection_denied &&
        win_http_connect.error == ERROR_ACCESS_DENIED &&
        win_inet_wide_connect.connection_denied &&
        win_inet_wide_connect.error == ERROR_ACCESS_DENIED &&
        win_inet_ansi_connect.connection_denied &&
        win_inet_ansi_connect.error == ERROR_ACCESS_DENIED;
    const bool events_flushed =
        flush_events != nullptr && flush_events(5'000) != FALSE;
    WSACleanup();
    if (!connect_passed) {
        if (connect_result != SOCKET_ERROR || connect_error != WSAEACCES) {
            return 250;
        }
        if (wsa_connect_result != SOCKET_ERROR ||
            wsa_connect_error != WSAEACCES) {
            return 251;
        }
        if (invalid_address_result != SOCKET_ERROR ||
            invalid_address_error != WSAEACCES) {
            return 252;
        }
        if (!connect_ex_ready) {
            if (connect_ex_socket == INVALID_SOCKET) {
                return 20'000 + connect_ex_socket_error;
            }
            if (connect_ex_bind_status != 0) {
                return 261;
            }
            if (extension_status != 0) {
                return 262;
            }
            if (extension_bytes != sizeof(connect_ex)) {
                return 263;
            }
            if (connect_ex == nullptr) {
                return 264;
            }
            return completion_event == nullptr ? 265 : 253;
        }
        if (connect_ex_result != FALSE || connect_ex_error != WSAEACCES) {
            return 254;
        }
        if (!connect_ex_not_completed) {
            return 255;
        }
        if (short_extension_status != SOCKET_ERROR ||
            short_extension_error != WSAEFAULT) {
            return 256;
        }
        return 257;
    }
    if (!address_resolution_passed) {
        return 203;
    }
    if (!dns_query_passed) {
        return 205;
    }
    if (!datagram_passed) {
        return 206;
    }
    if (!asynchronous_resolution_passed) {
        return 207;
    }
    if (!asynchronous_ansi_resolution_passed) {
        return 208;
    }
    if (!dns_query_ex_passed) {
        return 209;
    }
    if (!high_level_network_passed) {
        return 240;
    }
    return events_flushed ? 0 : 204;
}

bool RunNetworkHookTests() {
    const std::wstring executable = CurrentExecutable();
    if (executable.empty()) {
        return false;
    }
    const auto policy_payload = bolt::tests::SealPolicy(
        {{bolt::tests::FilesystemRuleKind::kReadWrite,
          std::filesystem::path(executable).root_path()}},
        bolt::tests::ChildProcessPolicyKind::kDeny,
        bolt::tests::NetworkPolicyKind::kDenied);
    constexpr std::array<std::uint8_t, 16> nonce = {
        0x4E, 0x4E, 0x4E, 0x4E, 0x4E, 0x4E, 0x4E, 0x4E,
        0x4E, 0x4E, 0x4E, 0x4E, 0x4E, 0x4E, 0x4E, 0x4E,
    };
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    const HANDLE release = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    bolt::common::ImmutablePolicyMapping policy;
    bolt::common::PrivatePipe event_pipe;
    const std::wstring pipe_name = PipeName(GetCurrentProcessId());
    if (release == nullptr || policy_payload.empty() ||
        bolt::common::ImmutablePolicyMapping::Create(
            policy_payload.data(), policy_payload.size(), policy) !=
            bolt::common::PolicyMappingStatus::kSuccess ||
        bolt::common::PrivatePipe::Create(pipe_name, event_pipe) !=
            bolt::common::PipeStatus::kSuccess) {
        if (release != nullptr) {
            CloseHandle(release);
        }
        return false;
    }
    HANDLE event_client = CreateFileW(
        pipe_name.c_str(), FILE_WRITE_DATA, 0, &inheritable, OPEN_EXISTING, 0,
        nullptr);
    if (event_client == INVALID_HANDLE_VALUE ||
        event_pipe.Accept() != bolt::common::PipeStatus::kSuccess) {
        if (event_client != INVALID_HANDLE_VALUE) {
            CloseHandle(event_client);
        }
        CloseHandle(release);
        return false;
    }

#if defined(_WIN64)
    constexpr auto hook_name = L"bolt-sandbox-x64.dll";
#else
    constexpr auto hook_name = L"bolt-sandbox-x86.dll";
#endif
    const std::filesystem::path hook_path =
        std::filesystem::path(executable).parent_path() / hook_name;
    const std::wstring command_line =
        L"\"" + executable + L"\" --network-hook-child";
    const HANDLE inherited[] = {policy.handle(), event_client, release};
    const bolt::common::ProcessLaunchOptions options{
        executable, command_line, L"", nullptr, inherited, std::size(inherited), 0};
    bolt::common::SuspendedProcess process;
    bolt::common::ExecutionJob job;
    const bool initialized =
        bolt::common::ExecutionJob::Create(job) == bolt::common::JobStatus::kSuccess &&
        bolt::common::SuspendedProcess::Create(options, process) ==
            bolt::common::ProcessStatus::kSuccess &&
        process.AssignTo(job) == bolt::common::ProcessStatus::kSuccess &&
        process.InstallRuntimePayload(
            policy.handle(), policy.length(), event_client, release, nonce) ==
            bolt::common::ProcessStatus::kSuccess &&
        process.Inject(hook_path.string()) == bolt::common::ProcessStatus::kSuccess &&
        process.BeginHookInitialization() == bolt::common::ProcessStatus::kSuccess;
    CloseHandle(event_client);

    std::array<std::uint8_t, bolt::protocol::kReadyFrameLength> ready{};
    DWORD bytes_read = 0;
    const bool ready_ok =
        initialized &&
        ReadFile(
            event_pipe.handle(), ready.data(), static_cast<DWORD>(ready.size()),
            &bytes_read, nullptr) != FALSE &&
        bytes_read == ready.size() &&
        bolt::protocol::ValidateReadyFrame(ready.data(), ready.size(), nonce) ==
            bolt::protocol::ReadyFrameStatus::kSuccess &&
        process.ReleaseAfterReady() == bolt::common::ProcessStatus::kSuccess &&
        process.Wait(5'000) == bolt::common::ProcessStatus::kSuccess;
    DWORD exit_code = 0;
    const bool child_ok = ready_ok &&
                          process.ExitCode(exit_code) ==
                              bolt::common::ProcessStatus::kSuccess &&
                          exit_code == 0;
    const auto process_id =
        static_cast<std::uint32_t>(GetProcessId(process.process_handle()));
    const bool events_ok = child_ok && process_id != 0 &&
                           ReadNetworkViolation(
                               event_pipe.handle(), process_id, 1,
                               bolt::protocol::NetworkAddressFamily::kIpv4) &&
                           ReadNetworkViolation(
                               event_pipe.handle(), process_id, 2,
                               bolt::protocol::NetworkAddressFamily::kIpv6) &&
                           ReadNetworkViolation(
                               event_pipe.handle(), process_id, 3,
                               bolt::protocol::NetworkAddressFamily::kIpv4) &&
                           ReadDomainNetworkViolation(
                               event_pipe.handle(), process_id, 4, "localhost") &&
                           ReadDomainNetworkViolation(
                               event_pipe.handle(), process_id, 5, "localhost");
    const bool dns_query_events_ok =
        events_ok &&
        ReadDomainNetworkViolation(
            event_pipe.handle(), process_id, 6, "localhost") &&
        ReadDomainNetworkViolation(
            event_pipe.handle(), process_id, 7, "localhost") &&
        ReadDomainNetworkViolation(
            event_pipe.handle(), process_id, 8, "localhost");
    const bool asynchronous_event_ok =
        dns_query_events_ok &&
        ReadDomainNetworkViolation(
            event_pipe.handle(), process_id, 9, "localhost") &&
        ReadDomainNetworkViolation(
            event_pipe.handle(), process_id, 10, "localhost") &&
        ReadDomainNetworkViolation(
            event_pipe.handle(), process_id, 11, "localhost");
    const bool datagram_events_ok =
        asynchronous_event_ok &&
        ReadNetworkViolation(
            event_pipe.handle(), process_id, 12,
            bolt::protocol::NetworkAddressFamily::kIpv4,
            bolt::protocol::NetworkOperation::kSend) &&
        ReadNetworkViolation(
            event_pipe.handle(), process_id, 13,
            bolt::protocol::NetworkAddressFamily::kIpv6,
            bolt::protocol::NetworkOperation::kSend);
    const bool high_level_events_ok =
        datagram_events_ok &&
        ReadDomainNetworkViolation(
            event_pipe.handle(), process_id, 14, "localhost",
            bolt::protocol::NetworkOperation::kConnect) &&
        ReadDomainNetworkViolation(
            event_pipe.handle(), process_id, 15, "localhost",
            bolt::protocol::NetworkOperation::kConnect) &&
        ReadDomainNetworkViolation(
            event_pipe.handle(), process_id, 16, "localhost",
            bolt::protocol::NetworkOperation::kConnect);
    CloseHandle(release);
    event_pipe.Close();
    if (!child_ok || !high_level_events_ok) {
        std::fprintf(
            stderr, "network denied fixture failed with exit code %lu, events %s\n",
            static_cast<unsigned long>(exit_code),
            high_level_events_ok ? "valid" : "invalid");
    }
    return child_ok && high_level_events_ok;
}

int RunNetworkAllowListChild(const int argument_count, wchar_t** arguments) {
    if (argument_count != 5) {
        return 210;
    }
    WSADATA winsock{};
    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) {
        return 211;
    }
    std::string domain;
    for (const wchar_t* cursor = arguments[2]; *cursor != L'\0'; ++cursor) {
        if (*cursor > 0x7f) {
            return 213;
        }
        domain.push_back(static_cast<char>(*cursor));
    }
    const std::string port = std::to_string(_wtoi(arguments[3]));
    ADDRINFOA hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    ADDRINFOA* results = nullptr;
    const int resolve_status =
        getaddrinfo(domain.c_str(), port.c_str(), &hints, &results);
    const SOCKET allowed_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    const int connect_status =
        resolve_status == 0 && results != nullptr
            ? connect(allowed_socket, results->ai_addr,
                      static_cast<int>(results->ai_addrlen))
            : SOCKET_ERROR;
    sockaddr_in connected_peer{};
    int connected_peer_length = sizeof(connected_peer);
    const bool peer_is_original_target = connect_status == 0 &&
        getpeername(
            allowed_socket, reinterpret_cast<sockaddr*>(&connected_peer),
            &connected_peer_length) == 0 &&
        connected_peer.sin_family == AF_INET &&
        ntohs(connected_peer.sin_port) ==
            static_cast<std::uint16_t>(_wtoi(arguments[3]));
    closesocket(allowed_socket);
    sockaddr_in closed_peer{};
    int closed_peer_length = sizeof(closed_peer);
    const int closed_peer_status = getpeername(
        allowed_socket, reinterpret_cast<sockaddr*>(&closed_peer),
        &closed_peer_length);
    const int closed_peer_error = WSAGetLastError();
    const std::string ipv6_port = std::to_string(_wtoi(arguments[4]));
    ADDRINFOA ipv6_hints{};
    ipv6_hints.ai_family = AF_INET6;
    ipv6_hints.ai_socktype = SOCK_STREAM;
    ipv6_hints.ai_protocol = IPPROTO_TCP;
    ADDRINFOA* ipv6_results = nullptr;
    const int ipv6_resolve_status = getaddrinfo(
        domain.c_str(), ipv6_port.c_str(), &ipv6_hints, &ipv6_results);
    const SOCKET ipv6_socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    const int ipv6_connect_status =
        ipv6_resolve_status == 0 && ipv6_results != nullptr
            ? connect(
                  ipv6_socket, ipv6_results->ai_addr,
                  static_cast<int>(ipv6_results->ai_addrlen))
            : SOCKET_ERROR;
    sockaddr_in6 ipv6_peer{};
    int ipv6_peer_length = sizeof(ipv6_peer);
    const bool ipv6_peer_is_original_target = ipv6_connect_status == 0 &&
        getpeername(
            ipv6_socket, reinterpret_cast<sockaddr*>(&ipv6_peer),
            &ipv6_peer_length) == 0 && ipv6_peer.sin6_family == AF_INET6 &&
        ntohs(ipv6_peer.sin6_port) ==
            static_cast<std::uint16_t>(_wtoi(arguments[4]));
    ADDRINFOW wide_hints{};
    wide_hints.ai_family = AF_INET;
    wide_hints.ai_socktype = SOCK_STREAM;
    wide_hints.ai_protocol = IPPROTO_TCP;
    ADDRINFOW* wide_results = nullptr;
    const int wide_resolve_status = GetAddrInfoW(
        arguments[2], arguments[3], &wide_hints, &wide_results);
    ADDRINFOEXW* extended_results = nullptr;
    const HANDLE extended_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    OVERLAPPED extended_overlapped{};
    extended_overlapped.hEvent = extended_event;
    HANDLE extended_lookup = reinterpret_cast<HANDLE>(
        static_cast<std::uintptr_t>(1));
    const int extended_status = GetAddrInfoExW(
        arguments[2], arguments[3], NS_DNS, nullptr, nullptr,
        &extended_results, nullptr, &extended_overlapped, LookupCompletion,
        &extended_lookup);
    const bool extended_event_unsignaled = extended_event != nullptr &&
        WaitForSingleObject(extended_event, 0) == WAIT_TIMEOUT;
    const bool extended_callback_absent =
        InterlockedCompareExchange(&g_lookup_completion_count, 0, 0) == 0;
    const bool extended_synchronous = extended_status == 0 &&
        extended_results != nullptr && extended_lookup == nullptr &&
        extended_event_unsignaled && extended_callback_absent;
    DNS_RECORD* dns_a_records = nullptr;
    const DNS_STATUS dns_a_status = DnsQuery_A(
        domain.c_str(), DNS_TYPE_A, DNS_QUERY_STANDARD, nullptr,
        &dns_a_records, nullptr);
    DNS_RECORD* dns_w_records = nullptr;
    const DNS_STATUS dns_w_status = DnsQuery_W(
        arguments[2], DNS_TYPE_A, DNS_QUERY_STANDARD, nullptr,
        &dns_w_records, nullptr);
    const bool dns_records_present =
        dns_a_records != nullptr && dns_w_records != nullptr;
    const HANDLE dns_ex_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    DNS_QUERY_REQUEST dns_ex_request{};
    dns_ex_request.Version = DNS_QUERY_REQUEST_VERSION1;
    dns_ex_request.QueryName = arguments[2];
    dns_ex_request.QueryType = DNS_TYPE_A;
    dns_ex_request.QueryOptions = DNS_QUERY_STANDARD;
    dns_ex_request.pQueryCompletionCallback = DnsQueryCompletion;
    dns_ex_request.pQueryContext = dns_ex_event;
    DNS_QUERY_RESULT dns_ex_result{};
    dns_ex_result.Version = DNS_QUERY_REQUEST_VERSION1;
    DNS_QUERY_CANCEL dns_ex_cancel{};
    std::fill(
        std::begin(dns_ex_cancel.Reserved), std::end(dns_ex_cancel.Reserved),
        static_cast<char>(0x5A));
    const DNS_STATUS dns_ex_status =
        DnsQueryEx(&dns_ex_request, &dns_ex_result, &dns_ex_cancel);
    const bool dns_ex_synchronous = dns_ex_status == ERROR_SUCCESS &&
        dns_ex_result.QueryStatus == ERROR_SUCCESS &&
        dns_ex_result.pQueryRecords != nullptr && dns_ex_event != nullptr &&
        WaitForSingleObject(dns_ex_event, 0) == WAIT_TIMEOUT &&
        InterlockedCompareExchange(&g_dns_query_completion_count, 0, 0) == 0 &&
        std::all_of(
            std::begin(dns_ex_cancel.Reserved),
            std::end(dns_ex_cancel.Reserved),
            [](const char byte) { return byte == 0; });

    const SOCKET allowed_connect_ex_socket =
        socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in connect_ex_local{};
    connect_ex_local.sin_family = AF_INET;
    connect_ex_local.sin_addr.s_addr = htonl(INADDR_ANY);
    connect_ex_local.sin_port = 0;
    GUID connect_ex_guid = WSAID_CONNECTEX;
    LPFN_CONNECTEX allowed_connect_ex = nullptr;
    DWORD connect_ex_extension_bytes = 0;
    const int connect_ex_extension_status = WSAIoctl(
        allowed_connect_ex_socket, SIO_GET_EXTENSION_FUNCTION_POINTER,
        &connect_ex_guid, sizeof(connect_ex_guid), &allowed_connect_ex,
        sizeof(allowed_connect_ex), &connect_ex_extension_bytes, nullptr,
        nullptr);
    const HANDLE connect_ex_event =
        CreateEventW(nullptr, TRUE, FALSE, nullptr);
    OVERLAPPED connect_ex_overlapped{};
    connect_ex_overlapped.hEvent = connect_ex_event;
    DWORD connect_ex_bytes = 99;
    const bool connect_ex_ready =
        allowed_connect_ex_socket != INVALID_SOCKET &&
        bind(
            allowed_connect_ex_socket,
            reinterpret_cast<const sockaddr*>(&connect_ex_local),
            sizeof(connect_ex_local)) == 0 &&
        connect_ex_extension_status == 0 && allowed_connect_ex != nullptr &&
        connect_ex_extension_bytes == sizeof(allowed_connect_ex) &&
        connect_ex_event != nullptr && results != nullptr;
    const BOOL allowed_connect_ex_result =
        connect_ex_ready
            ? allowed_connect_ex(
                  allowed_connect_ex_socket, results->ai_addr,
                  static_cast<int>(results->ai_addrlen), nullptr, 0,
                  &connect_ex_bytes, &connect_ex_overlapped)
            : FALSE;
    const int allowed_connect_ex_error = WSAGetLastError();
    DWORD connect_ex_transferred = 0;
    DWORD connect_ex_flags = 0;
    const bool connect_ex_completed =
        (allowed_connect_ex_result != FALSE && connect_ex_bytes == 0) ||
        (allowed_connect_ex_result == FALSE &&
         allowed_connect_ex_error == WSA_IO_PENDING &&
         WaitForSingleObject(connect_ex_event, 5'000) == WAIT_OBJECT_0 &&
         WSAGetOverlappedResult(
             allowed_connect_ex_socket, &connect_ex_overlapped,
             &connect_ex_transferred, FALSE, &connect_ex_flags) != FALSE &&
         connect_ex_transferred == 0);
    sockaddr_in connect_ex_peer{};
    int connect_ex_peer_length = sizeof(connect_ex_peer);
    const bool connect_ex_peer_is_original = connect_ex_completed &&
        getpeername(
            allowed_connect_ex_socket,
            reinterpret_cast<sockaddr*>(&connect_ex_peer),
            &connect_ex_peer_length) == 0 &&
        ntohs(connect_ex_peer.sin_port) ==
            static_cast<std::uint16_t>(_wtoi(arguments[3]));

    sockaddr_in wrong_port{};
    if (results != nullptr && results->ai_addrlen >= sizeof(wrong_port)) {
        std::memcpy(&wrong_port, results->ai_addr, sizeof(wrong_port));
    }
    std::uint16_t denied_port = 1;
    while (denied_port == static_cast<std::uint16_t>(_wtoi(arguments[3])) ||
           denied_port == static_cast<std::uint16_t>(_wtoi(arguments[4]))) {
        ++denied_port;
    }
    wrong_port.sin_port = htons(denied_port);
    const SOCKET denied_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    const int denied_connect = connect(
        denied_socket, reinterpret_cast<const sockaddr*>(&wrong_port),
        sizeof(wrong_port));
    const int denied_connect_error = WSAGetLastError();
    ADDRINFOA* denied_results = nullptr;
    const int denied_resolve =
        getaddrinfo("denied.invalid", port.c_str(), &hints, &denied_results);
    const int denied_resolve_error = WSAGetLastError();
    const SOCKET allowed_udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    char udp_byte = 'x';
    const int allowed_udp_send =
        results != nullptr
            ? sendto(
                  allowed_udp, &udp_byte, 1, 0, results->ai_addr,
                  static_cast<int>(results->ai_addrlen))
            : SOCKET_ERROR;

    if (results != nullptr) {
        freeaddrinfo(results);
    }
    if (ipv6_results != nullptr) {
        freeaddrinfo(ipv6_results);
    }
    if (denied_results != nullptr) {
        freeaddrinfo(denied_results);
    }
    if (wide_results != nullptr) {
        FreeAddrInfoW(wide_results);
    }
    if (extended_results != nullptr) {
        FreeAddrInfoExW(extended_results);
    }
    if (extended_event != nullptr) {
        CloseHandle(extended_event);
    }
    if (dns_a_records != nullptr) {
        DnsRecordListFree(dns_a_records, DnsFreeRecordList);
    }
    if (dns_w_records != nullptr) {
        DnsRecordListFree(dns_w_records, DnsFreeRecordList);
    }
    if (dns_ex_result.pQueryRecords != nullptr) {
        DnsRecordListFree(dns_ex_result.pQueryRecords, DnsFreeRecordList);
    }
    if (dns_ex_event != nullptr) {
        CloseHandle(dns_ex_event);
    }
    closesocket(denied_socket);
    closesocket(ipv6_socket);
    closesocket(allowed_connect_ex_socket);
    if (connect_ex_event != nullptr) {
        CloseHandle(connect_ex_event);
    }
    closesocket(allowed_udp);
    WSACleanup();
    if (resolve_status != 0) {
        return 1'000 + resolve_status;
    }
    if (connect_status != 0) {
        return 221;
    }
    if (!peer_is_original_target) {
        return 233;
    }
    if (ipv6_resolve_status != 0 || ipv6_connect_status != 0) {
        return 235;
    }
    if (!ipv6_peer_is_original_target) {
        return 236;
    }
    if (!connect_ex_ready || !connect_ex_completed ||
        !connect_ex_peer_is_original) {
        return 237;
    }
    if (closed_peer_status != SOCKET_ERROR ||
        closed_peer_error != WSAENOTSOCK) {
        return 234;
    }
    if (wide_resolve_status != 0) {
        return 224;
    }
    if (allowed_udp_send != 1) {
        return 225;
    }
    if (extended_status != 0) {
        return 3'000 + extended_status;
    }
    if (extended_results == nullptr) {
        return 227;
    }
    if (extended_lookup != nullptr) {
        return 228;
    }
    if (!extended_event_unsignaled) {
        return 229;
    }
    if (!extended_callback_absent || !extended_synchronous) {
        return 230;
    }
    if (dns_a_status != ERROR_SUCCESS || dns_w_status != ERROR_SUCCESS ||
        !dns_records_present) {
        return 231;
    }
    if (!dns_ex_synchronous) {
        return 232;
    }
    if (denied_connect != SOCKET_ERROR || denied_connect_error != WSAEACCES) {
        return 222;
    }
    return denied_resolve == WSAEACCES && denied_resolve_error == WSAEACCES
               ? 0
               : 223;
}

bool RunNetworkAllowListTests() {
    WSADATA winsock{};
    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) {
        return false;
    }
    const SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in endpoint{};
    endpoint.sin_family = AF_INET;
    endpoint.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    endpoint.sin_port = 0;
    int endpoint_length = sizeof(endpoint);
    if (listener == INVALID_SOCKET ||
        bind(listener, reinterpret_cast<const sockaddr*>(&endpoint), sizeof(endpoint)) != 0 ||
        listen(listener, 1) != 0 ||
        getsockname(listener, reinterpret_cast<sockaddr*>(&endpoint), &endpoint_length) != 0) {
        closesocket(listener);
        WSACleanup();
        return false;
    }
    const std::uint16_t port = ntohs(endpoint.sin_port);
    const SOCKET ipv6_listener = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in6 ipv6_endpoint{};
    ipv6_endpoint.sin6_family = AF_INET6;
    ipv6_endpoint.sin6_addr = in6addr_loopback;
    ipv6_endpoint.sin6_port = 0;
    int ipv6_endpoint_length = sizeof(ipv6_endpoint);
    constexpr DWORD ipv6_only = 1;
    if (ipv6_listener == INVALID_SOCKET ||
        setsockopt(
            ipv6_listener, IPPROTO_IPV6, IPV6_V6ONLY,
            reinterpret_cast<const char*>(&ipv6_only), sizeof(ipv6_only)) != 0 ||
        bind(
            ipv6_listener, reinterpret_cast<const sockaddr*>(&ipv6_endpoint),
            sizeof(ipv6_endpoint)) != 0 ||
        listen(ipv6_listener, 1) != 0 ||
        getsockname(
            ipv6_listener, reinterpret_cast<sockaddr*>(&ipv6_endpoint),
            &ipv6_endpoint_length) != 0) {
        closesocket(listener);
        if (ipv6_listener != INVALID_SOCKET) {
            closesocket(ipv6_listener);
        }
        WSACleanup();
        return false;
    }
    const std::uint16_t ipv6_port = ntohs(ipv6_endpoint.sin6_port);
    const std::string allowed_domain = "localhost";
    const std::wstring allowed_domain_w = L"localhost";
    const std::wstring executable = CurrentExecutable();
    bolt::tests::NetworkAddressRule loopback{};
    loopback.family = 4;
    loopback.prefix_length = 32;
    loopback.address[0] = 127;
    loopback.address[3] = 1;
    const bolt::tests::NetworkAllowListRules allow_list{
        {{false, allowed_domain}}, {loopback},
        {{port, port}, {ipv6_port, ipv6_port}}};
    const auto payload = bolt::tests::SealPolicy(
        {{bolt::tests::FilesystemRuleKind::kReadWrite,
          std::filesystem::path(executable).root_path()}},
        bolt::tests::ChildProcessPolicyKind::kDeny,
        bolt::tests::NetworkPolicyKind::kAllowList, allow_list);
    std::unique_ptr<bolt::network::NetworkPolicy> checked_policy;
    if (bolt::network::NetworkPolicy::Load(
            payload.data(), payload.size(), checked_policy) !=
            bolt::network::PolicyLoadStatus::kValid ||
        checked_policy->DecideDomain("localhost") !=
            bolt::network::Decision::kAllow ||
        checked_policy->DecidePort(port) != bolt::network::Decision::kAllow) {
        std::fprintf(stderr, "allow-list fixture policy mismatch at port %u\n", port);
        closesocket(ipv6_listener);
        return false;
    }
    constexpr std::array<std::uint8_t, 16> nonce = {0x6A};
    std::array<std::uint8_t, 32> dns_key{};
    dns_key[0] = 0x5A;
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    const HANDLE release = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    bolt::common::ImmutablePolicyMapping policy;
    bolt::common::PrivatePipe event_pipe;
    const std::wstring pipe_name = PipeName(GetCurrentProcessId());
    if (release == nullptr || payload.empty() ||
        bolt::common::ImmutablePolicyMapping::Create(payload.data(), payload.size(), policy) !=
            bolt::common::PolicyMappingStatus::kSuccess ||
        bolt::common::PrivatePipe::Create(pipe_name, event_pipe) !=
            bolt::common::PipeStatus::kSuccess) {
        closesocket(listener);
        closesocket(ipv6_listener);
        WSACleanup();
        return false;
    }
    HANDLE event_client = CreateFileW(
        pipe_name.c_str(), FILE_WRITE_DATA, 0, &inheritable, OPEN_EXISTING, 0, nullptr);
    if (event_client == INVALID_HANDLE_VALUE ||
        event_pipe.Accept() != bolt::common::PipeStatus::kSuccess) {
        CloseHandle(release);
        closesocket(listener);
        closesocket(ipv6_listener);
        WSACleanup();
        return false;
    }
#if defined(_WIN64)
    constexpr auto hook_name = L"bolt-sandbox-x64.dll";
    const auto proxy_path =
        std::filesystem::path(executable).parent_path() /
        L"bolt-sandbox-dns-proxy.exe";
#else
    constexpr auto hook_name = L"bolt-sandbox-x86.dll";
    const auto proxy_path =
        std::filesystem::path(executable).parent_path().parent_path().parent_path() /
        L"x64\\Debug\\bolt-sandbox-dns-proxy.exe";
#endif
    bolt::protocol::DnsProxySession dns_session{};
    dns_session.nonce = nonce;
    dns_session.authentication_key = dns_key;
    std::unique_ptr<bolt::network::DnsProxyProcess> dns_proxy;
    if (bolt::network::DnsProxyProcess::Start(
            proxy_path, payload.data(), payload.size(), dns_session, 1'024, 16,
            dns_proxy) != bolt::network::DnsProxyProcessStatus::kSuccess ||
        !SetHandleInformation(
            dns_proxy->request_write_handle(), HANDLE_FLAG_INHERIT,
            HANDLE_FLAG_INHERIT) ||
        !SetHandleInformation(
            dns_proxy->response_read_handle(), HANDLE_FLAG_INHERIT,
            HANDLE_FLAG_INHERIT)) {
        return false;
    }
    const auto hook_path = std::filesystem::path(executable).parent_path() / hook_name;
    const std::wstring command_line = L"\"" + executable +
        L"\" --network-allow-list-child " + allowed_domain_w + L" " +
        std::to_wstring(port) + L" " + std::to_wstring(ipv6_port);
    const HANDLE inherited[] = {
        policy.handle(), event_client, release,
        dns_proxy->request_write_handle(), dns_proxy->response_read_handle()};
    const bolt::common::ProcessLaunchOptions options{
        executable, command_line, L"", nullptr, inherited, std::size(inherited), 0};
    bolt::common::SuspendedProcess process;
    bolt::common::ExecutionJob job;
    const bool initialized =
        bolt::common::ExecutionJob::Create(job) == bolt::common::JobStatus::kSuccess &&
        bolt::common::SuspendedProcess::Create(options, process) ==
            bolt::common::ProcessStatus::kSuccess &&
        process.AssignTo(job) == bolt::common::ProcessStatus::kSuccess &&
        process.InstallRuntimePayload(
            policy.handle(), policy.length(), event_client, release, nonce,
            dns_proxy->request_write_handle(), dns_proxy->response_read_handle(),
            &dns_key, 1'024, dns_proxy->tcp_proxy_port(),
            dns_proxy->tcp_proxy_ipv6_port()) ==
            bolt::common::ProcessStatus::kSuccess &&
        process.Inject(hook_path.string()) == bolt::common::ProcessStatus::kSuccess &&
        process.BeginHookInitialization() == bolt::common::ProcessStatus::kSuccess;
    CloseHandle(event_client);
    std::array<std::uint8_t, bolt::protocol::kReadyFrameLength> ready{};
    DWORD read = 0;
    const bool ready_ok = initialized &&
        ReadFile(event_pipe.handle(), ready.data(), static_cast<DWORD>(ready.size()), &read, nullptr) &&
        read == ready.size() &&
        bolt::protocol::ValidateReadyFrame(ready.data(), ready.size(), nonce) ==
            bolt::protocol::ReadyFrameStatus::kSuccess &&
        process.ReleaseAfterReady() == bolt::common::ProcessStatus::kSuccess;
    const SOCKET accepted = ready_ok ? AcceptWithTimeout(listener, 5'000)
                                     : INVALID_SOCKET;
    if (accepted != INVALID_SOCKET) {
        shutdown(accepted, SD_BOTH);
        closesocket(accepted);
    }
    const SOCKET ipv6_accepted =
        ready_ok ? AcceptWithTimeout(ipv6_listener, 5'000) : INVALID_SOCKET;
    if (ipv6_accepted != INVALID_SOCKET) {
        shutdown(ipv6_accepted, SD_BOTH);
        closesocket(ipv6_accepted);
    }
    const SOCKET connect_ex_accepted =
        ready_ok ? AcceptWithTimeout(listener, 2'000) : INVALID_SOCKET;
    if (connect_ex_accepted != INVALID_SOCKET) {
        shutdown(connect_ex_accepted, SD_BOTH);
        closesocket(connect_ex_accepted);
    }
    const bool waited =
        process.Wait(5'000) == bolt::common::ProcessStatus::kSuccess;
    dns_proxy->CloseClientHandles();
    DWORD exit_code = 0;
    const bool proxy_waited =
        dns_proxy->Wait(5'000) == bolt::network::DnsProxyProcessStatus::kSuccess;
    const bool passed = ready_ok && waited && accepted != INVALID_SOCKET &&
        ipv6_accepted != INVALID_SOCKET && proxy_waited &&
        connect_ex_accepted != INVALID_SOCKET &&
        process.ExitCode(exit_code) == bolt::common::ProcessStatus::kSuccess && exit_code == 0;
    closesocket(listener);
    closesocket(ipv6_listener);
    CloseHandle(release);
    event_pipe.Close();
    WSACleanup();
    if (!passed) {
        std::fprintf(
            stderr,
            "allow-list fixture failed: port=%u ready=%d waited=%d proxy=%d exit=%lu\n",
            port,
            ready_ok ? 1 : 0, waited ? 1 : 0, proxy_waited ? 1 : 0,
            static_cast<unsigned long>(exit_code));
    }
    return passed;
}
