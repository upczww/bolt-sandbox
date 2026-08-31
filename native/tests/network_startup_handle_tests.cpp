#include "common/suspended_process.h"

#include <cstdint>
#include <string>

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>

namespace {

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

std::wstring HandleText(const std::uintptr_t value) {
    return std::to_wstring(static_cast<unsigned long long>(value));
}

}  // namespace

int RunNetworkStartupHandleChild(
    const int argument_count,
    wchar_t** arguments) {
    if (argument_count != 4) {
        return 610;
    }
    const auto allowed_value = static_cast<std::uintptr_t>(
        _wcstoui64(arguments[2], nullptr, 10));
    const auto socket_value = static_cast<std::uintptr_t>(
        _wcstoui64(arguments[3], nullptr, 10));
    const HANDLE allowed = reinterpret_cast<HANDLE>(allowed_value);
    DWORD flags = 0;
    const bool allowed_present =
        GetHandleInformation(allowed, &flags) != FALSE &&
        WaitForSingleObject(allowed, 0) == WAIT_TIMEOUT;
    WSADATA winsock{};
    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) {
        return 611;
    }
    int socket_type = 0;
    int socket_type_length = sizeof(socket_type);
    const int socket_status = getsockopt(
        static_cast<SOCKET>(socket_value), SOL_SOCKET, SO_TYPE,
        reinterpret_cast<char*>(&socket_type), &socket_type_length);
    const int socket_error = WSAGetLastError();
    WSACleanup();
    return allowed_present && socket_status == SOCKET_ERROR &&
            socket_error == WSAENOTSOCK
        ? 0
        : 612;
}

bool RunNetworkStartupHandleTests() {
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
        WSACleanup();
        return false;
    }
    const SOCKET ambient_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ambient_socket == INVALID_SOCKET ||
        connect(
            ambient_socket, reinterpret_cast<const sockaddr*>(&endpoint),
            sizeof(endpoint)) != 0) {
        if (ambient_socket != INVALID_SOCKET) {
            closesocket(ambient_socket);
        }
        closesocket(listener);
        WSACleanup();
        return false;
    }
    const SOCKET server_socket = accept(listener, nullptr, nullptr);
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    const HANDLE allowed_event =
        CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    const bool handles_ready = server_socket != INVALID_SOCKET &&
        allowed_event != nullptr &&
        SetHandleInformation(
            reinterpret_cast<HANDLE>(ambient_socket), HANDLE_FLAG_INHERIT,
            HANDLE_FLAG_INHERIT) != FALSE;
    const std::wstring executable = CurrentExecutable();
    const std::wstring command =
        L"\"" + executable + L"\" --network-startup-handle-child " +
        HandleText(reinterpret_cast<std::uintptr_t>(allowed_event)) + L" " +
        HandleText(static_cast<std::uintptr_t>(ambient_socket));
    const HANDLE inherited[] = {allowed_event};
    const bolt::common::ProcessLaunchOptions options{
        executable, command, L"", nullptr, inherited, std::size(inherited), 0};
    bolt::common::SuspendedProcess process;
    const bool created = handles_ready && !executable.empty() &&
        bolt::common::SuspendedProcess::Create(options, process) ==
            bolt::common::ProcessStatus::kSuccess;
    const bool resumed = created &&
        ResumeThread(process.thread_handle()) != static_cast<DWORD>(-1);
    DWORD exit_code = 0;
    const bool passed = resumed &&
        process.Wait(3'000) == bolt::common::ProcessStatus::kSuccess &&
        process.ExitCode(exit_code) == bolt::common::ProcessStatus::kSuccess &&
        exit_code == 0;
    process.Close();
    if (allowed_event != nullptr) {
        CloseHandle(allowed_event);
    }
    closesocket(ambient_socket);
    if (server_socket != INVALID_SOCKET) {
        closesocket(server_socket);
    }
    closesocket(listener);
    WSACleanup();
    return passed;
}
