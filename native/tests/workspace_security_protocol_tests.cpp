#include "protocol/workspace_security_protocol.h"

#include <filesystem>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

bool RunWorkspaceSecurityProtocolTests() {
    const bolt::protocol::WorkspaceSecurityRequest expected{
        bolt::protocol::WorkspaceSecurityOperation::kCopy,
        100,
        L"C:\\work\\source",
        L"C:\\work\\staged"};
    std::vector<std::uint8_t> encoded;
    bolt::protocol::WorkspaceSecurityRequest decoded{};
    if (bolt::protocol::EncodeWorkspaceSecurityRequest(expected, encoded) !=
            bolt::protocol::WorkspaceSecurityProtocolStatus::kSuccess ||
        bolt::protocol::DecodeWorkspaceSecurityRequest(
            encoded.data(), encoded.size(), decoded) !=
            bolt::protocol::WorkspaceSecurityProtocolStatus::kSuccess ||
        !(decoded == expected)) {
        return false;
    }
    auto tampered = encoded;
    tampered.back() ^= 1;
    if (bolt::protocol::DecodeWorkspaceSecurityRequest(
            tampered.data(), tampered.size(), decoded) !=
        bolt::protocol::WorkspaceSecurityProtocolStatus::kDigestMismatch) {
        return false;
    }
    const auto response = bolt::protocol::EncodeWorkspaceSecurityResponse(
        bolt::protocol::WorkspaceSecurityResult::kMismatch);
    bolt::protocol::WorkspaceSecurityResult result{};
    return bolt::protocol::DecodeWorkspaceSecurityResponse(
               response.data(), response.size(), result) ==
               bolt::protocol::WorkspaceSecurityProtocolStatus::kSuccess &&
           result == bolt::protocol::WorkspaceSecurityResult::kMismatch;
}

bool RunWorkspaceSecurityLauncherTests(
    const std::filesystem::path& directory) {
#if defined(_WIN64)
    const auto launcher = directory / L"bolt-sandbox-launcher.exe";
#else
    const auto launcher = directory / L"bolt-sandbox-launcher-x86.exe";
#endif
    wchar_t temporary[MAX_PATH]{};
    const DWORD temporary_length = GetTempPathW(MAX_PATH, temporary);
    if (temporary_length == 0 || temporary_length >= MAX_PATH) {
        return false;
    }
    const auto fixture = std::filesystem::path(temporary) /
                         (L"bolt-workspace-helper-" +
                          std::to_wstring(GetCurrentProcessId()) + L"-" +
                          std::to_wstring(GetTickCount64()));
    const auto source = fixture / L"source";
    const auto staged = fixture / L"staged";
    std::error_code error;
    if (!std::filesystem::create_directories(source) ||
        !std::filesystem::create_directories(staged)) {
        return false;
    }
    bolt::protocol::WorkspaceSecurityRequest request{
        bolt::protocol::WorkspaceSecurityOperation::kCopy,
        16,
        source.native(),
        staged.native()};
    std::vector<std::uint8_t> encoded;
    if (bolt::protocol::EncodeWorkspaceSecurityRequest(request, encoded) !=
        bolt::protocol::WorkspaceSecurityProtocolStatus::kSuccess) {
        std::filesystem::remove_all(fixture, error);
        return false;
    }
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    HANDLE input_read = nullptr;
    HANDLE input_write = nullptr;
    HANDLE output_read = nullptr;
    HANDLE output_write = nullptr;
    const HANDLE null_error = CreateFileW(
        L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        &inheritable, OPEN_EXISTING, 0, nullptr);
    if (!CreatePipe(&input_read, &input_write, &inheritable, 0) ||
        !CreatePipe(&output_read, &output_write, &inheritable, 0) ||
        null_error == INVALID_HANDLE_VALUE ||
        !SetHandleInformation(input_write, HANDLE_FLAG_INHERIT, 0) ||
        !SetHandleInformation(output_read, HANDLE_FLAG_INHERIT, 0)) {
        std::filesystem::remove_all(fixture, error);
        return false;
    }
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = input_read;
    startup.hStdOutput = output_write;
    startup.hStdError = null_error;
    PROCESS_INFORMATION process{};
    std::wstring command =
        L"\"" + launcher.native() + L"\" --workspace-security";
    const bool created = CreateProcessW(
        launcher.c_str(), command.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process) != FALSE;
    CloseHandle(input_read);
    CloseHandle(output_write);
    CloseHandle(null_error);
    std::array<
        std::uint8_t, bolt::protocol::kWorkspaceSecurityResponseLength>
        response{};
    DWORD written = 0;
    const bool wrote = created &&
                       WriteFile(
                           input_write, encoded.data(),
                           static_cast<DWORD>(encoded.size()), &written,
                           nullptr) &&
                       written == encoded.size();
    CloseHandle(input_write);
    DWORD read = 0;
    const bool responded = wrote &&
                           ReadFile(
                               output_read, response.data(),
                               static_cast<DWORD>(response.size()), &read,
                               nullptr) &&
                           read == response.size();
    CloseHandle(output_read);
    DWORD exit_code = ERROR_PROCESS_ABORTED;
    const bool exited = created &&
                        WaitForSingleObject(process.hProcess, 5'000) ==
                            WAIT_OBJECT_0 &&
                        GetExitCodeProcess(process.hProcess, &exit_code);
    if (created) {
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
    }
    bolt::protocol::WorkspaceSecurityResult result{};
    const bool decoded = responded &&
                         bolt::protocol::DecodeWorkspaceSecurityResponse(
                             response.data(), response.size(), result) ==
                             bolt::protocol::WorkspaceSecurityProtocolStatus::kSuccess;
    std::filesystem::remove_all(fixture, error);
    return decoded && exited && exit_code == ERROR_SUCCESS &&
           result == bolt::protocol::WorkspaceSecurityResult::kSuccess &&
           !error;
}
