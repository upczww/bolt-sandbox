#include "common/execution_job.h"
#include "common/immutable_policy_mapping.h"
#include "common/private_pipe.h"
#include "common/suspended_process.h"
#include "protocol/event_frame.h"

#include <cstdint>
#include <filesystem>
#include <string>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace {

std::wstring CurrentExecutable() {
    std::wstring path(32'768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (length == 0 || length == path.size()) {
        return {};
    }
    path.resize(length);
    return path;
}

std::wstring HandleText(const HANDLE handle) {
    return std::to_wstring(reinterpret_cast<std::uintptr_t>(handle));
}

}  // namespace

int RunProcessChild(const int argument_count, wchar_t** arguments) {
    if (argument_count != 5) {
        return 80;
    }
    const auto allowed = reinterpret_cast<HANDLE>(_wcstoui64(arguments[2], nullptr, 10));
    const auto denied = reinterpret_cast<HANDLE>(_wcstoui64(arguments[3], nullptr, 10));
    if (!SetEvent(allowed)) {
        return 81;
    }
    if (SetEvent(denied)) {
        return 82;
    }
    if (GetModuleHandleW(arguments[4]) == nullptr) {
        return 83;
    }
    const HMODULE hook = GetModuleHandleW(arguments[4]);
    const auto initialized = reinterpret_cast<BOOL(WINAPI*)()>(
        GetProcAddress(hook, "BoltSandboxRuntimeInitialized"));
    if (initialized == nullptr || !initialized()) {
        return 84;
    }
    return 0;
}

bool RunProcessTests() {
    constexpr std::array<std::uint8_t, 54> policy_payload = {
        0x42, 0x4c, 0x50, 0x31, 0x01, 0x00, 0x2c, 0x00, 0x0a, 0x00, 0x00, 0x00,
        0x0c, 0xee, 0x19, 0x24, 0xbb, 0x11, 0x38, 0x05, 0x95, 0x58, 0xbc, 0x22,
        0x1f, 0x5a, 0x7a, 0x1c, 0xf1, 0x59, 0x59, 0x20, 0x23, 0x31, 0x0c, 0x7d,
        0x00, 0xcd, 0xa8, 0x2e, 0xed, 0x90, 0xbb, 0xeb, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    };
    constexpr std::array<std::uint8_t, 16> nonce = {
        0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
        0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
    };
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    const HANDLE allowed = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    const HANDLE denied = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    const HANDLE release = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    bolt::common::ImmutablePolicyMapping policy;
    bolt::common::PrivatePipe event_pipe;
    const std::wstring pipe_name = L"\\\\.\\pipe\\bolt-sandbox-0123456789abcdef0123456789abcdef";
    if (allowed == nullptr || denied == nullptr || release == nullptr ||
        bolt::common::ImmutablePolicyMapping::Create(
            policy_payload.data(), policy_payload.size(), policy) !=
            bolt::common::PolicyMappingStatus::kSuccess ||
        bolt::common::PrivatePipe::Create(pipe_name, event_pipe) !=
            bolt::common::PipeStatus::kSuccess) {
        return false;
    }
    const HANDLE event_client = CreateFileW(
        pipe_name.c_str(), GENERIC_WRITE, 0, &inheritable, OPEN_EXISTING, 0, nullptr);
    if (event_client == INVALID_HANDLE_VALUE ||
        event_pipe.Accept() != bolt::common::PipeStatus::kSuccess) {
        return false;
    }

    const std::wstring executable = CurrentExecutable();
#if defined(_WIN64)
    constexpr auto hook_name = L"bolt-sandbox-x64.dll";
#else
    constexpr auto hook_name = L"bolt-sandbox-x86.dll";
#endif
    const std::filesystem::path hook_path =
        std::filesystem::path(executable).parent_path() / hook_name;
    const std::wstring command_line = L"\"" + executable + L"\" --process-child " +
                                      HandleText(allowed) + L" " + HandleText(denied) + L" " +
                                      hook_name;
    const HANDLE inherited[] = {allowed, policy.handle(), event_client, release};
    bolt::common::ProcessLaunchOptions options{
        executable,
        command_line,
        L"",
        nullptr,
        inherited,
        std::size(inherited),
        0,
    };
    bolt::common::SuspendedProcess process;
    bolt::common::ExecutionJob job;
    const bool created = bolt::common::ExecutionJob::Create(job) ==
                             bolt::common::JobStatus::kSuccess &&
                         bolt::common::SuspendedProcess::Create(options, process) ==
                             bolt::common::ProcessStatus::kSuccess;
    if (!created || process.Wait(100) != bolt::common::ProcessStatus::kWaitTimeout ||
        process.Resume() != bolt::common::ProcessStatus::kInvalidState ||
        process.AssignTo(job) != bolt::common::ProcessStatus::kSuccess ||
        process.Resume() != bolt::common::ProcessStatus::kInvalidState ||
        process.InstallRuntimePayload(
            policy.handle(), policy.length(), event_client, release, nonce) !=
            bolt::common::ProcessStatus::kSuccess ||
        process.Inject(hook_path.string()) != bolt::common::ProcessStatus::kSuccess ||
        process.BeginHookInitialization() != bolt::common::ProcessStatus::kSuccess) {
        return false;
    }
    std::array<std::uint8_t, bolt::protocol::kReadyFrameLength> ready{};
    DWORD bytes_read = 0;
    if (!ReadFile(
            event_pipe.handle(), ready.data(), static_cast<DWORD>(ready.size()), &bytes_read,
            nullptr) ||
        bytes_read != ready.size() ||
        bolt::protocol::ValidateReadyFrame(ready.data(), ready.size(), nonce) !=
            bolt::protocol::ReadyFrameStatus::kSuccess ||
        WaitForSingleObject(allowed, 0) != WAIT_TIMEOUT ||
        process.ReleaseAfterReady() != bolt::common::ProcessStatus::kSuccess ||
        process.Wait(5'000) != bolt::common::ProcessStatus::kSuccess) {
        CloseHandle(allowed);
        CloseHandle(denied);
        return false;
    }
    DWORD exit_code = 0;
    const bool exact_exit = process.ExitCode(exit_code) == bolt::common::ProcessStatus::kSuccess &&
                            exit_code == 0 &&
                            WaitForSingleObject(allowed, 0) == WAIT_OBJECT_0 &&
                            WaitForSingleObject(denied, 0) == WAIT_TIMEOUT;
    CloseHandle(allowed);
    CloseHandle(denied);
    CloseHandle(event_client);
    CloseHandle(release);
    if (!exact_exit) {
        return false;
    }

    auto breakaway = options;
    breakaway.creation_flags = CREATE_BREAKAWAY_FROM_JOB;
    bolt::common::SuspendedProcess rejected;
    return bolt::common::SuspendedProcess::Create(breakaway, rejected) ==
           bolt::common::ProcessStatus::kUnsupportedFlags;
}
