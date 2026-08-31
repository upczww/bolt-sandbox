#include "protocol/launcher_startup.h"
#include "protocol/event_frame.h"
#include "protocol/policy_payload.h"

#include "common/execution_job.h"
#include "common/immutable_policy_mapping.h"
#include "common/private_pipe.h"
#include "common/suspended_process.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <limits>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace {

constexpr DWORD kStartupTimeoutMilliseconds = 5'000;

bool ParseHandle(const wchar_t* const text, HANDLE& output) noexcept {
    if (text == nullptr || *text == L'\0' || *text == L'-') {
        return false;
    }
    wchar_t* end = nullptr;
    errno = 0;
    const unsigned long long value = std::wcstoull(text, &end, 10);
    if (errno != 0 || end == text || *end != L'\0' || value == 0 ||
        value > (std::numeric_limits<std::uintptr_t>::max)()) {
        return false;
    }
    output = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(value));
    DWORD flags = 0;
    return GetHandleInformation(output, &flags) != FALSE;
}

bool HasKillOnClose(const HANDLE job) noexcept {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    return QueryInformationJobObject(
               job, JobObjectExtendedLimitInformation, &limits,
               sizeof(limits), nullptr) != FALSE &&
           (limits.BasicLimitInformation.LimitFlags &
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) != 0;
}

DWORD WaitForStartupSignal(
    const HANDLE expected,
    const HANDLE shutdown,
    const HANDLE owner) noexcept {
    const std::array<HANDLE, 3> handles = {expected, shutdown, owner};
    return WaitForMultipleObjects(
        static_cast<DWORD>(handles.size()), handles.data(), FALSE,
        kStartupTimeoutMilliseconds);
}

bool ReadExact(
    const HANDLE input,
    std::uint8_t* bytes,
    const std::size_t length) noexcept {
    std::size_t offset = 0;
    while (offset < length) {
        DWORD read = 0;
        const DWORD remaining = static_cast<DWORD>(length - offset);
        if (!ReadFile(input, bytes + offset, remaining, &read, nullptr) ||
            read == 0) {
            return false;
        }
        offset += read;
    }
    return true;
}

bool WriteExact(
    const HANDLE output,
    const std::uint8_t* bytes,
    const std::size_t length) noexcept {
    std::size_t offset = 0;
    while (offset < length) {
        DWORD written = 0;
        if (!WriteFile(
                output, bytes + offset, static_cast<DWORD>(length - offset),
                &written, nullptr) ||
            written == 0) {
            return false;
        }
        offset += written;
    }
    return true;
}

std::wstring EventPipeName(
    const std::array<std::uint8_t, 16>& nonce) {
    constexpr wchar_t digits[] = L"0123456789abcdef";
    std::wstring name = L"\\\\.\\pipe\\bolt-sandbox-";
    name.reserve(name.size() + nonce.size() * 2);
    for (const std::uint8_t byte : nonce) {
        name.push_back(digits[byte >> 4]);
        name.push_back(digits[byte & 0x0f]);
    }
    return name;
}

bool ToAnsiPath(const std::wstring& path, std::string& encoded) {
    const int required = WideCharToMultiByte(
        CP_ACP, WC_NO_BEST_FIT_CHARS, path.c_str(), -1, nullptr, 0, nullptr,
        nullptr);
    if (required <= 1) {
        return false;
    }
    encoded.resize(static_cast<std::size_t>(required));
    BOOL used_default = FALSE;
    if (WideCharToMultiByte(
            CP_ACP, WC_NO_BEST_FIT_CHARS, path.c_str(), -1, encoded.data(),
            required, nullptr, &used_default) != required ||
        used_default) {
        encoded.clear();
        return false;
    }
    encoded.pop_back();
    return true;
}

int RunDecodedSession(
    const bolt::protocol::LauncherStartRequest& request) noexcept {
    bolt::common::ImmutablePolicyMapping policy;
    bolt::common::PrivatePipe event_pipe;
    bolt::common::ExecutionJob job;
    const HANDLE release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    const std::wstring pipe_name = EventPipeName(request.nonce);
    if (release == nullptr ||
        bolt::common::ImmutablePolicyMapping::Create(
            request.policy.data(), request.policy.size(), policy) !=
            bolt::common::PolicyMappingStatus::kSuccess ||
        bolt::common::PrivatePipe::Create(pipe_name, event_pipe) !=
            bolt::common::PipeStatus::kSuccess ||
        bolt::common::ExecutionJob::Create(job) !=
            bolt::common::JobStatus::kSuccess) {
        if (release != nullptr) {
            CloseHandle(release);
        }
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    const HANDLE event_client = CreateFileW(
        pipe_name.c_str(), FILE_WRITE_DATA, 0, &inheritable, OPEN_EXISTING, 0,
        nullptr);
    if (event_client == INVALID_HANDLE_VALUE ||
        event_pipe.Accept() != bolt::common::PipeStatus::kSuccess) {
        if (event_client != INVALID_HANDLE_VALUE) {
            CloseHandle(event_client);
        }
        CloseHandle(release);
        return ERROR_PIPE_NOT_CONNECTED;
    }
    std::wstring command(
        request.command_line.begin(), request.command_line.end() - 1);
    const HANDLE inherited[] = {policy.handle(), event_client};
    bolt::common::ProcessLaunchOptions options{
        request.program,
        command,
        request.cwd,
        const_cast<wchar_t*>(request.environment_block.data()),
        inherited,
        std::size(inherited),
        0};
    bolt::common::SuspendedProcess process;
    std::string hook_path;
    const bool prepared = ToAnsiPath(request.hook_path, hook_path) &&
        bolt::common::SuspendedProcess::Create(options, process) ==
            bolt::common::ProcessStatus::kSuccess &&
        process.AssignTo(job) == bolt::common::ProcessStatus::kSuccess &&
        process.InstallRuntimePayload(
            policy.handle(), policy.length(), event_client, release,
            request.nonce) == bolt::common::ProcessStatus::kSuccess &&
        process.Inject(hook_path) == bolt::common::ProcessStatus::kSuccess &&
        process.BeginHookInitialization() ==
            bolt::common::ProcessStatus::kSuccess;
    CloseHandle(event_client);
    std::array<std::uint8_t, bolt::protocol::kReadyFrameLength> ready{};
    const bool ready_ok = prepared &&
        ReadExact(event_pipe.handle(), ready.data(), ready.size()) &&
        bolt::protocol::ValidateReadyFrame(
            ready.data(), ready.size(), request.nonce) ==
            bolt::protocol::ReadyFrameStatus::kSuccess &&
        process.ReleaseAfterReady() == bolt::common::ProcessStatus::kSuccess;
    if (!ready_ok) {
        job.Terminate(ERROR_DLL_INIT_FAILED);
        process.Wait(5'000);
        CloseHandle(release);
        return ERROR_DLL_INIT_FAILED;
    }
    std::array<std::uint8_t, 12> acknowledgment{
        'B', 'L', 'A', '1', 1, 0, 12, 0, 0, 0, 0, 0};
    const DWORD process_id = GetProcessId(process.process_handle());
    std::memcpy(acknowledgment.data() + 8, &process_id, sizeof(process_id));
    if (process_id == 0 ||
        !WriteExact(
            GetStdHandle(STD_OUTPUT_HANDLE), acknowledgment.data(),
            acknowledgment.size())) {
        job.Terminate(ERROR_BROKEN_PIPE);
        process.Wait(5'000);
        CloseHandle(release);
        return ERROR_BROKEN_PIPE;
    }
    const DWORD wait_milliseconds =
        request.has_timeout
            ? static_cast<DWORD>((std::min)(
                  request.timeout_milliseconds,
                  static_cast<std::uint64_t>(INFINITE - 1)))
            : INFINITE;
    const auto wait_status = process.Wait(wait_milliseconds);
    if (wait_status == bolt::common::ProcessStatus::kWaitTimeout) {
        job.Terminate(408);
        process.Wait(5'000);
        CloseHandle(release);
        return 408;
    }
    DWORD exit_code = ERROR_PROCESS_ABORTED;
    const bool exited = wait_status == bolt::common::ProcessStatus::kSuccess &&
        process.ExitCode(exit_code) == bolt::common::ProcessStatus::kSuccess;
    CloseHandle(release);
    return exited ? static_cast<int>(exit_code) : ERROR_PROCESS_ABORTED;
}

int RunStdioSession() noexcept {
    const HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    if (input == nullptr || input == INVALID_HANDLE_VALUE) {
        return ERROR_INVALID_HANDLE;
    }
    std::vector<std::uint8_t> encoded;
    try {
        encoded.resize(bolt::protocol::kLauncherStartHeaderLength);
    } catch (...) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    if (!ReadExact(input, encoded.data(), encoded.size())) {
        return ERROR_INVALID_DATA;
    }
    std::uint32_t total_length = 0;
    std::memcpy(&total_length, encoded.data() + 8, sizeof(total_length));
    if (total_length < bolt::protocol::kLauncherStartHeaderLength ||
        total_length > bolt::protocol::kLauncherStartMaximumLength) {
        return ERROR_INVALID_DATA;
    }
    try {
        encoded.resize(total_length);
    } catch (...) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    if (!ReadExact(
            input, encoded.data() + bolt::protocol::kLauncherStartHeaderLength,
            encoded.size() - bolt::protocol::kLauncherStartHeaderLength)) {
        return ERROR_INVALID_DATA;
    }
    bolt::protocol::LauncherStartRequest request{};
    if (bolt::protocol::DecodeLauncherStartRequest(
            encoded.data(), encoded.size(), request) !=
            bolt::protocol::LauncherStartStatus::kSuccess ||
        bolt::protocol::ValidatePolicyPayload(
            request.policy.data(), request.policy.size()) !=
            bolt::protocol::PolicyPayloadStatus::kValid) {
        return ERROR_INVALID_DATA;
    }
    const DWORD program_attributes = GetFileAttributesW(request.program.c_str());
    const DWORD cwd_attributes = GetFileAttributesW(request.cwd.c_str());
    const DWORD hook_attributes = GetFileAttributesW(request.hook_path.c_str());
    if (program_attributes == INVALID_FILE_ATTRIBUTES ||
        (program_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
        cwd_attributes == INVALID_FILE_ATTRIBUTES ||
        (cwd_attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
        hook_attributes == INVALID_FILE_ATTRIBUTES ||
        (hook_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        return ERROR_FILE_NOT_FOUND;
    }
    return RunDecodedSession(request);
}

}  // namespace

int wmain(const int argument_count, wchar_t** arguments) noexcept {
    if (argument_count == 2 &&
        std::wcscmp(arguments[1], L"--stdio-session") == 0) {
        return RunStdioSession();
    }
    if (argument_count != 8 ||
        std::wcscmp(arguments[1], L"--supervise-job") != 0) {
        return ERROR_INVALID_HANDLE;
    }
    HANDLE job = nullptr;
    HANDLE target_ready = nullptr;
    HANDLE host_ready = nullptr;
    HANDLE release = nullptr;
    HANDLE shutdown = nullptr;
    HANDLE owner = nullptr;
    if (!ParseHandle(arguments[2], job) ||
        !ParseHandle(arguments[3], target_ready) ||
        !ParseHandle(arguments[4], host_ready) ||
        !ParseHandle(arguments[5], release) ||
        !ParseHandle(arguments[6], shutdown) ||
        !ParseHandle(arguments[7], owner) || !HasKillOnClose(job)) {
        return ERROR_INVALID_HANDLE;
    }

    const DWORD target_status =
        WaitForStartupSignal(target_ready, shutdown, owner);
    if (target_status != WAIT_OBJECT_0) {
        return target_status == WAIT_TIMEOUT ? WAIT_TIMEOUT
                                             : ERROR_PROCESS_ABORTED;
    }
    if (!SetEvent(host_ready)) {
        return GetLastError();
    }
    const DWORD release_status = WaitForStartupSignal(release, shutdown, owner);
    if (release_status != WAIT_OBJECT_0) {
        return release_status == WAIT_TIMEOUT ? WAIT_TIMEOUT
                                              : ERROR_PROCESS_ABORTED;
    }

    const std::array<HANDLE, 2> terminal_handles = {shutdown, owner};
    const DWORD terminal_status = WaitForMultipleObjects(
        static_cast<DWORD>(terminal_handles.size()), terminal_handles.data(),
        FALSE, INFINITE);
    return terminal_status == WAIT_OBJECT_0 ? ERROR_SUCCESS
                                           : ERROR_PROCESS_ABORTED;
}
