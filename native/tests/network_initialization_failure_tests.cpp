#include "common/execution_job.h"
#include "common/immutable_policy_mapping.h"
#include "common/private_pipe.h"
#include "common/suspended_process.h"
#include "protocol/event_frame.h"
#include "tests/policy_fixture.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <string>

#define WIN32_LEAN_AND_MEAN
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

std::wstring PipeName(const DWORD suffix) {
    std::wostringstream encoded;
    encoded << std::hex << std::nouppercase << std::setfill(L'0')
            << std::setw(32) << static_cast<std::uint64_t>(suffix);
    return L"\\\\.\\pipe\\bolt-sandbox-" + encoded.str();
}

bool ReadReadyWithin(
    const HANDLE pipe,
    const HANDLE process,
    const std::array<std::uint8_t, 16>& nonce,
    const DWORD timeout_milliseconds) {
    const ULONGLONG deadline = GetTickCount64() + timeout_milliseconds;
    while (GetTickCount64() < deadline) {
        DWORD available = 0;
        if (PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr) &&
            available >= bolt::protocol::kReadyFrameLength) {
            std::array<std::uint8_t, bolt::protocol::kReadyFrameLength> ready{};
            DWORD read = 0;
            return ReadFile(
                       pipe, ready.data(), static_cast<DWORD>(ready.size()),
                       &read, nullptr) != FALSE &&
                read == ready.size() &&
                bolt::protocol::ValidateReadyFrame(
                    ready.data(), ready.size(), nonce) ==
                    bolt::protocol::ReadyFrameStatus::kSuccess;
        }
        if (WaitForSingleObject(process, 0) == WAIT_OBJECT_0) {
            return false;
        }
        Sleep(10);
    }
    return false;
}

bool RunMode(
    const bolt::tests::NetworkPolicyKind mode,
    const bool expect_ready,
    const std::filesystem::path& marker,
    const DWORD suffix) {
    DeleteFileW(marker.c_str());
    const std::wstring executable = CurrentExecutable();
#if defined(_WIN64)
    constexpr auto hook_name = L"bolt-sandbox-x64.dll";
#else
    constexpr auto hook_name = L"bolt-sandbox-x86.dll";
#endif
    const auto hook_path =
        std::filesystem::path(executable).parent_path() / hook_name;
    const auto payload = bolt::tests::SealPolicy(
        {{bolt::tests::FilesystemRuleKind::kReadWrite,
          std::filesystem::path(executable).root_path()}},
        bolt::tests::ChildProcessPolicyKind::kDeny, mode);
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    const HANDLE release = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    bolt::common::ImmutablePolicyMapping policy;
    bolt::common::PrivatePipe event_pipe;
    const std::wstring pipe_name = PipeName(suffix);
    const auto mapping_status = payload.empty()
        ? bolt::common::PolicyMappingStatus::kInvalidArgument
        : bolt::common::ImmutablePolicyMapping::Create(
              payload.data(), payload.size(), policy);
    const auto pipe_status = bolt::common::PrivatePipe::Create(
        pipe_name, event_pipe);
    if (release == nullptr || payload.empty() ||
        mapping_status != bolt::common::PolicyMappingStatus::kSuccess ||
        pipe_status != bolt::common::PipeStatus::kSuccess) {
        std::fprintf(
            stderr,
            "network init setup failed: mode=%u release=%d payload=%d "
            "mapping=%u pipe=%u error=%lu\n",
            static_cast<unsigned int>(mode), release != nullptr ? 1 : 0,
            payload.empty() ? 0 : 1,
            static_cast<unsigned int>(mapping_status),
            static_cast<unsigned int>(pipe_status),
            static_cast<unsigned long>(GetLastError()));
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
        std::fprintf(
            stderr,
            "network init event pipe failed: mode=%u client=%d error=%lu\n",
            static_cast<unsigned int>(mode),
            event_client != INVALID_HANDLE_VALUE ? 1 : 0,
            static_cast<unsigned long>(GetLastError()));
        if (event_client != INVALID_HANDLE_VALUE) {
            CloseHandle(event_client);
        }
        CloseHandle(release);
        return false;
    }
    const std::wstring command =
        L"\"" + executable + L"\" --network-init-marker \"" +
        marker.wstring() + L"\"";
    const HANDLE inherited[] = {policy.handle(), event_client};
    const bolt::common::ProcessLaunchOptions options{
        executable, command, L"", nullptr, inherited, std::size(inherited), 0};
    constexpr std::array<std::uint8_t, 16> nonce = {0x7B};
    bolt::common::SuspendedProcess process;
    bolt::common::ExecutionJob job;
    const bool initialized =
        bolt::common::ExecutionJob::Create(job) ==
            bolt::common::JobStatus::kSuccess &&
        bolt::common::SuspendedProcess::Create(options, process) ==
            bolt::common::ProcessStatus::kSuccess &&
        process.AssignTo(job) == bolt::common::ProcessStatus::kSuccess &&
        process.InstallRuntimePayload(
            policy.handle(), policy.length(), event_client, release, nonce) ==
            bolt::common::ProcessStatus::kSuccess &&
        process.Inject(hook_path.string()) ==
            bolt::common::ProcessStatus::kSuccess &&
        process.BeginHookInitialization() ==
            bolt::common::ProcessStatus::kSuccess;
    CloseHandle(event_client);
    const bool ready = initialized && ReadReadyWithin(
        event_pipe.handle(), process.process_handle(), nonce, 2'000);
    bool passed = false;
    if (expect_ready) {
        DWORD exit_code = 0;
        const auto release_status = ready
            ? process.ReleaseAfterReady()
            : bolt::common::ProcessStatus::kInvalidState;
        const auto wait_status =
            release_status == bolt::common::ProcessStatus::kSuccess
            ? process.Wait(2'000)
            : bolt::common::ProcessStatus::kInvalidState;
        const auto exit_status =
            wait_status == bolt::common::ProcessStatus::kSuccess
            ? process.ExitCode(exit_code)
            : bolt::common::ProcessStatus::kInvalidState;
        const bool marker_present =
            GetFileAttributesW(marker.c_str()) != INVALID_FILE_ATTRIBUTES;
        passed = ready &&
            release_status == bolt::common::ProcessStatus::kSuccess &&
            wait_status == bolt::common::ProcessStatus::kSuccess &&
            exit_status == bolt::common::ProcessStatus::kSuccess &&
            exit_code == 0 && marker_present;
        if (!passed) {
            std::fprintf(
                stderr,
                "network init control failed: mode=%u initialized=%d ready=%d "
                "release=%u wait=%u exit_status=%u exit=%lu marker=%d\n",
                static_cast<unsigned int>(mode), initialized ? 1 : 0,
                ready ? 1 : 0, static_cast<unsigned int>(release_status),
                static_cast<unsigned int>(wait_status),
                static_cast<unsigned int>(exit_status),
                static_cast<unsigned long>(exit_code), marker_present ? 1 : 0);
        }
    } else {
        const auto wait_status = process.Wait(2'000);
        const bool marker_absent =
            GetFileAttributesW(marker.c_str()) == INVALID_FILE_ATTRIBUTES;
        passed = initialized && !ready &&
            wait_status == bolt::common::ProcessStatus::kSuccess &&
            marker_absent;
        if (!passed) {
            std::fprintf(
                stderr,
                "network init failure failed: mode=%u initialized=%d ready=%d "
                "wait=%u marker_absent=%d\n",
                static_cast<unsigned int>(mode), initialized ? 1 : 0,
                ready ? 1 : 0, static_cast<unsigned int>(wait_status),
                marker_absent ? 1 : 0);
        }
    }
    process.Close();
    CloseHandle(release);
    event_pipe.Close();
    DeleteFileW(marker.c_str());
    return passed;
}

}  // namespace

int RunNetworkInitializationMarkerChild(
    const int argument_count,
    wchar_t** arguments) {
    if (argument_count != 3) {
        return 620;
    }
    const HANDLE marker = CreateFileW(
        arguments[2], GENERIC_WRITE, 0, nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (marker == INVALID_HANDLE_VALUE) {
        return 621;
    }
    CloseHandle(marker);
    return 0;
}

bool RunNetworkInitializationFailureTests() {
    const auto root = std::filesystem::temp_directory_path();
    const DWORD process_id = GetCurrentProcessId();
    const bool unrestricted = RunMode(
        bolt::tests::NetworkPolicyKind::kUnrestricted, true,
        root / (L"bolt-network-init-unrestricted-" +
                std::to_wstring(process_id) + L".marker"),
        process_id ^ 0x1000U);
    const bool denied = RunMode(
        bolt::tests::NetworkPolicyKind::kDenied, true,
        root / (L"bolt-network-init-denied-" +
                std::to_wstring(process_id) + L".marker"),
        process_id ^ 0x2000U);
    const bool allow_list = RunMode(
        bolt::tests::NetworkPolicyKind::kAllowList, false,
        root / (L"bolt-network-init-allow-list-" +
                std::to_wstring(process_id) + L".marker"),
        process_id ^ 0x3000U);
    if (!unrestricted || !denied || !allow_list) {
        std::fprintf(
            stderr, "network init modes failed: unrestricted=%d denied=%d "
                    "allow_list=%d\n",
            unrestricted ? 1 : 0, denied ? 1 : 0, allow_list ? 1 : 0);
    }
    return unrestricted && denied && allow_list;
}
