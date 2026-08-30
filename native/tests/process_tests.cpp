#include "common/execution_job.h"
#include "common/immutable_policy_mapping.h"
#include "common/private_pipe.h"
#include "common/suspended_process.h"
#include "protocol/event_frame.h"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

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

bool ReadExact(const HANDLE handle, std::uint8_t* bytes, const std::size_t length) {
    std::size_t offset = 0;
    while (offset < length) {
        DWORD bytes_read = 0;
        if (!ReadFile(
                handle, bytes + offset, static_cast<DWORD>(length - offset), &bytes_read,
                nullptr) ||
            bytes_read == 0) {
            return false;
        }
        offset += bytes_read;
    }
    return true;
}

std::uint32_t ReadU32(const std::uint8_t* bytes) {
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < 4; ++index) {
        value |= static_cast<std::uint32_t>(bytes[index]) << (index * 8);
    }
    return value;
}

bool ReadFilesystemViolation(
    const HANDLE event_pipe,
    const std::uint32_t process_id,
    const bolt::protocol::FilesystemOperation operation,
    const std::wstring& path,
    const std::uint64_t sequence) {
    std::array<std::uint8_t, bolt::protocol::kEventHeaderLength> header{};
    if (!ReadExact(event_pipe, header.data(), header.size())) {
        return false;
    }
    const std::size_t payload_length = ReadU32(header.data() + 8);
    const std::size_t frame_length = header.size() + payload_length;
    if (frame_length != bolt::protocol::FilesystemViolationFrameLength(path.c_str())) {
        return false;
    }
    std::vector<std::uint8_t> actual(frame_length);
    std::copy(header.begin(), header.end(), actual.begin());
    if (!ReadExact(
            event_pipe, actual.data() + header.size(), frame_length - header.size())) {
        return false;
    }
    std::vector<std::uint8_t> expected(frame_length);
    std::size_t written = 0;
    return bolt::protocol::EncodeFilesystemViolationFrame(
               process_id, operation, path.c_str(), sequence, expected.data(), expected.size(),
               written) == bolt::protocol::FrameEncodeStatus::kSuccess &&
           written == expected.size() && actual == expected;
}

}  // namespace

int RunProcessChild(const int argument_count, wchar_t** arguments) {
    if (argument_count != 12) {
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
    const auto initialized = reinterpret_cast<BOOL(*)()>(
        GetProcAddress(hook, "BoltSandboxRuntimeInitialized"));
    if (initialized == nullptr || !initialized()) {
        return 84;
    }
    const HANDLE denied_file = CreateFileW(
        arguments[5], GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (denied_file != INVALID_HANDLE_VALUE || GetLastError() != ERROR_ACCESS_DENIED) {
        if (denied_file != INVALID_HANDLE_VALUE) {
            CloseHandle(denied_file);
        }
        return 85;
    }
    if (DeleteFileW(arguments[6]) || GetLastError() != ERROR_ACCESS_DENIED) {
        return 86;
    }
    if (CreateDirectoryW(arguments[7], nullptr) || GetLastError() != ERROR_ACCESS_DENIED) {
        return 87;
    }
    if (RemoveDirectoryW(arguments[8]) || GetLastError() != ERROR_ACCESS_DENIED) {
        return 88;
    }
    if (MoveFileExW(arguments[9], arguments[10], MOVEFILE_REPLACE_EXISTING) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 89;
    }
    if (CreateHardLinkW(arguments[11], arguments[9], nullptr) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 90;
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
    HANDLE event_client = CreateFileW(
        pipe_name.c_str(), FILE_WRITE_DATA, 0, &inheritable, OPEN_EXISTING, 0, nullptr);
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
    const auto unique_suffix = std::to_wstring(GetCurrentProcessId()) + L".txt";
    const std::filesystem::path denied_path =
        std::filesystem::temp_directory_path() /
        (L"bolt-sandbox-denied-create-" + unique_suffix);
    const std::filesystem::path denied_delete_path =
        std::filesystem::temp_directory_path() /
        (L"bolt-sandbox-denied-delete-" + unique_suffix);
    const std::filesystem::path denied_create_directory =
        std::filesystem::temp_directory_path() /
        (L"bolt-sandbox-denied-mkdir-" + unique_suffix);
    const std::filesystem::path denied_remove_directory =
        std::filesystem::temp_directory_path() /
        (L"bolt-sandbox-denied-rmdir-" + unique_suffix);
    const std::filesystem::path denied_move_source =
        std::filesystem::temp_directory_path() /
        (L"bolt-sandbox-denied-move-source-" + unique_suffix);
    const std::filesystem::path denied_move_destination =
        std::filesystem::temp_directory_path() /
        (L"bolt-sandbox-denied-move-destination-" + unique_suffix);
    const std::filesystem::path denied_hardlink_destination =
        std::filesystem::temp_directory_path() /
        (L"bolt-sandbox-denied-hardlink-" + unique_suffix);
    DeleteFileW(denied_path.c_str());
    DeleteFileW(denied_delete_path.c_str());
    RemoveDirectoryW(denied_create_directory.c_str());
    RemoveDirectoryW(denied_remove_directory.c_str());
    DeleteFileW(denied_move_source.c_str());
    DeleteFileW(denied_move_destination.c_str());
    DeleteFileW(denied_hardlink_destination.c_str());
    const HANDLE delete_fixture = CreateFileW(
        denied_delete_path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (delete_fixture == INVALID_HANDLE_VALUE) {
        return false;
    }
    CloseHandle(delete_fixture);
    const HANDLE move_fixture = CreateFileW(
        denied_move_source.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (move_fixture == INVALID_HANDLE_VALUE) {
        DeleteFileW(denied_delete_path.c_str());
        return false;
    }
    CloseHandle(move_fixture);
    if (!CreateDirectoryW(denied_remove_directory.c_str(), nullptr)) {
        DeleteFileW(denied_delete_path.c_str());
        return false;
    }
    const std::wstring command_line = L"\"" + executable + L"\" --process-child " +
                                      HandleText(allowed) + L" " + HandleText(denied) + L" " +
                                      hook_name + L" \"" + denied_path.wstring() + L"\" \"" +
                                      denied_delete_path.wstring() + L"\" \"" +
                                      denied_create_directory.wstring() + L"\" \"" +
                                      denied_remove_directory.wstring() + L"\" \"" +
                                      denied_move_source.wstring() + L"\" \"" +
                                      denied_move_destination.wstring() + L"\" \"" +
                                      denied_hardlink_destination.wstring() + L"\"";
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
    const auto wait_suspended = process.Wait(100);
    const auto early_resume = process.Resume();
    const auto assigned = process.AssignTo(job);
    const auto assigned_resume = process.Resume();
    const auto wrong_mapping_status = process.InstallRuntimePayload(
        release, policy.length(), event_client, release, nonce);
    const auto payload_status = process.InstallRuntimePayload(
        policy.handle(), policy.length(), event_client, release, nonce);
    const auto inject_status = process.Inject(hook_path.string());
    const auto initialization_status = process.BeginHookInitialization();
    if (!created || wait_suspended != bolt::common::ProcessStatus::kWaitTimeout ||
        early_resume != bolt::common::ProcessStatus::kInvalidState ||
        assigned != bolt::common::ProcessStatus::kSuccess ||
        assigned_resume != bolt::common::ProcessStatus::kInvalidState ||
        wrong_mapping_status != bolt::common::ProcessStatus::kInvalidRuntimePayload ||
        payload_status != bolt::common::ProcessStatus::kSuccess ||
        inject_status != bolt::common::ProcessStatus::kSuccess ||
        initialization_status != bolt::common::ProcessStatus::kSuccess) {
        return false;
    }
    CloseHandle(event_client);
    event_client = INVALID_HANDLE_VALUE;
    std::array<std::uint8_t, bolt::protocol::kReadyFrameLength> ready{};
    DWORD bytes_read = 0;
    const BOOL read_ok = ReadFile(
        event_pipe.handle(), ready.data(), static_cast<DWORD>(ready.size()), &bytes_read, nullptr);
    const auto ready_status = bolt::protocol::ValidateReadyFrame(ready.data(), ready.size(), nonce);
    if (!read_ok || bytes_read != ready.size() ||
        ready_status != bolt::protocol::ReadyFrameStatus::kSuccess ||
        WaitForSingleObject(allowed, 0) != WAIT_TIMEOUT ||
        process.ReleaseAfterReady() != bolt::common::ProcessStatus::kSuccess ||
        process.Wait(5'000) != bolt::common::ProcessStatus::kSuccess) {
        CloseHandle(allowed);
        CloseHandle(denied);
        return false;
    }
    const std::uint32_t child_process_id = GetProcessId(process.process_handle());
    const bool violation_events =
        child_process_id != 0 &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kCreate, denied_path.wstring(), 1) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kDelete, denied_delete_path.wstring(), 2) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kCreate,
            denied_create_directory.wstring(), 3) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kDelete,
            denied_remove_directory.wstring(), 4) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRename, denied_move_source.wstring(), 5) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kCreate,
            denied_hardlink_destination.wstring(), 6);
    DWORD exit_code = 0;
    const bool exact_exit = process.ExitCode(exit_code) == bolt::common::ProcessStatus::kSuccess &&
                            violation_events &&
                            exit_code == 0 &&
                            WaitForSingleObject(allowed, 0) == WAIT_OBJECT_0 &&
                            WaitForSingleObject(denied, 0) == WAIT_TIMEOUT &&
                            !std::filesystem::exists(denied_path) &&
                            std::filesystem::exists(denied_delete_path) &&
                            !std::filesystem::exists(denied_create_directory) &&
                            std::filesystem::is_directory(denied_remove_directory) &&
                            std::filesystem::exists(denied_move_source) &&
                            !std::filesystem::exists(denied_move_destination) &&
                            !std::filesystem::exists(denied_hardlink_destination);
    CloseHandle(allowed);
    CloseHandle(denied);
    if (event_client != INVALID_HANDLE_VALUE) {
        CloseHandle(event_client);
    }
    CloseHandle(release);
    DeleteFileW(denied_delete_path.c_str());
    RemoveDirectoryW(denied_remove_directory.c_str());
    DeleteFileW(denied_move_source.c_str());
    if (!exact_exit) {
        return false;
    }

    auto breakaway = options;
    breakaway.creation_flags = CREATE_BREAKAWAY_FROM_JOB;
    bolt::common::SuspendedProcess rejected;
    const auto breakaway_status = bolt::common::SuspendedProcess::Create(breakaway, rejected);
    return breakaway_status == bolt::common::ProcessStatus::kUnsupportedFlags;
}
