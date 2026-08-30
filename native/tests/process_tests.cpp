#include "common/execution_job.h"
#include "common/immutable_policy_mapping.h"
#include "common/private_pipe.h"
#include "common/suspended_process.h"
#include "protocol/event_frame.h"
#include "tests/policy_fixture.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>

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

std::wstring PipeName(const DWORD process_id) {
    std::wostringstream suffix;
    suffix << std::hex << std::nouppercase << std::setfill(L'0') << std::setw(32)
           << static_cast<std::uint64_t>(process_id);
    return L"\\\\.\\pipe\\bolt-sandbox-" + suffix.str();
}

std::string AnsiPath(const wchar_t* path) {
    const int length = WideCharToMultiByte(CP_ACP, 0, path, -1, nullptr, 0, nullptr, nullptr);
    if (length <= 1) {
        return {};
    }
    std::string converted(static_cast<std::size_t>(length), '\0');
    if (WideCharToMultiByte(
            CP_ACP, 0, path, -1, converted.data(), length, nullptr, nullptr) != length) {
        return {};
    }
    converted.pop_back();
    return converted;
}

bool WriteFixture(const std::filesystem::path& path, const std::string_view content) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream.write(content.data(), static_cast<std::streamsize>(content.size()));
    return stream.good();
}

std::string ReadFixture(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    return {std::istreambuf_iterator<char>{stream}, std::istreambuf_iterator<char>{}};
}

bool CreateJunction(
    const std::filesystem::path& junction,
    const std::filesystem::path& target) {
    struct MountPointReparseDataBuffer {
        ULONG tag;
        USHORT data_length;
        USHORT reserved;
        USHORT substitute_offset;
        USHORT substitute_length;
        USHORT print_offset;
        USHORT print_length;
        WCHAR path_buffer[1];
    };
    constexpr DWORD reparse_header_size = 8;
    if (!CreateDirectoryW(junction.c_str(), nullptr)) {
        return false;
    }
    const HANDLE handle = CreateFileW(
        junction.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        RemoveDirectoryW(junction.c_str());
        return false;
    }

    const std::wstring substitute = L"\\??\\" + target.wstring();
    const std::wstring print_name = target.wstring();
    std::array<std::uint8_t, MAXIMUM_REPARSE_DATA_BUFFER_SIZE> storage{};
    auto* const reparse =
        reinterpret_cast<MountPointReparseDataBuffer*>(storage.data());
    reparse->tag = IO_REPARSE_TAG_MOUNT_POINT;
    reparse->substitute_offset = 0;
    reparse->substitute_length =
        static_cast<USHORT>(substitute.size() * sizeof(wchar_t));
    reparse->print_offset = reparse->substitute_length + sizeof(wchar_t);
    reparse->print_length =
        static_cast<USHORT>(print_name.size() * sizeof(wchar_t));
    std::memcpy(
        reparse->path_buffer, substitute.data(), reparse->substitute_length);
    std::memcpy(
        reinterpret_cast<std::uint8_t*>(reparse->path_buffer) + reparse->print_offset,
        print_name.data(), reparse->print_length);
    const DWORD path_bytes = reparse->print_offset + reparse->print_length +
                             sizeof(wchar_t);
    reparse->data_length = static_cast<USHORT>(8 + path_bytes);
    DWORD returned = 0;
    const BOOL created = DeviceIoControl(
        handle, FSCTL_SET_REPARSE_POINT, reparse,
        reparse_header_size + reparse->data_length, nullptr, 0, &returned,
        nullptr);
    CloseHandle(handle);
    if (!created) {
        RemoveDirectoryW(junction.c_str());
    }
    return created != FALSE;
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
    if (argument_count != 24) {
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
    if (MoveFileW(arguments[9], arguments[10]) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 105;
    }
    const std::string ansi_move_source = AnsiPath(arguments[9]);
    const std::string ansi_move_destination = AnsiPath(arguments[10]);
    if (ansi_move_source.empty() || ansi_move_destination.empty()) {
        return 106;
    }
    if (MoveFileA(ansi_move_source.c_str(), ansi_move_destination.c_str()) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 107;
    }
    if (MoveFileExA(
            ansi_move_source.c_str(), ansi_move_destination.c_str(),
            MOVEFILE_REPLACE_EXISTING) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 108;
    }
    if (MoveFileWithProgressW(
            arguments[9], arguments[10], nullptr, nullptr, MOVEFILE_REPLACE_EXISTING) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 109;
    }
    if (MoveFileWithProgressA(
            ansi_move_source.c_str(), ansi_move_destination.c_str(), nullptr, nullptr,
            MOVEFILE_REPLACE_EXISTING) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 110;
    }
    if (MoveFileTransactedW(
            arguments[9], arguments[10], nullptr, nullptr, MOVEFILE_REPLACE_EXISTING,
            INVALID_HANDLE_VALUE) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 111;
    }
    if (MoveFileTransactedA(
            ansi_move_source.c_str(), ansi_move_destination.c_str(), nullptr, nullptr,
            MOVEFILE_REPLACE_EXISTING, INVALID_HANDLE_VALUE) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 112;
    }
    if (CreateHardLinkW(arguments[11], arguments[9], nullptr) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 90;
    }
    if (CopyFileW(arguments[12], arguments[13], FALSE) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 91;
    }
    if (CopyFileExW(arguments[12], arguments[13], nullptr, nullptr, nullptr, 0) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 92;
    }
    const std::string ansi_copy_source = AnsiPath(arguments[12]);
    const std::string ansi_copy_destination = AnsiPath(arguments[13]);
    if (ansi_copy_source.empty() || ansi_copy_destination.empty()) {
        return 93;
    }
    if (CopyFileA(ansi_copy_source.c_str(), ansi_copy_destination.c_str(), FALSE) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 94;
    }
    if (CopyFileExA(
            ansi_copy_source.c_str(), ansi_copy_destination.c_str(), nullptr, nullptr, nullptr,
            0) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 95;
    }
    using CopyFile2Function = HRESULT(WINAPI*)(
        PCWSTR, PCWSTR, const COPYFILE2_EXTENDED_PARAMETERS*);
    const auto copy_file_2 = reinterpret_cast<CopyFile2Function>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CopyFile2"));
    if (copy_file_2 == nullptr ||
        copy_file_2(arguments[12], arguments[13], nullptr) !=
            HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED)) {
        return 96;
    }
    if (CopyFileTransactedW(
            arguments[12], arguments[13], nullptr, nullptr, nullptr, 0,
            INVALID_HANDLE_VALUE) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 97;
    }
    if (CopyFileTransactedA(
            ansi_copy_source.c_str(), ansi_copy_destination.c_str(), nullptr, nullptr, nullptr, 0,
            INVALID_HANDLE_VALUE) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 98;
    }
    if (!CopyFileW(arguments[14], arguments[15], TRUE)) {
        return 99;
    }
    if (CopyFileExW(arguments[14], arguments[13], nullptr, nullptr, nullptr, 0) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 100;
    }
    if (CopyFileW(arguments[16], arguments[17], TRUE) ||
        GetLastError() != ERROR_FILE_NOT_FOUND) {
        return 101;
    }
    if (CopyFileW(arguments[14], arguments[18], FALSE) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 102;
    }
    if (MoveFileExW(arguments[19], arguments[20], MOVEFILE_REPLACE_EXISTING) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 103;
    }
    if (ReplaceFileW(arguments[21], arguments[12], nullptr, 0, nullptr, nullptr) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 113;
    }
    const std::string ansi_replace_target = AnsiPath(arguments[21]);
    if (ansi_replace_target.empty() ||
        ReplaceFileA(
            ansi_replace_target.c_str(), ansi_copy_source.c_str(), nullptr, 0, nullptr,
            nullptr) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 114;
    }
    const HANDLE rename_handle = CreateFileW(
        arguments[22], DELETE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (rename_handle == INVALID_HANDLE_VALUE) {
        return 115;
    }
    const std::size_t rename_name_bytes = std::wcslen(arguments[23]) * sizeof(wchar_t);
    std::vector<std::uint8_t> rename_buffer(
        offsetof(FILE_RENAME_INFO, FileName) + rename_name_bytes);
    auto* rename_info = reinterpret_cast<FILE_RENAME_INFO*>(rename_buffer.data());
    rename_info->ReplaceIfExists = FALSE;
    rename_info->RootDirectory = nullptr;
    rename_info->FileNameLength = static_cast<DWORD>(rename_name_bytes);
    std::memcpy(rename_info->FileName, arguments[23], rename_name_bytes);
    if (SetFileInformationByHandle(
            rename_handle, FileRenameInfo, rename_info,
            static_cast<DWORD>(rename_buffer.size())) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        CloseHandle(rename_handle);
        return 116;
    }
    CloseHandle(rename_handle);
    const auto flush_events = reinterpret_cast<BOOL (*)(DWORD)>(
        GetProcAddress(hook, "BoltSandboxFlushEvents"));
    if (flush_events == nullptr || !flush_events(5'000)) {
        return 104;
    }
    return 0;
}

bool RunProcessTests() {
    const std::wstring unique_suffix = std::to_wstring(GetCurrentProcessId());
    const std::filesystem::path test_root =
        std::filesystem::temp_directory_path() /
        (L"bolt-sandbox-process-" + unique_suffix);
    const std::filesystem::path denied_root = test_root / L"denied";
    const std::filesystem::path allowed_root = test_root / L"allowed";
    std::error_code filesystem_error;
    std::filesystem::remove_all(test_root, filesystem_error);
    filesystem_error.clear();
    if (!std::filesystem::create_directories(denied_root, filesystem_error) || filesystem_error ||
        !std::filesystem::create_directories(allowed_root, filesystem_error) || filesystem_error) {
        return false;
    }

    const std::filesystem::path denied_path = denied_root / L"create.txt";
    const std::filesystem::path denied_delete_path = denied_root / L"delete.txt";
    const std::filesystem::path denied_create_directory = denied_root / L"mkdir";
    const std::filesystem::path denied_remove_directory = denied_root / L"rmdir";
    const std::filesystem::path denied_move_source = denied_root / L"move-source.txt";
    const std::filesystem::path denied_move_destination = denied_root / L"move-destination.txt";
    const std::filesystem::path denied_hardlink_destination = denied_root / L"hardlink.txt";
    const std::filesystem::path denied_copy_source = denied_root / L"copy-source.txt";
    const std::filesystem::path denied_copy_destination = denied_root / L"copy-destination.txt";
    const std::filesystem::path allowed_copy_source = allowed_root / L"copy-source.txt";
    const std::filesystem::path allowed_copy_destination = allowed_root / L"copy-destination.txt";
    const std::filesystem::path missing_copy_source = allowed_root / L"missing-source.txt";
    const std::filesystem::path missing_copy_destination = allowed_root / L"missing-destination.txt";
    const std::filesystem::path denied_junction_target = denied_root / L"junction-target";
    const std::filesystem::path denied_alias_target = denied_junction_target / L"protected.txt";
    const std::filesystem::path allowed_junction = allowed_root / L"junction";
    const std::filesystem::path alias_copy_destination = allowed_junction / L"protected.txt";
    const std::filesystem::path allowed_alias_move_source = allowed_root / L"move-source.txt";
    const std::filesystem::path alias_move_destination = allowed_junction / L"move-target.txt";
    const std::filesystem::path denied_alias_move_target =
        denied_junction_target / L"move-target.txt";
    const std::filesystem::path allowed_replace_target =
        allowed_root / L"replace-target.txt";
    const std::filesystem::path allowed_handle_rename_source =
        allowed_root / L"handle-rename-source.txt";
    const std::filesystem::path denied_handle_rename_destination =
        denied_root / L"handle-rename-destination.txt";
    if (!std::filesystem::create_directories(denied_junction_target, filesystem_error) ||
        filesystem_error) {
        return false;
    }
    const auto policy_payload = bolt::tests::SealPolicy({
        {bolt::tests::FilesystemRuleKind::kReadWrite, test_root},
        {bolt::tests::FilesystemRuleKind::kDeny, denied_root},
    });
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
    const std::wstring pipe_name = PipeName(GetCurrentProcessId());
    const auto policy_status = bolt::common::ImmutablePolicyMapping::Create(
        policy_payload.data(), policy_payload.size(), policy);
    if (policy_payload.empty() || allowed == nullptr || denied == nullptr || release == nullptr ||
        policy_status != bolt::common::PolicyMappingStatus::kSuccess ||
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
    DeleteFileW(denied_path.c_str());
    DeleteFileW(denied_delete_path.c_str());
    RemoveDirectoryW(denied_create_directory.c_str());
    RemoveDirectoryW(denied_remove_directory.c_str());
    DeleteFileW(denied_move_source.c_str());
    DeleteFileW(denied_move_destination.c_str());
    DeleteFileW(denied_hardlink_destination.c_str());
    DeleteFileW(denied_copy_source.c_str());
    DeleteFileW(denied_copy_destination.c_str());
    DeleteFileW(allowed_copy_source.c_str());
    DeleteFileW(allowed_copy_destination.c_str());
    DeleteFileW(missing_copy_source.c_str());
    DeleteFileW(missing_copy_destination.c_str());
    DeleteFileW(allowed_replace_target.c_str());
    DeleteFileW(allowed_handle_rename_source.c_str());
    DeleteFileW(denied_handle_rename_destination.c_str());
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
    const HANDLE copy_fixture = CreateFileW(
        denied_copy_source.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (copy_fixture == INVALID_HANDLE_VALUE) {
        DeleteFileW(denied_delete_path.c_str());
        DeleteFileW(denied_move_source.c_str());
        return false;
    }
    CloseHandle(copy_fixture);
    constexpr std::string_view replacement_nonce = "denied-replacement";
    constexpr std::string_view replace_target_nonce = "replace-target";
    if (!WriteFixture(denied_copy_source, replacement_nonce) ||
        !WriteFixture(allowed_replace_target, replace_target_nonce)) {
        return false;
    }
    constexpr std::string_view handle_rename_nonce = "handle-rename-source";
    if (!WriteFixture(allowed_handle_rename_source, handle_rename_nonce)) {
        return false;
    }
    constexpr std::string_view copy_nonce = "bolt-copy-nonce";
    if (!WriteFixture(allowed_copy_source, copy_nonce)) {
        DeleteFileW(denied_delete_path.c_str());
        DeleteFileW(denied_move_source.c_str());
        DeleteFileW(denied_copy_source.c_str());
        return false;
    }
    constexpr std::string_view protected_nonce = "protected-target";
    if (!WriteFixture(denied_alias_target, protected_nonce) ||
        !CreateJunction(allowed_junction, denied_junction_target)) {
        return false;
    }
    constexpr std::string_view move_nonce = "move-source";
    if (!WriteFixture(allowed_alias_move_source, move_nonce)) {
        return false;
    }
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
                                      denied_hardlink_destination.wstring() + L"\" \"" +
                                      denied_copy_source.wstring() + L"\" \"" +
                                      denied_copy_destination.wstring() + L"\" \"" +
                                      allowed_copy_source.wstring() + L"\" \"" +
                                      allowed_copy_destination.wstring() + L"\" \"" +
                                      missing_copy_source.wstring() + L"\" \"" +
                                      missing_copy_destination.wstring() + L"\" \"" +
                                      alias_copy_destination.wstring() + L"\" \"" +
                                      allowed_alias_move_source.wstring() + L"\" \"" +
                                      alias_move_destination.wstring() + L"\" \"" +
                                      allowed_replace_target.wstring() + L"\" \"" +
                                      allowed_handle_rename_source.wstring() + L"\" \"" +
                                      denied_handle_rename_destination.wstring() + L"\"";
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
            bolt::protocol::FilesystemOperation::kRename, denied_move_source.wstring(), 6) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRename, denied_move_source.wstring(), 7) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRename, denied_move_source.wstring(), 8) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRename, denied_move_source.wstring(), 9) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRename, denied_move_source.wstring(), 10) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRename, denied_move_source.wstring(), 11) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRename, denied_move_source.wstring(), 12) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRead, denied_move_source.wstring(), 13) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRead, denied_copy_source.wstring(), 14) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRead, denied_copy_source.wstring(), 15) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRead, denied_copy_source.wstring(), 16) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRead, denied_copy_source.wstring(), 17) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRead, denied_copy_source.wstring(), 18) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRead, denied_copy_source.wstring(), 19) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRead, denied_copy_source.wstring(), 20) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kCreate,
            denied_copy_destination.wstring(), 21) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kCreate, denied_alias_target.wstring(), 22) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRename,
            denied_alias_move_target.wstring(), 23) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRename, denied_copy_source.wstring(), 24) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRename, denied_copy_source.wstring(), 25) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRename,
            denied_handle_rename_destination.wstring(), 26);
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
                            !std::filesystem::exists(denied_hardlink_destination) &&
                            ReadFixture(denied_copy_source) == replacement_nonce &&
                            !std::filesystem::exists(denied_copy_destination) &&
                            ReadFixture(allowed_copy_source) == copy_nonce &&
                            ReadFixture(allowed_copy_destination) == copy_nonce &&
                            !std::filesystem::exists(missing_copy_source) &&
                            !std::filesystem::exists(missing_copy_destination) &&
                            ReadFixture(denied_alias_target) == protected_nonce &&
                            ReadFixture(allowed_alias_move_source) == move_nonce &&
                            !std::filesystem::exists(denied_alias_move_target) &&
                            ReadFixture(allowed_replace_target) == replace_target_nonce &&
                            ReadFixture(allowed_handle_rename_source) == handle_rename_nonce &&
                            !std::filesystem::exists(denied_handle_rename_destination);
    CloseHandle(allowed);
    CloseHandle(denied);
    if (event_client != INVALID_HANDLE_VALUE) {
        CloseHandle(event_client);
    }
    CloseHandle(release);
    DeleteFileW(denied_delete_path.c_str());
    RemoveDirectoryW(denied_remove_directory.c_str());
    DeleteFileW(denied_move_source.c_str());
    DeleteFileW(denied_copy_source.c_str());
    DeleteFileW(denied_copy_destination.c_str());
    DeleteFileW(allowed_copy_source.c_str());
    DeleteFileW(allowed_copy_destination.c_str());
    DeleteFileW(allowed_alias_move_source.c_str());
    DeleteFileW(allowed_replace_target.c_str());
    DeleteFileW(allowed_handle_rename_source.c_str());
    std::filesystem::remove_all(test_root, filesystem_error);
    if (!exact_exit) {
        return false;
    }

    auto breakaway = options;
    breakaway.creation_flags = CREATE_BREAKAWAY_FROM_JOB;
    bolt::common::SuspendedProcess rejected;
    const auto breakaway_status = bolt::common::SuspendedProcess::Create(breakaway, rejected);
    return breakaway_status == bolt::common::ProcessStatus::kUnsupportedFlags;
}
