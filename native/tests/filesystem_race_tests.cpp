#include "common/execution_job.h"
#include "common/immutable_policy_mapping.h"
#include "common/private_pipe.h"
#include "common/suspended_process.h"
#include "protocol/event_frame.h"
#include "tests/policy_fixture.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>
#include <winioctl.h>
#include <winternl.h>

namespace {

constexpr std::size_t kWriteIterations = 32;

struct ThreadpoolIoContext {
    HANDLE completed = nullptr;
    volatile LONG result = ERROR_IO_PENDING;
    volatile LONG bytes = 0;
};

VOID CALLBACK ThreadpoolIoCallback(
    PTP_CALLBACK_INSTANCE instance,
    PVOID context,
    PVOID overlapped,
    ULONG io_result,
    ULONG_PTR bytes_transferred,
    PTP_IO io) {
    static_cast<void>(instance);
    static_cast<void>(overlapped);
    static_cast<void>(io);
    auto* state = static_cast<ThreadpoolIoContext*>(context);
    InterlockedExchange(&state->result, static_cast<LONG>(io_result));
    InterlockedExchange(&state->bytes, static_cast<LONG>(bytes_transferred));
    SetEvent(state->completed);
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

std::wstring HandleText(const HANDLE handle) {
    return std::to_wstring(reinterpret_cast<std::uintptr_t>(handle));
}

std::filesystem::path EnvironmentPath(const wchar_t* name) {
    const DWORD required = GetEnvironmentVariableW(name, nullptr, 0);
    if (required == 0) {
        return {};
    }
    std::wstring value(required, L'\0');
    const DWORD written = GetEnvironmentVariableW(
        name, value.data(), static_cast<DWORD>(value.size()));
    if (written == 0 || written >= value.size()) {
        return {};
    }
    value.resize(written);
    return std::filesystem::path(value);
}

std::wstring PipeName(const std::uint64_t ordinal) {
    const std::uint64_t high = 0x7261'6365'0000'0000ULL ^ ordinal;
    const std::uint64_t low =
        (static_cast<std::uint64_t>(GetCurrentProcessId()) << 32U) ^ ordinal;
    std::wostringstream suffix;
    suffix << std::hex << std::nouppercase << std::setfill(L'0')
           << std::setw(16) << high << std::setw(16) << low;
    return L"\\\\.\\pipe\\bolt-sandbox-" + suffix.str();
}

bool WriteFixture(
    const std::filesystem::path& path,
    const std::string_view content) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream.write(content.data(), static_cast<std::streamsize>(content.size()));
    return stream.good();
}

bool ReadSecurityDescriptor(
    const std::filesystem::path& path,
    std::vector<std::uint8_t>& descriptor) {
    DWORD required = 0;
    if (GetFileSecurityW(
            path.c_str(), DACL_SECURITY_INFORMATION, nullptr, 0, &required) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER || required == 0) {
        return false;
    }
    descriptor.assign(required, 0);
    return GetFileSecurityW(
               path.c_str(), DACL_SECURITY_INFORMATION, descriptor.data(),
               required, &required) != FALSE;
}

bool ApplyReadWriteDeniedAcl(const std::filesystem::path& path) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(D;;0x00000007;;;WD)(A;;0x00100080;;;WD)(A;;GA;;;SY)(A;;GA;;;BA)(A;;WDWO;;;OW)",
            SDDL_REVISION_1, &descriptor, nullptr)) {
        return false;
    }
    const bool applied = SetFileSecurityW(
                             path.c_str(), DACL_SECURITY_INFORMATION,
                             descriptor) != FALSE;
    LocalFree(descriptor);
    return applied;
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
    auto* reparse = reinterpret_cast<MountPointReparseDataBuffer*>(storage.data());
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
        reinterpret_cast<std::uint8_t*>(reparse->path_buffer) +
            reparse->print_offset,
        print_name.data(), reparse->print_length);
    reparse->data_length = static_cast<USHORT>(
        8 + reparse->print_offset + reparse->print_length + sizeof(wchar_t));
    DWORD returned = 0;
    const BOOL created = DeviceIoControl(
        handle, FSCTL_SET_REPARSE_POINT, reparse,
        reparse_header_size + reparse->data_length, nullptr, 0, &returned,
        nullptr);
    const DWORD error = GetLastError();
    CloseHandle(handle);
    if (!created) {
        RemoveDirectoryW(junction.c_str());
        SetLastError(error);
    }
    return created != FALSE;
}

std::string ReadFixture(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    return std::string(
        std::istreambuf_iterator<char>(stream),
        std::istreambuf_iterator<char>());
}

std::filesystem::path BoundaryLongPath(const std::filesystem::path& root) {
    std::filesystem::path path = root;
    for (std::size_t index = 0; index < 12; ++index) {
        path /= L"long-segment-0123456789";
    }
    return path / L"boundary.txt";
}

bool ReadExact(
    const HANDLE handle,
    std::uint8_t* bytes,
    const std::size_t length) {
    std::size_t offset = 0;
    while (offset < length) {
        DWORD bytes_read = 0;
        if (!ReadFile(
                handle, bytes + offset,
                static_cast<DWORD>(length - offset), &bytes_read, nullptr) ||
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

bool ReadExpectedViolations(
    const HANDLE pipe,
    const std::uint32_t process_id,
    const bolt::protocol::FilesystemOperation operation,
    const std::filesystem::path& path,
    const std::size_t count) {
    for (std::uint64_t sequence = 1; sequence <= count; ++sequence) {
        std::array<std::uint8_t, bolt::protocol::kEventHeaderLength> header{};
        if (!ReadExact(pipe, header.data(), header.size())) {
            return false;
        }
        const std::size_t frame_length =
            header.size() + ReadU32(header.data() + 8);
        if (frame_length !=
            bolt::protocol::FilesystemViolationFrameLength(path.c_str())) {
            return false;
        }
        std::vector<std::uint8_t> actual(frame_length);
        std::copy(header.begin(), header.end(), actual.begin());
        if (!ReadExact(
                pipe, actual.data() + header.size(),
                frame_length - header.size())) {
            return false;
        }
        std::vector<std::uint8_t> expected(frame_length);
        std::size_t written = 0;
        if (bolt::protocol::EncodeFilesystemViolationFrame(
                process_id, operation, path.c_str(), sequence,
                expected.data(), expected.size(), written) !=
                bolt::protocol::FrameEncodeStatus::kSuccess ||
            written != expected.size() || actual != expected) {
            return false;
        }
    }
    return true;
}

bool PipeHasNoEvents(const HANDLE pipe) {
    DWORD available = 0;
    if (PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr)) {
        return available == 0;
    }
    return GetLastError() == ERROR_BROKEN_PIPE;
}

bool PipeHasNoViolationForPath(
    const HANDLE pipe,
    const std::filesystem::path& forbidden_path) {
    for (;;) {
        std::array<std::uint8_t, bolt::protocol::kEventHeaderLength> header{};
        DWORD first_read = 0;
        if (!ReadFile(
                pipe, header.data(), static_cast<DWORD>(header.size()),
                &first_read, nullptr)) {
            return GetLastError() == ERROR_BROKEN_PIPE;
        }
        if (first_read != header.size()) {
            return false;
        }
        const std::size_t payload_length = ReadU32(header.data() + 8);
        std::vector<std::uint8_t> payload(payload_length);
        if (!ReadExact(pipe, payload.data(), payload.size())) {
            return false;
        }
        if (payload.size() < 9) {
            continue;
        }
        const std::size_t path_length = ReadU32(payload.data() + 5);
        if (9 + path_length * sizeof(wchar_t) != payload.size()) {
            continue;
        }
        std::wstring path(path_length, L'\0');
        std::memcpy(
            path.data(), payload.data() + 9, path.size() * sizeof(wchar_t));
        if (CompareStringOrdinal(
                path.c_str(), -1, forbidden_path.c_str(), -1, TRUE) ==
            CSTR_EQUAL) {
            std::fprintf(
                stderr, "forbidden-path violation operation=%u\n",
                static_cast<unsigned>(payload[4]));
            return false;
        }
    }
}

bool PipeContainsViolationForPath(
    const HANDLE pipe,
    const bolt::protocol::FilesystemOperation expected_operation,
    const std::filesystem::path& expected_path) {
    bool found = false;
    for (;;) {
        std::array<std::uint8_t, bolt::protocol::kEventHeaderLength> header{};
        DWORD first_read = 0;
        if (!ReadFile(
                pipe, header.data(), static_cast<DWORD>(header.size()),
                &first_read, nullptr)) {
            return GetLastError() == ERROR_BROKEN_PIPE && found;
        }
        if (first_read != header.size()) {
            return false;
        }
        const std::size_t payload_length = ReadU32(header.data() + 8);
        std::vector<std::uint8_t> payload(payload_length);
        if (!ReadExact(pipe, payload.data(), payload.size())) {
            return false;
        }
        if (payload.size() < 9 || payload[4] != static_cast<std::uint8_t>(expected_operation)) {
            continue;
        }
        const std::size_t path_length = ReadU32(payload.data() + 5);
        if (9 + path_length * sizeof(wchar_t) != payload.size()) {
            continue;
        }
        std::wstring path(path_length, L'\0');
        std::memcpy(
            path.data(), payload.data() + 9, path.size() * sizeof(wchar_t));
        found = found || CompareStringOrdinal(
                              path.c_str(), -1, expected_path.c_str(), -1,
                              TRUE) == CSTR_EQUAL;
    }
}

bool EnumeratesDirectory(const std::filesystem::path& directory) {
    WIN32_FIND_DATAW data{};
    const std::filesystem::path wildcard = directory / L"*";
    const HANDLE find = FindFirstFileW(wildcard.c_str(), &data);
    if (find == INVALID_HANDLE_VALUE) {
        return false;
    }
    FindClose(find);
    return true;
}

using FlushEventsFunction = BOOL (*)(DWORD);

bool FlushEvents() {
#if defined(_WIN64)
    constexpr auto hook_name = L"bolt-sandbox-x64.dll";
#else
    constexpr auto hook_name = L"bolt-sandbox-x86.dll";
#endif
    const HMODULE hook = GetModuleHandleW(hook_name);
    const auto flush = hook == nullptr
                           ? nullptr
                           : reinterpret_cast<FlushEventsFunction>(
                                 GetProcAddress(hook, "BoltSandboxFlushEvents"));
    return flush != nullptr && flush(5'000) != FALSE;
}

class RaceProcess final {
  public:
    ~RaceProcess() {
        if (release_ != nullptr) {
            CloseHandle(release_);
        }
        if (ready_ != nullptr) {
            CloseHandle(ready_);
        }
    }

    bool Start(
        const std::wstring& executable,
        const std::filesystem::path& hook_path,
        const std::vector<bolt::tests::FilesystemRule>& filesystem_rules,
        const std::wstring_view mode,
        const std::filesystem::path& first_path,
        const std::filesystem::path& second_path,
        const HANDLE start,
        const std::uint64_t ordinal,
        const HANDLE extra_handle = nullptr) {
        const auto policy_payload = bolt::tests::SealPolicy(
            filesystem_rules, bolt::tests::ChildProcessPolicyKind::kDeny);
        constexpr std::array<std::uint8_t, 16> nonce = {
            0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48,
            0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48,
        };
        SECURITY_ATTRIBUTES inheritable{};
        inheritable.nLength = sizeof(inheritable);
        inheritable.bInheritHandle = TRUE;
        release_ = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
        ready_ = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
        const std::wstring pipe_name = PipeName(ordinal);
        if (policy_payload.empty() || release_ == nullptr || ready_ == nullptr ||
            bolt::common::ImmutablePolicyMapping::Create(
                policy_payload.data(), policy_payload.size(), policy_) !=
                bolt::common::PolicyMappingStatus::kSuccess ||
            bolt::common::PrivatePipe::Create(pipe_name, event_pipe_) !=
                bolt::common::PipeStatus::kSuccess) {
            return false;
        }
        HANDLE event_client = CreateFileW(
            pipe_name.c_str(), FILE_WRITE_DATA, 0, &inheritable, OPEN_EXISTING,
            0, nullptr);
        if (event_client == INVALID_HANDLE_VALUE ||
            event_pipe_.Accept() != bolt::common::PipeStatus::kSuccess) {
            if (event_client != INVALID_HANDLE_VALUE) {
                CloseHandle(event_client);
            }
            return false;
        }

        const std::wstring command_line =
            L"\"" + executable + L"\" --filesystem-race-child " +
            std::wstring(mode) + L" \"" + first_path.wstring() + L"\" \"" +
            second_path.wstring() + L"\" " + HandleText(start) + L" " +
            HandleText(ready_) + L" " + HandleText(extra_handle);
        std::vector<HANDLE> inherited = {
            policy_.handle(), event_client, start, ready_};
        if (extra_handle != nullptr) {
            inherited.push_back(extra_handle);
        }
        const bolt::common::ProcessLaunchOptions options{
            executable, command_line, L"", nullptr, inherited.data(),
            inherited.size(), 0};
        const bool initialized =
            bolt::common::ExecutionJob::Create(job_) ==
                bolt::common::JobStatus::kSuccess &&
            bolt::common::SuspendedProcess::Create(options, process_) ==
                bolt::common::ProcessStatus::kSuccess &&
            process_.AssignTo(job_) == bolt::common::ProcessStatus::kSuccess &&
            process_.InstallRuntimePayload(
                policy_.handle(), policy_.length(), event_client, release_,
                nonce) == bolt::common::ProcessStatus::kSuccess &&
            process_.Inject(hook_path.string()) ==
                bolt::common::ProcessStatus::kSuccess &&
            process_.BeginHookInitialization() ==
                bolt::common::ProcessStatus::kSuccess;
        CloseHandle(event_client);

        std::array<std::uint8_t, bolt::protocol::kReadyFrameLength> ready_frame{};
        DWORD bytes_read = 0;
        const bool ready_frame_ok =
            initialized &&
            ReadFile(
                event_pipe_.handle(), ready_frame.data(),
                static_cast<DWORD>(ready_frame.size()), &bytes_read, nullptr) !=
                FALSE &&
            bytes_read == ready_frame.size() &&
            bolt::protocol::ValidateReadyFrame(
                ready_frame.data(), ready_frame.size(), nonce) ==
                bolt::protocol::ReadyFrameStatus::kSuccess &&
            process_.ReleaseAfterReady() ==
                bolt::common::ProcessStatus::kSuccess;
        process_id_ = static_cast<std::uint32_t>(
            GetProcessId(process_.process_handle()));
        return ready_frame_ok && process_id_ != 0;
    }

    bool WaitAtBarrier() const {
        return WaitForSingleObject(ready_, 5'000) == WAIT_OBJECT_0;
    }

    bool ResetBarrierReady() const {
        return ResetEvent(ready_) != FALSE;
    }

    bool WaitForExit(const DWORD timeout_milliseconds = 10'000) {
        if (process_.Wait(timeout_milliseconds) !=
            bolt::common::ProcessStatus::kSuccess) {
            return false;
        }
        return process_.ExitCode(exit_code_) ==
                   bolt::common::ProcessStatus::kSuccess &&
               exit_code_ == 0;
    }

    bool Terminate(const DWORD exit_code) {
        return job_.Terminate(exit_code) == bolt::common::JobStatus::kSuccess;
    }

    HANDLE event_pipe() const {
        return event_pipe_.handle();
    }

    std::uint32_t process_id() const {
        return process_id_;
    }

    DWORD exit_code() const {
        return exit_code_;
    }

  private:
    HANDLE release_ = nullptr;
    HANDLE ready_ = nullptr;
    bolt::common::ImmutablePolicyMapping policy_;
    bolt::common::PrivatePipe event_pipe_;
    bolt::common::SuspendedProcess process_;
    bolt::common::ExecutionJob job_;
    std::uint32_t process_id_ = 0;
    DWORD exit_code_ = STILL_ACTIVE;
};

std::vector<bolt::tests::FilesystemRule> RacePolicyRules(
    const std::wstring& executable,
    const std::filesystem::path& policy_root,
    const bolt::tests::FilesystemRuleKind rule_kind) {
    return {
        {bolt::tests::FilesystemRuleKind::kReadOnly,
         std::filesystem::path(executable).root_path()},
        {rule_kind, policy_root},
    };
}

bool RunWriteRace(
    const std::wstring& executable,
    const std::filesystem::path& hook_path,
    const std::filesystem::path& test_root,
    std::uint64_t& ordinal) {
    const auto target = test_root / L"write-race.txt";
    if (!WriteFixture(target, "OO")) {
        return false;
    }
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    const HANDLE start = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    RaceProcess allowed;
    RaceProcess denied;
    const auto allowed_rules = RacePolicyRules(
        executable, test_root, bolt::tests::FilesystemRuleKind::kReadWrite);
    const auto denied_rules = RacePolicyRules(
        executable, test_root, bolt::tests::FilesystemRuleKind::kReadOnly);
    const bool started =
        start != nullptr &&
        allowed.Start(
            executable, hook_path, allowed_rules, L"allowed-write",
            target, {}, start, ordinal++) &&
        denied.Start(
            executable, hook_path, denied_rules, L"denied-write",
            target, {}, start, ordinal++);
    const bool released =
        started && allowed.WaitAtBarrier() && denied.WaitAtBarrier() &&
        SetEvent(start) != FALSE;
    const bool exited =
        released && allowed.WaitForExit() && denied.WaitForExit();
    const bool passed =
        exited && ReadFixture(target) == "AO" &&
        PipeHasNoEvents(allowed.event_pipe()) &&
        ReadExpectedViolations(
            denied.event_pipe(), denied.process_id(),
            bolt::protocol::FilesystemOperation::kWrite, target,
            kWriteIterations);
    if (start != nullptr) {
        CloseHandle(start);
    }
    return passed;
}

bool RunRenameDeleteRace(
    const std::wstring& executable,
    const std::filesystem::path& hook_path,
    const std::filesystem::path& test_root,
    std::uint64_t& ordinal) {
    const auto source = test_root / L"rename-delete-source.txt";
    const auto destination = test_root / L"rename-delete-destination.txt";
    if (!WriteFixture(source, "race")) {
        return false;
    }
    DeleteFileW(destination.c_str());
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    const HANDLE start = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    RaceProcess allowed;
    RaceProcess denied;
    const auto allowed_rules = RacePolicyRules(
        executable, test_root, bolt::tests::FilesystemRuleKind::kReadWrite);
    const auto denied_rules = RacePolicyRules(
        executable, test_root, bolt::tests::FilesystemRuleKind::kReadOnly);
    const bool started =
        start != nullptr &&
        allowed.Start(
            executable, hook_path, allowed_rules, L"allowed-rename",
            source, destination, start, ordinal++) &&
        denied.Start(
            executable, hook_path, denied_rules, L"denied-delete",
            source, {}, start, ordinal++);
    const bool released =
        started && allowed.WaitAtBarrier() && denied.WaitAtBarrier() &&
        SetEvent(start) != FALSE;
    const bool exited =
        released && allowed.WaitForExit() && denied.WaitForExit();
    const bool passed =
        exited && !std::filesystem::exists(source) &&
        ReadFixture(destination) == "race" &&
        PipeHasNoEvents(allowed.event_pipe()) &&
        ReadExpectedViolations(
            denied.event_pipe(), denied.process_id(),
            bolt::protocol::FilesystemOperation::kDelete, source, 1);
    if (start != nullptr) {
        CloseHandle(start);
    }
    return passed;
}

bool RunMixedTreeRenameTest(
    const std::wstring& executable,
    const std::filesystem::path& hook_path,
    const std::filesystem::path& test_root,
    std::uint64_t& ordinal) {
    const auto source = test_root / L"mixed-tree";
    const auto denied_child = source / L"denied-child";
    const auto denied_file = denied_child / L"protected.txt";
    const auto destination = test_root / L"mixed-tree-moved";
    std::error_code error;
    std::filesystem::remove_all(source, error);
    error.clear();
    std::filesystem::remove_all(destination, error);
    error.clear();
    if (!std::filesystem::create_directories(denied_child, error) || error ||
        !WriteFixture(denied_file, "protected")) {
        return false;
    }

    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    const HANDLE start = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    const std::vector<bolt::tests::FilesystemRule> rules = {
        {bolt::tests::FilesystemRuleKind::kReadOnly,
         std::filesystem::path(executable).root_path()},
        {bolt::tests::FilesystemRuleKind::kReadWrite, test_root},
        {bolt::tests::FilesystemRuleKind::kDeny, denied_child},
    };
    RaceProcess process;
    const bool started =
        start != nullptr &&
        process.Start(
            executable, hook_path, rules, L"denied-mixed-rename", source,
            destination, start, ordinal++);
    const bool released =
        started && process.WaitAtBarrier() && SetEvent(start) != FALSE;
    const bool exited = released && process.WaitForExit();
    const bool passed =
        exited && std::filesystem::is_directory(source) &&
        ReadFixture(denied_file) == "protected" &&
        !std::filesystem::exists(destination) &&
        ReadExpectedViolations(
            process.event_pipe(), process.process_id(),
            bolt::protocol::FilesystemOperation::kRename, source, 1);
    if (start != nullptr) {
        CloseHandle(start);
    }
    if (!passed) {
        std::fprintf(
            stderr,
            "mixed tree rename failed: exit=%lu source=%d destination=%d\n",
            static_cast<unsigned long>(process.exit_code()),
            std::filesystem::exists(source) ? 1 : 0,
            std::filesystem::exists(destination) ? 1 : 0);
    }
    return passed;
}

bool RunAllowedReplaceRenameTest(
    const std::wstring& executable,
    const std::filesystem::path& hook_path,
    const std::filesystem::path& test_root,
    std::uint64_t& ordinal) {
    const auto replacement = test_root / L"allowed-replacement.txt";
    const auto target = test_root / L"allowed-replace-target.txt";
    const auto renamed = test_root / L"allowed-replace-renamed.txt";
    DeleteFileW(replacement.c_str());
    DeleteFileW(target.c_str());
    DeleteFileW(renamed.c_str());
    if (!WriteFixture(replacement, "new-content") ||
        !WriteFixture(target, "old-content")) {
        return false;
    }
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    const HANDLE start = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    const auto rules = RacePolicyRules(
        executable, test_root, bolt::tests::FilesystemRuleKind::kReadWrite);
    RaceProcess process;
    const bool started =
        start != nullptr &&
        process.Start(
            executable, hook_path, rules, L"allowed-replace-rename", test_root,
            {}, start, ordinal++);
    const bool released =
        started && process.WaitAtBarrier() && SetEvent(start) != FALSE;
    const bool exited = released && process.WaitForExit();
    const bool passed =
        exited && !std::filesystem::exists(replacement) &&
        !std::filesystem::exists(target) &&
        ReadFixture(renamed) == "new-content" &&
        PipeHasNoEvents(process.event_pipe());
    if (start != nullptr) {
        CloseHandle(start);
    }
    if (!passed) {
        std::fprintf(
            stderr,
            "allowed replace/rename failed: exit=%lu replacement=%d target=%d renamed=%d renamed_size=%zu\n",
            static_cast<unsigned long>(process.exit_code()),
            std::filesystem::exists(replacement) ? 1 : 0,
            std::filesystem::exists(target) ? 1 : 0,
            std::filesystem::exists(renamed) ? 1 : 0,
            ReadFixture(renamed).size());
    }
    return passed;
}

bool RunPolicySemanticsTest(
    const std::wstring& executable,
    const std::filesystem::path& hook_path,
    const std::filesystem::path& test_root,
    std::uint64_t& ordinal) {
    const auto allowed = test_root / L"semantics-allowed";
    const auto read_only = test_root / L"semantics-read-only";
    const auto metadata = test_root / L"semantics-metadata";
    const auto denied = test_root / L"semantics-denied";
    const auto outside = test_root / L"semantics-outside";
    const auto parent = test_root / L"semantics-parent";
    const auto child_grant = parent / L"child-grant";
    std::error_code error;
    for (const auto& path : {
             allowed, read_only, metadata, denied, outside, child_grant}) {
        if (!std::filesystem::create_directories(path, error) || error) {
            return false;
        }
    }
    if (!WriteFixture(read_only / L"read-only.txt", "read-only") ||
        !WriteFixture(metadata / L"metadata.txt", "metadata") ||
        !WriteFixture(denied / L"denied.txt", "denied") ||
        !WriteFixture(outside / L"outside.txt", "outside") ||
        !WriteFixture(child_grant / L"granted.txt", "granted")) {
        return false;
    }

    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    const HANDLE start = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    const std::vector<bolt::tests::FilesystemRule> rules = {
        {bolt::tests::FilesystemRuleKind::kReadWrite, allowed},
        {bolt::tests::FilesystemRuleKind::kReadOnly, read_only},
        {bolt::tests::FilesystemRuleKind::kMetadataRead, metadata},
        {bolt::tests::FilesystemRuleKind::kDeny, denied},
        {bolt::tests::FilesystemRuleKind::kReadWrite, child_grant},
    };
    RaceProcess process;
    const bool started =
        start != nullptr &&
        process.Start(
            executable, hook_path, rules, L"policy-semantics", test_root, {},
            start, ordinal++);
    const bool released =
        started && process.WaitAtBarrier() && SetEvent(start) != FALSE;
    const bool exited = released && process.WaitForExit();
    const bool passed =
        exited && ReadFixture(allowed / L"nested" / L"created.txt") == "created" &&
        ReadFixture(read_only / L"read-only.txt") == "read-only" &&
        ReadFixture(metadata / L"metadata.txt") == "metadata" &&
        ReadFixture(denied / L"denied.txt") == "denied" &&
        ReadFixture(outside / L"outside.txt") == "outside" &&
        ReadFixture(child_grant / L"granted.txt") == "granted";
    if (start != nullptr) {
        CloseHandle(start);
    }
    if (!passed) {
        std::fprintf(
            stderr, "policy semantics failed: exit=%lu created=%d\n",
            static_cast<unsigned long>(process.exit_code()),
            std::filesystem::exists(allowed / L"nested" / L"created.txt") ? 1 : 0);
    }
    return passed;
}

bool RunInheritUserAclTest(
    const std::wstring& executable,
    const std::filesystem::path& hook_path,
    const std::filesystem::path& test_root,
    std::uint64_t& ordinal) {
    const auto inherit_root = test_root / L"inherit-user";
    const auto allowed_file = inherit_root / L"allowed.txt";
    const auto denied_file = inherit_root / L"acl-denied.txt";
    std::error_code error;
    if (!std::filesystem::create_directories(inherit_root, error) || error ||
        !WriteFixture(allowed_file, "allowed") ||
        !WriteFixture(denied_file, "denied")) {
        return false;
    }
    std::vector<std::uint8_t> original_descriptor;
    if (!ReadSecurityDescriptor(denied_file, original_descriptor) ||
        !ApplyReadWriteDeniedAcl(denied_file)) {
        return false;
    }

    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    const HANDLE start = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    const std::vector<bolt::tests::FilesystemRule> rules = {
        {bolt::tests::FilesystemRuleKind::kInheritUser, inherit_root},
    };
    RaceProcess process;
    const bool started =
        start != nullptr &&
        process.Start(
            executable, hook_path, rules, L"inherit-user-acl", inherit_root, {},
            start, ordinal++);
    const bool released =
        started && process.WaitAtBarrier() && SetEvent(start) != FALSE;
    const bool exited = released && process.WaitForExit();
    const bool no_violation =
        exited && PipeHasNoViolationForPath(process.event_pipe(), denied_file);

    const bool restored = SetFileSecurityW(
                              denied_file.c_str(), DACL_SECURITY_INFORMATION,
                              original_descriptor.data()) != FALSE;
    const bool passed =
        no_violation && restored && ReadFixture(allowed_file) == "Allowed" &&
        ReadFixture(denied_file) == "denied";
    if (start != nullptr) {
        CloseHandle(start);
    }
    if (!passed) {
        std::fprintf(
            stderr,
            "inherit_user ACL failed: exit=%lu no_violation=%d restored=%d allowed=%zu denied=%zu\n",
            static_cast<unsigned long>(process.exit_code()), no_violation ? 1 : 0,
            restored ? 1 : 0, ReadFixture(allowed_file).size(),
            ReadFixture(denied_file).size());
    }
    return passed;
}

bool RunPathFormsTest(
    const std::wstring& executable,
    const std::filesystem::path& hook_path,
    const std::filesystem::path& test_root,
    std::uint64_t& ordinal) {
    const auto allowed = test_root / L"path-forms-allowed";
    const auto denied = test_root / L"path-forms-denied";
    std::error_code error;
    if (!std::filesystem::create_directories(allowed, error) || error ||
        !std::filesystem::create_directories(denied, error) || error ||
        !WriteFixture(denied / L"base.txt", "denied")) {
        return false;
    }
    const auto boundary_long_path = BoundaryLongPath(allowed);
    const std::wstring extended_long_parent =
        L"\\\\?\\" + boundary_long_path.parent_path().wstring();
    if (!std::filesystem::create_directories(extended_long_parent, error) || error ||
        !WriteFixture(L"\\\\?\\" + boundary_long_path.wstring(), "long")) {
        return false;
    }
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    const HANDLE start = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    const std::vector<bolt::tests::FilesystemRule> rules = {
        {bolt::tests::FilesystemRuleKind::kReadWrite, allowed},
        {bolt::tests::FilesystemRuleKind::kDeny, denied},
    };
    RaceProcess process;
    const bool started =
        start != nullptr &&
        process.Start(
            executable, hook_path, rules, L"path-forms", test_root, {}, start,
            ordinal++);
    const bool released =
        started && process.WaitAtBarrier() && SetEvent(start) != FALSE;
    const bool exited = released && process.WaitForExit();
    const bool passed =
        exited && ReadFixture(allowed / L"relative.txt") == "relative" &&
        ReadFixture(allowed / L"base.txt:stream") == "stream" &&
        ReadFixture(allowed / L"unicode-\u00e9.txt") == "composed" &&
        ReadFixture(allowed / L"unicode-e\u0301.txt") == "decomposed" &&
        ReadFixture(L"\\\\?\\" + boundary_long_path.wstring()) == "long" &&
        !std::filesystem::exists(allowed / L"delete-on-close.tmp") &&
        ReadFixture(denied / L"base.txt") == "denied";
    if (start != nullptr) {
        CloseHandle(start);
    }
    if (!passed) {
        std::fprintf(
            stderr, "path forms failed: exit=%lu\n",
            static_cast<unsigned long>(process.exit_code()));
    }
    return passed;
}

bool RunUncPathTest(
    const std::wstring& executable,
    const std::filesystem::path& hook_path,
    std::uint64_t& ordinal) {
    const auto fixture_root = EnvironmentPath(L"BOLT_TEST_UNC_ROOT");
    if (fixture_root.empty()) {
        std::fprintf(stderr, "filesystem capability BOLT_TEST_UNC_ROOT=not_present\n");
        return true;
    }
    const auto test_root = fixture_root /
                           (L"bolt-sandbox-unc-" +
                            std::to_wstring(GetCurrentProcessId()));
    const auto allowed = test_root / L"allowed";
    const auto denied = test_root / L"denied";
    std::error_code error;
    std::filesystem::remove_all(test_root, error);
    error.clear();
    if (!std::filesystem::create_directories(allowed, error) || error ||
        !std::filesystem::create_directories(denied, error) || error ||
        !WriteFixture(denied / L"protected.txt", "protected")) {
        return false;
    }

    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    const HANDLE start = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    const std::vector<bolt::tests::FilesystemRule> rules = {
        {bolt::tests::FilesystemRuleKind::kReadWrite, allowed},
        {bolt::tests::FilesystemRuleKind::kDeny, denied},
    };
    RaceProcess process;
    const bool started =
        start != nullptr &&
        process.Start(
            executable, hook_path, rules, L"unc-paths", test_root, {}, start,
            ordinal++);
    const bool released =
        started && process.WaitAtBarrier() && SetEvent(start) != FALSE;
    const bool exited = released && process.WaitForExit();
    const bool passed =
        exited && ReadFixture(allowed / L"plain.txt") == "extended" &&
        !std::filesystem::exists(denied / L"blocked.txt") &&
        ReadFixture(denied / L"protected.txt") == "protected";
    if (start != nullptr) {
        CloseHandle(start);
    }
    std::filesystem::remove_all(test_root, error);
    if (!passed) {
        std::fprintf(
            stderr, "UNC path capability failed: exit=%lu\n",
            static_cast<unsigned long>(process.exit_code()));
    }
    return passed;
}

bool RunCaseSensitivePathTest(
    const std::wstring& executable,
    const std::filesystem::path& hook_path,
    std::uint64_t& ordinal) {
    const auto fixture_root =
        EnvironmentPath(L"BOLT_TEST_CASE_SENSITIVE_ROOT");
    if (fixture_root.empty()) {
        std::fprintf(
            stderr,
            "filesystem capability BOLT_TEST_CASE_SENSITIVE_ROOT=not_present\n");
        return true;
    }
    const auto test_root = fixture_root /
                           (L"bolt-sandbox-case-" +
                            std::to_wstring(GetCurrentProcessId()));
    const auto allowed = test_root / L"PolicyTarget.txt";
    const auto denied = test_root / L"policytarget.txt";
    std::error_code error;
    std::filesystem::remove_all(test_root, error);
    error.clear();
    if (!std::filesystem::create_directories(test_root, error) || error ||
        !WriteFixture(allowed, "allowed") ||
        !WriteFixture(denied, "denied") ||
        ReadFixture(allowed) == ReadFixture(denied)) {
        return false;
    }

    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    const HANDLE start = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    const std::vector<bolt::tests::FilesystemRule> rules = {
        {bolt::tests::FilesystemRuleKind::kReadWrite, allowed},
        {bolt::tests::FilesystemRuleKind::kDeny, denied},
    };
    RaceProcess process;
    const bool started =
        start != nullptr &&
        process.Start(
            executable, hook_path, rules, L"case-sensitive-paths", test_root,
            {}, start, ordinal++);
    const bool released =
        started && process.WaitAtBarrier() && SetEvent(start) != FALSE;
    const bool exited = released && process.WaitForExit();
    const bool passed =
        exited && ReadFixture(allowed) == "Allowed" &&
        ReadFixture(denied) == "denied";
    if (start != nullptr) {
        CloseHandle(start);
    }
    std::filesystem::remove_all(test_root, error);
    if (!passed) {
        std::fprintf(
            stderr, "case-sensitive path capability failed: exit=%lu\n",
            static_cast<unsigned long>(process.exit_code()));
    }
    return passed;
}

bool RunCaseInsensitiveCollisionRejectionTest(
    const std::wstring& executable,
    const std::filesystem::path& hook_path,
    const std::filesystem::path& test_root,
    std::uint64_t& ordinal) {
    const auto collision_root = test_root / L"case-insensitive-collision";
    const auto allowed = collision_root / L"PolicyTarget.txt";
    const auto denied = collision_root / L"policytarget.txt";
    std::error_code error;
    if (!std::filesystem::create_directories(collision_root, error) || error ||
        !WriteFixture(allowed, "single-identity")) {
        return false;
    }
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    const HANDLE start = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    const std::vector<bolt::tests::FilesystemRule> rules = {
        {bolt::tests::FilesystemRuleKind::kReadWrite, allowed},
        {bolt::tests::FilesystemRuleKind::kDeny, denied},
    };
    RaceProcess process;
    const bool rejected =
        start != nullptr &&
        !process.Start(
            executable, hook_path, rules, L"case-sensitive-paths",
            collision_root, {}, start, ordinal++);
    if (start != nullptr) {
        CloseHandle(start);
    }
    if (!rejected) {
        std::fprintf(
            stderr,
            "case-insensitive policy collision was not rejected: exit=%lu\n",
            static_cast<unsigned long>(process.exit_code()));
    }
    return rejected;
}

bool RunVolumeGuidAliasTest(
    const std::wstring& executable,
    const std::filesystem::path& hook_path,
    const std::filesystem::path& test_root,
    std::uint64_t& ordinal) {
    const auto allowed = test_root / L"volume-guid-allowed.txt";
    const auto denied = test_root / L"volume-guid-denied.txt";
    if (!WriteFixture(allowed, "allowed-volume") ||
        !WriteFixture(denied, "denied-volume")) {
        return false;
    }
    const std::wstring mount_point = test_root.root_path().wstring();
    std::array<wchar_t, 64> volume_name{};
    if (mount_point.empty() ||
        !GetVolumeNameForVolumeMountPointW(
            mount_point.c_str(), volume_name.data(),
            static_cast<DWORD>(volume_name.size()))) {
        return false;
    }
    const auto volume_alias = [&](const std::filesystem::path& path) {
        const auto relative = path.lexically_relative(test_root.root_path());
        return std::filesystem::path(volume_name.data()) / relative;
    };
    const auto allowed_alias = volume_alias(allowed);
    const auto denied_alias = volume_alias(denied);
    const std::vector<bolt::tests::FilesystemRule> rules = {
        {bolt::tests::FilesystemRuleKind::kReadOnly,
         std::filesystem::path(executable).root_path()},
        {bolt::tests::FilesystemRuleKind::kReadOnly, allowed},
        {bolt::tests::FilesystemRuleKind::kDeny, denied},
    };
    const auto run_alias = [&](
                               const std::wstring_view mode,
                               const std::filesystem::path& allowed_path,
                               const std::filesystem::path& denied_path,
                               const char* label) {
        SECURITY_ATTRIBUTES inheritable{};
        inheritable.nLength = sizeof(inheritable);
        inheritable.bInheritHandle = TRUE;
        const HANDLE start = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
        const HANDLE stage_mapping = CreateFileMappingW(
            INVALID_HANDLE_VALUE, &inheritable, PAGE_READWRITE, 0, sizeof(LONG),
            nullptr);
        auto* stage = stage_mapping == nullptr
                          ? nullptr
                          : static_cast<volatile LONG*>(MapViewOfFile(
                                stage_mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0,
                                0, sizeof(LONG)));
        if (stage != nullptr) {
            InterlockedExchange(stage, 0);
        }
        RaceProcess process;
        const bool started =
            start != nullptr && stage_mapping != nullptr && stage != nullptr &&
            process.Start(
                executable, hook_path, rules, mode, allowed_path, denied_path,
                start, ordinal++, stage_mapping);
        const bool released =
            started && process.WaitAtBarrier() && SetEvent(start) != FALSE;
        const bool exited = released && process.WaitForExit(3'000);
        const LONG final_stage =
            stage == nullptr ? -1 : InterlockedCompareExchange(stage, 0, 0);
        if (released && !exited) {
            process.Terminate(0xF016);
        }
        const bool passed =
            exited && final_stage == 4 &&
            PipeContainsViolationForPath(
                process.event_pipe(),
                bolt::protocol::FilesystemOperation::kRead, denied);
        if (stage != nullptr) {
            UnmapViewOfFile(const_cast<LONG*>(stage));
        }
        if (stage_mapping != nullptr) {
            CloseHandle(stage_mapping);
        }
        if (start != nullptr) {
            CloseHandle(start);
        }
        if (!passed) {
            std::fprintf(
                stderr,
                "%s alias failed: exit=%lu stage=%ld started=%d released=%d\n",
                label, static_cast<unsigned long>(process.exit_code()),
                final_stage, started ? 1 : 0, released ? 1 : 0);
        }
        return passed;
    };
    const wchar_t drive_name[] = {mount_point[0], L':', L'\0'};
    std::array<wchar_t, 32'768> device_name{};
    if (QueryDosDeviceW(
            drive_name, device_name.data(),
            static_cast<DWORD>(device_name.size())) == 0) {
        return false;
    }
    const auto device_alias = [&](const std::filesystem::path& path) {
        std::wstring alias(device_name.data());
        alias.push_back(L'\\');
        alias.append(path.lexically_relative(test_root.root_path()).wstring());
        return std::filesystem::path(alias);
    };
    const auto local_device_alias = [](const std::filesystem::path& path) {
        return std::filesystem::path(L"\\\\.\\" + path.wstring());
    };
    return run_alias(
               L"volume-guid-aliases", allowed_alias, denied_alias,
               "volume GUID") &&
           run_alias(
               L"volume-guid-aliases", local_device_alias(allowed),
               local_device_alias(denied), "local device") &&
           run_alias(
               L"native-device-aliases", device_alias(allowed),
               device_alias(denied), "native device");
}

bool RunExistingSymlinkTest(
    const std::wstring& executable,
    const std::filesystem::path& hook_path,
    std::uint64_t& ordinal) {
    const std::filesystem::path link_root = L"C:\\Users\\All Users";
    const std::filesystem::path alias = link_root / L"Microsoft";
    const std::filesystem::path target = L"C:\\ProgramData\\Microsoft";
    const DWORD link_attributes = GetFileAttributesW(link_root.c_str());
    if (link_attributes == INVALID_FILE_ATTRIBUTES ||
        (link_attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 ||
        !std::filesystem::is_directory(target)) {
        return false;
    }
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    const HANDLE start = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    const std::vector<bolt::tests::FilesystemRule> allowed_rules = {
        {bolt::tests::FilesystemRuleKind::kReadOnly, alias},
        {bolt::tests::FilesystemRuleKind::kReadOnly, target},
    };
    const std::vector<bolt::tests::FilesystemRule> denied_rules = {
        {bolt::tests::FilesystemRuleKind::kReadOnly, alias},
        {bolt::tests::FilesystemRuleKind::kDeny, target},
    };
    RaceProcess allowed;
    RaceProcess denied;
    const bool started =
        start != nullptr &&
        allowed.Start(
            executable, hook_path, allowed_rules, L"symlink-allowed", alias, {},
            start, ordinal++) &&
        denied.Start(
            executable, hook_path, denied_rules, L"symlink-denied", alias, {},
            start, ordinal++);
    const bool released =
        started && allowed.WaitAtBarrier() && denied.WaitAtBarrier() &&
        SetEvent(start) != FALSE;
    const bool exited =
        released && allowed.WaitForExit() && denied.WaitForExit();
    const bool passed =
        exited && PipeContainsViolationForPath(
                      denied.event_pipe(),
                      bolt::protocol::FilesystemOperation::kMetadata, target);
    if (start != nullptr) {
        CloseHandle(start);
    }
    if (!passed) {
        std::fprintf(
            stderr, "existing symlink failed: allowed_exit=%lu denied_exit=%lu\n",
            static_cast<unsigned long>(allowed.exit_code()),
            static_cast<unsigned long>(denied.exit_code()));
    }
    return passed;
}

bool RunJunctionSwapTest(
    const std::wstring& executable,
    const std::filesystem::path& hook_path,
    const std::filesystem::path& test_root,
    std::uint64_t& ordinal) {
    const auto allowed_target = test_root / L"swap-allowed-target";
    const auto denied_target = test_root / L"swap-denied-target";
    const auto junction = test_root / L"swap-link";
    const auto alias_file = junction / L"payload.txt";
    const auto denied_file = denied_target / L"payload.txt";
    std::error_code error;
    std::filesystem::remove_all(junction, error);
    error.clear();
    if (!std::filesystem::create_directories(allowed_target, error) || error ||
        !std::filesystem::create_directories(denied_target, error) || error ||
        !WriteFixture(allowed_target / L"payload.txt", "allowed") ||
        !WriteFixture(denied_file, "denied") ||
        !CreateJunction(junction, allowed_target)) {
        return false;
    }
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    const HANDLE start = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    const std::vector<bolt::tests::FilesystemRule> rules = {
        {bolt::tests::FilesystemRuleKind::kReadOnly, junction},
        {bolt::tests::FilesystemRuleKind::kReadOnly, allowed_target},
        {bolt::tests::FilesystemRuleKind::kDeny, denied_target},
    };
    RaceProcess process;
    const bool started =
        start != nullptr &&
        process.Start(
            executable, hook_path, rules, L"junction-swap", alias_file, {},
            start, ordinal++);
    const bool first_release =
        started && process.WaitAtBarrier() && process.ResetBarrierReady() &&
        SetEvent(start) != FALSE;
    const bool primed = first_release && process.WaitAtBarrier();
    const bool swapped =
        primed && RemoveDirectoryW(junction.c_str()) != FALSE &&
        CreateJunction(junction, denied_target);
    const bool second_release = swapped && SetEvent(start) != FALSE;
    const bool exited = second_release && process.WaitForExit();
    const bool passed =
        exited && ReadFixture(denied_file) == "denied" &&
        PipeContainsViolationForPath(
            process.event_pipe(), bolt::protocol::FilesystemOperation::kRead,
            denied_file);
    if (start != nullptr) {
        CloseHandle(start);
    }
    if (!passed) {
        std::fprintf(
            stderr, "junction swap failed: exit=%lu primed=%d swapped=%d\n",
            static_cast<unsigned long>(process.exit_code()), primed ? 1 : 0,
            swapped ? 1 : 0);
    }
    return passed;
}

bool RunReparseFailureTest(
    const std::wstring& executable,
    const std::filesystem::path& hook_path,
    const std::filesystem::path& test_root,
    std::uint64_t& ordinal) {
    const auto root = test_root / L"reparse-failures";
    const auto real_target = root / L"real-target";
    const auto loop_a = root / L"loop-a";
    const auto loop_b = root / L"loop-b";
    const auto malformed_holder = root / L"malformed-holder";
    std::error_code error;
    std::filesystem::remove_all(root, error);
    error.clear();
    if (!std::filesystem::create_directories(real_target, error) || error ||
        !std::filesystem::create_directories(loop_b, error) || error ||
        !std::filesystem::create_directories(malformed_holder, error) || error ||
        !WriteFixture(real_target / L"payload.txt", "payload") ||
        !CreateJunction(loop_a, loop_b) || !RemoveDirectoryW(loop_b.c_str()) ||
        !CreateJunction(loop_b, loop_a)) {
        return false;
    }
    std::filesystem::path next = real_target;
    for (std::size_t index = 300; index-- > 0;) {
        const auto link = root / (L"depth-" + std::to_wstring(index));
        if (!CreateJunction(link, next)) {
            return false;
        }
        next = link;
    }
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    const HANDLE start = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    const std::vector<bolt::tests::FilesystemRule> rules = {
        {bolt::tests::FilesystemRuleKind::kReadWrite, root},
    };
    RaceProcess process;
    const bool started =
        start != nullptr &&
        process.Start(
            executable, hook_path, rules, L"reparse-failures", root, {}, start,
            ordinal++);
    const bool released =
        started && process.WaitAtBarrier() && SetEvent(start) != FALSE;
    const bool exited = released && process.WaitForExit();
    const bool passed =
        exited &&
        (GetFileAttributesW(malformed_holder.c_str()) &
         FILE_ATTRIBUTE_REPARSE_POINT) == 0;
    if (start != nullptr) {
        CloseHandle(start);
    }
    if (!passed) {
        std::fprintf(
            stderr, "reparse failure test failed: exit=%lu\n",
            static_cast<unsigned long>(process.exit_code()));
    }
    return passed;
}

bool RunAsyncIoAndMappingTest(
    const std::wstring& executable,
    const std::filesystem::path& hook_path,
    const std::filesystem::path& test_root,
    std::uint64_t& ordinal) {
    const auto allowed = test_root / L"async-allowed";
    const auto denied = test_root / L"async-denied";
    const auto allowed_file = allowed / L"io.txt";
    const auto denied_file = denied / L"io.txt";
    std::error_code error;
    if (!std::filesystem::create_directories(allowed, error) || error ||
        !std::filesystem::create_directories(denied, error) || error ||
        !WriteFixture(allowed_file, "allowed-io") ||
        !WriteFixture(denied_file, "denied-io")) {
        return false;
    }
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    const HANDLE denied_handle = CreateFileW(
        denied_file.c_str(), GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, &inheritable,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, nullptr);
    const HANDLE start = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    if (denied_handle == INVALID_HANDLE_VALUE || start == nullptr) {
        if (denied_handle != INVALID_HANDLE_VALUE) {
            CloseHandle(denied_handle);
        }
        if (start != nullptr) {
            CloseHandle(start);
        }
        return false;
    }
    const std::vector<bolt::tests::FilesystemRule> rules = {
        {bolt::tests::FilesystemRuleKind::kReadOnly,
         std::filesystem::path(executable).root_path()},
        {bolt::tests::FilesystemRuleKind::kReadWrite, allowed},
        {bolt::tests::FilesystemRuleKind::kDeny, denied},
    };
    RaceProcess process;
    const bool started = process.Start(
        executable, hook_path, rules, L"async-io-mapping", test_root, {}, start,
        ordinal++, denied_handle);
    const bool released =
        started && process.WaitAtBarrier() && SetEvent(start) != FALSE;
    const bool exited = released && process.WaitForExit();
    const bool passed =
        exited && ReadFixture(allowed_file) == "allowed-io" &&
        ReadFixture(denied_file) == "denied-io";
    CloseHandle(denied_handle);
    CloseHandle(start);
    if (!passed) {
        std::fprintf(
            stderr, "async I/O and mapping failed: exit=%lu\n",
            static_cast<unsigned long>(process.exit_code()));
    }
    return passed;
}

bool RunPrivateAnonymousPipeTest(
    const std::wstring& executable,
    const std::filesystem::path& hook_path,
    std::uint64_t& ordinal) {
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    const HANDLE start = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    const std::vector<bolt::tests::FilesystemRule> rules = {
        {bolt::tests::FilesystemRuleKind::kReadOnly, executable},
        {bolt::tests::FilesystemRuleKind::kDeny, L"C:\\Device"},
    };
    RaceProcess process;
    const bool started =
        start != nullptr &&
        process.Start(
            executable, hook_path, rules, L"private-anonymous-pipe", {}, {},
            start, ordinal++);
    const bool released =
        started && process.WaitAtBarrier() && SetEvent(start) != FALSE;
    const bool exited = released && process.WaitForExit();
    const bool denied_named_pipe_reported =
        exited && PipeContainsViolationForPath(
                      process.event_pipe(),
                      bolt::protocol::FilesystemOperation::kCreate,
                      L"<private-anonymous-pipe>");
    if (start != nullptr) {
        CloseHandle(start);
    }
    if (!denied_named_pipe_reported) {
        std::fprintf(
            stderr, "private anonymous pipe failed: exit=%lu\n",
            static_cast<unsigned long>(process.exit_code()));
    }
    return denied_named_pipe_reported;
}

}  // namespace

int RunFilesystemRaceChild(
    const int argument_count,
    wchar_t** arguments) {
    if (argument_count != 8) {
        return 290;
    }
    const std::wstring_view mode(arguments[2]);
    const auto start = reinterpret_cast<HANDLE>(
        _wcstoui64(arguments[5], nullptr, 10));
    const auto ready = reinterpret_cast<HANDLE>(
        _wcstoui64(arguments[6], nullptr, 10));
    if (!SetEvent(ready) || WaitForSingleObject(start, 5'000) != WAIT_OBJECT_0) {
        return 291;
    }

    if (mode == L"allowed-write" || mode == L"denied-write") {
        const bool allowed = mode == L"allowed-write";
        for (std::size_t iteration = 0; iteration < kWriteIterations; ++iteration) {
            SetLastError(ERROR_SUCCESS);
            const HANDLE file = CreateFileW(
                arguments[3], GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            const DWORD open_error = GetLastError();
            if (!allowed) {
                if (file != INVALID_HANDLE_VALUE) {
                    LARGE_INTEGER offset{};
                    offset.QuadPart = 1;
                    DWORD written = 0;
                    const char denied_byte = 'D';
                    SetFilePointerEx(file, offset, nullptr, FILE_BEGIN);
                    WriteFile(file, &denied_byte, 1, &written, nullptr);
                    CloseHandle(file);
                    return 292;
                }
                if (open_error != ERROR_ACCESS_DENIED) {
                    return 293;
                }
                continue;
            }
            if (file == INVALID_HANDLE_VALUE) {
                return 294;
            }
            LARGE_INTEGER offset{};
            DWORD written = 0;
            const char allowed_byte = 'A';
            const bool wrote =
                SetFilePointerEx(file, offset, nullptr, FILE_BEGIN) != FALSE &&
                WriteFile(file, &allowed_byte, 1, &written, nullptr) != FALSE &&
                written == 1;
            CloseHandle(file);
            if (!wrote) {
                return 295;
            }
        }
    } else if (mode == L"allowed-rename") {
        if (!MoveFileExW(
                arguments[3], arguments[4], MOVEFILE_REPLACE_EXISTING)) {
            return 296;
        }
    } else if (mode == L"denied-delete") {
        if (DeleteFileW(arguments[3]) || GetLastError() != ERROR_ACCESS_DENIED) {
            return 297;
        }
    } else if (mode == L"denied-mixed-rename") {
        if (MoveFileExW(
                arguments[3], arguments[4], MOVEFILE_REPLACE_EXISTING) ||
            GetLastError() != ERROR_ACCESS_DENIED) {
            return 300;
        }
    } else if (mode == L"allowed-replace-rename") {
        const std::filesystem::path root(arguments[3]);
        const auto replacement = root / L"allowed-replacement.txt";
        const auto target = root / L"allowed-replace-target.txt";
        const auto renamed = root / L"allowed-replace-renamed.txt";
        if (!ReplaceFileW(
                target.c_str(), replacement.c_str(), nullptr, 0, nullptr,
                nullptr) ||
            !MoveFileW(target.c_str(), renamed.c_str())) {
            return 301;
        }
    } else if (mode == L"policy-semantics") {
        const std::filesystem::path root(arguments[3]);
        const auto allowed = root / L"semantics-allowed";
        const auto read_only = root / L"semantics-read-only";
        const auto metadata = root / L"semantics-metadata";
        const auto denied = root / L"semantics-denied";
        const auto outside = root / L"semantics-outside";
        const auto parent = root / L"semantics-parent";
        const auto child_grant = parent / L"child-grant";
        const auto nested = allowed / L"nested";
        if (!CreateDirectoryW(nested.c_str(), nullptr)) {
            return 302;
        }
        const auto created = nested / L"created.txt";
        const HANDLE created_file = CreateFileW(
            created.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        DWORD written = 0;
        const bool created_ok =
            created_file != INVALID_HANDLE_VALUE &&
            WriteFile(created_file, "created", 7, &written, nullptr) != FALSE &&
            written == 7;
        if (created_file != INVALID_HANDLE_VALUE) {
            CloseHandle(created_file);
        }
        if (!created_ok || !EnumeratesDirectory(nested) ||
            !EnumeratesDirectory(read_only)) {
            return 303;
        }
        SetLastError(ERROR_SUCCESS);
        if (EnumeratesDirectory(denied) || GetLastError() != ERROR_ACCESS_DENIED) {
            return 304;
        }
        SetLastError(ERROR_SUCCESS);
        if (EnumeratesDirectory(outside) || GetLastError() != ERROR_ACCESS_DENIED) {
            return 305;
        }
        if (ReadFixture(child_grant / L"granted.txt") != "granted") {
            return 306;
        }
        SetLastError(ERROR_SUCCESS);
        if (GetFileAttributesW(parent.c_str()) != INVALID_FILE_ATTRIBUTES ||
            GetLastError() != ERROR_ACCESS_DENIED) {
            return 307;
        }
        if (GetFileAttributesW((metadata / L"metadata.txt").c_str()) ==
            INVALID_FILE_ATTRIBUTES) {
            return 308;
        }
        SetLastError(ERROR_SUCCESS);
        const HANDLE metadata_read = CreateFileW(
            (metadata / L"metadata.txt").c_str(), GENERIC_READ,
            FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (metadata_read != INVALID_HANDLE_VALUE ||
            GetLastError() != ERROR_ACCESS_DENIED) {
            if (metadata_read != INVALID_HANDLE_VALUE) {
                CloseHandle(metadata_read);
            }
            return 309;
        }
        const HANDLE read_only_file = CreateFileW(
            (read_only / L"read-only.txt").c_str(), GENERIC_READ,
            FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (read_only_file == INVALID_HANDLE_VALUE) {
            return 310;
        }
        CloseHandle(read_only_file);
    } else if (mode == L"inherit-user-acl") {
        const std::filesystem::path root(arguments[3]);
        const auto allowed_file = root / L"allowed.txt";
        const auto denied_file = root / L"acl-denied.txt";
        const HANDLE allowed = CreateFileW(
            allowed_file.c_str(), GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (allowed == INVALID_HANDLE_VALUE) {
            return 311;
        }
        std::array<char, 7> content{};
        DWORD read = 0;
        DWORD written = 0;
        LARGE_INTEGER beginning{};
        const bool allowed_ok =
            ReadFile(allowed, content.data(), 7, &read, nullptr) != FALSE &&
            read == 7 && std::string_view(content.data(), content.size()) == "allowed" &&
            SetFilePointerEx(allowed, beginning, nullptr, FILE_BEGIN) != FALSE &&
            WriteFile(allowed, "Allowed", 7, &written, nullptr) != FALSE &&
            written == 7;
        CloseHandle(allowed);
        if (!allowed_ok) {
            return 312;
        }
        SetLastError(ERROR_SUCCESS);
        const HANDLE denied = CreateFileW(
            denied_file.c_str(), GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
            nullptr);
        const DWORD denied_error = GetLastError();
        if (denied != INVALID_HANDLE_VALUE || denied_error != ERROR_ACCESS_DENIED) {
            if (denied != INVALID_HANDLE_VALUE) {
                CloseHandle(denied);
            }
            return 313;
        }
    } else if (mode == L"path-forms") {
        const std::filesystem::path root(arguments[3]);
        const auto allowed = root / L"path-forms-allowed";
        const auto denied = root / L"path-forms-denied";
        if (!SetCurrentDirectoryW(allowed.c_str()) ||
            !CreateDirectoryW(L"nested", nullptr) ||
            !CreateDirectoryW(L"nested-trailing\\", nullptr)) {
            return 314;
        }
        const auto write_text = [](const wchar_t* path, const char* text) {
            const HANDLE file = CreateFileW(
                path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file == INVALID_HANDLE_VALUE) {
                return false;
            }
            DWORD written = 0;
            const bool wrote = WriteFile(
                                   file, text,
                                   static_cast<DWORD>(std::strlen(text)), &written,
                                   nullptr) != FALSE &&
                               written == std::strlen(text);
            CloseHandle(file);
            return wrote;
        };
        const auto can_read = [](const wchar_t* path) {
            const HANDLE file = CreateFileW(
                path, GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file == INVALID_HANDLE_VALUE) {
                return false;
            }
            CloseHandle(file);
            return true;
        };
        if (!write_text(L".\\relative.txt", "relative") ||
            !can_read(L"nested\\..\\relative.txt") ||
            !can_read(L".//nested\\..//relative.txt")) {
            return 315;
        }
        const std::wstring drive_relative =
            allowed.root_name().wstring() + L"relative.txt";
        if (!can_read(drive_relative.c_str()) ||
            !can_read(L"relative.txt... ")) {
            return 316;
        }
        const std::wstring allowed_extended = L"\\\\?\\" +
                                              (allowed / L"relative.txt").wstring();
        if (!can_read(allowed_extended.c_str())) {
            return 317;
        }
        const auto boundary_long_path = BoundaryLongPath(allowed);
        const std::wstring extended_boundary =
            L"\\\\?\\" + boundary_long_path.wstring();
        if (!can_read(boundary_long_path.c_str())) {
            return 350;
        }
        if (!can_read(extended_boundary.c_str())) {
            return 351;
        }
        const std::wstring denied_extended =
            L"\\\\?\\" + (denied / L"base.txt").wstring();
        SetLastError(ERROR_SUCCESS);
        if (can_read(denied_extended.c_str()) ||
            GetLastError() != ERROR_ACCESS_DENIED) {
            return 318;
        }
        if (!write_text(L"base.txt", "base") ||
            !write_text(L"base.txt:stream", "stream")) {
            return 319;
        }
        SetLastError(ERROR_SUCCESS);
        const HANDLE denied_stream = CreateFileW(
            (denied / L"base.txt:stream").c_str(), GENERIC_READ | GENERIC_WRITE,
            0, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (denied_stream != INVALID_HANDLE_VALUE ||
            GetLastError() != ERROR_ACCESS_DENIED) {
            if (denied_stream != INVALID_HANDLE_VALUE) {
                CloseHandle(denied_stream);
            }
            return 320;
        }
        if (!write_text(L"unicode-\u00e9.txt", "composed") ||
            !write_text(L"unicode-e\u0301.txt", "decomposed")) {
            return 321;
        }
        const HANDLE temporary = CreateFileW(
            L"delete-on-close.tmp", GENERIC_READ | GENERIC_WRITE, 0, nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
        if (temporary == INVALID_HANDLE_VALUE) {
            return 322;
        }
        CloseHandle(temporary);
        SetLastError(ERROR_SUCCESS);
        const HANDLE denied_temporary = CreateFileW(
            (denied / L"delete-on-close.tmp").c_str(),
            GENERIC_READ | GENERIC_WRITE | DELETE, 0, nullptr, CREATE_ALWAYS,
            FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
        if (denied_temporary != INVALID_HANDLE_VALUE ||
            GetLastError() != ERROR_ACCESS_DENIED) {
            if (denied_temporary != INVALID_HANDLE_VALUE) {
                CloseHandle(denied_temporary);
            }
            return 323;
        }
        const HANDLE backup_directory = CreateFileW(
            allowed.c_str(), FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (backup_directory == INVALID_HANDLE_VALUE) {
            return 324;
        }
        CloseHandle(backup_directory);
        for (const wchar_t* null_device : {L"NUL", L"\\\\.\\NUL"}) {
            SetLastError(ERROR_SUCCESS);
            const HANDLE null_handle = CreateFileW(
                null_device, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            const char discarded[] = "discarded";
            DWORD written = 0;
            std::array<char, 1> empty{};
            DWORD read = 1;
            const bool null_semantics =
                null_handle != INVALID_HANDLE_VALUE &&
                WriteFile(
                    null_handle, discarded,
                    static_cast<DWORD>(sizeof(discarded) - 1), &written,
                    nullptr) != FALSE &&
                written == sizeof(discarded) - 1 &&
                ReadFile(null_handle, empty.data(), 1, &read, nullptr) != FALSE &&
                read == 0;
            if (null_handle != INVALID_HANDLE_VALUE) {
                CloseHandle(null_handle);
            }
            if (!null_semantics) {
                return 325;
            }
        }
        for (const wchar_t* denied_device : {
                 L"CONOUT$", L"\\\\.\\pipe\\bolt-arbitrary"}) {
            SetLastError(ERROR_SUCCESS);
            const HANDLE denied_handle = CreateFileW(
                denied_device, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            const DWORD denied_error = GetLastError();
            const bool console_unavailable =
                CompareStringOrdinal(
                    denied_device, -1, L"CONOUT$", -1, TRUE) == CSTR_EQUAL &&
                denied_error == ERROR_FILE_NOT_FOUND;
            if (denied_handle != INVALID_HANDLE_VALUE ||
                (denied_error != ERROR_ACCESS_DENIED &&
                 !console_unavailable)) {
                if (denied_handle != INVALID_HANDLE_VALUE) {
                    CloseHandle(denied_handle);
                }
                return 325;
            }
        }
        const std::wstring pipe_name =
            L"\\\\.\\pipe\\bolt-arbitrary-" +
            std::to_wstring(GetCurrentProcessId());
        SetLastError(ERROR_SUCCESS);
        const HANDLE arbitrary_pipe = CreateNamedPipeW(
            pipe_name.c_str(), PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 1'024, 1'024,
            0, nullptr);
        if (arbitrary_pipe != INVALID_HANDLE_VALUE ||
            GetLastError() != ERROR_ACCESS_DENIED) {
            if (arbitrary_pipe != INVALID_HANDLE_VALUE) {
                CloseHandle(arbitrary_pipe);
            }
            return 326;
        }
        const std::wstring mailslot_name =
            L"\\\\.\\mailslot\\bolt-arbitrary-" +
            std::to_wstring(GetCurrentProcessId());
        SetLastError(ERROR_SUCCESS);
        const HANDLE arbitrary_mailslot = CreateMailslotW(
            mailslot_name.c_str(), 0, MAILSLOT_WAIT_FOREVER, nullptr);
        if (arbitrary_mailslot != INVALID_HANDLE_VALUE ||
            GetLastError() != ERROR_ACCESS_DENIED) {
            if (arbitrary_mailslot != INVALID_HANDLE_VALUE) {
                CloseHandle(arbitrary_mailslot);
            }
            return 327;
        }
    } else if (mode == L"native-device-aliases") {
        using NtCreateFileFunction = NTSTATUS(NTAPI*)(
            PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
            PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
        const auto nt_create_file = reinterpret_cast<NtCreateFileFunction>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateFile"));
        const std::filesystem::path allowed(arguments[3]);
        const std::filesystem::path denied(arguments[4]);
        const HANDLE stage_mapping = reinterpret_cast<HANDLE>(
            _wcstoui64(arguments[7], nullptr, 10));
        auto* stage = static_cast<volatile LONG*>(MapViewOfFile(
            stage_mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(LONG)));
        if (nt_create_file == nullptr || stage == nullptr) {
            return 368;
        }
        const auto open_native = [&](const std::filesystem::path& path) {
            const std::wstring value = path.wstring();
            UNICODE_STRING name{};
            name.Length = static_cast<USHORT>(value.size() * sizeof(wchar_t));
            name.MaximumLength = name.Length;
            name.Buffer = const_cast<PWSTR>(value.data());
            OBJECT_ATTRIBUTES attributes{};
            attributes.Length = sizeof(attributes);
            attributes.ObjectName = &name;
            attributes.Attributes = OBJ_CASE_INSENSITIVE;
            IO_STATUS_BLOCK io_status{};
            HANDLE file = nullptr;
            const NTSTATUS status = nt_create_file(
                &file, FILE_GENERIC_READ | SYNCHRONIZE, &attributes, &io_status,
                nullptr, FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, nullptr,
                0);
            if (file != nullptr) {
                CloseHandle(file);
            }
            return status;
        };
        InterlockedExchange(stage, 1);
        const NTSTATUS allowed_status = open_native(allowed);
        InterlockedExchange(stage, 2);
        if (allowed_status != 0) {
            UnmapViewOfFile(const_cast<LONG*>(stage));
            return 369;
        }
        InterlockedExchange(stage, 3);
        constexpr NTSTATUS status_access_denied =
            static_cast<NTSTATUS>(0xC0000022UL);
        const NTSTATUS denied_status = open_native(denied);
        InterlockedExchange(stage, 4);
        UnmapViewOfFile(const_cast<LONG*>(stage));
        if (denied_status != status_access_denied) {
            return 370;
        }
    } else if (mode == L"volume-guid-aliases") {
        const std::filesystem::path allowed(arguments[3]);
        const std::filesystem::path denied(arguments[4]);
        const HANDLE stage_mapping = reinterpret_cast<HANDLE>(
            _wcstoui64(arguments[7], nullptr, 10));
        auto* stage = static_cast<volatile LONG*>(MapViewOfFile(
            stage_mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0,
            sizeof(LONG)));
        if (stage == nullptr) {
            return 364;
        }
        InterlockedExchange(stage, 1);
        const HANDLE allowed_file = CreateFileW(
            allowed.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        InterlockedExchange(stage, 2);
        if (allowed_file == INVALID_HANDLE_VALUE) {
            UnmapViewOfFile(const_cast<LONG*>(stage));
            return 365;
        }
        CloseHandle(allowed_file);
        InterlockedExchange(stage, 3);
        SetLastError(ERROR_SUCCESS);
        const HANDLE denied_file = CreateFileW(
            denied.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        const DWORD denied_error = GetLastError();
        InterlockedExchange(stage, 4);
        UnmapViewOfFile(const_cast<LONG*>(stage));
        if (denied_file != INVALID_HANDLE_VALUE) {
            CloseHandle(denied_file);
            return 366;
        }
        if (denied_error != ERROR_ACCESS_DENIED) {
            return 367;
        }
    } else if (mode == L"unc-paths") {
        const std::filesystem::path root(arguments[3]);
        const auto allowed_file = root / L"allowed" / L"plain.txt";
        const auto denied_file = root / L"denied" / L"blocked.txt";
        const auto protected_file = root / L"denied" / L"protected.txt";
        const auto write_text = [](const wchar_t* path, const char* text) {
            const HANDLE file = CreateFileW(
                path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file == INVALID_HANDLE_VALUE) {
                return false;
            }
            DWORD written = 0;
            const bool wrote =
                WriteFile(
                    file, text, static_cast<DWORD>(std::strlen(text)), &written,
                    nullptr) != FALSE &&
                written == std::strlen(text);
            CloseHandle(file);
            return wrote;
        };
        const auto extended_unc = [](const std::filesystem::path& path) {
            const std::wstring value = path.wstring();
            return value.rfind(L"\\\\", 0) == 0
                       ? L"\\\\?\\UNC\\" + value.substr(2)
                       : std::wstring{};
        };
        const std::wstring extended_allowed = extended_unc(allowed_file);
        const std::wstring extended_denied = extended_unc(denied_file);
        if (extended_allowed.empty() || extended_denied.empty()) {
            return 352;
        }
        if (!write_text(allowed_file.c_str(), "plain")) {
            return 353;
        }
        if (!write_text(extended_allowed.c_str(), "extended")) {
            return 354;
        }
        if (ReadFixture(allowed_file) != "extended") {
            return 355;
        }
        for (const auto& denied_path :
             {denied_file.wstring(), extended_denied}) {
            SetLastError(ERROR_SUCCESS);
            const HANDLE denied = CreateFileW(
                denied_path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL, nullptr);
            const DWORD error = GetLastError();
            if (denied != INVALID_HANDLE_VALUE) {
                CloseHandle(denied);
                return 356;
            }
            if (error != ERROR_ACCESS_DENIED) {
                return 357;
            }
        }
        SetLastError(ERROR_SUCCESS);
        const HANDLE protected_handle = CreateFileW(
            protected_file.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        const DWORD protected_error = GetLastError();
        if (protected_handle != INVALID_HANDLE_VALUE) {
            CloseHandle(protected_handle);
            return 358;
        }
        if (protected_error != ERROR_ACCESS_DENIED) {
            return 359;
        }
    } else if (mode == L"case-sensitive-paths") {
        const std::filesystem::path root(arguments[3]);
        const auto allowed_file = root / L"PolicyTarget.txt";
        const auto denied_file = root / L"policytarget.txt";
        const HANDLE allowed = CreateFileW(
            allowed_file.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        if (allowed == INVALID_HANDLE_VALUE) {
            return 360;
        }
        constexpr char allowed_text[] = "Allowed";
        DWORD written = 0;
        const bool allowed_written =
            WriteFile(
                allowed, allowed_text, sizeof(allowed_text) - 1, &written,
                nullptr) != FALSE &&
            written == sizeof(allowed_text) - 1;
        CloseHandle(allowed);
        if (!allowed_written) {
            return 361;
        }
        SetLastError(ERROR_SUCCESS);
        const HANDLE denied = CreateFileW(
            denied_file.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        const DWORD denied_error = GetLastError();
        if (denied != INVALID_HANDLE_VALUE) {
            CloseHandle(denied);
            return 362;
        }
        if (denied_error != ERROR_ACCESS_DENIED) {
            return 363;
        }
    } else if (mode == L"symlink-allowed" || mode == L"symlink-denied") {
        const std::filesystem::path alias(arguments[3]);
        SetLastError(ERROR_SUCCESS);
        const DWORD attributes = GetFileAttributesW(alias.c_str());
        const DWORD error = GetLastError();
        if (mode == L"symlink-allowed") {
            if (attributes == INVALID_FILE_ATTRIBUTES ||
                (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
                return 328;
            }
        } else if (attributes != INVALID_FILE_ATTRIBUTES ||
                   error != ERROR_ACCESS_DENIED) {
            return 329;
        }
    } else if (mode == L"junction-swap") {
        const std::filesystem::path alias_file(arguments[3]);
        if (ReadFixture(alias_file) != "allowed") {
            return 330;
        }
        if (!ResetEvent(start) || !SetEvent(ready) ||
            WaitForSingleObject(start, 5'000) != WAIT_OBJECT_0) {
            return 331;
        }
        SetLastError(ERROR_SUCCESS);
        const HANDLE swapped = CreateFileW(
            alias_file.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        const DWORD swapped_error = GetLastError();
        if (swapped != INVALID_HANDLE_VALUE) {
            std::array<char, 6> content{};
            DWORD read = 0;
            ReadFile(swapped, content.data(), static_cast<DWORD>(content.size()), &read, nullptr);
            CloseHandle(swapped);
            return 332;
        }
        if (swapped_error != ERROR_ACCESS_DENIED) {
            return 333;
        }
    } else if (mode == L"reparse-failures") {
        const std::filesystem::path root(arguments[3]);
        const auto fails_closed = [](const std::filesystem::path& path) {
            SetLastError(ERROR_SUCCESS);
            const HANDLE file = CreateFileW(
                path.c_str(), GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            const DWORD error = GetLastError();
            if (file != INVALID_HANDLE_VALUE) {
                CloseHandle(file);
                return false;
            }
            return error != ERROR_SUCCESS;
        };
        if (!fails_closed(root / L"loop-a" / L"payload.txt")) {
            return 334;
        }
        if (!fails_closed(root / L"depth-0" / L"payload.txt")) {
            return 337;
        }
        const auto holder = root / L"malformed-holder";
        const HANDLE directory = CreateFileW(
            holder.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (directory == INVALID_HANDLE_VALUE) {
            return 335;
        }
        std::array<std::uint8_t, 32> unsupported{};
        *reinterpret_cast<ULONG*>(unsupported.data()) = 0xA00000FFU;
        std::array<std::uint8_t, 32> malformed{};
        *reinterpret_cast<ULONG*>(malformed.data()) = IO_REPARSE_TAG_MOUNT_POINT;
        *reinterpret_cast<USHORT*>(malformed.data() + 4) = 24;
        *reinterpret_cast<USHORT*>(malformed.data() + 8) = 30;
        *reinterpret_cast<USHORT*>(malformed.data() + 10) = 20;
        DWORD returned = 0;
        SetLastError(ERROR_SUCCESS);
        const BOOL unsupported_result = DeviceIoControl(
            directory, FSCTL_SET_REPARSE_POINT, unsupported.data(),
            static_cast<DWORD>(unsupported.size()), nullptr, 0, &returned,
            nullptr);
        const DWORD unsupported_error = GetLastError();
        SetLastError(ERROR_SUCCESS);
        const BOOL malformed_result = DeviceIoControl(
            directory, FSCTL_SET_REPARSE_POINT, malformed.data(),
            static_cast<DWORD>(malformed.size()), nullptr, 0, &returned,
            nullptr);
        const DWORD malformed_error = GetLastError();
        CloseHandle(directory);
        if (unsupported_result || unsupported_error != ERROR_ACCESS_DENIED ||
            malformed_result || malformed_error != ERROR_ACCESS_DENIED) {
            return 336;
        }
    } else if (mode == L"private-anonymous-pipe") {
        SECURITY_ATTRIBUTES pipe_security{};
        pipe_security.nLength = sizeof(pipe_security);
        pipe_security.bInheritHandle = TRUE;
        HANDLE win32_read = nullptr;
        HANDLE win32_write = nullptr;
        const char win32_payload[] = "win32-private-pipe";
        char win32_result[sizeof(win32_payload)]{};
        DWORD win32_written = 0;
        DWORD win32_read_count = 0;
        const bool win32_pipe_allowed =
            CreatePipe(
                &win32_read, &win32_write, &pipe_security, 0) != FALSE &&
            WriteFile(
                win32_write, win32_payload,
                static_cast<DWORD>(sizeof(win32_payload)), &win32_written,
                nullptr) != FALSE &&
            ReadFile(
                win32_read, win32_result,
                static_cast<DWORD>(sizeof(win32_result)), &win32_read_count,
                nullptr) != FALSE &&
            win32_written == sizeof(win32_payload) &&
            win32_read_count == sizeof(win32_payload) &&
            std::memcmp(
                win32_result, win32_payload, sizeof(win32_payload)) == 0;
        if (win32_read != nullptr) {
            CloseHandle(win32_read);
        }
        if (win32_write != nullptr) {
            CloseHandle(win32_write);
        }
        if (!win32_pipe_allowed) {
            return 353;
        }
        using NtCreateNamedPipeFileFunction = NTSTATUS(NTAPI*)(
            PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG,
            ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG,
            PLARGE_INTEGER);
        using NtOpenFileFunction = NTSTATUS(NTAPI*)(
            PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG,
            ULONG);
        using NtCreateMailslotFileFunction = NTSTATUS(NTAPI*)(
            PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG,
            ULONG, ULONG, PLARGE_INTEGER);
        const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        const auto nt_create_named_pipe_file =
            ntdll == nullptr
                ? nullptr
                : reinterpret_cast<NtCreateNamedPipeFileFunction>(
                      GetProcAddress(ntdll, "NtCreateNamedPipeFile"));
        const auto nt_open_file =
            ntdll == nullptr
                ? nullptr
                : reinterpret_cast<NtOpenFileFunction>(
                      GetProcAddress(ntdll, "NtOpenFile"));
        const auto nt_create_mailslot_file =
            ntdll == nullptr
                ? nullptr
                : reinterpret_cast<NtCreateMailslotFileFunction>(
                      GetProcAddress(ntdll, "NtCreateMailslotFile"));
        if (nt_create_named_pipe_file == nullptr || nt_open_file == nullptr ||
            nt_create_mailslot_file == nullptr) {
            return 347;
        }

        const std::wstring pipe_filesystem = L"\\Device\\NamedPipe\\";
        UNICODE_STRING pipe_filesystem_name{};
        pipe_filesystem_name.Length = static_cast<USHORT>(
            pipe_filesystem.size() * sizeof(wchar_t));
        pipe_filesystem_name.MaximumLength = pipe_filesystem_name.Length;
        pipe_filesystem_name.Buffer =
            const_cast<PWSTR>(pipe_filesystem.data());
        OBJECT_ATTRIBUTES attributes{};
        attributes.Length = sizeof(attributes);
        attributes.ObjectName = &pipe_filesystem_name;
        IO_STATUS_BLOCK io_status{};
        HANDLE pipe_root = nullptr;
        const NTSTATUS root_status = nt_open_file(
            &pipe_root, SYNCHRONIZE | GENERIC_READ, &attributes, &io_status,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_SYNCHRONOUS_IO_NONALERT);
        if (root_status < 0 || pipe_root == nullptr) {
            return 348;
        }

        UNICODE_STRING empty_name{};
        attributes.RootDirectory = pipe_root;
        attributes.ObjectName = &empty_name;
        LARGE_INTEGER timeout{};
        timeout.QuadPart = -500'000;
        HANDLE server = nullptr;
        const NTSTATUS server_status = nt_create_named_pipe_file(
            &server, SYNCHRONIZE | GENERIC_READ, &attributes, &io_status,
            FILE_SHARE_WRITE, FILE_CREATE, 0, 0, 0, 0, 1, 64 * 1024,
            64 * 1024, &timeout);
        if (server_status < 0 || server == nullptr) {
            CloseHandle(pipe_root);
            return 349;
        }

        const std::wstring forbidden_name = L"bolt-forbidden";
        UNICODE_STRING named_pipe{};
        named_pipe.Length = static_cast<USHORT>(
            forbidden_name.size() * sizeof(wchar_t));
        named_pipe.MaximumLength = named_pipe.Length;
        named_pipe.Buffer = const_cast<PWSTR>(forbidden_name.data());
        attributes.RootDirectory = pipe_root;
        attributes.ObjectName = &named_pipe;
        HANDLE forbidden = nullptr;
        constexpr NTSTATUS status_access_denied =
            static_cast<NTSTATUS>(0xC0000022UL);
        const NTSTATUS forbidden_status = nt_create_named_pipe_file(
            &forbidden, SYNCHRONIZE | GENERIC_READ, &attributes, &io_status,
            FILE_SHARE_WRITE, FILE_CREATE, 0, 0, 0, 0, 1, 4'096, 4'096,
            &timeout);
        if (forbidden_status != status_access_denied || forbidden != nullptr) {
            if (forbidden != nullptr) {
                CloseHandle(forbidden);
            }
            CloseHandle(server);
            CloseHandle(pipe_root);
            return 350;
        }
        HANDLE forbidden_mailslot = nullptr;
        const NTSTATUS forbidden_mailslot_status = nt_create_mailslot_file(
            &forbidden_mailslot, SYNCHRONIZE | GENERIC_READ, &attributes,
            &io_status, 0, 4'096, 4'096, &timeout);
        if (forbidden_mailslot_status != status_access_denied ||
            forbidden_mailslot != nullptr) {
            if (forbidden_mailslot != nullptr) {
                CloseHandle(forbidden_mailslot);
            }
            CloseHandle(server);
            CloseHandle(pipe_root);
            return 352;
        }

        attributes.RootDirectory = server;
        attributes.ObjectName = &empty_name;
        attributes.Attributes = OBJ_INHERIT;
        HANDLE client = nullptr;
        const NTSTATUS client_status = nt_open_file(
            &client,
            SYNCHRONIZE | GENERIC_WRITE | FILE_READ_ATTRIBUTES, &attributes,
            &io_status, 0,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
        HANDLE server_copy = nullptr;
        const bool server_duplicated =
            client_status >= 0 && client != nullptr &&
            DuplicateHandle(
                GetCurrentProcess(), server, GetCurrentProcess(),
                &server_copy, 0, FALSE, DUPLICATE_SAME_ACCESS) != FALSE;
        if (server_duplicated) {
            CloseHandle(server);
            server = server_copy;
        }
        const char payload[] = "private-pipe";
        DWORD written = 0;
        const HANDLE completed = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        OVERLAPPED overlapped{};
        overlapped.hEvent = completed;
        std::array<char, sizeof(payload)> received{};
        DWORD immediate_read = 0;
        const bool wrote = server_duplicated &&
            WriteFile(
                client, payload, static_cast<DWORD>(sizeof(payload)),
                &written, nullptr) != FALSE &&
            written == sizeof(payload);
        const BOOL read_started =
            wrote && completed != nullptr
                ? ReadFile(
                      server, received.data(),
                      static_cast<DWORD>(received.size()), &immediate_read,
                      &overlapped)
                : FALSE;
        const DWORD read_error = GetLastError();
        DWORD completed_read = immediate_read;
        const bool read =
            read_started != FALSE ||
            (read_error == ERROR_IO_PENDING &&
             WaitForSingleObject(completed, 5'000) == WAIT_OBJECT_0 &&
             GetOverlappedResult(
                 server, &overlapped, &completed_read, FALSE) != FALSE);
        if (completed != nullptr) {
            CloseHandle(completed);
        }
        if (client != nullptr) {
            CloseHandle(client);
        }
        CloseHandle(server);
        CloseHandle(pipe_root);
        if (!read || completed_read != sizeof(payload) ||
            std::memcmp(received.data(), payload, sizeof(payload)) != 0) {
            return 351;
        }
    } else if (mode == L"async-io-mapping") {
        const std::filesystem::path root(arguments[3]);
        const auto allowed = root / L"async-allowed";
        const auto allowed_file = allowed / L"io.txt";
        const auto denied_handle = reinterpret_cast<HANDLE>(
            _wcstoui64(arguments[7], nullptr, 10));

        const HANDLE directory = CreateFileW(
            allowed.c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
            nullptr);
        const HANDLE notification_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        std::array<std::uint8_t, 1'024> notifications{};
        OVERLAPPED notification_overlapped{};
        notification_overlapped.hEvent = notification_event;
        if (directory == INVALID_HANDLE_VALUE || notification_event == nullptr ||
            !ReadDirectoryChangesW(
                directory, notifications.data(),
                static_cast<DWORD>(notifications.size()), FALSE,
                FILE_NOTIFY_CHANGE_FILE_NAME, nullptr, &notification_overlapped,
                nullptr) ||
            !CancelIoEx(directory, &notification_overlapped) ||
            WaitForSingleObject(notification_event, 5'000) != WAIT_OBJECT_0) {
            if (directory != INVALID_HANDLE_VALUE) {
                CloseHandle(directory);
            }
            if (notification_event != nullptr) {
                CloseHandle(notification_event);
            }
            return 338;
        }
        DWORD notification_bytes = 0;
        SetLastError(ERROR_SUCCESS);
        const BOOL notification_result = GetOverlappedResult(
            directory, &notification_overlapped, &notification_bytes, FALSE);
        const DWORD notification_error = GetLastError();
        CloseHandle(notification_event);
        CloseHandle(directory);
        if (notification_result || notification_error != ERROR_OPERATION_ABORTED) {
            return 339;
        }

        const HANDLE iocp_file = CreateFileW(
            allowed_file.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, nullptr);
        const HANDLE iocp = iocp_file == INVALID_HANDLE_VALUE
                                ? nullptr
                                : CreateIoCompletionPort(iocp_file, nullptr, 0xA11U, 0);
        std::array<char, 10> iocp_buffer{};
        OVERLAPPED iocp_overlapped{};
        DWORD immediate_bytes = 0;
        const BOOL iocp_read = iocp_file == INVALID_HANDLE_VALUE
                                   ? FALSE
                                   : ReadFile(
                                         iocp_file, iocp_buffer.data(),
                                         static_cast<DWORD>(iocp_buffer.size()),
                                         &immediate_bytes, &iocp_overlapped);
        const DWORD iocp_read_error = GetLastError();
        DWORD completed_bytes = 0;
        ULONG_PTR completion_key = 0;
        LPOVERLAPPED completed_overlapped = nullptr;
        const BOOL completed =
            iocp != nullptr &&
            GetQueuedCompletionStatus(
                iocp, &completed_bytes, &completion_key, &completed_overlapped,
                5'000);
        if (iocp != nullptr) {
            CloseHandle(iocp);
        }
        if (iocp_file != INVALID_HANDLE_VALUE) {
            CloseHandle(iocp_file);
        }
        if ((!iocp_read && iocp_read_error != ERROR_IO_PENDING) || !completed ||
            completed_bytes != iocp_buffer.size() || completion_key != 0xA11U ||
            completed_overlapped != &iocp_overlapped ||
            std::string_view(iocp_buffer.data(), iocp_buffer.size()) != "allowed-io") {
            return 340;
        }

        const HANDLE denied_iocp = CreateIoCompletionPort(
            denied_handle, nullptr, 0xD31U, 0);
        std::array<char, 4> denied_buffer{};
        OVERLAPPED denied_overlapped{};
        DWORD denied_bytes = 123;
        SetLastError(ERROR_SUCCESS);
        const BOOL denied_read = ReadFile(
            denied_handle, denied_buffer.data(),
            static_cast<DWORD>(denied_buffer.size()), &denied_bytes,
            &denied_overlapped);
        const DWORD denied_error = GetLastError();
        completed_bytes = 0;
        completion_key = 0;
        completed_overlapped = nullptr;
        SetLastError(ERROR_SUCCESS);
        const BOOL denied_completion = denied_iocp != nullptr &&
            GetQueuedCompletionStatus(
                denied_iocp, &completed_bytes, &completion_key,
                &completed_overlapped, 0);
        const DWORD denied_completion_error = GetLastError();
        if (denied_iocp != nullptr) {
            CloseHandle(denied_iocp);
        }
        if (denied_read || denied_error != ERROR_ACCESS_DENIED || denied_bytes != 0 ||
            denied_completion || denied_completion_error != WAIT_TIMEOUT ||
            completed_overlapped != nullptr) {
            return 341;
        }

        const HANDLE threadpool_file = CreateFileW(
            allowed_file.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, nullptr);
        ThreadpoolIoContext threadpool_context{};
        threadpool_context.completed = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        PTP_IO threadpool_io = threadpool_file == INVALID_HANDLE_VALUE
                                   ? nullptr
                                   : CreateThreadpoolIo(
                                         threadpool_file, ThreadpoolIoCallback,
                                         &threadpool_context, nullptr);
        std::array<char, 10> threadpool_buffer{};
        OVERLAPPED threadpool_overlapped{};
        if (threadpool_io == nullptr || threadpool_context.completed == nullptr) {
            return 342;
        }
        StartThreadpoolIo(threadpool_io);
        const BOOL threadpool_read = ReadFile(
            threadpool_file, threadpool_buffer.data(),
            static_cast<DWORD>(threadpool_buffer.size()), nullptr,
            &threadpool_overlapped);
        const DWORD threadpool_error = GetLastError();
        if (!threadpool_read && threadpool_error != ERROR_IO_PENDING) {
            CancelThreadpoolIo(threadpool_io);
            CloseThreadpoolIo(threadpool_io);
            CloseHandle(threadpool_context.completed);
            CloseHandle(threadpool_file);
            return 343;
        }
        const bool threadpool_completed =
            WaitForSingleObject(threadpool_context.completed, 5'000) == WAIT_OBJECT_0;
        WaitForThreadpoolIoCallbacks(threadpool_io, FALSE);
        CloseThreadpoolIo(threadpool_io);
        CloseHandle(threadpool_context.completed);
        CloseHandle(threadpool_file);
        if (!threadpool_completed || threadpool_context.result != ERROR_SUCCESS ||
            threadpool_context.bytes !=
                static_cast<LONG>(threadpool_buffer.size()) ||
            std::string_view(threadpool_buffer.data(), threadpool_buffer.size()) !=
                "allowed-io") {
            return 344;
        }

        const HANDLE mapping_file = CreateFileW(
            allowed_file.c_str(), GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        const HANDLE copy_mapping = mapping_file == INVALID_HANDLE_VALUE
                                        ? nullptr
                                        : CreateFileMappingW(
                                              mapping_file, nullptr, PAGE_WRITECOPY,
                                              0, 0, nullptr);
        void* copy_view = copy_mapping == nullptr
                              ? nullptr
                              : MapViewOfFile(copy_mapping, FILE_MAP_COPY, 0, 0, 0);
        if (copy_view == nullptr) {
            return 345;
        }
        static_cast<char*>(copy_view)[0] = 'X';
        const bool copy_flushed = FlushViewOfFile(copy_view, 1) != FALSE;
        UnmapViewOfFile(copy_view);
        CloseHandle(copy_mapping);
        CloseHandle(mapping_file);
        if (!copy_flushed || ReadFixture(allowed_file) != "allowed-io") {
            return 346;
        }

    } else {
        return 298;
    }
    return FlushEvents() ? 0 : 299;
}

bool RunFilesystemRaceTests() {
    const std::wstring executable = CurrentExecutable();
    if (executable.empty()) {
        return false;
    }
#if defined(_WIN64)
    constexpr auto hook_name = L"bolt-sandbox-x64.dll";
#else
    constexpr auto hook_name = L"bolt-sandbox-x86.dll";
#endif
    const std::filesystem::path hook_path =
        std::filesystem::path(executable).parent_path() / hook_name;
    const std::filesystem::path test_root =
        std::filesystem::temp_directory_path() /
        (L"bolt-sandbox-race-" + std::to_wstring(GetCurrentProcessId()));
    std::error_code error;
    std::filesystem::remove_all(test_root, error);
    error.clear();
    if (!std::filesystem::create_directories(test_root, error) || error) {
        return false;
    }
    std::uint64_t ordinal = 1;
    const bool passed =
        RunWriteRace(executable, hook_path, test_root, ordinal) &&
        RunRenameDeleteRace(
            executable, hook_path, test_root, ordinal) &&
        RunMixedTreeRenameTest(
            executable, hook_path, test_root, ordinal) &&
        RunAllowedReplaceRenameTest(
            executable, hook_path, test_root, ordinal) &&
        RunPolicySemanticsTest(
            executable, hook_path, test_root, ordinal) &&
        RunInheritUserAclTest(
            executable, hook_path, test_root, ordinal) &&
        RunPathFormsTest(executable, hook_path, test_root, ordinal) &&
        RunUncPathTest(executable, hook_path, ordinal) &&
        RunCaseSensitivePathTest(executable, hook_path, ordinal) &&
        RunCaseInsensitiveCollisionRejectionTest(
            executable, hook_path, test_root, ordinal) &&
        RunVolumeGuidAliasTest(
            executable, hook_path, test_root, ordinal) &&
        RunExistingSymlinkTest(executable, hook_path, ordinal) &&
        RunJunctionSwapTest(executable, hook_path, test_root, ordinal) &&
        RunReparseFailureTest(executable, hook_path, test_root, ordinal) &&
        RunPrivateAnonymousPipeTest(executable, hook_path, ordinal) &&
        RunAsyncIoAndMappingTest(executable, hook_path, test_root, ordinal);
    std::filesystem::remove_all(test_root, error);
    if (!passed) {
        std::fprintf(stderr, "filesystem race fixture failed\n");
    }
    return passed;
}
