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

namespace {

constexpr std::size_t kWriteIterations = 32;

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

std::string ReadFixture(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    return std::string(
        std::istreambuf_iterator<char>(stream),
        std::istreambuf_iterator<char>());
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
        const std::uint64_t ordinal) {
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
            HandleText(ready_);
        const HANDLE inherited[] = {
            policy_.handle(), event_client, release_, start, ready_};
        const bolt::common::ProcessLaunchOptions options{
            executable, command_line, L"", nullptr, inherited,
            std::size(inherited), 0};
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

    bool WaitForExit() {
        if (process_.Wait(10'000) != bolt::common::ProcessStatus::kSuccess) {
            return false;
        }
        return process_.ExitCode(exit_code_) ==
                   bolt::common::ProcessStatus::kSuccess &&
               exit_code_ == 0;
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

}  // namespace

int RunFilesystemRaceChild(
    const int argument_count,
    wchar_t** arguments) {
    if (argument_count != 7) {
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
            executable, hook_path, test_root, ordinal);
    std::filesystem::remove_all(test_root, error);
    if (!passed) {
        std::fprintf(stderr, "filesystem race fixture failed\n");
    }
    return passed;
}
