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
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <shobjidl.h>

namespace {

constexpr FILEOP_FLAGS kFileOperationFlags =
    FOF_NOCONFIRMATION | FOF_NOCONFIRMMKDIR | FOF_NOERRORUI | FOF_SILENT;

enum class ShellOperation {
    kCopy,
    kMove,
    kRename,
    kDelete,
};

using FlushEventsFunction = BOOL (*)(DWORD);

struct ConcurrentCreateContext {
    HANDLE start = nullptr;
    std::wstring path;
    volatile LONG passed = 0;
};

struct ConcurrentFlushContext {
    HANDLE start = nullptr;
    FlushEventsFunction flush = nullptr;
    volatile LONG passed = 0;
};

DWORD WINAPI RunDeniedCreateThread(LPVOID parameter) {
    auto* context = static_cast<ConcurrentCreateContext*>(parameter);
    if (WaitForSingleObject(context->start, 5'000) != WAIT_OBJECT_0) {
        return 1;
    }
    SetLastError(ERROR_SUCCESS);
    const HANDLE file = CreateFileW(
        context->path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    const DWORD error = GetLastError();
    if (file != INVALID_HANDLE_VALUE) {
        CloseHandle(file);
        DeleteFileW(context->path.c_str());
    }
    InterlockedExchange(
        &context->passed,
        file == INVALID_HANDLE_VALUE && error == ERROR_ACCESS_DENIED ? 1 : 0);
    return 0;
}

DWORD WINAPI RunConcurrentFlushThread(LPVOID parameter) {
    auto* context = static_cast<ConcurrentFlushContext*>(parameter);
    if (WaitForSingleObject(context->start, 5'000) != WAIT_OBJECT_0) {
        return 1;
    }
    InterlockedExchange(
        &context->passed,
        context->flush != nullptr && context->flush(5'000) ? 1 : 0);
    return 0;
}

bool RunConcurrentReentrancyProbe(
    const std::filesystem::path& read_only_root,
    const FlushEventsFunction flush) {
    constexpr std::size_t worker_count = 16;
    if (flush == nullptr || !flush(5'000)) {
        return false;
    }
    const HANDLE start = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (start == nullptr) {
        return false;
    }

    std::array<ConcurrentCreateContext, worker_count> contexts{};
    std::array<HANDLE, worker_count + 1> threads{};
    bool created = true;
    for (std::size_t index = 0; index < worker_count; ++index) {
        contexts[index].start = start;
        contexts[index].path =
            read_only_root /
            (L"concurrent-denied-" + std::to_wstring(index) + L".txt");
        threads[index] = CreateThread(
            nullptr, 0, RunDeniedCreateThread, &contexts[index], 0, nullptr);
        created = created && threads[index] != nullptr;
    }
    ConcurrentFlushContext flush_context{start, flush, 0};
    threads[worker_count] = CreateThread(
        nullptr, 0, RunConcurrentFlushThread, &flush_context, 0, nullptr);
    created = created && threads[worker_count] != nullptr;

    const bool started = SetEvent(start) != FALSE;
    const DWORD wait = created && started
                           ? WaitForMultipleObjects(
                                 static_cast<DWORD>(threads.size()),
                                 threads.data(), TRUE, 5'000)
                           : WAIT_FAILED;
    bool passed = created && started && wait == WAIT_OBJECT_0 &&
                  flush_context.passed == 1;
    for (std::size_t index = 0; index < worker_count; ++index) {
        passed = passed && contexts[index].passed == 1 &&
                 !std::filesystem::exists(contexts[index].path);
    }
    for (const HANDLE thread : threads) {
        if (thread != nullptr) {
            CloseHandle(thread);
        }
    }
    CloseHandle(start);
    return passed && flush(5'000);
}

std::filesystem::path LongDeniedPath(
    const std::filesystem::path& read_only_root) {
    constexpr std::size_t target_code_units = 30'000;
    std::wstring path = read_only_root.wstring();
    path.push_back(L'\\');
    if (path.size() < target_code_units) {
        path.append(target_code_units - path.size(), L'x');
    }
    return path;
}

class ComApartment final {
  public:
    ComApartment() : status_(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED)) {}

    ~ComApartment() {
        if (SUCCEEDED(status_)) {
            CoUninitialize();
        }
    }

    bool initialized() const {
        return SUCCEEDED(status_);
    }

  private:
    HRESULT status_;
};

template <typename T>
class ComPtr final {
  public:
    ComPtr() = default;
    ~ComPtr() {
        if (value_ != nullptr) {
            value_->Release();
        }
    }

    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;

    T** put() {
        return &value_;
    }

    T* get() const {
        return value_;
    }

    T* operator->() const {
        return value_;
    }

  private:
    T* value_ = nullptr;
};

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

std::wstring PipeName(const DWORD process_id) {
    constexpr std::uint64_t shell_pipe_namespace = 0x5348'454C'4C00'0000;
    std::wostringstream suffix;
    suffix << std::hex << std::nouppercase << std::setfill(L'0')
           << std::setw(32)
           << (shell_pipe_namespace ^ static_cast<std::uint64_t>(process_id));
    return L"\\\\.\\pipe\\bolt-sandbox-" + suffix.str();
}

bool WriteFixture(
    const std::filesystem::path& path,
    const std::string_view content) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream.write(content.data(), static_cast<std::streamsize>(content.size()));
    return stream.good();
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

std::uint16_t ReadU16(const std::uint8_t* bytes) {
    return static_cast<std::uint16_t>(bytes[0]) |
           static_cast<std::uint16_t>(bytes[1]) << 8;
}

std::uint64_t ReadU64(const std::uint8_t* bytes) {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < 8; ++index) {
        value |= static_cast<std::uint64_t>(bytes[index]) << (index * 8);
    }
    return value;
}

struct FilesystemViolation {
    bolt::protocol::FilesystemOperation operation;
    std::wstring path;
};

bool ReadFilesystemViolations(
    const HANDLE event_pipe,
    const std::uint32_t process_id,
    std::vector<FilesystemViolation>& violations) {
    violations.clear();
    std::uint64_t expected_sequence = 1;
    for (;;) {
        std::array<std::uint8_t, bolt::protocol::kEventHeaderLength> header{};
        DWORD first_read = 0;
        const BOOL header_read = ReadFile(
            event_pipe, header.data(), static_cast<DWORD>(header.size()),
            &first_read, nullptr);
        if (!header_read) {
            const DWORD error = GetLastError();
            if (error == ERROR_BROKEN_PIPE) {
                return !violations.empty();
            }
            if (error != ERROR_MORE_DATA || first_read != header.size()) {
                std::fprintf(
                    stderr, "event header read failed: error=%lu bytes=%lu count=%zu\n",
                    static_cast<unsigned long>(error),
                    static_cast<unsigned long>(first_read), violations.size());
                return false;
            }
        }
        if (first_read == 0 || first_read > header.size() ||
            (first_read < header.size() &&
             !ReadExact(
                 event_pipe, header.data() + first_read,
                 header.size() - first_read))) {
            std::fprintf(stderr, "event header was truncated\n");
            return false;
        }

        const std::size_t payload_length = ReadU32(header.data() + 8);
        if (ReadU16(header.data() + 6) != 2 || payload_length < 9 ||
            payload_length > 9 +
                                 bolt::protocol::kMaximumEventPathCodeUnits *
                                     sizeof(wchar_t) ||
            ReadU64(header.data() + 12) != expected_sequence) {
            std::fprintf(
                stderr,
                "event header invalid: kind=%u payload=%zu sequence=%llu expected=%llu\n",
                static_cast<unsigned>(ReadU16(header.data() + 6)), payload_length,
                static_cast<unsigned long long>(ReadU64(header.data() + 12)),
                static_cast<unsigned long long>(expected_sequence));
            return false;
        }
        std::vector<std::uint8_t> frame(header.size() + payload_length);
        std::copy(header.begin(), header.end(), frame.begin());
        if (!ReadExact(
                event_pipe, frame.data() + header.size(), payload_length) ||
            ReadU32(frame.data() + 24) != process_id || frame[28] > 6) {
            std::fprintf(
                stderr, "event payload read failed: payload=%zu sequence=%llu\n",
                payload_length,
                static_cast<unsigned long long>(expected_sequence));
            return false;
        }
        const std::size_t path_length = ReadU32(frame.data() + 29);
        if (path_length == 0 ||
            33 + path_length * sizeof(wchar_t) != frame.size()) {
            std::fprintf(
                stderr, "event path invalid: length=%zu frame=%zu\n",
                path_length, frame.size());
            return false;
        }

        std::wstring path(path_length, L'\0');
        std::memcpy(
            path.data(), frame.data() + 33,
            path_length * sizeof(wchar_t));
        const auto operation =
            static_cast<bolt::protocol::FilesystemOperation>(frame[28]);
        std::vector<std::uint8_t> expected(frame.size());
        std::size_t written = 0;
        if (bolt::protocol::EncodeFilesystemViolationFrame(
                process_id, operation, path.c_str(), expected_sequence,
                expected.data(), expected.size(), written) !=
                bolt::protocol::FrameEncodeStatus::kSuccess ||
            written != expected.size() || expected != frame) {
            std::fprintf(
                stderr, "event checksum mismatch: sequence=%llu\n",
                static_cast<unsigned long long>(expected_sequence));
            return false;
        }
        violations.push_back({operation, std::move(path)});
        ++expected_sequence;
    }
}

bool ContainsViolation(
    const std::vector<FilesystemViolation>& violations,
    const bolt::protocol::FilesystemOperation operation,
    const std::filesystem::path& path) {
    return std::any_of(
        violations.begin(), violations.end(),
        [&](const FilesystemViolation& violation) {
            return violation.operation == operation &&
                   CompareStringOrdinal(
                       violation.path.c_str(), -1, path.c_str(), -1, TRUE) ==
                       CSTR_EQUAL;
        });
}

bool CreateShellItem(
    const std::filesystem::path& path,
    ComPtr<IShellItem>& item) {
    return SUCCEEDED(SHCreateItemFromParsingName(
        path.c_str(), nullptr, IID_PPV_ARGS(item.put())));
}

bool RunFileOperation(
    const ShellOperation operation,
    const std::filesystem::path& source,
    const std::filesystem::path& destination,
    const wchar_t* new_name,
    const bool should_succeed) {
    ComPtr<IFileOperation> file_operation;
    ComPtr<IShellItem> source_item;
    ComPtr<IShellItem> destination_item;
    if (FAILED(CoCreateInstance(
            CLSID_FileOperation, nullptr, CLSCTX_INPROC_SERVER,
            IID_PPV_ARGS(file_operation.put()))) ||
        FAILED(file_operation->SetOperationFlags(kFileOperationFlags)) ||
        !CreateShellItem(source, source_item)) {
        return false;
    }

    HRESULT queued = E_INVALIDARG;
    switch (operation) {
        case ShellOperation::kCopy:
            if (!CreateShellItem(destination, destination_item)) {
                return false;
            }
            queued = file_operation->CopyItem(
                source_item.get(), destination_item.get(), new_name, nullptr);
            break;
        case ShellOperation::kMove:
            if (!CreateShellItem(destination, destination_item)) {
                return false;
            }
            queued = file_operation->MoveItem(
                source_item.get(), destination_item.get(), new_name, nullptr);
            break;
        case ShellOperation::kRename:
            queued = file_operation->RenameItem(
                source_item.get(), new_name, nullptr);
            break;
        case ShellOperation::kDelete:
            queued = file_operation->DeleteItem(source_item.get(), nullptr);
            break;
    }
    if (FAILED(queued)) {
        return !should_succeed;
    }

    const HRESULT performed = file_operation->PerformOperations();
    BOOL aborted = FALSE;
    if (FAILED(file_operation->GetAnyOperationsAborted(&aborted))) {
        return false;
    }
    return should_succeed ? SUCCEEDED(performed) && aborted == FALSE
                          : FAILED(performed) || aborted != FALSE;
}

}  // namespace

int RunShellFileOperationChild(
    const int argument_count,
    wchar_t** arguments) {
    if (argument_count != 15) {
        return 240;
    }
    ComApartment apartment;
    if (!apartment.initialized()) {
        return 241;
    }

    if (!RunFileOperation(
            ShellOperation::kCopy, arguments[2], arguments[3],
            L"allowed-copy.txt", true) ||
        !RunFileOperation(
            ShellOperation::kMove, arguments[4], arguments[3],
            L"allowed-move.txt", true) ||
        !RunFileOperation(
            ShellOperation::kRename, arguments[5], {},
            L"allowed-renamed.txt", true) ||
        !RunFileOperation(
            ShellOperation::kDelete, arguments[6], {}, nullptr, true)) {
        return 242;
    }

    if (!RunFileOperation(
            ShellOperation::kCopy, arguments[7], arguments[8],
            L"denied-copy.txt", false) ||
        !RunFileOperation(
            ShellOperation::kMove, arguments[9], arguments[8],
            L"denied-move.txt", false) ||
        !RunFileOperation(
            ShellOperation::kRename, arguments[10], {},
            L"denied-renamed.txt", false) ||
        !RunFileOperation(
            ShellOperation::kDelete, arguments[11], {}, nullptr, false)) {
        return 243;
    }

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
    if (!RunConcurrentReentrancyProbe(arguments[8], flush)) {
        return 245;
    }
    const std::filesystem::path long_denied_path = LongDeniedPath(arguments[8]);
    SetLastError(ERROR_SUCCESS);
    const HANDLE long_denied_file = CreateFileW(
        long_denied_path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    const DWORD long_denied_error = GetLastError();
    if (long_denied_file != INVALID_HANDLE_VALUE) {
        CloseHandle(long_denied_file);
        DeleteFileW(long_denied_path.c_str());
    }
    if (long_denied_file != INVALID_HANDLE_VALUE ||
        long_denied_error != ERROR_ACCESS_DENIED || !flush(5'000)) {
        return 246;
    }

    const auto release = reinterpret_cast<HANDLE>(
        _wcstoui64(arguments[12], nullptr, 10));
    return SetEvent(release) ? 0 : 244;
}

bool RunShellFileOperationTests() {
    const std::wstring executable = CurrentExecutable();
    if (executable.empty()) {
        std::fprintf(stderr, "IFileOperation fixture: executable path unavailable\n");
        return false;
    }

    const std::filesystem::path test_root =
        std::filesystem::temp_directory_path() /
        (L"bolt-sandbox-shell-" + std::to_wstring(GetCurrentProcessId()));
    const std::filesystem::path allowed_root = test_root / L"allowed";
    const std::filesystem::path read_only_root = test_root / L"read-only";
    std::error_code error;
    std::filesystem::remove_all(test_root, error);
    error.clear();
    if (!std::filesystem::create_directories(allowed_root, error) || error ||
        !std::filesystem::create_directories(read_only_root, error) || error) {
        std::fprintf(stderr, "IFileOperation fixture: directory setup failed\n");
        return false;
    }

    const auto allowed_copy_source = allowed_root / L"allowed-copy-source.txt";
    const auto allowed_move_source = allowed_root / L"allowed-move-source.txt";
    const auto allowed_rename_source = allowed_root / L"allowed-rename-source.txt";
    const auto allowed_delete_source = allowed_root / L"allowed-delete-source.txt";
    const auto denied_copy_source = allowed_root / L"denied-copy-source.txt";
    const auto denied_move_source = allowed_root / L"denied-move-source.txt";
    const auto denied_rename_source = read_only_root / L"denied-rename-source.txt";
    const auto denied_delete_source = read_only_root / L"denied-delete-source.txt";

    constexpr std::string_view nonce = "shell-file-operation";
    if (!WriteFixture(allowed_copy_source, nonce) ||
        !WriteFixture(allowed_move_source, nonce) ||
        !WriteFixture(allowed_rename_source, nonce) ||
        !WriteFixture(allowed_delete_source, nonce) ||
        !WriteFixture(denied_copy_source, nonce) ||
        !WriteFixture(denied_move_source, nonce) ||
        !WriteFixture(denied_rename_source, nonce) ||
        !WriteFixture(denied_delete_source, nonce)) {
        std::fprintf(stderr, "IFileOperation fixture: file setup failed\n");
        std::filesystem::remove_all(test_root, error);
        return false;
    }

    const auto policy_payload = bolt::tests::SealPolicy({
        {bolt::tests::FilesystemRuleKind::kReadOnly,
         std::filesystem::path(executable).root_path()},
        {bolt::tests::FilesystemRuleKind::kReadWrite, test_root},
        {bolt::tests::FilesystemRuleKind::kReadOnly, read_only_root},
    }, bolt::tests::ChildProcessPolicyKind::kDeny);
    constexpr std::array<std::uint8_t, 16> nonce_bytes = {
        0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3,
        0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3,
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
        std::fprintf(stderr, "IFileOperation fixture: runtime resource setup failed\n");
        if (release != nullptr) {
            CloseHandle(release);
        }
        std::filesystem::remove_all(test_root, error);
        return false;
    }

    HANDLE event_client = CreateFileW(
        pipe_name.c_str(), FILE_WRITE_DATA, 0, &inheritable, OPEN_EXISTING, 0,
        nullptr);
    if (event_client == INVALID_HANDLE_VALUE ||
        event_pipe.Accept() != bolt::common::PipeStatus::kSuccess) {
        std::fprintf(stderr, "IFileOperation fixture: event pipe connection failed\n");
        CloseHandle(release);
        std::filesystem::remove_all(test_root, error);
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
        L"\"" + executable + L"\" --shell-file-operation-child \"" +
        allowed_copy_source.wstring() + L"\" \"" + allowed_root.wstring() +
        L"\" \"" + allowed_move_source.wstring() + L"\" \"" +
        allowed_rename_source.wstring() + L"\" \"" +
        allowed_delete_source.wstring() + L"\" \"" +
        denied_copy_source.wstring() + L"\" \"" + read_only_root.wstring() +
        L"\" \"" + denied_move_source.wstring() + L"\" \"" +
        denied_rename_source.wstring() + L"\" \"" +
        denied_delete_source.wstring() + L"\" " + HandleText(release) +
        L" unused unused";
    const HANDLE inherited[] = {policy.handle(), event_client, release};
    const bolt::common::ProcessLaunchOptions options{
        executable, command_line, L"", nullptr, inherited,
        std::size(inherited), 0};
    bolt::common::SuspendedProcess process;
    bolt::common::ExecutionJob job;
    const bool initialized =
        bolt::common::ExecutionJob::Create(job) ==
            bolt::common::JobStatus::kSuccess &&
        bolt::common::SuspendedProcess::Create(options, process) ==
            bolt::common::ProcessStatus::kSuccess &&
        process.AssignTo(job) == bolt::common::ProcessStatus::kSuccess &&
        process.InstallRuntimePayload(
            policy.handle(), policy.length(), event_client, release,
            nonce_bytes) == bolt::common::ProcessStatus::kSuccess &&
        process.Inject(hook_path.string()) ==
            bolt::common::ProcessStatus::kSuccess &&
        process.BeginHookInitialization() ==
            bolt::common::ProcessStatus::kSuccess;
    CloseHandle(event_client);

    std::array<std::uint8_t, bolt::protocol::kReadyFrameLength> ready{};
    DWORD bytes_read = 0;
    const bool ready_ok =
        initialized &&
        ReadFile(
            event_pipe.handle(), ready.data(),
            static_cast<DWORD>(ready.size()), &bytes_read, nullptr) != FALSE &&
        bytes_read == ready.size() &&
        bolt::protocol::ValidateReadyFrame(
            ready.data(), ready.size(), nonce_bytes) ==
            bolt::protocol::ReadyFrameStatus::kSuccess &&
        process.ReleaseAfterReady() == bolt::common::ProcessStatus::kSuccess &&
        process.Wait(10'000) == bolt::common::ProcessStatus::kSuccess;
    DWORD exit_code = 0;
    const bool child_ok =
        ready_ok &&
        process.ExitCode(exit_code) == bolt::common::ProcessStatus::kSuccess &&
        exit_code == 0 && WaitForSingleObject(release, 0) == WAIT_OBJECT_0;

    const auto child_process_id =
        static_cast<std::uint32_t>(GetProcessId(process.process_handle()));
    std::vector<FilesystemViolation> violations;
    const bool event_stream_ok =
        child_ok && child_process_id != 0 &&
        ReadFilesystemViolations(
            event_pipe.handle(), child_process_id, violations);
    bool events_ok =
        event_stream_ok &&
        ContainsViolation(
            violations,
            bolt::protocol::FilesystemOperation::kCreate,
            read_only_root / L"denied-copy.txt") &&
        ContainsViolation(
            violations,
            bolt::protocol::FilesystemOperation::kRename,
            read_only_root / L"denied-move.txt") &&
        ContainsViolation(
            violations,
            bolt::protocol::FilesystemOperation::kWrite,
            denied_rename_source) &&
        ContainsViolation(
            violations,
            bolt::protocol::FilesystemOperation::kDelete,
            denied_delete_source);
    for (std::size_t index = 0; index < 16; ++index) {
        events_ok = events_ok && ContainsViolation(
            violations, bolt::protocol::FilesystemOperation::kCreate,
            read_only_root /
                (L"concurrent-denied-" + std::to_wstring(index) + L".txt"));
    }
    const std::filesystem::path long_denied_path = LongDeniedPath(read_only_root);
    events_ok = events_ok && ContainsViolation(
        violations, bolt::protocol::FilesystemOperation::kCreate,
        long_denied_path);

    bool side_effects_ok =
        std::filesystem::exists(allowed_root / L"allowed-copy.txt") &&
        !std::filesystem::exists(allowed_move_source) &&
        std::filesystem::exists(allowed_root / L"allowed-move.txt") &&
        !std::filesystem::exists(allowed_rename_source) &&
        std::filesystem::exists(allowed_root / L"allowed-renamed.txt") &&
        !std::filesystem::exists(allowed_delete_source) &&
        std::filesystem::exists(denied_copy_source) &&
        !std::filesystem::exists(read_only_root / L"denied-copy.txt") &&
        std::filesystem::exists(denied_move_source) &&
        !std::filesystem::exists(read_only_root / L"denied-move.txt") &&
        std::filesystem::exists(denied_rename_source) &&
        !std::filesystem::exists(read_only_root / L"denied-renamed.txt") &&
        std::filesystem::exists(denied_delete_source);
    for (std::size_t index = 0; index < 16; ++index) {
        side_effects_ok =
            side_effects_ok &&
            !std::filesystem::exists(
                read_only_root /
                (L"concurrent-denied-" + std::to_wstring(index) + L".txt"));
    }
    side_effects_ok =
        side_effects_ok && !std::filesystem::exists(long_denied_path);

    CloseHandle(release);
    event_pipe.Close();
    std::filesystem::remove_all(test_root, error);
    if (!child_ok || !events_ok || !side_effects_ok) {
        std::fprintf(
            stderr,
            "IFileOperation fixture failed with exit code %lu, pid %lu, stream %s, frames %zu, events %s, side effects %s\n",
            static_cast<unsigned long>(exit_code),
            static_cast<unsigned long>(child_process_id),
            event_stream_ok ? "valid" : "invalid", violations.size(),
            events_ok ? "valid" : "invalid",
            side_effects_ok ? "valid" : "invalid");
        for (const auto& violation : violations) {
            std::string narrow_path;
            narrow_path.reserve(violation.path.size());
            for (const wchar_t code_unit : violation.path) {
                narrow_path.push_back(
                    code_unit <= 0x7f ? static_cast<char>(code_unit) : '?');
            }
            std::fprintf(
                stderr, "  operation=%u path=%s\n",
                static_cast<unsigned>(violation.operation),
                narrow_path.c_str());
        }
    }
    return child_ok && events_ok && side_effects_ok;
}
