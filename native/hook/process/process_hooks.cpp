#include "hook/process/process_hooks.h"
#include "hook/process/native_process_abi.h"
#include "hook/event_sink.h"
#include "common/required_mitigations.h"

#include "protocol/policy_payload.h"
#include "protocol/runtime_payload.h"
#include "protocol/version.h"

#include "DetouredFunctionTypes.h"
#include "DetouredScope.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <cwchar>
#include <limits>
#include <string>
#include <vector>

#include <detours.h>
#include <shellapi.h>

namespace bolt::process {
namespace {

enum class ChildProcessPolicy : std::uint8_t {
    kInherit = 0,
    kDeny = 1,
};

enum class ProcessArchitecture : std::uint8_t {
    kX86,
    kX64,
    kUnsupported,
};

CreateProcessW_t g_create_process_w = CreateProcessW;
CreateProcessA_t g_create_process_a = CreateProcessA;
CreateProcessAsUserW_t g_create_process_as_user_w = CreateProcessAsUserW;
CreateProcessAsUserA_t g_create_process_as_user_a = CreateProcessAsUserA;
decltype(&ShellExecuteExW) g_shell_execute_ex_w = ShellExecuteExW;
decltype(&CreateProcessWithTokenW) g_create_process_with_token_w =
    CreateProcessWithTokenW;
decltype(&CreateProcessWithLogonW) g_create_process_with_logon_w =
    CreateProcessWithLogonW;
decltype(&SetProcessMitigationPolicy) g_set_process_mitigation_policy =
    SetProcessMitigationPolicy;
decltype(&SetInformationJobObject) g_set_information_job_object =
    SetInformationJobObject;
decltype(&CreateJobObjectW) g_create_job_object_w = CreateJobObjectW;
decltype(&CreateJobObjectA) g_create_job_object_a = CreateJobObjectA;
using NtCompareObjectsFunction = NTSTATUS(NTAPI*)(HANDLE, HANDLE);
NtCompareObjectsFunction g_nt_compare_objects = nullptr;
constexpr std::size_t kMaximumTrackedJobs = 32;
std::array<HANDLE, kMaximumTrackedJobs> g_tracked_jobs{};
SRWLOCK g_tracked_jobs_lock = SRWLOCK_INIT;
native::RtlCreateUserProcessFunction g_rtl_create_user_process = nullptr;
native::NtCreateUserProcessFunction g_nt_create_user_process = nullptr;
ChildProcessPolicy g_child_process_policy = ChildProcessPolicy::kDeny;
bool g_prepared = false;
bool g_isolated_named_pipes = false;
bool g_runtime_configured = false;
protocol::RuntimePayload g_runtime_payload{};
std::string g_hook_dll_path;
std::vector<std::uint8_t> g_policy_payload;

template <typename StartupInfo, typename ExtendedStartupInfo>
class MitigatedStartupInfo final {
  public:
    bool Initialize(const StartupInfo* const source) noexcept {
        if (source == nullptr) {
            return false;
        }
        SIZE_T bytes = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
        try {
            storage_.resize(bytes);
        } catch (...) {
            return false;
        }
        extended_.StartupInfo = *source;
        extended_.StartupInfo.cb = sizeof(ExtendedStartupInfo);
        extended_.lpAttributeList =
            reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage_.data());
        mitigation_policy_ = common::kRequiredCreationMitigationPolicy;
        if (!InitializeProcThreadAttributeList(
                extended_.lpAttributeList, 1, 0, &bytes) ||
            !UpdateProcThreadAttribute(
                extended_.lpAttributeList, 0,
                PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &mitigation_policy_,
                sizeof(mitigation_policy_), nullptr, nullptr)) {
            extended_.lpAttributeList = nullptr;
            return false;
        }
        return true;
    }

    ~MitigatedStartupInfo() noexcept {
        if (extended_.lpAttributeList != nullptr) {
            DeleteProcThreadAttributeList(extended_.lpAttributeList);
        }
    }

    StartupInfo* get() noexcept { return &extended_.StartupInfo; }

  private:
    ExtendedStartupInfo extended_{};
    std::vector<std::uint8_t> storage_;
    std::uint64_t mitigation_policy_ = 0;
};

bool CreateReadOnlyPolicyMapping(HANDLE& output) noexcept {
    output = nullptr;
    if (g_policy_payload.empty() ||
        g_policy_payload.size() > (std::numeric_limits<DWORD>::max)()) {
        return false;
    }
    const HANDLE writable = CreateFileMappingW(
        INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
        static_cast<DWORD>(g_policy_payload.size()), nullptr);
    if (writable == nullptr) {
        return false;
    }
    void* const view = MapViewOfFile(
        writable, FILE_MAP_WRITE, 0, 0, g_policy_payload.size());
    if (view == nullptr) {
        CloseHandle(writable);
        return false;
    }
    std::memcpy(view, g_policy_payload.data(), g_policy_payload.size());
    UnmapViewOfFile(view);
    const BOOL duplicated = DuplicateHandle(
        GetCurrentProcess(), writable, GetCurrentProcess(), &output,
        FILE_MAP_READ, FALSE, 0);
    const DWORD error = duplicated ? ERROR_SUCCESS : GetLastError();
    CloseHandle(writable);
    if (!duplicated) {
        SetLastError(error);
        return false;
    }
    return true;
}

ProcessArchitecture QueryProcessArchitecture(const HANDLE process) noexcept {
    using IsWow64Process2Function = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
    const auto is_wow64_process_2 = reinterpret_cast<IsWow64Process2Function>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2"));
    if (is_wow64_process_2 != nullptr) {
        USHORT process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
        USHORT native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
        if (!is_wow64_process_2(process, &process_machine, &native_machine)) {
            return ProcessArchitecture::kUnsupported;
        }
        if (process_machine == IMAGE_FILE_MACHINE_I386) {
            return ProcessArchitecture::kX86;
        }
        if (process_machine == IMAGE_FILE_MACHINE_UNKNOWN &&
            native_machine == IMAGE_FILE_MACHINE_AMD64) {
            return ProcessArchitecture::kX64;
        }
        return ProcessArchitecture::kUnsupported;
    }

    BOOL target_is_wow64 = FALSE;
    if (!IsWow64Process(process, &target_is_wow64)) {
        return ProcessArchitecture::kUnsupported;
    }
    if (target_is_wow64) {
        return ProcessArchitecture::kX86;
    }
#if defined(_WIN64)
    return ProcessArchitecture::kX64;
#else
    BOOL current_is_wow64 = FALSE;
    if (!IsWow64Process(GetCurrentProcess(), &current_is_wow64)) {
        return ProcessArchitecture::kUnsupported;
    }
    return current_is_wow64 ? ProcessArchitecture::kX64
                            : ProcessArchitecture::kX86;
#endif
}

bool SelectHookDll(
    const HANDLE process,
    std::string& selected_path) noexcept {
    const ProcessArchitecture architecture = QueryProcessArchitecture(process);
    const char* const file_name =
        architecture == ProcessArchitecture::kX86
            ? "bolt-sandbox-x86.dll"
            : architecture == ProcessArchitecture::kX64
                  ? "bolt-sandbox-x64.dll"
                  : nullptr;
    if (file_name == nullptr) {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return false;
    }
    const std::size_t separator = g_hook_dll_path.find_last_of("\\/");
    if (separator == std::string::npos) {
        SetLastError(ERROR_INVALID_NAME);
        return false;
    }
    try {
        selected_path.assign(g_hook_dll_path, 0, separator + 1);
        selected_path.append(file_name);
    } catch (...) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return false;
    }
    const DWORD attributes = GetFileAttributesA(selected_path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        if (attributes != INVALID_FILE_ATTRIBUTES) {
            SetLastError(ERROR_FILE_NOT_FOUND);
        }
        return false;
    }
    return true;
}

bool RequiresArchitectureHelper(const HANDLE process) noexcept {
    const ProcessArchitecture architecture = QueryProcessArchitecture(process);
#if defined(_WIN64)
    return architecture == ProcessArchitecture::kX86;
#else
    return architecture == ProcessArchitecture::kX64;
#endif
}

bool AppendEnvironmentEntry(
    char* const environment,
    const std::size_t capacity,
    std::size_t& offset,
    const char* const name,
    const char* const value) noexcept {
    const std::size_t name_length = std::strlen(name);
    const std::size_t value_length = std::strlen(value);
    const std::size_t required = name_length + 1 + value_length + 1;
    if (offset > capacity || required > capacity - offset) {
        return false;
    }
    std::memcpy(environment + offset, name, name_length);
    offset += name_length;
    environment[offset++] = '=';
    std::memcpy(environment + offset, value, value_length);
    offset += value_length;
    environment[offset++] = '\0';
    return true;
}

bool RunArchitectureHelper(
    const DWORD target_process_id,
    const char* const hook_dll_path) noexcept {
    if (hook_dll_path == nullptr) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }
    const std::size_t hook_path_length = std::strlen(hook_dll_path);
    if (hook_path_length == 0 || hook_path_length >= 4'096) {
        SetLastError(ERROR_INVALID_NAME);
        return false;
    }
    const std::size_t payload_size =
        sizeof(DETOUR_EXE_HELPER) + 4 + hook_path_length + 1;
    std::vector<std::uint8_t> payload;
    try {
        payload.resize(payload_size);
    } catch (...) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return false;
    }
    auto* const helper =
        reinterpret_cast<PDETOUR_EXE_HELPER>(payload.data());
    helper->cb = static_cast<DWORD>(payload.size());
    helper->pid = target_process_id;
    helper->nDlls = 1;
    std::memcpy(helper->rDlls, hook_dll_path, hook_path_length + 1);

    std::array<char, MAX_PATH> windows_directory{};
    const UINT windows_directory_length = GetWindowsDirectoryA(
        windows_directory.data(), static_cast<UINT>(windows_directory.size()));
    if (windows_directory_length == 0 ||
        windows_directory_length >= windows_directory.size()) {
        return false;
    }
    std::string helper_executable;
    std::string helper_command_line;
    try {
        helper_executable.assign(windows_directory.data(), windows_directory_length);
#if defined(_WIN64)
        helper_executable.append("\\SysWOW64\\rundll32.exe");
#else
        helper_executable.append("\\Sysnative\\rundll32.exe");
#endif
        helper_command_line = "rundll32.exe \"";
        helper_command_line.append(hook_dll_path);
        helper_command_line.append("\",#1");
    } catch (...) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return false;
    }
    std::vector<char> mutable_command_line;
    try {
        mutable_command_line.assign(
            helper_command_line.begin(), helper_command_line.end());
        mutable_command_line.push_back('\0');
    } catch (...) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return false;
    }
    std::array<char, MAX_PATH * 2 + 32> helper_environment{};
    std::size_t offset = 0;
    if (!AppendEnvironmentEntry(
            helper_environment.data(), helper_environment.size(), offset,
            "SystemRoot", windows_directory.data()) ||
        !AppendEnvironmentEntry(
            helper_environment.data(), helper_environment.size(), offset,
            "WINDIR", windows_directory.data()) ||
        offset >= helper_environment.size()) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return false;
    }
    helper_environment[offset] = '\0';

    STARTUPINFOA startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!g_create_process_a(
            helper_executable.c_str(), mutable_command_line.data(), nullptr,
            nullptr, FALSE, CREATE_SUSPENDED, helper_environment.data(), nullptr,
            &startup, &process)) {
        return false;
    }
    if (!DetourCopyPayloadToProcess(
            process.hProcess, DETOUR_EXE_HELPER_GUID, payload.data(),
            static_cast<DWORD>(payload.size()))) {
        const DWORD error = GetLastError();
        TerminateProcess(process.hProcess, ERROR_PROCESS_ABORTED);
        WaitForSingleObject(process.hProcess, 5'000);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        SetLastError(error);
        return false;
    }
    bool succeeded = false;
    if (ResumeThread(process.hThread) != static_cast<DWORD>(-1)) {
        const DWORD wait = WaitForSingleObject(process.hProcess, 30'000);
        DWORD exit_code = ERROR_PROCESS_ABORTED;
        succeeded = wait == WAIT_OBJECT_0 &&
                    GetExitCodeProcess(process.hProcess, &exit_code) != FALSE &&
                    exit_code == ERROR_SUCCESS;
    }
    if (!succeeded) {
        TerminateProcess(process.hProcess, ERROR_PROCESS_ABORTED);
        WaitForSingleObject(process.hProcess, 5'000);
    }
    const DWORD error = succeeded ? ERROR_SUCCESS : ERROR_DLL_INIT_FAILED;
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    SetLastError(error);
    return succeeded;
}

HANDLE HandleFromWire(const std::uint64_t value) noexcept {
    return reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(value));
}

void ClearProcessInformation(
    const LPPROCESS_INFORMATION process_information) noexcept {
    if (process_information != nullptr) {
        std::memset(process_information, 0, sizeof(*process_information));
    }
}

BOOL DenyChildCreation(
    const LPPROCESS_INFORMATION process_information) noexcept {
    ClearProcessInformation(process_information);
    SetLastError(ERROR_ACCESS_DENIED);
    return FALSE;
}

bool DuplicateIntoProcess(
    const HANDLE process,
    const HANDLE source,
    HANDLE& remote) noexcept {
    remote = nullptr;
    return DuplicateHandle(
               GetCurrentProcess(), source, process, &remote, 0, FALSE,
               DUPLICATE_SAME_ACCESS) != FALSE;
}

bool DuplicateIntoProcessWithAccess(
    const HANDLE process,
    const HANDLE source,
    const DWORD access,
    HANDLE& remote) noexcept {
    remote = nullptr;
    return DuplicateHandle(
               GetCurrentProcess(), source, process, &remote, access, FALSE,
               0) != FALSE;
}

void AbortCreatedProcess(
    const LPPROCESS_INFORMATION process_information,
    const DWORD error) noexcept {
    if (process_information != nullptr) {
        if (process_information->hProcess != nullptr) {
            TerminateProcess(process_information->hProcess, ERROR_PROCESS_ABORTED);
            WaitForSingleObject(process_information->hProcess, 5'000);
        }
        if (process_information->hThread != nullptr) {
            CloseHandle(process_information->hThread);
        }
        if (process_information->hProcess != nullptr) {
            CloseHandle(process_information->hProcess);
        }
    }
    ClearProcessInformation(process_information);
    SetLastError(error == ERROR_SUCCESS ? ERROR_ACCESS_DENIED : error);
}

bool InstallDescendantRuntime(
    const DWORD caller_creation_flags,
    const LPPROCESS_INFORMATION process_information) noexcept {
    const HANDLE ready = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    const HANDLE release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (ready == nullptr || release == nullptr) {
        const DWORD error = GetLastError();
        if (ready != nullptr) {
            CloseHandle(ready);
        }
        if (release != nullptr) {
            CloseHandle(release);
        }
        SetLastError(error);
        return false;
    }

    HANDLE local_policy = nullptr;
    HANDLE remote_policy = nullptr;
    HANDLE remote_event = nullptr;
    HANDLE remote_ready = nullptr;
    HANDLE remote_release = nullptr;
    HANDLE remote_dns_request = nullptr;
    HANDLE remote_dns_response = nullptr;
    HANDLE remote_standard_output = nullptr;
    HANDLE remote_standard_error = nullptr;
    HANDLE remote_event_write_mutex = nullptr;
    HANDLE remote_recovery_request = nullptr;
    HANDLE remote_recovery_response = nullptr;
    HANDLE remote_recovery_mutex = nullptr;
    HANDLE remote_recovery_counter = nullptr;
    const bool dns_proxy_configured =
        g_runtime_payload.dns_request_handle != 0 &&
        g_runtime_payload.dns_response_handle != 0;
    const bool standard_streams_configured =
        g_runtime_payload.standard_output_handle != 0 &&
        g_runtime_payload.standard_error_handle != 0;
    const bool recovery_configured =
        g_runtime_payload.recovery_request_handle != 0 &&
        g_runtime_payload.recovery_response_handle != 0 &&
        g_runtime_payload.recovery_mutex_handle != 0 &&
        g_runtime_payload.recovery_counter_handle != 0;
    const bool duplicated =
        CreateReadOnlyPolicyMapping(local_policy) &&
        DuplicateIntoProcess(
            process_information->hProcess, local_policy, remote_policy) &&
        DuplicateIntoProcess(
            process_information->hProcess,
            HandleFromWire(g_runtime_payload.event_handle), remote_event) &&
        DuplicateIntoProcessWithAccess(
            process_information->hProcess, ready, EVENT_MODIFY_STATE,
            remote_ready) &&
        DuplicateIntoProcessWithAccess(
            process_information->hProcess, release, SYNCHRONIZE,
            remote_release) &&
        DuplicateIntoProcessWithAccess(
            process_information->hProcess,
            HandleFromWire(g_runtime_payload.event_write_mutex_handle),
            SYNCHRONIZE | MUTEX_MODIFY_STATE, remote_event_write_mutex) &&
        (!dns_proxy_configured ||
         (DuplicateIntoProcess(
              process_information->hProcess,
              HandleFromWire(g_runtime_payload.dns_request_handle),
              remote_dns_request) &&
          DuplicateIntoProcess(
              process_information->hProcess,
              HandleFromWire(g_runtime_payload.dns_response_handle),
              remote_dns_response))) &&
        (!standard_streams_configured ||
         (DuplicateIntoProcess(
              process_information->hProcess,
              HandleFromWire(g_runtime_payload.standard_output_handle),
              remote_standard_output) &&
          DuplicateIntoProcess(
              process_information->hProcess,
              HandleFromWire(g_runtime_payload.standard_error_handle),
              remote_standard_error))) &&
        (!recovery_configured ||
         (DuplicateIntoProcess(
              process_information->hProcess,
              HandleFromWire(g_runtime_payload.recovery_request_handle),
              remote_recovery_request) &&
          DuplicateIntoProcess(
              process_information->hProcess,
              HandleFromWire(g_runtime_payload.recovery_response_handle),
              remote_recovery_response) &&
          DuplicateIntoProcessWithAccess(
              process_information->hProcess,
              HandleFromWire(g_runtime_payload.recovery_mutex_handle),
              SYNCHRONIZE | MUTEX_MODIFY_STATE, remote_recovery_mutex) &&
          DuplicateIntoProcess(
              process_information->hProcess,
              HandleFromWire(g_runtime_payload.recovery_counter_handle),
              remote_recovery_counter)));
    const DWORD duplication_error = duplicated ? ERROR_SUCCESS : GetLastError();
    if (local_policy != nullptr) {
        CloseHandle(local_policy);
    }
    if (!duplicated) {
        hook::TryReportChildInjectionFailure(
            process_information->dwProcessId,
            protocol::ChildInjectionFailureReason::kPolicyUnavailable);
        CloseHandle(ready);
        CloseHandle(release);
        SetLastError(duplication_error);
        return false;
    }

    protocol::RuntimePayload child_payload = g_runtime_payload;
    child_payload.target_process_id = process_information->dwProcessId;
    child_payload.policy_handle = reinterpret_cast<std::uintptr_t>(remote_policy);
    child_payload.event_handle = reinterpret_cast<std::uintptr_t>(remote_event);
    child_payload.release_handle = reinterpret_cast<std::uintptr_t>(remote_release);
    child_payload.descendant_ready_handle =
        reinterpret_cast<std::uintptr_t>(remote_ready);
    child_payload.event_write_mutex_handle =
        reinterpret_cast<std::uintptr_t>(remote_event_write_mutex);
    child_payload.startup_fault = g_runtime_payload.descendant_startup_fault;
    child_payload.descendant_startup_fault =
        protocol::RuntimeStartupFault::kNone;
    child_payload.isolated_console =
        g_runtime_payload.isolated_console ||
        (caller_creation_flags & CREATE_NEW_CONSOLE) != 0;
    if (dns_proxy_configured) {
        child_payload.dns_request_handle =
            reinterpret_cast<std::uintptr_t>(remote_dns_request);
        child_payload.dns_response_handle =
            reinterpret_cast<std::uintptr_t>(remote_dns_response);
    }
    if (standard_streams_configured) {
        child_payload.standard_output_handle =
            reinterpret_cast<std::uintptr_t>(remote_standard_output);
        child_payload.standard_error_handle =
            reinterpret_cast<std::uintptr_t>(remote_standard_error);
    }
    if (recovery_configured) {
        child_payload.recovery_request_handle =
            reinterpret_cast<std::uintptr_t>(remote_recovery_request);
        child_payload.recovery_response_handle =
            reinterpret_cast<std::uintptr_t>(remote_recovery_response);
        child_payload.recovery_mutex_handle =
            reinterpret_cast<std::uintptr_t>(remote_recovery_mutex);
        child_payload.recovery_counter_handle =
            reinterpret_cast<std::uintptr_t>(remote_recovery_counter);
    }
    auto encoded = protocol::EncodeRuntimePayload(child_payload);
    if (!DetourCopyPayloadToProcess(
            process_information->hProcess, protocol::kRuntimePayloadGuid,
            encoded.data(), static_cast<DWORD>(encoded.size()))) {
        const DWORD error = GetLastError();
        CloseHandle(ready);
        CloseHandle(release);
        SetLastError(error);
        return false;
    }
    std::string selected_hook_path;
    if (!SelectHookDll(process_information->hProcess, selected_hook_path)) {
        const DWORD error = GetLastError();
        hook::TryReportChildInjectionFailure(
            process_information->dwProcessId,
            protocol::ChildInjectionFailureReason::kUnsupportedArchitecture);
        CloseHandle(ready);
        CloseHandle(release);
        SetLastError(error);
        return false;
    }
    LPCSTR dlls[] = {selected_hook_path.c_str()};
    const BOOL injected = RequiresArchitectureHelper(process_information->hProcess)
                              ? RunArchitectureHelper(
                                    process_information->dwProcessId, dlls[0])
                              : DetourUpdateProcessWithDll(
                                    process_information->hProcess, dlls, 1);
    if (!injected) {
        const DWORD error = GetLastError();
        hook::TryReportChildInjectionFailure(
            process_information->dwProcessId,
            protocol::ChildInjectionFailureReason::kInjectionFailed);
        CloseHandle(ready);
        CloseHandle(release);
        SetLastError(error);
        return false;
    }
    if (ResumeThread(process_information->hThread) == static_cast<DWORD>(-1)) {
        const DWORD error = GetLastError();
        hook::TryReportChildInjectionFailure(
            process_information->dwProcessId,
            protocol::ChildInjectionFailureReason::kInjectionFailed);
        CloseHandle(ready);
        CloseHandle(release);
        SetLastError(error);
        return false;
    }
    const HANDLE readiness_waits[] = {ready, process_information->hProcess};
    const DWORD ready_wait = WaitForMultipleObjects(
        static_cast<DWORD>(std::size(readiness_waits)), readiness_waits, FALSE,
        5'000);
    if (ready_wait != WAIT_OBJECT_0) {
        const DWORD error = ready_wait == WAIT_TIMEOUT
                                ? ERROR_TIMEOUT
                                : ready_wait == WAIT_OBJECT_0 + 1
                                      ? ERROR_DLL_INIT_FAILED
                                      : GetLastError();
        const auto reason =
            child_payload.startup_fault ==
                    protocol::RuntimeStartupFault::kMitigationFailure
                ? protocol::ChildInjectionFailureReason::kMitigationFailed
                : protocol::ChildInjectionFailureReason::kHandshakeFailed;
        hook::TryReportChildInjectionFailure(
            process_information->dwProcessId, reason);
        CloseHandle(ready);
        CloseHandle(release);
        SetLastError(error);
        return false;
    }

    if ((caller_creation_flags & CREATE_SUSPENDED) != 0 &&
        SuspendThread(process_information->hThread) == static_cast<DWORD>(-1)) {
        const DWORD error = GetLastError();
        CloseHandle(ready);
        CloseHandle(release);
        SetLastError(error);
        return false;
    }
    const BOOL released = SetEvent(release);
    const DWORD release_error = released ? ERROR_SUCCESS : GetLastError();
    CloseHandle(ready);
    CloseHandle(release);
    if (!released) {
        SetLastError(release_error);
        return false;
    }
    return true;
}

bool CompleteInheritedCreation(
    const DWORD caller_creation_flags,
    const LPPROCESS_INFORMATION process_information) noexcept {
    if (InstallDescendantRuntime(caller_creation_flags, process_information)) {
        return true;
    }
    const DWORD error = GetLastError();
    AbortCreatedProcess(process_information, error);
    return false;
}

bool DenyRequestedBreakaway(
    const DWORD creation_flags,
    const LPPROCESS_INFORMATION process_information) noexcept {
    if ((creation_flags & CREATE_BREAKAWAY_FROM_JOB) == 0) {
        return false;
    }
    hook::TryReportProcessViolation(protocol::ProcessOperation::kBreakaway);
    DenyChildCreation(process_information);
    return true;
}

bool IsDeniedBrokerName(const wchar_t* const application_name) noexcept {
    if (application_name == nullptr || *application_name == L'\0') {
        return false;
    }
    const wchar_t* name = application_name;
    for (const wchar_t* cursor = application_name; *cursor != L'\0'; ++cursor) {
        if (*cursor == L'\\' || *cursor == L'/') {
            name = cursor + 1;
        }
    }
    for (const wchar_t* denied : {
             L"schtasks.exe", L"sc.exe", L"wmic.exe", L"at.exe"}) {
        if (CompareStringOrdinal(name, -1, denied, -1, TRUE) == CSTR_EQUAL) {
            return true;
        }
    }
    return false;
}

bool IsDeniedBrokerName(const char* const application_name) noexcept {
    if (application_name == nullptr || *application_name == '\0') {
        return false;
    }
    const char* name = application_name;
    for (const char* cursor = application_name; *cursor != '\0'; ++cursor) {
        if (*cursor == '\\' || *cursor == '/') {
            name = cursor + 1;
        }
    }
    return _stricmp(name, "schtasks.exe") == 0 ||
           _stricmp(name, "sc.exe") == 0 ||
           _stricmp(name, "wmic.exe") == 0 ||
           _stricmp(name, "at.exe") == 0;
}

template <typename Character>
bool DenyRequestedDelegation(
    const Character* const application_name,
    const LPPROCESS_INFORMATION process_information) noexcept {
    if (!IsDeniedBrokerName(application_name)) {
        return false;
    }
    hook::TryReportProcessViolation(
        protocol::ProcessOperation::kExternalDelegation);
    DenyChildCreation(process_information);
    return true;
}

bool ReadMitigationFlags(
    const PVOID buffer,
    const SIZE_T length,
    DWORD& flags) noexcept {
    if (buffer == nullptr || length != sizeof(flags)) {
        return false;
    }
    SIZE_T bytes_read = 0;
    return ReadProcessMemory(
               GetCurrentProcess(), buffer, &flags, sizeof(flags),
               &bytes_read) != FALSE &&
           bytes_read == sizeof(flags);
}

bool RequestsRequiredMitigationWeakening(
    const PROCESS_MITIGATION_POLICY policy,
    const PVOID buffer,
    const SIZE_T length) noexcept {
    DWORD required_flags = 0;
    if (policy == ProcessExtensionPointDisablePolicy) {
        required_flags = 0x00000001;
    } else if (policy == ProcessImageLoadPolicy) {
        required_flags = 0x00000007;
    } else {
        return false;
    }

    DWORD requested_flags = 0;
    return ReadMitigationFlags(buffer, length, requested_flags) &&
           (requested_flags & required_flags) != required_flags;
}

BOOL WINAPI DetouredSetProcessMitigationPolicy(
    const PROCESS_MITIGATION_POLICY policy,
    const PVOID buffer,
    const SIZE_T length) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_set_process_mitigation_policy(policy, buffer, length);
    }
    if (RequestsRequiredMitigationWeakening(policy, buffer, length)) {
        hook::TryReportProcessViolation(
            protocol::ProcessOperation::kMitigationWeakening);
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return g_set_process_mitigation_policy(policy, buffer, length);
}

bool JobContainsCurrentProcess(const HANDLE job) noexcept {
    struct ProcessIdList {
        DWORD assigned_processes;
        DWORD process_count;
        std::array<ULONG_PTR, 64> process_ids;
    };
    ProcessIdList processes{};
    if (!QueryInformationJobObject(
            job, JobObjectBasicProcessIdList, &processes, sizeof(processes),
            nullptr)) {
        return GetLastError() == ERROR_MORE_DATA;
    }
    const ULONG_PTR current = GetCurrentProcessId();
    const std::size_t process_count =
        (std::min)(
            static_cast<std::size_t>(processes.process_count),
            processes.process_ids.size());
    return std::find(
               processes.process_ids.begin(),
               processes.process_ids.begin() + process_count,
               current) !=
           processes.process_ids.begin() + process_count;
}

bool PreservesRequiredJobContainment(
    const JOBOBJECTINFOCLASS information_class,
    const LPVOID information,
    const DWORD information_length) noexcept {
    if (information_class != JobObjectExtendedLimitInformation ||
        information == nullptr ||
        information_length < sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)) {
        return false;
    }
    DWORD flags = 0;
    __try {
        flags = static_cast<const JOBOBJECT_EXTENDED_LIMIT_INFORMATION*>(
                    information)
                    ->BasicLimitInformation.LimitFlags;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    constexpr DWORD breakaway = JOB_OBJECT_LIMIT_BREAKAWAY_OK |
                                JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;
    return (flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) != 0 &&
           (flags & breakaway) == 0;
}

bool JobUpdateAvoidsBreakaway(
    const JOBOBJECTINFOCLASS information_class,
    const LPVOID information,
    const DWORD information_length) noexcept {
    if (information_class != JobObjectExtendedLimitInformation ||
        information == nullptr ||
        information_length < sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)) {
        return false;
    }
    DWORD flags = 0;
    __try {
        flags = static_cast<const JOBOBJECT_EXTENDED_LIMIT_INFORMATION*>(
                    information)
                    ->BasicLimitInformation.LimitFlags;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    constexpr DWORD breakaway = JOB_OBJECT_LIMIT_BREAKAWAY_OK |
                                JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;
    return (flags & breakaway) == 0;
}

void TrackTargetOwnedJob(const HANDLE job) noexcept {
    if (job == nullptr || g_nt_compare_objects == nullptr) {
        return;
    }
    HANDLE lease = nullptr;
    if (!DuplicateHandle(
            GetCurrentProcess(), job, GetCurrentProcess(), &lease, 0, FALSE,
            DUPLICATE_SAME_ACCESS)) {
        return;
    }
    AcquireSRWLockExclusive(&g_tracked_jobs_lock);
    const auto available = std::find(
        g_tracked_jobs.begin(), g_tracked_jobs.end(), nullptr);
    if (available != g_tracked_jobs.end()) {
        *available = lease;
        lease = nullptr;
    }
    ReleaseSRWLockExclusive(&g_tracked_jobs_lock);
    if (lease != nullptr) {
        CloseHandle(lease);
    }
}

bool IsTargetOwnedJob(const HANDLE job) noexcept {
    if (job == nullptr || g_nt_compare_objects == nullptr) {
        return false;
    }
    bool found = false;
    AcquireSRWLockShared(&g_tracked_jobs_lock);
    for (const HANDLE tracked : g_tracked_jobs) {
        if (tracked != nullptr && g_nt_compare_objects(job, tracked) >= 0) {
            found = true;
            break;
        }
    }
    ReleaseSRWLockShared(&g_tracked_jobs_lock);
    return found;
}

HANDLE WINAPI DetouredCreateJobObjectW(
    const LPSECURITY_ATTRIBUTES attributes,
    const LPCWSTR name) noexcept {
    DetouredScope scope;
    const HANDLE job = g_create_job_object_w(attributes, name);
    if (!scope.Detoured_IsDisabled() && job != nullptr) {
        TrackTargetOwnedJob(job);
    }
    return job;
}

HANDLE WINAPI DetouredCreateJobObjectA(
    const LPSECURITY_ATTRIBUTES attributes,
    const LPCSTR name) noexcept {
    DetouredScope scope;
    const HANDLE job = g_create_job_object_a(attributes, name);
    if (!scope.Detoured_IsDisabled() && job != nullptr) {
        TrackTargetOwnedJob(job);
    }
    return job;
}

BOOL WINAPI DetouredSetInformationJobObject(
    const HANDLE job,
    const JOBOBJECTINFOCLASS information_class,
    const LPVOID information,
    const DWORD information_length) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_set_information_job_object(
            job, information_class, information, information_length);
    }
    const bool target_owned_update = IsTargetOwnedJob(job) &&
        JobUpdateAvoidsBreakaway(
            information_class, information, information_length);
    if (JobContainsCurrentProcess(job) && !target_owned_update &&
        !PreservesRequiredJobContainment(
            information_class, information, information_length)) {
        hook::TryReportProcessViolation(
            protocol::ProcessOperation::kMitigationWeakening);
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return g_set_information_job_object(
        job, information_class, information, information_length);
}

BOOL WINAPI DetouredCreateProcessW(
    const LPCWSTR application_name,
    const LPWSTR command_line,
    const LPSECURITY_ATTRIBUTES process_attributes,
    const LPSECURITY_ATTRIBUTES thread_attributes,
    const BOOL inherit_handles,
    const DWORD creation_flags,
    const LPVOID environment,
    const LPCWSTR current_directory,
    const LPSTARTUPINFOW startup_information,
    const LPPROCESS_INFORMATION process_information) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_create_process_w(
            application_name, command_line, process_attributes,
            thread_attributes, inherit_handles, creation_flags, environment,
            current_directory, startup_information, process_information);
    }
    if (DenyRequestedDelegation(application_name, process_information)) {
        return FALSE;
    }
    if (DenyRequestedBreakaway(creation_flags, process_information)) {
        return FALSE;
    }
    if (g_child_process_policy == ChildProcessPolicy::kDeny) {
        return DenyChildCreation(process_information);
    }
    if (process_information == nullptr || !g_runtime_configured) {
        return DenyChildCreation(process_information);
    }
    MitigatedStartupInfo<STARTUPINFOW, STARTUPINFOEXW> mitigated_startup;
    LPSTARTUPINFOW selected_startup = startup_information;
    DWORD selected_flags = creation_flags | CREATE_SUSPENDED;
    if ((creation_flags & EXTENDED_STARTUPINFO_PRESENT) == 0) {
        if (!mitigated_startup.Initialize(startup_information)) {
            return DenyChildCreation(process_information);
        }
        selected_startup = mitigated_startup.get();
        selected_flags |= EXTENDED_STARTUPINFO_PRESENT;
    }
    if (!g_create_process_w(
            application_name, command_line, process_attributes, thread_attributes,
            inherit_handles, selected_flags, environment, current_directory,
            selected_startup, process_information)) {
        return FALSE;
    }
    return CompleteInheritedCreation(creation_flags, process_information) ? TRUE : FALSE;
}

BOOL WINAPI DetouredCreateProcessA(
    const LPCSTR application_name,
    const LPSTR command_line,
    const LPSECURITY_ATTRIBUTES process_attributes,
    const LPSECURITY_ATTRIBUTES thread_attributes,
    const BOOL inherit_handles,
    const DWORD creation_flags,
    const LPVOID environment,
    const LPCSTR current_directory,
    const LPSTARTUPINFOA startup_information,
    const LPPROCESS_INFORMATION process_information) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_create_process_a(
            application_name, command_line, process_attributes,
            thread_attributes, inherit_handles, creation_flags, environment,
            current_directory, startup_information, process_information);
    }
    if (DenyRequestedDelegation(application_name, process_information)) {
        return FALSE;
    }
    if (DenyRequestedBreakaway(creation_flags, process_information)) {
        return FALSE;
    }
    if (g_child_process_policy == ChildProcessPolicy::kDeny) {
        return DenyChildCreation(process_information);
    }
    if (process_information == nullptr || !g_runtime_configured) {
        return DenyChildCreation(process_information);
    }
    MitigatedStartupInfo<STARTUPINFOA, STARTUPINFOEXA> mitigated_startup;
    LPSTARTUPINFOA selected_startup = startup_information;
    DWORD selected_flags = creation_flags | CREATE_SUSPENDED;
    if ((creation_flags & EXTENDED_STARTUPINFO_PRESENT) == 0) {
        if (!mitigated_startup.Initialize(startup_information)) {
            return DenyChildCreation(process_information);
        }
        selected_startup = mitigated_startup.get();
        selected_flags |= EXTENDED_STARTUPINFO_PRESENT;
    }
    if (!g_create_process_a(
            application_name, command_line, process_attributes, thread_attributes,
            inherit_handles, selected_flags, environment, current_directory,
            selected_startup, process_information)) {
        return FALSE;
    }
    return CompleteInheritedCreation(creation_flags, process_information) ? TRUE : FALSE;
}

void ClearNativeProcessInformation(
    native::RtlUserProcessInformation* const process_information) noexcept {
    if (process_information != nullptr) {
        std::memset(process_information, 0, sizeof(*process_information));
    }
}

void ClearNativeProcessHandles(
    const PHANDLE process_handle,
    const PHANDLE thread_handle) noexcept {
    if (process_handle != nullptr) {
        *process_handle = nullptr;
    }
    if (thread_handle != nullptr) {
        *thread_handle = nullptr;
    }
}

NTSTATUS StatusFromWin32Error(const DWORD error) noexcept {
    constexpr NTSTATUS status_unsuccessful =
        static_cast<NTSTATUS>(0xC0000001UL);
    if (error == ERROR_SUCCESS) {
        return status_unsuccessful;
    }
    constexpr ULONG ntwin32_error = 0xC0070000UL;
    return static_cast<NTSTATUS>(
        ntwin32_error | (static_cast<ULONG>(error) & 0x0000FFFFUL));
}

BOOL WINAPI DetouredCreateProcessAsUserW(
    const HANDLE token,
    const LPCWSTR application_name,
    const LPWSTR command_line,
    const LPSECURITY_ATTRIBUTES process_attributes,
    const LPSECURITY_ATTRIBUTES thread_attributes,
    const BOOL inherit_handles,
    const DWORD creation_flags,
    const LPVOID environment,
    const LPCWSTR current_directory,
    const LPSTARTUPINFOW startup_information,
    const LPPROCESS_INFORMATION process_information) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_create_process_as_user_w(
            token, application_name, command_line, process_attributes,
            thread_attributes, inherit_handles, creation_flags, environment,
            current_directory, startup_information, process_information);
    }
    if (DenyRequestedDelegation(application_name, process_information)) {
        return FALSE;
    }
    if (DenyRequestedBreakaway(creation_flags, process_information)) {
        return FALSE;
    }
    if (g_child_process_policy == ChildProcessPolicy::kDeny ||
        process_information == nullptr || !g_runtime_configured) {
        return DenyChildCreation(process_information);
    }
    if (!g_create_process_as_user_w(
            token, application_name, command_line, process_attributes,
            thread_attributes, inherit_handles,
            creation_flags | CREATE_SUSPENDED, environment, current_directory,
            startup_information, process_information)) {
        return FALSE;
    }
    return CompleteInheritedCreation(creation_flags, process_information) ? TRUE : FALSE;
}

BOOL WINAPI DetouredCreateProcessAsUserA(
    const HANDLE token,
    const LPCSTR application_name,
    const LPSTR command_line,
    const LPSECURITY_ATTRIBUTES process_attributes,
    const LPSECURITY_ATTRIBUTES thread_attributes,
    const BOOL inherit_handles,
    const DWORD creation_flags,
    const LPVOID environment,
    const LPCSTR current_directory,
    const LPSTARTUPINFOA startup_information,
    const LPPROCESS_INFORMATION process_information) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_create_process_as_user_a(
            token, application_name, command_line, process_attributes,
            thread_attributes, inherit_handles, creation_flags, environment,
            current_directory, startup_information, process_information);
    }
    if (DenyRequestedDelegation(application_name, process_information)) {
        return FALSE;
    }
    if (DenyRequestedBreakaway(creation_flags, process_information)) {
        return FALSE;
    }
    if (g_child_process_policy == ChildProcessPolicy::kDeny ||
        process_information == nullptr || !g_runtime_configured) {
        return DenyChildCreation(process_information);
    }
    if (!g_create_process_as_user_a(
            token, application_name, command_line, process_attributes,
            thread_attributes, inherit_handles,
            creation_flags | CREATE_SUSPENDED, environment, current_directory,
            startup_information, process_information)) {
        return FALSE;
    }
    return CompleteInheritedCreation(creation_flags, process_information) ? TRUE : FALSE;
}

NTSTATUS NTAPI DetouredRtlCreateUserProcess(
    const PCUNICODE_STRING nt_image_path_name,
    const ULONG extended_parameters,
    const PRTL_USER_PROCESS_PARAMETERS process_parameters,
    const PSECURITY_DESCRIPTOR process_security_descriptor,
    const PSECURITY_DESCRIPTOR thread_security_descriptor,
    const HANDLE parent_process,
    const BOOLEAN inherit_handles,
    const HANDLE debug_port,
    const HANDLE token_handle,
    native::RtlUserProcessInformation* const process_information) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_rtl_create_user_process(
            nt_image_path_name, extended_parameters, process_parameters,
            process_security_descriptor, thread_security_descriptor,
            parent_process, inherit_handles, debug_port, token_handle,
            process_information);
    }

    constexpr NTSTATUS status_access_denied =
        static_cast<NTSTATUS>(0xC0000022UL);
    if (g_child_process_policy == ChildProcessPolicy::kDeny ||
        process_information == nullptr || !g_runtime_configured) {
        ClearNativeProcessInformation(process_information);
        return status_access_denied;
    }

    const NTSTATUS create_status = g_rtl_create_user_process(
        nt_image_path_name, extended_parameters, process_parameters,
        process_security_descriptor, thread_security_descriptor, parent_process,
        inherit_handles, debug_port, token_handle, process_information);
    if (create_status < 0) {
        return create_status;
    }

    PROCESS_INFORMATION inherited_process{
        process_information->process,
        process_information->thread,
        static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(
            process_information->client_id.UniqueProcess)),
        static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(
            process_information->client_id.UniqueThread))};
    if (CompleteInheritedCreation(CREATE_SUSPENDED, &inherited_process)) {
        return create_status;
    }

    const DWORD error = GetLastError();
    ClearNativeProcessInformation(process_information);
    return StatusFromWin32Error(error);
}

NTSTATUS NTAPI DetouredNtCreateUserProcess(
    const PHANDLE process_handle,
    const PHANDLE thread_handle,
    const ACCESS_MASK process_desired_access,
    const ACCESS_MASK thread_desired_access,
    const POBJECT_ATTRIBUTES process_object_attributes,
    const POBJECT_ATTRIBUTES thread_object_attributes,
    const ULONG process_flags,
    const ULONG thread_flags,
    const PRTL_USER_PROCESS_PARAMETERS process_parameters,
    native::PsCreateInfo* const create_info,
    native::PsAttributeList* const attribute_list) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_nt_create_user_process(
            process_handle, thread_handle, process_desired_access,
            thread_desired_access, process_object_attributes,
            thread_object_attributes, process_flags, thread_flags,
            process_parameters, create_info, attribute_list);
    }

    constexpr NTSTATUS status_access_denied =
        static_cast<NTSTATUS>(0xC0000022UL);
    constexpr ULONG process_create_flags_breakaway = 0x00000001;
    if ((process_flags & process_create_flags_breakaway) != 0) {
        hook::TryReportProcessViolation(protocol::ProcessOperation::kBreakaway);
        ClearNativeProcessHandles(process_handle, thread_handle);
        return status_access_denied;
    }
    if (g_child_process_policy == ChildProcessPolicy::kDeny ||
        process_handle == nullptr || thread_handle == nullptr ||
        !g_runtime_configured) {
        ClearNativeProcessHandles(process_handle, thread_handle);
        return status_access_denied;
    }

    constexpr ULONG thread_create_flags_create_suspended = 0x00000001;
    const NTSTATUS create_status = g_nt_create_user_process(
        process_handle, thread_handle, process_desired_access,
        thread_desired_access, process_object_attributes,
        thread_object_attributes, process_flags,
        thread_flags | thread_create_flags_create_suspended,
        process_parameters, create_info, attribute_list);
    if (create_status < 0) {
        return create_status;
    }

    const DWORD process_id = GetProcessId(*process_handle);
    const DWORD thread_id = GetThreadId(*thread_handle);
    PROCESS_INFORMATION inherited_process{
        *process_handle, *thread_handle, process_id, thread_id};
    constexpr ULONG process_create_flags_create_suspended = 0x00000200;
    const DWORD caller_creation_flags =
        ((thread_flags & thread_create_flags_create_suspended) != 0 ||
         (process_flags & process_create_flags_create_suspended) != 0)
            ? CREATE_SUSPENDED
            : 0;
    if (process_id != 0 && thread_id != 0 &&
        CompleteInheritedCreation(caller_creation_flags, &inherited_process)) {
        return create_status;
    }

    const DWORD error = GetLastError();
    if (inherited_process.hProcess != nullptr ||
        inherited_process.hThread != nullptr) {
        AbortCreatedProcess(&inherited_process, error);
    }
    ClearNativeProcessHandles(process_handle, thread_handle);
    return StatusFromWin32Error(error);
}

BOOL WINAPI DetouredCreateProcessWithTokenW(
    const HANDLE token,
    const DWORD logon_flags,
    const LPCWSTR application_name,
    const LPWSTR command_line,
    const DWORD creation_flags,
    const LPVOID environment,
    const LPCWSTR current_directory,
    const LPSTARTUPINFOW startup_information,
    const LPPROCESS_INFORMATION process_information) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_create_process_with_token_w(
            token, logon_flags, application_name, command_line, creation_flags,
            environment, current_directory, startup_information,
            process_information);
    }
    if (DenyRequestedBreakaway(creation_flags, process_information)) {
        return FALSE;
    }
    hook::TryReportProcessViolation(
        protocol::ProcessOperation::kCreateWithToken);
    return DenyChildCreation(process_information);
}

BOOL WINAPI DetouredCreateProcessWithLogonW(
    const LPCWSTR username,
    const LPCWSTR domain,
    const LPCWSTR password,
    const DWORD logon_flags,
    const LPCWSTR application_name,
    const LPWSTR command_line,
    const DWORD creation_flags,
    const LPVOID environment,
    const LPCWSTR current_directory,
    const LPSTARTUPINFOW startup_information,
    const LPPROCESS_INFORMATION process_information) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_create_process_with_logon_w(
            username, domain, password, logon_flags, application_name,
            command_line, creation_flags, environment, current_directory,
            startup_information, process_information);
    }
    if (DenyRequestedBreakaway(creation_flags, process_information)) {
        return FALSE;
    }
    hook::TryReportProcessViolation(
        protocol::ProcessOperation::kCreateWithLogon);
    return DenyChildCreation(process_information);
}

bool IsElevationVerb(const LPCWSTR verb) noexcept {
    return verb != nullptr &&
           CompareStringOrdinal(verb, -1, L"runas", -1, TRUE) == CSTR_EQUAL;
}

bool IsDirectExecutableImage(const wchar_t* const path) noexcept {
    if (path == nullptr || *path == L'\0') {
        return false;
    }
    const wchar_t* const extension = std::wcsrchr(path, L'.');
    return extension != nullptr &&
           (CompareStringOrdinal(
                extension, -1, L".exe", -1, TRUE) == CSTR_EQUAL ||
            CompareStringOrdinal(
                extension, -1, L".com", -1, TRUE) == CSTR_EQUAL);
}

bool IsOpenVerb(const wchar_t* const verb) noexcept {
    return verb == nullptr || *verb == L'\0' ||
           CompareStringOrdinal(verb, -1, L"open", -1, TRUE) == CSTR_EQUAL;
}

BOOL LaunchDirectExecutable(
    SHELLEXECUTEINFOW* const execute_information) noexcept {
    try {
        std::wstring command_line = L"\"";
        command_line.append(execute_information->lpFile);
        command_line.push_back(L'\"');
        if (execute_information->lpParameters != nullptr &&
            *execute_information->lpParameters != L'\0') {
            command_line.push_back(L' ');
            command_line.append(execute_information->lpParameters);
        }

        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        startup.dwFlags = STARTF_USESHOWWINDOW;
        startup.wShowWindow = static_cast<WORD>(execute_information->nShow);
        PROCESS_INFORMATION process{};
        if (!DetouredCreateProcessW(
                execute_information->lpFile, command_line.data(), nullptr,
                nullptr, FALSE, 0, nullptr, execute_information->lpDirectory,
                &startup, &process)) {
            execute_information->hProcess = nullptr;
            return FALSE;
        }
        CloseHandle(process.hThread);
        if ((execute_information->fMask & SEE_MASK_NOCLOSEPROCESS) != 0) {
            execute_information->hProcess = process.hProcess;
        } else {
            CloseHandle(process.hProcess);
            execute_information->hProcess = nullptr;
        }
        execute_information->hInstApp = reinterpret_cast<HINSTANCE>(33);
        return TRUE;
    } catch (...) {
        execute_information->hProcess = nullptr;
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
}

BOOL WINAPI DetouredShellExecuteExW(
    SHELLEXECUTEINFOW* const execute_information) noexcept {
    if (execute_information != nullptr &&
        execute_information->cbSize >= sizeof(SHELLEXECUTEINFOW) &&
        IsElevationVerb(execute_information->lpVerb)) {
        hook::TryReportProcessViolation(
            protocol::ProcessOperation::kElevation);
        execute_information->hProcess = nullptr;
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    if (execute_information == nullptr ||
        execute_information->cbSize < sizeof(SHELLEXECUTEINFOW)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!IsDirectExecutableImage(execute_information->lpFile) ||
        !IsOpenVerb(execute_information->lpVerb) ||
        execute_information->lpIDList != nullptr ||
        execute_information->lpClass != nullptr ||
        execute_information->hkeyClass != nullptr) {
        hook::TryReportProcessViolation(
            protocol::ProcessOperation::kExternalDelegation);
        execute_information->hProcess = nullptr;
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return LaunchDirectExecutable(execute_information);
}

}  // namespace

bool ConfigureProcessRuntime(
    const protocol::RuntimePayload& payload,
    const char* const hook_dll_path) noexcept {
    if (g_runtime_configured || hook_dll_path == nullptr || hook_dll_path[0] == '\0') {
        return false;
    }
    try {
        g_hook_dll_path.assign(hook_dll_path);
    } catch (...) {
        return false;
    }
    const DWORD attributes = GetFileAttributesA(g_hook_dll_path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        g_hook_dll_path.clear();
        return false;
    }
    g_runtime_payload = payload;
    g_runtime_configured = true;
    return true;
}

bool AllowsIsolatedConsole() noexcept {
    return g_runtime_configured && g_runtime_payload.isolated_console;
}

bool AllowsIsolatedNamedPipes() noexcept {
    return g_prepared && g_isolated_named_pipes;
}

bool RewriteIsolatedNamedPipePath(
    const wchar_t* const path,
    std::wstring& rewritten) noexcept {
    rewritten.clear();
    if (!AllowsIsolatedNamedPipes() || !g_runtime_configured || path == nullptr) {
        return false;
    }
    constexpr wchar_t local_prefix[] = L"\\\\.\\pipe\\";
    constexpr wchar_t extended_prefix[] = L"\\\\?\\pipe\\";
    const wchar_t* relative = nullptr;
    if (_wcsnicmp(path, local_prefix, std::size(local_prefix) - 1) == 0) {
        relative = path + std::size(local_prefix) - 1;
    } else if (_wcsnicmp(
                   path, extended_prefix,
                   std::size(extended_prefix) - 1) == 0) {
        relative = path + std::size(extended_prefix) - 1;
    } else {
        return false;
    }
    const std::size_t relative_length = std::wcslen(relative);
    if (relative_length == 0 || relative_length > 160) {
        return false;
    }
    try {
        rewritten.assign(local_prefix);
        rewritten.append(L"bolt-isolated-");
        constexpr wchar_t hex[] = L"0123456789abcdef";
        for (const std::uint8_t byte : g_runtime_payload.handshake_nonce) {
            rewritten.push_back(hex[byte >> 4U]);
            rewritten.push_back(hex[byte & 0x0fU]);
        }
        rewritten.push_back(L'-');
        for (std::size_t index = 0; index < relative_length; ++index) {
            const wchar_t value = relative[index];
            rewritten.push_back(value == L'\\' || value == L'/' ? L'-' : value);
        }
        return true;
    } catch (...) {
        rewritten.clear();
        return false;
    }
}

ProcessHookPrepareStatus PrepareProcessHooks(
    const std::uint8_t* policy_payload,
    const std::size_t policy_length) noexcept {
    if (g_prepared) {
        return ProcessHookPrepareStatus::kAlreadyPrepared;
    }
    if (protocol::ValidatePolicyPayload(policy_payload, policy_length) !=
            protocol::PolicyPayloadStatus::kValid ||
        policy_length <= protocol::kPolicyEnvelopeLength) {
        return ProcessHookPrepareStatus::kInvalidPolicy;
    }
    const std::uint8_t encoded_policy =
        policy_payload[protocol::kPolicyEnvelopeLength];
    if (encoded_policy > 3) {
        return ProcessHookPrepareStatus::kInvalidPolicy;
    }
    g_isolated_named_pipes = (encoded_policy & 2U) != 0;
    g_child_process_policy =
        static_cast<ChildProcessPolicy>(encoded_policy & 1U);
    try {
        g_policy_payload.assign(policy_payload, policy_payload + policy_length);
    } catch (...) {
        return ProcessHookPrepareStatus::kInvalidPolicy;
    }
    g_prepared = true;
    return ProcessHookPrepareStatus::kSuccess;
}

LONG AttachProcessHooks() noexcept {
    if (!g_prepared) {
        return ERROR_INVALID_STATE;
    }
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) {
        return ERROR_MOD_NOT_FOUND;
    }
    g_rtl_create_user_process =
        reinterpret_cast<native::RtlCreateUserProcessFunction>(
            GetProcAddress(ntdll, "RtlCreateUserProcess"));
    g_nt_create_user_process =
        reinterpret_cast<native::NtCreateUserProcessFunction>(
            GetProcAddress(ntdll, "NtCreateUserProcess"));
    g_nt_compare_objects = reinterpret_cast<NtCompareObjectsFunction>(
        GetProcAddress(ntdll, "NtCompareObjects"));
    if (g_rtl_create_user_process == nullptr ||
        g_nt_create_user_process == nullptr || g_nt_compare_objects == nullptr) {
        return ERROR_PROC_NOT_FOUND;
    }
    const LONG wide_status = DetourAttach(
        reinterpret_cast<PVOID*>(&g_create_process_w),
        reinterpret_cast<PVOID>(DetouredCreateProcessW));
    if (wide_status != NO_ERROR) {
        return wide_status;
    }
    const LONG ansi_status = DetourAttach(
        reinterpret_cast<PVOID*>(&g_create_process_a),
        reinterpret_cast<PVOID>(DetouredCreateProcessA));
    if (ansi_status != NO_ERROR) {
        return ansi_status;
    }
    const LONG as_user_wide_status = DetourAttach(
        reinterpret_cast<PVOID*>(&g_create_process_as_user_w),
        reinterpret_cast<PVOID>(DetouredCreateProcessAsUserW));
    if (as_user_wide_status != NO_ERROR) {
        return as_user_wide_status;
    }
    const LONG as_user_ansi_status = DetourAttach(
        reinterpret_cast<PVOID*>(&g_create_process_as_user_a),
        reinterpret_cast<PVOID>(DetouredCreateProcessAsUserA));
    if (as_user_ansi_status != NO_ERROR) {
        return as_user_ansi_status;
    }
    const LONG rtl_status = DetourAttach(
        reinterpret_cast<PVOID*>(&g_rtl_create_user_process),
        reinterpret_cast<PVOID>(DetouredRtlCreateUserProcess));
    if (rtl_status != NO_ERROR) {
        return rtl_status;
    }
    const LONG nt_status = DetourAttach(
        reinterpret_cast<PVOID*>(&g_nt_create_user_process),
        reinterpret_cast<PVOID>(DetouredNtCreateUserProcess));
    if (nt_status != NO_ERROR) {
        return nt_status;
    }
    const LONG shell_status = DetourAttach(
        reinterpret_cast<PVOID*>(&g_shell_execute_ex_w),
        reinterpret_cast<PVOID>(DetouredShellExecuteExW));
    if (shell_status != NO_ERROR) {
        return shell_status;
    }
    const LONG token_status = DetourAttach(
        reinterpret_cast<PVOID*>(&g_create_process_with_token_w),
        reinterpret_cast<PVOID>(DetouredCreateProcessWithTokenW));
    if (token_status != NO_ERROR) {
        return token_status;
    }
    const LONG logon_status = DetourAttach(
        reinterpret_cast<PVOID*>(&g_create_process_with_logon_w),
        reinterpret_cast<PVOID>(DetouredCreateProcessWithLogonW));
    if (logon_status != NO_ERROR) {
        return logon_status;
    }
    const LONG mitigation_status = DetourAttach(
        reinterpret_cast<PVOID*>(&g_set_process_mitigation_policy),
        reinterpret_cast<PVOID>(DetouredSetProcessMitigationPolicy));
    if (mitigation_status != NO_ERROR) {
        return mitigation_status;
    }
    const LONG create_job_wide_status = DetourAttach(
        reinterpret_cast<PVOID*>(&g_create_job_object_w),
        reinterpret_cast<PVOID>(DetouredCreateJobObjectW));
    if (create_job_wide_status != NO_ERROR) {
        return create_job_wide_status;
    }
    const LONG create_job_ansi_status = DetourAttach(
        reinterpret_cast<PVOID*>(&g_create_job_object_a),
        reinterpret_cast<PVOID>(DetouredCreateJobObjectA));
    if (create_job_ansi_status != NO_ERROR) {
        return create_job_ansi_status;
    }
    return DetourAttach(
        reinterpret_cast<PVOID*>(&g_set_information_job_object),
        reinterpret_cast<PVOID>(DetouredSetInformationJobObject));
}

}  // namespace bolt::process
