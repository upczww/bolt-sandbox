#include "hook/process/process_hooks.h"
#include "hook/process/native_process_abi.h"
#include "hook/event_sink.h"

#include "protocol/policy_payload.h"
#include "protocol/runtime_payload.h"
#include "protocol/version.h"

#include "DetouredFunctionTypes.h"
#include "DetouredScope.h"

#include <array>
#include <cstring>
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
native::RtlCreateUserProcessFunction g_rtl_create_user_process = nullptr;
ChildProcessPolicy g_child_process_policy = ChildProcessPolicy::kDeny;
bool g_prepared = false;
bool g_runtime_configured = false;
protocol::RuntimePayload g_runtime_payload{};
std::string g_hook_dll_path;

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

    HANDLE remote_policy = nullptr;
    HANDLE remote_event = nullptr;
    HANDLE remote_ready = nullptr;
    HANDLE remote_release = nullptr;
    const bool duplicated =
        DuplicateIntoProcess(
            process_information->hProcess,
            HandleFromWire(g_runtime_payload.policy_handle), remote_policy) &&
        DuplicateIntoProcess(
            process_information->hProcess,
            HandleFromWire(g_runtime_payload.event_handle), remote_event) &&
        DuplicateIntoProcess(process_information->hProcess, ready, remote_ready) &&
        DuplicateIntoProcess(process_information->hProcess, release, remote_release);
    if (!duplicated) {
        const DWORD error = GetLastError();
        CloseHandle(ready);
        CloseHandle(release);
        SetLastError(error);
        return false;
    }

    protocol::RuntimePayload child_payload = g_runtime_payload;
    child_payload.target_process_id = process_information->dwProcessId;
    child_payload.policy_handle = reinterpret_cast<std::uintptr_t>(remote_policy);
    child_payload.event_handle = reinterpret_cast<std::uintptr_t>(remote_event);
    child_payload.release_handle = reinterpret_cast<std::uintptr_t>(remote_release);
    child_payload.descendant_ready_handle =
        reinterpret_cast<std::uintptr_t>(remote_ready);
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
        CloseHandle(ready);
        CloseHandle(release);
        SetLastError(error);
        return false;
    }
    if (ResumeThread(process_information->hThread) == static_cast<DWORD>(-1)) {
        const DWORD error = GetLastError();
        CloseHandle(ready);
        CloseHandle(release);
        SetLastError(error);
        return false;
    }
    const DWORD ready_wait = WaitForSingleObject(ready, 30'000);
    if (ready_wait != WAIT_OBJECT_0) {
        const DWORD error =
            ready_wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
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
    if (g_child_process_policy == ChildProcessPolicy::kDeny) {
        return DenyChildCreation(process_information);
    }
    if (process_information == nullptr || !g_runtime_configured) {
        return DenyChildCreation(process_information);
    }
    if (!g_create_process_w(
            application_name, command_line, process_attributes, thread_attributes,
            inherit_handles, creation_flags | CREATE_SUSPENDED, environment,
            current_directory, startup_information, process_information)) {
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
    if (g_child_process_policy == ChildProcessPolicy::kDeny) {
        return DenyChildCreation(process_information);
    }
    if (process_information == nullptr || !g_runtime_configured) {
        return DenyChildCreation(process_information);
    }
    if (!g_create_process_a(
            application_name, command_line, process_attributes, thread_attributes,
            inherit_handles, creation_flags | CREATE_SUSPENDED, environment,
            current_directory, startup_information, process_information)) {
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
    if (g_child_process_policy == ChildProcessPolicy::kDeny ||
        process_information == nullptr || !g_runtime_configured) {
        return DenyChildCreation(process_information);
    }
    if (!g_create_process_as_user_w(
            token, application_name, command_line, process_attributes,
            thread_attributes, inherit_handles, creation_flags | CREATE_SUSPENDED,
            environment, current_directory, startup_information,
            process_information)) {
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
    if (g_child_process_policy == ChildProcessPolicy::kDeny ||
        process_information == nullptr || !g_runtime_configured) {
        return DenyChildCreation(process_information);
    }
    if (!g_create_process_as_user_a(
            token, application_name, command_line, process_attributes,
            thread_attributes, inherit_handles, creation_flags | CREATE_SUSPENDED,
            environment, current_directory, startup_information,
            process_information)) {
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
    hook::TryReportProcessViolation(
        protocol::ProcessOperation::kCreateWithLogon);
    return DenyChildCreation(process_information);
}

bool IsElevationVerb(const LPCWSTR verb) noexcept {
    return verb != nullptr &&
           CompareStringOrdinal(verb, -1, L"runas", -1, TRUE) == CSTR_EQUAL;
}

BOOL WINAPI DetouredShellExecuteExW(
    SHELLEXECUTEINFOW* const execute_information) noexcept {
    {
        DetouredScope scope;
        if (scope.Detoured_IsDisabled()) {
            return g_shell_execute_ex_w(execute_information);
        }
        if (execute_information != nullptr &&
            execute_information->cbSize >= sizeof(SHELLEXECUTEINFOW) &&
            IsElevationVerb(execute_information->lpVerb)) {
            hook::TryReportProcessViolation(
                protocol::ProcessOperation::kElevation);
            execute_information->hProcess = nullptr;
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
    }
    return g_shell_execute_ex_w(execute_information);
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
    if (encoded_policy > static_cast<std::uint8_t>(ChildProcessPolicy::kDeny)) {
        return ProcessHookPrepareStatus::kInvalidPolicy;
    }
    g_child_process_policy =
        static_cast<ChildProcessPolicy>(encoded_policy);
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
    if (g_rtl_create_user_process == nullptr) {
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
    return DetourAttach(
        reinterpret_cast<PVOID*>(&g_create_process_with_logon_w),
        reinterpret_cast<PVOID>(DetouredCreateProcessWithLogonW));
}

}  // namespace bolt::process
