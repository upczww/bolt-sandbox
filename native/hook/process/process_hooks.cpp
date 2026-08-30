#include "hook/process/process_hooks.h"

#include "protocol/policy_payload.h"
#include "protocol/runtime_payload.h"
#include "protocol/version.h"

#include "DetouredFunctionTypes.h"
#include "DetouredScope.h"

#include <cstring>
#include <string>

#include <detours.h>

namespace bolt::process {
namespace {

enum class ChildProcessPolicy : std::uint8_t {
    kInherit = 0,
    kDeny = 1,
};

CreateProcessW_t g_create_process_w = CreateProcessW;
CreateProcessA_t g_create_process_a = CreateProcessA;
ChildProcessPolicy g_child_process_policy = ChildProcessPolicy::kDeny;
bool g_prepared = false;
bool g_runtime_configured = false;
protocol::RuntimePayload g_runtime_payload{};
std::string g_hook_dll_path;

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
    LPCSTR dlls[] = {g_hook_dll_path.c_str()};
    if (!DetourUpdateProcessWithDll(process_information->hProcess, dlls, 1)) {
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
    const LONG wide_status = DetourAttach(
        reinterpret_cast<PVOID*>(&g_create_process_w),
        reinterpret_cast<PVOID>(DetouredCreateProcessW));
    if (wide_status != NO_ERROR) {
        return wide_status;
    }
    return DetourAttach(
        reinterpret_cast<PVOID*>(&g_create_process_a),
        reinterpret_cast<PVOID>(DetouredCreateProcessA));
}

}  // namespace bolt::process
