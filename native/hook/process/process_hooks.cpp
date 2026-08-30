#include "hook/process/process_hooks.h"

#include "protocol/policy_payload.h"
#include "protocol/version.h"

#include "DetouredFunctionTypes.h"
#include "DetouredScope.h"

#include <cstring>

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
    // Inherit remains fail-closed until the BuildXL-derived descendant
    // injection adapter can prove readiness before user code is resumed.
    static_cast<void>(g_child_process_policy);
    return DenyChildCreation(process_information);
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
    static_cast<void>(g_child_process_policy);
    return DenyChildCreation(process_information);
}

}  // namespace

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
