#include "hook/process/process_mitigations.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace bolt::process {
namespace {

template <typename Policy>
ProcessMitigationStatus ApplyPolicy(
    const PROCESS_MITIGATION_POLICY policy_kind,
    const DWORD required_flags) noexcept {
    static_assert(sizeof(Policy) == sizeof(DWORD));
    Policy policy{};
    if (!GetProcessMitigationPolicy(
            GetCurrentProcess(), policy_kind, &policy, sizeof(policy))) {
        return ProcessMitigationStatus::kQueryFailed;
    }
    if ((policy.Flags & required_flags) != required_flags) {
        policy.Flags |= required_flags;
        if (!SetProcessMitigationPolicy(
                policy_kind, &policy, sizeof(policy))) {
            return ProcessMitigationStatus::kApplyFailed;
        }
    }

    Policy verified{};
    if (!GetProcessMitigationPolicy(
            GetCurrentProcess(), policy_kind, &verified, sizeof(verified))) {
        return ProcessMitigationStatus::kVerifyFailed;
    }
    return (verified.Flags & required_flags) == required_flags
               ? ProcessMitigationStatus::kSuccess
               : ProcessMitigationStatus::kVerifyFailed;
}

}  // namespace

ProcessMitigationStatus ApplyRequiredProcessMitigations() noexcept {
    constexpr DWORD extension_point_flags = 0x00000001;
    const ProcessMitigationStatus status =
        ApplyPolicy<PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY>(
            ProcessExtensionPointDisablePolicy, extension_point_flags);
    if (status != ProcessMitigationStatus::kSuccess) {
        return status;
    }

    constexpr DWORD image_load_flags = 0x00000007;
    return ApplyPolicy<PROCESS_MITIGATION_IMAGE_LOAD_POLICY>(
        ProcessImageLoadPolicy, image_load_flags);
}

}  // namespace bolt::process
