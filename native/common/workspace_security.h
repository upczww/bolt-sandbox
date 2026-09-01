#pragma once

#include <cstdint>
#include <filesystem>

namespace bolt::common {

enum class WorkspaceSecurityStatus : std::uint8_t {
    kSuccess,
    kInvalidRoot,
    kUnsupportedObject,
    kQuotaExceeded,
    kSecurityQueryFailed,
    kSecurityApplyFailed,
    kMismatch,
};

WorkspaceSecurityStatus CopyWorkspaceAuthorization(
    const std::filesystem::path& source_root,
    const std::filesystem::path& destination_root,
    std::uint32_t maximum_items) noexcept;

WorkspaceSecurityStatus VerifyWorkspaceAuthorization(
    const std::filesystem::path& source_root,
    const std::filesystem::path& destination_root,
    std::uint32_t maximum_items) noexcept;

}  // namespace bolt::common
