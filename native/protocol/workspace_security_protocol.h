#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace bolt::protocol {

inline constexpr std::size_t kWorkspaceSecurityHeaderLength = 64;
inline constexpr std::size_t kWorkspaceSecurityResponseLength = 12;
inline constexpr std::size_t kWorkspaceSecurityMaximumRequestLength =
    256 * 1'024;

enum class WorkspaceSecurityOperation : std::uint16_t {
    kCopy = 1,
    kVerify = 2,
    kCopyRoot = 3,
};

enum class WorkspaceSecurityResult : std::uint32_t {
    kSuccess = 0,
    kInvalidRoot = 1,
    kUnsupportedObject = 2,
    kQuotaExceeded = 3,
    kSecurityQueryFailed = 4,
    kSecurityApplyFailed = 5,
    kMismatch = 6,
    kProtocolError = 7,
};

struct WorkspaceSecurityRequest {
    WorkspaceSecurityOperation operation = WorkspaceSecurityOperation::kCopy;
    std::uint32_t maximum_items = 0;
    std::wstring source_root;
    std::wstring destination_root;

    bool operator==(const WorkspaceSecurityRequest& other) const noexcept;
};

enum class WorkspaceSecurityProtocolStatus : std::uint8_t {
    kSuccess,
    kInvalidArgument,
    kInvalidLength,
    kInvalidMagic,
    kUnsupportedVersion,
    kInvalidHeader,
    kInvalidField,
    kDigestMismatch,
    kAllocationFailed,
};

WorkspaceSecurityProtocolStatus EncodeWorkspaceSecurityRequest(
    const WorkspaceSecurityRequest& request,
    std::vector<std::uint8_t>& encoded) noexcept;

WorkspaceSecurityProtocolStatus DecodeWorkspaceSecurityRequest(
    const std::uint8_t* encoded,
    std::size_t length,
    WorkspaceSecurityRequest& request) noexcept;

std::array<std::uint8_t, kWorkspaceSecurityResponseLength>
EncodeWorkspaceSecurityResponse(WorkspaceSecurityResult result) noexcept;

WorkspaceSecurityProtocolStatus DecodeWorkspaceSecurityResponse(
    const std::uint8_t* encoded,
    std::size_t length,
    WorkspaceSecurityResult& result) noexcept;

}  // namespace bolt::protocol
