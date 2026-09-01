#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace bolt::protocol {

inline constexpr std::size_t kProjectedWorkspaceHeaderLength = 80;
inline constexpr std::size_t kProjectedWorkspaceMaximumRequestLength =
    256 * 1'024;
inline constexpr std::size_t kProjectedWorkspaceResponseLength = 12;
inline constexpr std::size_t kProjectedWorkspaceControlLength = 8;

struct ProjectedWorkspaceRequest {
    std::wstring source_root;
    std::wstring projection_root;
    std::uint32_t maximum_items = 0;
    std::uint64_t maximum_bytes = 0;

    bool operator==(const ProjectedWorkspaceRequest& other) const noexcept;
};

enum class ProjectedWorkspaceResponseKind : std::uint8_t {
    kReady,
    kFinished,
};

enum class ProjectedWorkspaceResult : std::uint32_t {
    kSuccess = 0,
    kUnavailable = 1,
    kInvalidRoot = 2,
    kUnsupportedObject = 3,
    kQuotaExceeded = 4,
    kSecurityFailure = 5,
    kIo = 6,
    kConflict = 7,
    kProtocolError = 8,
};

enum class ProjectedWorkspaceControl : std::uint16_t {
    kMaterialize = 1,
    kDiscard = 2,
};

enum class ProjectedWorkspaceProtocolStatus : std::uint8_t {
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

ProjectedWorkspaceProtocolStatus EncodeProjectedWorkspaceRequest(
    const ProjectedWorkspaceRequest& request,
    std::vector<std::uint8_t>& encoded) noexcept;
ProjectedWorkspaceProtocolStatus DecodeProjectedWorkspaceRequest(
    const std::uint8_t* encoded,
    std::size_t length,
    ProjectedWorkspaceRequest& request) noexcept;

std::array<std::uint8_t, kProjectedWorkspaceResponseLength>
EncodeProjectedWorkspaceResponse(
    ProjectedWorkspaceResponseKind kind,
    ProjectedWorkspaceResult result) noexcept;
ProjectedWorkspaceProtocolStatus DecodeProjectedWorkspaceResponse(
    const std::uint8_t* encoded,
    std::size_t length,
    ProjectedWorkspaceResponseKind expected_kind,
    ProjectedWorkspaceResult& result) noexcept;

std::array<std::uint8_t, kProjectedWorkspaceControlLength>
EncodeProjectedWorkspaceControl(ProjectedWorkspaceControl control) noexcept;
ProjectedWorkspaceProtocolStatus DecodeProjectedWorkspaceControl(
    const std::uint8_t* encoded,
    std::size_t length,
    ProjectedWorkspaceControl& control) noexcept;

}  // namespace bolt::protocol
