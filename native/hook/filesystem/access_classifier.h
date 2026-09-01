#pragma once

#include "hook/filesystem/filesystem_policy.h"
#include "protocol/event_frame.h"

#include <cstdint>

namespace bolt::filesystem {

struct ClassifiedAccess {
    Access access;
    protocol::FilesystemOperation operation;
};

ClassifiedAccess ClassifyCreateFileRequest(
    std::uint32_t desired_access,
    std::uint32_t creation_disposition) noexcept;

ClassifiedAccess ClassifyCreateFileRequestWithFlags(
    std::uint32_t desired_access,
    std::uint32_t creation_disposition,
    std::uint32_t flags_and_attributes) noexcept;

bool RequiresPreOpenFinalResolution(
    const ClassifiedAccess& request,
    std::uint32_t flags_and_attributes) noexcept;

}  // namespace bolt::filesystem
