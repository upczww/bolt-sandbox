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

}  // namespace bolt::filesystem
