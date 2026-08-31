#pragma once

#include "protocol/recovery_protocol.h"
#include "protocol/runtime_payload.h"

#include <cstdint>

namespace bolt::recovery {

enum class RecoveryClientStatus : std::uint8_t {
    kDisabled,
    kSuccess,
    kFailed,
};

bool ConfigureRecoveryClient(
    const protocol::RuntimePayload& payload) noexcept;

RecoveryClientStatus BackupPath(
    const wchar_t* path,
    protocol::RecoveryOperation operation) noexcept;

}  // namespace bolt::recovery
