#pragma once

#include <cstdint>

namespace bolt::process {

enum class ProcessMitigationStatus : std::uint8_t {
    kSuccess,
    kQueryFailed,
    kApplyFailed,
    kVerifyFailed,
};

ProcessMitigationStatus ApplyRequiredProcessMitigations() noexcept;

}  // namespace bolt::process
