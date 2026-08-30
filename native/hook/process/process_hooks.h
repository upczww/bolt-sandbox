#pragma once

#include <cstddef>
#include <cstdint>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace bolt::process {

enum class ProcessHookPrepareStatus : std::uint8_t {
    kSuccess,
    kInvalidPolicy,
    kAlreadyPrepared,
};

ProcessHookPrepareStatus PrepareProcessHooks(
    const std::uint8_t* policy_payload,
    std::size_t policy_length) noexcept;

LONG AttachProcessHooks() noexcept;

}  // namespace bolt::process
