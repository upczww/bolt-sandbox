#pragma once

#include <cstddef>
#include <cstdint>

namespace bolt::filesystem {

enum class HookInstallStatus : std::uint8_t {
    kSuccess,
    kInvalidPolicy,
    kTransactionFailed,
};

HookInstallStatus InstallFileHooks(
    const std::uint8_t* policy_payload,
    std::size_t policy_length) noexcept;

}  // namespace bolt::filesystem
