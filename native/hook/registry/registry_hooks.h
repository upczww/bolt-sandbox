#pragma once

#include <cstddef>
#include <cstdint>

namespace bolt::registry {

enum class RegistryHookInstallStatus : std::uint8_t {
    kSuccess,
    kInvalidPolicy,
    kMissingFunction,
    kTransactionFailed,
};

RegistryHookInstallStatus InstallRegistryHooks(
    const std::uint8_t* policy_payload,
    std::size_t policy_length) noexcept;

}  // namespace bolt::registry
