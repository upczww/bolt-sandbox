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

std::uint32_t LastRegistryDenialReason() noexcept;
std::uint32_t LastRegistryDenialDetails() noexcept;
bool LastRegistryDenialMatchesSuffix(const wchar_t* suffix) noexcept;
std::uint32_t CopyLastRegistryDenialName(
    wchar_t* output,
    std::uint32_t capacity) noexcept;

}  // namespace bolt::registry
