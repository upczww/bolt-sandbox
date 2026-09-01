#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace bolt::filesystem {

enum class HookInstallStatus : std::uint8_t {
    kSuccess,
    kInvalidPolicy,
    kTransactionFailed,
};

HookInstallStatus InstallFileHooks(
    const std::uint8_t* policy_payload,
    std::size_t policy_length,
    HANDLE trusted_stdout,
    HANDLE trusted_stderr) noexcept;

bool AllowsPrivateStatePath(const wchar_t* path) noexcept;

bool RegisterInheritedPipeHandles(
    const std::vector<std::uint64_t>& handles) noexcept;

std::uint32_t InstalledFileHookCount() noexcept;

}  // namespace bolt::filesystem
