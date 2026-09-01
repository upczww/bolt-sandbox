#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace bolt::protocol {
struct RuntimePayload;
}

namespace bolt::process {

enum class ProcessHookPrepareStatus : std::uint8_t {
    kSuccess,
    kInvalidPolicy,
    kAlreadyPrepared,
};

bool ConfigureProcessRuntime(
    const protocol::RuntimePayload& payload,
    const char* hook_dll_path) noexcept;

bool AllowsIsolatedConsole() noexcept;

bool AllowsIsolatedNamedPipes() noexcept;

bool RewriteIsolatedNamedPipePath(
    const wchar_t* path,
    std::wstring& rewritten) noexcept;

ProcessHookPrepareStatus PrepareProcessHooks(
    const std::uint8_t* policy_payload,
    std::size_t policy_length) noexcept;

LONG AttachProcessHooks() noexcept;

}  // namespace bolt::process
