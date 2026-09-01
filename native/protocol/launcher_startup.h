#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace bolt::protocol {

inline constexpr std::uint16_t kLauncherStartVersion = 2;
inline constexpr std::size_t kLauncherStartHeaderLength = 112;
inline constexpr std::size_t kLauncherStartMaximumLength = 3 * 1'048'576;

struct LauncherStartRequest {
    std::wstring program;
    std::wstring cwd;
    std::vector<wchar_t> command_line;
    std::vector<wchar_t> environment_block;
    std::vector<std::uint8_t> policy;
    std::wstring hook_path;
    bool has_timeout = false;
    std::uint64_t timeout_milliseconds = 0;
    std::array<std::uint8_t, 16> nonce{};
    std::array<std::uint8_t, 16> endpoint_identifier{};
    bool recovery_enabled = false;

    bool operator==(const LauncherStartRequest& other) const noexcept;
};

enum class LauncherStartStatus : std::uint8_t {
    kSuccess,
    kInvalidArgument,
    kInvalidLength,
    kInvalidMagic,
    kUnsupportedVersion,
    kInvalidHeader,
    kInvalidFlags,
    kInvalidField,
    kDigestMismatch,
    kAllocationFailed,
};

LauncherStartStatus EncodeLauncherStartRequest(
    const LauncherStartRequest& request,
    std::vector<std::uint8_t>& encoded) noexcept;

LauncherStartStatus DecodeLauncherStartRequest(
    const std::uint8_t* encoded,
    std::size_t length,
    LauncherStartRequest& request) noexcept;

}  // namespace bolt::protocol
