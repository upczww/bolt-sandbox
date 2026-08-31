#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace bolt::protocol {

inline constexpr std::size_t kLauncherControlLength = 8;

enum class LauncherControlKind : std::uint16_t {
    kCancel = 1,
    kTimeout = 2,
};

enum class LauncherControlStatus : std::uint8_t {
    kSuccess,
    kInvalidArgument,
    kInvalidLength,
    kInvalidMagic,
    kUnsupportedVersion,
    kUnknownKind,
};

std::array<std::uint8_t, kLauncherControlLength> EncodeLauncherControl(
    LauncherControlKind kind) noexcept;

LauncherControlStatus DecodeLauncherControl(
    const std::uint8_t* encoded,
    std::size_t length,
    LauncherControlKind& kind) noexcept;

}  // namespace bolt::protocol
