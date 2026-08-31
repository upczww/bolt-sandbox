#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace bolt::protocol {

inline constexpr std::size_t kLauncherTransportHeaderLength = 12;
inline constexpr std::uint32_t kLauncherTransportMaximumPayload = 1'048'576;

enum class LauncherTransportKind : std::uint16_t {
    kStdout = 1,
    kStderr = 2,
    kEvent = 3,
    kStdoutEof = 4,
    kStderrEof = 5,
    kEventEof = 6,
    kProcessExit = 7,
    kInfrastructureFailure = 8,
    kRecoveryRequest = 9,
};

enum class LauncherTransportStatus : std::uint8_t {
    kSuccess,
    kInvalidArgument,
    kInvalidLength,
    kInvalidMagic,
    kUnsupportedVersion,
    kUnknownKind,
};

LauncherTransportStatus EncodeLauncherTransportHeader(
    LauncherTransportKind kind,
    std::uint32_t payload_length,
    std::array<std::uint8_t, kLauncherTransportHeaderLength>& output) noexcept;

LauncherTransportStatus DecodeLauncherTransportHeader(
    const std::uint8_t* encoded,
    std::size_t length,
    LauncherTransportKind& kind,
    std::uint32_t& payload_length) noexcept;

}  // namespace bolt::protocol
