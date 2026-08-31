#include "protocol/launcher_control.h"

#include "protocol/version.h"

#include <algorithm>

namespace bolt::protocol {
namespace {

constexpr std::array<std::uint8_t, 4> kMagic = {'B', 'L', 'C', '1'};

void WriteU16(
    std::uint8_t* const output,
    const std::size_t offset,
    const std::uint16_t value) noexcept {
    output[offset] = static_cast<std::uint8_t>(value);
    output[offset + 1] = static_cast<std::uint8_t>(value >> 8);
}

std::uint16_t ReadU16(
    const std::uint8_t* const input,
    const std::size_t offset) noexcept {
    return static_cast<std::uint16_t>(input[offset]) |
           static_cast<std::uint16_t>(input[offset + 1]) << 8;
}

bool IsKnown(const LauncherControlKind kind) noexcept {
    return kind == LauncherControlKind::kCancel ||
           kind == LauncherControlKind::kTimeout ||
           kind == LauncherControlKind::kProtocolIntegrity;
}

}  // namespace

std::array<std::uint8_t, kLauncherControlLength> EncodeLauncherControl(
    const LauncherControlKind kind) noexcept {
    std::array<std::uint8_t, kLauncherControlLength> encoded{};
    if (!IsKnown(kind)) {
        return encoded;
    }
    std::copy(kMagic.begin(), kMagic.end(), encoded.begin());
    WriteU16(encoded.data(), 4, kProtocolVersion);
    WriteU16(encoded.data(), 6, static_cast<std::uint16_t>(kind));
    return encoded;
}

LauncherControlStatus DecodeLauncherControl(
    const std::uint8_t* const encoded,
    const std::size_t length,
    LauncherControlKind& kind) noexcept {
    if (encoded == nullptr) {
        return LauncherControlStatus::kInvalidArgument;
    }
    if (length != kLauncherControlLength) {
        return LauncherControlStatus::kInvalidLength;
    }
    if (!std::equal(kMagic.begin(), kMagic.end(), encoded)) {
        return LauncherControlStatus::kInvalidMagic;
    }
    if (ReadU16(encoded, 4) != kProtocolVersion) {
        return LauncherControlStatus::kUnsupportedVersion;
    }
    const auto decoded = static_cast<LauncherControlKind>(ReadU16(encoded, 6));
    if (!IsKnown(decoded)) {
        return LauncherControlStatus::kUnknownKind;
    }
    kind = decoded;
    return LauncherControlStatus::kSuccess;
}

}  // namespace bolt::protocol
