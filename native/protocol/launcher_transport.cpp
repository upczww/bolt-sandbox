#include "protocol/launcher_transport.h"

#include "protocol/version.h"

#include <algorithm>
#include <cstring>

namespace bolt::protocol {
namespace {

constexpr std::array<std::uint8_t, 4> kMagic = {'B', 'L', 'X', '1'};

bool IsKnownKind(const LauncherTransportKind kind) noexcept {
    return kind >= LauncherTransportKind::kStdout &&
           kind <= LauncherTransportKind::kRecoveryRequest;
}

void WriteU16(
    std::uint8_t* const output,
    const std::size_t offset,
    const std::uint16_t value) noexcept {
    std::memcpy(output + offset, &value, sizeof(value));
}

void WriteU32(
    std::uint8_t* const output,
    const std::size_t offset,
    const std::uint32_t value) noexcept {
    std::memcpy(output + offset, &value, sizeof(value));
}

std::uint16_t ReadU16(
    const std::uint8_t* const input,
    const std::size_t offset) noexcept {
    std::uint16_t value = 0;
    std::memcpy(&value, input + offset, sizeof(value));
    return value;
}

std::uint32_t ReadU32(
    const std::uint8_t* const input,
    const std::size_t offset) noexcept {
    std::uint32_t value = 0;
    std::memcpy(&value, input + offset, sizeof(value));
    return value;
}

}  // namespace

LauncherTransportStatus EncodeLauncherTransportHeader(
    const LauncherTransportKind kind,
    const std::uint32_t payload_length,
    std::array<std::uint8_t, kLauncherTransportHeaderLength>& output) noexcept {
    output.fill(0);
    if (!IsKnownKind(kind)) {
        return LauncherTransportStatus::kUnknownKind;
    }
    if (payload_length > kLauncherTransportMaximumPayload) {
        return LauncherTransportStatus::kInvalidLength;
    }
    std::copy(kMagic.begin(), kMagic.end(), output.begin());
    WriteU16(output.data(), 4, kProtocolVersion);
    WriteU16(output.data(), 6, static_cast<std::uint16_t>(kind));
    WriteU32(output.data(), 8, payload_length);
    return LauncherTransportStatus::kSuccess;
}

LauncherTransportStatus DecodeLauncherTransportHeader(
    const std::uint8_t* const encoded,
    const std::size_t length,
    LauncherTransportKind& kind,
    std::uint32_t& payload_length) noexcept {
    if (encoded == nullptr) {
        return LauncherTransportStatus::kInvalidArgument;
    }
    if (length != kLauncherTransportHeaderLength) {
        return LauncherTransportStatus::kInvalidLength;
    }
    if (!std::equal(kMagic.begin(), kMagic.end(), encoded)) {
        return LauncherTransportStatus::kInvalidMagic;
    }
    if (ReadU16(encoded, 4) != kProtocolVersion) {
        return LauncherTransportStatus::kUnsupportedVersion;
    }
    const auto decoded_kind =
        static_cast<LauncherTransportKind>(ReadU16(encoded, 6));
    if (!IsKnownKind(decoded_kind)) {
        return LauncherTransportStatus::kUnknownKind;
    }
    const std::uint32_t decoded_length = ReadU32(encoded, 8);
    if (decoded_length > kLauncherTransportMaximumPayload) {
        return LauncherTransportStatus::kInvalidLength;
    }
    kind = decoded_kind;
    payload_length = decoded_length;
    return LauncherTransportStatus::kSuccess;
}

}  // namespace bolt::protocol
