#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include <guiddef.h>

namespace bolt::protocol {

inline constexpr GUID kInheritedHandlePayloadGuid = {
    0x78c727d4, 0xa680, 0x4b58, {0xa3, 0x97, 0x15, 0x1f, 0x61, 0xcb, 0x8b, 0x94}};
inline constexpr std::size_t kInheritedHandlePayloadHeaderLength = 16;
inline constexpr std::size_t kMaximumInheritedHandleCount = 128;

enum class InheritedHandlePayloadStatus : std::uint8_t {
    kSuccess,
    kInvalidArgument,
    kInvalidLength,
    kInvalidMagic,
    kUnsupportedVersion,
    kInvalidHeaderLength,
    kInvalidCount,
    kInvalidHandle,
    kNonCanonicalReservedBytes,
};

std::vector<std::uint8_t> EncodeInheritedHandlePayload(
    const std::vector<std::uint64_t>& handles);

InheritedHandlePayloadStatus DecodeInheritedHandlePayload(
    const std::uint8_t* encoded,
    std::size_t length,
    std::vector<std::uint64_t>& handles);

}  // namespace bolt::protocol
