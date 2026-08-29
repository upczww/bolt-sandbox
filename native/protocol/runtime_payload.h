#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include <guiddef.h>

namespace bolt::protocol {

inline constexpr std::size_t kRuntimePayloadLength = 56;
inline constexpr GUID kRuntimePayloadGuid = {
    0x4f8a6d21, 0x91c7, 0x4bb7, {0xa6, 0x7e, 0x31, 0x57, 0x2b, 0xd9, 0x46, 0x10}};

struct RuntimePayload {
    std::uint32_t target_process_id = 0;
    std::uint32_t policy_length = 0;
    std::uint64_t policy_handle = 0;
    std::uint64_t event_handle = 0;
    std::uint64_t release_handle = 0;
    std::array<std::uint8_t, 16> handshake_nonce{};

    bool operator==(const RuntimePayload& other) const noexcept {
        return target_process_id == other.target_process_id &&
               policy_length == other.policy_length && policy_handle == other.policy_handle &&
               event_handle == other.event_handle && release_handle == other.release_handle &&
               handshake_nonce == other.handshake_nonce;
    }
    bool operator!=(const RuntimePayload& other) const noexcept { return !(*this == other); }
};

enum class RuntimePayloadStatus : std::uint8_t {
    kSuccess,
    kInvalidArgument,
    kInvalidLength,
    kInvalidMagic,
    kUnsupportedVersion,
    kInvalidHeaderLength,
    kInvalidProcessId,
    kInvalidPolicyLength,
    kInvalidHandle,
};

std::array<std::uint8_t, kRuntimePayloadLength> EncodeRuntimePayload(
    const RuntimePayload& payload) noexcept;

RuntimePayloadStatus DecodeRuntimePayload(
    const std::uint8_t* encoded,
    std::size_t length,
    RuntimePayload& output) noexcept;

}  // namespace bolt::protocol
