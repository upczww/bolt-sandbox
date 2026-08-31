#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include <guiddef.h>

namespace bolt::protocol {

inline constexpr std::size_t kRuntimePayloadLength = 128;
inline constexpr GUID kRuntimePayloadGuid = {
    0x4f8a6d21, 0x91c7, 0x4bb7, {0xa6, 0x7e, 0x31, 0x57, 0x2b, 0xd9, 0x46, 0x10}};

enum class RuntimeStartupFault : std::uint8_t {
    kNone = 0,
    kMitigationFailure = 1,
};

struct RuntimePayload {
    std::uint32_t target_process_id = 0;
    std::uint32_t policy_length = 0;
    std::uint64_t policy_handle = 0;
    std::uint64_t event_handle = 0;
    std::uint64_t release_handle = 0;
    // Zero identifies the initial target. Descendants receive a private event
    // that is signaled after hooks are installed, without emitting another
    // session Ready frame.
    std::uint64_t descendant_ready_handle = 0;
    std::array<std::uint8_t, 16> handshake_nonce{};
    std::uint64_t dns_request_handle = 0;
    std::uint64_t dns_response_handle = 0;
    std::uint32_t dns_maximum_frame_length = 0;
    std::array<std::uint8_t, 32> dns_authentication_key{};
    std::uint16_t tcp_proxy_port = 0;
    std::uint16_t tcp_proxy_ipv6_port = 0;
    RuntimeStartupFault startup_fault = RuntimeStartupFault::kNone;
    RuntimeStartupFault descendant_startup_fault = RuntimeStartupFault::kNone;

    bool operator==(const RuntimePayload& other) const noexcept {
        return target_process_id == other.target_process_id &&
               policy_length == other.policy_length && policy_handle == other.policy_handle &&
               event_handle == other.event_handle && release_handle == other.release_handle &&
               descendant_ready_handle == other.descendant_ready_handle &&
               handshake_nonce == other.handshake_nonce &&
               dns_request_handle == other.dns_request_handle &&
               dns_response_handle == other.dns_response_handle &&
               dns_maximum_frame_length == other.dns_maximum_frame_length &&
               dns_authentication_key == other.dns_authentication_key &&
               tcp_proxy_port == other.tcp_proxy_port &&
               tcp_proxy_ipv6_port == other.tcp_proxy_ipv6_port &&
               startup_fault == other.startup_fault &&
               descendant_startup_fault == other.descendant_startup_fault;
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
    kInvalidDnsProxy,
    kInvalidStartupFault,
    kNonCanonicalReservedBytes,
};

std::array<std::uint8_t, kRuntimePayloadLength> EncodeRuntimePayload(
    const RuntimePayload& payload) noexcept;

RuntimePayloadStatus DecodeRuntimePayload(
    const std::uint8_t* encoded,
    std::size_t length,
    RuntimePayload& output) noexcept;

}  // namespace bolt::protocol
