#include "protocol/runtime_payload.h"

#include "protocol/version.h"

#include <algorithm>
#include <limits>

namespace bolt::protocol {
namespace {

constexpr std::array<std::uint8_t, 4> kMagic = {'B', 'L', 'R', '1'};
constexpr std::size_t kVersionOffset = 4;
constexpr std::size_t kHeaderLengthOffset = 6;
constexpr std::size_t kProcessIdOffset = 8;
constexpr std::size_t kPolicyLengthOffset = 12;
constexpr std::size_t kPolicyHandleOffset = 16;
constexpr std::size_t kEventHandleOffset = 24;
constexpr std::size_t kReleaseHandleOffset = 32;
constexpr std::size_t kDescendantReadyHandleOffset = 40;
constexpr std::size_t kNonceOffset = 48;
constexpr std::size_t kDnsRequestHandleOffset = 64;
constexpr std::size_t kDnsResponseHandleOffset = 72;
constexpr std::size_t kDnsMaximumFrameOffset = 80;
constexpr std::size_t kDnsKeyOffset = 88;
constexpr std::size_t kTcpProxyPortOffset = 120;
constexpr std::size_t kMinimumPolicyLength = kPolicyEnvelopeLength;
constexpr std::size_t kMaximumPolicyLength = kPolicyEnvelopeLength + kPolicyMaximumBodyLength;

void WriteU16(std::uint8_t* output, const std::size_t offset, const std::uint16_t value) noexcept {
    output[offset] = static_cast<std::uint8_t>(value);
    output[offset + 1] = static_cast<std::uint8_t>(value >> 8);
}

void WriteU32(std::uint8_t* output, const std::size_t offset, const std::uint32_t value) noexcept {
    for (std::size_t index = 0; index < 4; ++index) {
        output[offset + index] = static_cast<std::uint8_t>(value >> (index * 8));
    }
}

void WriteU64(std::uint8_t* output, const std::size_t offset, const std::uint64_t value) noexcept {
    for (std::size_t index = 0; index < 8; ++index) {
        output[offset + index] = static_cast<std::uint8_t>(value >> (index * 8));
    }
}

std::uint16_t ReadU16(const std::uint8_t* input, const std::size_t offset) noexcept {
    return static_cast<std::uint16_t>(input[offset]) |
           static_cast<std::uint16_t>(input[offset + 1]) << 8;
}

std::uint32_t ReadU32(const std::uint8_t* input, const std::size_t offset) noexcept {
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < 4; ++index) {
        value |= static_cast<std::uint32_t>(input[offset + index]) << (index * 8);
    }
    return value;
}

std::uint64_t ReadU64(const std::uint8_t* input, const std::size_t offset) noexcept {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < 8; ++index) {
        value |= static_cast<std::uint64_t>(input[offset + index]) << (index * 8);
    }
    return value;
}

bool IsValidHandleValue(const std::uint64_t value) noexcept {
    if (value == 0 || value == std::numeric_limits<std::uint64_t>::max()) {
        return false;
    }
#if !defined(_WIN64)
    if (value > std::numeric_limits<std::uint32_t>::max()) {
        return false;
    }
#endif
    return true;
}

}  // namespace

std::array<std::uint8_t, kRuntimePayloadLength> EncodeRuntimePayload(
    const RuntimePayload& payload) noexcept {
    std::array<std::uint8_t, kRuntimePayloadLength> encoded{};
    std::copy(kMagic.begin(), kMagic.end(), encoded.begin());
    WriteU16(encoded.data(), kVersionOffset, kProtocolVersion);
    WriteU16(encoded.data(), kHeaderLengthOffset, static_cast<std::uint16_t>(encoded.size()));
    WriteU32(encoded.data(), kProcessIdOffset, payload.target_process_id);
    WriteU32(encoded.data(), kPolicyLengthOffset, payload.policy_length);
    WriteU64(encoded.data(), kPolicyHandleOffset, payload.policy_handle);
    WriteU64(encoded.data(), kEventHandleOffset, payload.event_handle);
    WriteU64(encoded.data(), kReleaseHandleOffset, payload.release_handle);
    WriteU64(
        encoded.data(), kDescendantReadyHandleOffset,
        payload.descendant_ready_handle);
    std::copy(payload.handshake_nonce.begin(), payload.handshake_nonce.end(),
              encoded.begin() + kNonceOffset);
    WriteU64(encoded.data(), kDnsRequestHandleOffset, payload.dns_request_handle);
    WriteU64(encoded.data(), kDnsResponseHandleOffset, payload.dns_response_handle);
    WriteU32(encoded.data(), kDnsMaximumFrameOffset, payload.dns_maximum_frame_length);
    std::copy(
        payload.dns_authentication_key.begin(),
        payload.dns_authentication_key.end(), encoded.begin() + kDnsKeyOffset);
    WriteU16(encoded.data(), kTcpProxyPortOffset, payload.tcp_proxy_port);
    return encoded;
}

RuntimePayloadStatus DecodeRuntimePayload(
    const std::uint8_t* encoded,
    const std::size_t length,
    RuntimePayload& output) noexcept {
    if (encoded == nullptr) {
        return RuntimePayloadStatus::kInvalidArgument;
    }
    if (length != kRuntimePayloadLength) {
        return RuntimePayloadStatus::kInvalidLength;
    }
    if (!std::equal(kMagic.begin(), kMagic.end(), encoded)) {
        return RuntimePayloadStatus::kInvalidMagic;
    }
    if (ReadU16(encoded, kVersionOffset) != kProtocolVersion) {
        return RuntimePayloadStatus::kUnsupportedVersion;
    }
    if (ReadU16(encoded, kHeaderLengthOffset) != kRuntimePayloadLength) {
        return RuntimePayloadStatus::kInvalidHeaderLength;
    }

    RuntimePayload decoded{};
    decoded.target_process_id = ReadU32(encoded, kProcessIdOffset);
    decoded.policy_length = ReadU32(encoded, kPolicyLengthOffset);
    decoded.policy_handle = ReadU64(encoded, kPolicyHandleOffset);
    decoded.event_handle = ReadU64(encoded, kEventHandleOffset);
    decoded.release_handle = ReadU64(encoded, kReleaseHandleOffset);
    decoded.descendant_ready_handle =
        ReadU64(encoded, kDescendantReadyHandleOffset);
    std::copy(encoded + kNonceOffset, encoded + kNonceOffset + decoded.handshake_nonce.size(),
              decoded.handshake_nonce.begin());
    decoded.dns_request_handle = ReadU64(encoded, kDnsRequestHandleOffset);
    decoded.dns_response_handle = ReadU64(encoded, kDnsResponseHandleOffset);
    decoded.dns_maximum_frame_length = ReadU32(encoded, kDnsMaximumFrameOffset);
    std::copy(
        encoded + kDnsKeyOffset,
        encoded + kDnsKeyOffset + decoded.dns_authentication_key.size(),
        decoded.dns_authentication_key.begin());
    decoded.tcp_proxy_port = ReadU16(encoded, kTcpProxyPortOffset);
    if (decoded.target_process_id == 0) {
        return RuntimePayloadStatus::kInvalidProcessId;
    }
    if (decoded.policy_length < kMinimumPolicyLength ||
        decoded.policy_length > kMaximumPolicyLength) {
        return RuntimePayloadStatus::kInvalidPolicyLength;
    }
    if (!IsValidHandleValue(decoded.policy_handle) || !IsValidHandleValue(decoded.event_handle) ||
        !IsValidHandleValue(decoded.release_handle) ||
        (decoded.descendant_ready_handle != 0 &&
         !IsValidHandleValue(decoded.descendant_ready_handle))) {
        return RuntimePayloadStatus::kInvalidHandle;
    }
    const bool dns_key_zero = std::all_of(
        decoded.dns_authentication_key.begin(), decoded.dns_authentication_key.end(),
        [](const std::uint8_t byte) { return byte == 0; });
    const bool dns_absent = decoded.dns_request_handle == 0 &&
                            decoded.dns_response_handle == 0 &&
                            decoded.dns_maximum_frame_length == 0 &&
                            decoded.tcp_proxy_port == 0 && dns_key_zero;
    const bool dns_valid = IsValidHandleValue(decoded.dns_request_handle) &&
                           IsValidHandleValue(decoded.dns_response_handle) &&
                           decoded.dns_maximum_frame_length >= 68 &&
                           decoded.dns_maximum_frame_length <= 1'048'576 &&
                           decoded.tcp_proxy_port != 0 &&
                           !dns_key_zero;
    if (!dns_absent && !dns_valid) {
        return RuntimePayloadStatus::kInvalidDnsProxy;
    }
    output = decoded;
    return RuntimePayloadStatus::kSuccess;
}

}  // namespace bolt::protocol
