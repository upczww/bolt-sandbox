#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace bolt::protocol {

inline constexpr std::size_t kEventHeaderLength = 24;
inline constexpr std::size_t kReadyNonceLength = 16;
inline constexpr std::size_t kReadyFrameLength = kEventHeaderLength + kReadyNonceLength;

enum class ReadyFrameStatus : std::uint8_t {
    kSuccess,
    kInvalidArgument,
    kInvalidLength,
    kInvalidMagic,
    kUnsupportedVersion,
    kUnexpectedKind,
    kUnexpectedSequence,
    kChecksumMismatch,
    kNonceMismatch,
};

std::array<std::uint8_t, kReadyFrameLength> EncodeReadyFrame(
    const std::array<std::uint8_t, kReadyNonceLength>& nonce) noexcept;

ReadyFrameStatus ValidateReadyFrame(
    const std::uint8_t* encoded,
    std::size_t length,
    const std::array<std::uint8_t, kReadyNonceLength>& expected_nonce) noexcept;

void RewriteFrameChecksum(std::uint8_t* encoded, std::size_t length) noexcept;

}  // namespace bolt::protocol
