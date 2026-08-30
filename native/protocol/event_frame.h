#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace bolt::protocol {

inline constexpr std::size_t kEventHeaderLength = 24;
inline constexpr std::size_t kReadyNonceLength = 16;
inline constexpr std::size_t kReadyFrameLength = kEventHeaderLength + kReadyNonceLength;
inline constexpr std::size_t kMaximumEventPathCodeUnits = 32'767;

enum class FilesystemOperation : std::uint8_t {
    kRead = 0,
    kWrite = 1,
    kMetadata = 2,
    kCreate = 3,
    kDelete = 4,
    kRename = 5,
    kEnumerate = 6,
};

enum class FrameEncodeStatus : std::uint8_t {
    kSuccess,
    kInvalidArgument,
    kInvalidOperation,
    kInvalidPath,
    kInsufficientBuffer,
};

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

std::size_t FilesystemViolationFrameLength(const wchar_t* path) noexcept;

FrameEncodeStatus EncodeFilesystemViolationFrame(
    std::uint32_t process_id,
    FilesystemOperation operation,
    const wchar_t* path,
    std::uint64_t sequence,
    std::uint8_t* output,
    std::size_t capacity,
    std::size_t& written) noexcept;

void RewriteFrameChecksum(std::uint8_t* encoded, std::size_t length) noexcept;

}  // namespace bolt::protocol
