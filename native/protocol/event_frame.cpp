#include "protocol/event_frame.h"

#include "protocol/version.h"

#include <algorithm>

namespace bolt::protocol {
namespace {

constexpr std::array<std::uint8_t, 4> kMagic = {'B', 'L', 'T', '1'};
constexpr std::size_t kVersionOffset = 4;
constexpr std::size_t kKindOffset = 6;
constexpr std::size_t kLengthOffset = 8;
constexpr std::size_t kSequenceOffset = 12;
constexpr std::size_t kChecksumOffset = 20;
constexpr std::uint16_t kReadyKind = 1;
constexpr std::uint16_t kFilesystemViolationKind = 2;
constexpr std::size_t kFilesystemProcessIdOffset = kEventHeaderLength;
constexpr std::size_t kFilesystemOperationOffset = kFilesystemProcessIdOffset + 4;
constexpr std::size_t kFilesystemPathLengthOffset = kFilesystemOperationOffset + 1;
constexpr std::size_t kFilesystemPathOffset = kFilesystemPathLengthOffset + 4;

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

bool SequenceIsZero(const std::uint8_t* encoded) noexcept {
    std::uint8_t aggregate = 0;
    for (std::size_t index = 0; index < 8; ++index) {
        aggregate |= encoded[kSequenceOffset + index];
    }
    return aggregate == 0;
}

std::uint32_t FrameChecksum(const std::uint8_t* encoded, const std::size_t length) noexcept {
    std::uint32_t crc = 0xFFFF'FFFF;
    const auto update = [&crc](const std::uint8_t byte) {
        crc ^= byte;
        for (std::uint8_t bit = 0; bit < 8; ++bit) {
            const std::uint32_t mask = 0U - (crc & 1U);
            crc = (crc >> 1) ^ (0xEDB8'8320U & mask);
        }
    };
    for (std::size_t index = 0; index < kChecksumOffset; ++index) {
        update(encoded[index]);
    }
    for (std::size_t index = kEventHeaderLength; index < length; ++index) {
        update(encoded[index]);
    }
    return ~crc;
}

bool NonceMatches(
    const std::uint8_t* actual,
    const std::array<std::uint8_t, kReadyNonceLength>& expected) noexcept {
    std::uint8_t difference = 0;
    for (std::size_t index = 0; index < expected.size(); ++index) {
        difference |= actual[index] ^ expected[index];
    }
    return difference == 0;
}

}  // namespace

std::array<std::uint8_t, kReadyFrameLength> EncodeReadyFrame(
    const std::array<std::uint8_t, kReadyNonceLength>& nonce) noexcept {
    std::array<std::uint8_t, kReadyFrameLength> encoded{};
    std::copy(kMagic.begin(), kMagic.end(), encoded.begin());
    WriteU16(encoded.data(), kVersionOffset, kProtocolVersion);
    WriteU16(encoded.data(), kKindOffset, kReadyKind);
    WriteU32(encoded.data(), kLengthOffset, static_cast<std::uint32_t>(nonce.size()));
    std::copy(nonce.begin(), nonce.end(), encoded.begin() + kEventHeaderLength);
    RewriteFrameChecksum(encoded.data(), encoded.size());
    return encoded;
}

ReadyFrameStatus ValidateReadyFrame(
    const std::uint8_t* encoded,
    const std::size_t length,
    const std::array<std::uint8_t, kReadyNonceLength>& expected_nonce) noexcept {
    if (encoded == nullptr) {
        return ReadyFrameStatus::kInvalidArgument;
    }
    if (length != kReadyFrameLength || ReadU32(encoded, kLengthOffset) != kReadyNonceLength) {
        return ReadyFrameStatus::kInvalidLength;
    }
    if (!std::equal(kMagic.begin(), kMagic.end(), encoded)) {
        return ReadyFrameStatus::kInvalidMagic;
    }
    if (ReadU16(encoded, kVersionOffset) != kProtocolVersion) {
        return ReadyFrameStatus::kUnsupportedVersion;
    }
    if (ReadU16(encoded, kKindOffset) != kReadyKind) {
        return ReadyFrameStatus::kUnexpectedKind;
    }
    if (!SequenceIsZero(encoded)) {
        return ReadyFrameStatus::kUnexpectedSequence;
    }
    if (ReadU32(encoded, kChecksumOffset) != FrameChecksum(encoded, length)) {
        return ReadyFrameStatus::kChecksumMismatch;
    }
    if (!NonceMatches(encoded + kEventHeaderLength, expected_nonce)) {
        return ReadyFrameStatus::kNonceMismatch;
    }
    return ReadyFrameStatus::kSuccess;
}

std::size_t FilesystemViolationFrameLength(const wchar_t* path) noexcept {
    if (path == nullptr) {
        return 0;
    }
    std::size_t length = 0;
    while (length <= kMaximumEventPathCodeUnits && path[length] != L'\0') {
        ++length;
    }
    if (length == 0 || length > kMaximumEventPathCodeUnits) {
        return 0;
    }
    return kFilesystemPathOffset + length * sizeof(wchar_t);
}

FrameEncodeStatus EncodeFilesystemViolationFrame(
    const std::uint32_t process_id,
    const FilesystemOperation operation,
    const wchar_t* path,
    const std::uint64_t sequence,
    std::uint8_t* output,
    const std::size_t capacity,
    std::size_t& written) noexcept {
    written = 0;
    if (output == nullptr) {
        return FrameEncodeStatus::kInvalidArgument;
    }
    const auto operation_value = static_cast<std::uint8_t>(operation);
    if (operation_value > static_cast<std::uint8_t>(FilesystemOperation::kEnumerate)) {
        return FrameEncodeStatus::kInvalidOperation;
    }
    const std::size_t frame_length = FilesystemViolationFrameLength(path);
    if (frame_length == 0) {
        return FrameEncodeStatus::kInvalidPath;
    }
    if (capacity < frame_length) {
        return FrameEncodeStatus::kInsufficientBuffer;
    }

    const std::size_t path_length = (frame_length - kFilesystemPathOffset) / sizeof(wchar_t);
    std::fill_n(output, frame_length, std::uint8_t{0});
    std::copy(kMagic.begin(), kMagic.end(), output);
    WriteU16(output, kVersionOffset, kProtocolVersion);
    WriteU16(output, kKindOffset, kFilesystemViolationKind);
    WriteU32(
        output, kLengthOffset,
        static_cast<std::uint32_t>(frame_length - kEventHeaderLength));
    WriteU64(output, kSequenceOffset, sequence);
    WriteU32(output, kFilesystemProcessIdOffset, process_id);
    output[kFilesystemOperationOffset] = operation_value;
    WriteU32(output, kFilesystemPathLengthOffset, static_cast<std::uint32_t>(path_length));
    for (std::size_t index = 0; index < path_length; ++index) {
        WriteU16(
            output, kFilesystemPathOffset + index * sizeof(wchar_t),
            static_cast<std::uint16_t>(path[index]));
    }
    RewriteFrameChecksum(output, frame_length);
    written = frame_length;
    return FrameEncodeStatus::kSuccess;
}

void RewriteFrameChecksum(std::uint8_t* encoded, const std::size_t length) noexcept {
    if (encoded != nullptr && length >= kEventHeaderLength) {
        WriteU32(encoded, kChecksumOffset, FrameChecksum(encoded, length));
    }
}

}  // namespace bolt::protocol
