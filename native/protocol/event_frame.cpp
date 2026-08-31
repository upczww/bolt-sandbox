#include "protocol/event_frame.h"

#include "protocol/version.h"

#include <algorithm>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

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
constexpr std::uint16_t kRegistryViolationKind = 3;
constexpr std::uint16_t kNetworkViolationKind = 4;
constexpr std::uint16_t kProcessViolationKind = 8;
constexpr std::uint16_t kEventsDroppedKind = 9;
constexpr std::size_t kFilesystemProcessIdOffset = kEventHeaderLength;
constexpr std::size_t kFilesystemOperationOffset = kFilesystemProcessIdOffset + 4;
constexpr std::size_t kFilesystemPathLengthOffset = kFilesystemOperationOffset + 1;
constexpr std::size_t kFilesystemPathOffset = kFilesystemPathLengthOffset + 4;
constexpr std::size_t kProcessViolationProcessIdOffset = kEventHeaderLength;
constexpr std::size_t kProcessViolationOperationOffset =
    kProcessViolationProcessIdOffset + 4;
constexpr std::size_t kRegistryProcessIdOffset = kEventHeaderLength;
constexpr std::size_t kRegistryOperationOffset = kRegistryProcessIdOffset + 4;
constexpr std::size_t kRegistryKeyLengthOffset = kRegistryOperationOffset + 1;
constexpr std::size_t kRegistryKeyOffset = kRegistryKeyLengthOffset + 4;
constexpr std::size_t kNetworkProcessIdOffset = kEventHeaderLength;
constexpr std::size_t kNetworkOperationOffset = kNetworkProcessIdOffset + 4;
constexpr std::size_t kNetworkFamilyOffset = kNetworkOperationOffset + 1;
constexpr std::size_t kNetworkAddressOffset = kNetworkFamilyOffset + 1;
constexpr std::size_t kNetworkDomainLengthOffset = kNetworkFamilyOffset + 1;
constexpr std::size_t kNetworkDomainOffset = kNetworkDomainLengthOffset + 4;
constexpr std::size_t kEventsDroppedProcessIdOffset = kEventHeaderLength;
constexpr std::size_t kEventsDroppedCountOffset =
    kEventsDroppedProcessIdOffset + 4;

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

bool IsValidUtf8(const char* const text, const std::size_t length) noexcept {
    return text != nullptr && length != 0 &&
           length <= static_cast<std::size_t>(INT_MAX) &&
           MultiByteToWideChar(
               CP_UTF8, MB_ERR_INVALID_CHARS, text,
               static_cast<int>(length), nullptr, 0) > 0;
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

FrameEncodeStatus EncodeProcessViolationFrame(
    const std::uint32_t process_id,
    const ProcessOperation operation,
    const std::uint64_t sequence,
    std::uint8_t* const output,
    const std::size_t capacity,
    std::size_t& written) noexcept {
    written = 0;
    if (output == nullptr) {
        return FrameEncodeStatus::kInvalidArgument;
    }
    const auto operation_value = static_cast<std::uint8_t>(operation);
    if (operation_value >
        static_cast<std::uint8_t>(ProcessOperation::kExternalDelegation)) {
        return FrameEncodeStatus::kInvalidOperation;
    }
    if (capacity < kProcessViolationFrameLength) {
        return FrameEncodeStatus::kInsufficientBuffer;
    }
    std::fill_n(output, kProcessViolationFrameLength, std::uint8_t{0});
    std::copy(kMagic.begin(), kMagic.end(), output);
    WriteU16(output, kVersionOffset, kProtocolVersion);
    WriteU16(output, kKindOffset, kProcessViolationKind);
    WriteU32(output, kLengthOffset, 5);
    WriteU64(output, kSequenceOffset, sequence);
    WriteU32(output, kProcessViolationProcessIdOffset, process_id);
    output[kProcessViolationOperationOffset] = operation_value;
    RewriteFrameChecksum(output, kProcessViolationFrameLength);
    written = kProcessViolationFrameLength;
    return FrameEncodeStatus::kSuccess;
}

std::size_t RegistryViolationFrameLength(const char* const key) noexcept {
    if (key == nullptr) {
        return 0;
    }
    std::size_t length = 0;
    while (length <= 4'096 && key[length] != '\0') {
        ++length;
    }
    return length != 0 && length <= 4'096 && IsValidUtf8(key, length)
               ? kRegistryKeyOffset + length
               : 0;
}

FrameEncodeStatus EncodeRegistryViolationFrame(
    const std::uint32_t process_id,
    const RegistryOperation operation,
    const char* const key,
    const std::uint64_t sequence,
    std::uint8_t* const output,
    const std::size_t capacity,
    std::size_t& written) noexcept {
    written = 0;
    if (output == nullptr) {
        return FrameEncodeStatus::kInvalidArgument;
    }
    const auto operation_value = static_cast<std::uint8_t>(operation);
    if (operation_value >
        static_cast<std::uint8_t>(RegistryOperation::kRename)) {
        return FrameEncodeStatus::kInvalidOperation;
    }
    const std::size_t frame_length = RegistryViolationFrameLength(key);
    if (frame_length == 0) {
        return FrameEncodeStatus::kInvalidRegistryKey;
    }
    if (capacity < frame_length) {
        return FrameEncodeStatus::kInsufficientBuffer;
    }
    const std::size_t key_length = frame_length - kRegistryKeyOffset;
    std::fill_n(output, frame_length, std::uint8_t{0});
    std::copy(kMagic.begin(), kMagic.end(), output);
    WriteU16(output, kVersionOffset, kProtocolVersion);
    WriteU16(output, kKindOffset, kRegistryViolationKind);
    WriteU32(
        output, kLengthOffset,
        static_cast<std::uint32_t>(frame_length - kEventHeaderLength));
    WriteU64(output, kSequenceOffset, sequence);
    WriteU32(output, kRegistryProcessIdOffset, process_id);
    output[kRegistryOperationOffset] = operation_value;
    WriteU32(
        output, kRegistryKeyLengthOffset,
        static_cast<std::uint32_t>(key_length));
    std::copy_n(key, key_length, output + kRegistryKeyOffset);
    RewriteFrameChecksum(output, frame_length);
    written = frame_length;
    return FrameEncodeStatus::kSuccess;
}

FrameEncodeStatus EncodeNetworkViolationFrame(
    const std::uint32_t process_id,
    const NetworkOperation operation,
    const NetworkEndpoint& endpoint,
    const std::uint64_t sequence,
    std::uint8_t* const output,
    const std::size_t capacity,
    std::size_t& written) noexcept {
    written = 0;
    if (output == nullptr) {
        return FrameEncodeStatus::kInvalidArgument;
    }
    const auto operation_value = static_cast<std::uint8_t>(operation);
    if (operation_value > static_cast<std::uint8_t>(NetworkOperation::kSend)) {
        return FrameEncodeStatus::kInvalidOperation;
    }

    std::size_t address_length = 0;
    std::size_t frame_length = 0;
    switch (endpoint.family) {
        case NetworkAddressFamily::kIpv4:
            address_length = 4;
            frame_length = kIpv4NetworkViolationFrameLength;
            break;
        case NetworkAddressFamily::kIpv6:
            address_length = 16;
            frame_length = kIpv6NetworkViolationFrameLength;
            break;
        default:
            return FrameEncodeStatus::kInvalidAddress;
    }
    if (capacity < frame_length) {
        return FrameEncodeStatus::kInsufficientBuffer;
    }

    std::fill_n(output, frame_length, std::uint8_t{0});
    std::copy(kMagic.begin(), kMagic.end(), output);
    WriteU16(output, kVersionOffset, kProtocolVersion);
    WriteU16(output, kKindOffset, kNetworkViolationKind);
    WriteU32(
        output, kLengthOffset,
        static_cast<std::uint32_t>(frame_length - kEventHeaderLength));
    WriteU64(output, kSequenceOffset, sequence);
    WriteU32(output, kNetworkProcessIdOffset, process_id);
    output[kNetworkOperationOffset] = operation_value;
    output[kNetworkFamilyOffset] = static_cast<std::uint8_t>(endpoint.family);
    std::copy_n(endpoint.address.begin(), address_length, output + kNetworkAddressOffset);
    WriteU16(output, kNetworkAddressOffset + address_length, endpoint.port);
    RewriteFrameChecksum(output, frame_length);
    written = frame_length;
    return FrameEncodeStatus::kSuccess;
}

std::size_t DomainNetworkViolationFrameLength(const char* ascii_domain) noexcept {
    if (ascii_domain == nullptr) {
        return 0;
    }
    std::size_t length = 0;
    while (length <= kMaximumEventDomainBytes && ascii_domain[length] != '\0') {
        const auto byte = static_cast<unsigned char>(ascii_domain[length]);
        if (byte < 0x21U || byte > 0x7eU) {
            return 0;
        }
        ++length;
    }
    if (length == 0 || length > kMaximumEventDomainBytes) {
        return 0;
    }
    return kNetworkDomainOffset + length;
}

FrameEncodeStatus EncodeDomainNetworkViolationFrame(
    const std::uint32_t process_id,
    const NetworkOperation operation,
    const char* const ascii_domain,
    const std::uint64_t sequence,
    std::uint8_t* const output,
    const std::size_t capacity,
    std::size_t& written) noexcept {
    written = 0;
    if (output == nullptr) {
        return FrameEncodeStatus::kInvalidArgument;
    }
    const auto operation_value = static_cast<std::uint8_t>(operation);
    if (operation_value > static_cast<std::uint8_t>(NetworkOperation::kSend)) {
        return FrameEncodeStatus::kInvalidOperation;
    }
    const std::size_t frame_length =
        DomainNetworkViolationFrameLength(ascii_domain);
    if (frame_length == 0) {
        return FrameEncodeStatus::kInvalidDomain;
    }
    if (capacity < frame_length) {
        return FrameEncodeStatus::kInsufficientBuffer;
    }

    const std::size_t domain_length = frame_length - kNetworkDomainOffset;
    std::fill_n(output, frame_length, std::uint8_t{0});
    std::copy(kMagic.begin(), kMagic.end(), output);
    WriteU16(output, kVersionOffset, kProtocolVersion);
    WriteU16(output, kKindOffset, kNetworkViolationKind);
    WriteU32(
        output, kLengthOffset,
        static_cast<std::uint32_t>(frame_length - kEventHeaderLength));
    WriteU64(output, kSequenceOffset, sequence);
    WriteU32(output, kNetworkProcessIdOffset, process_id);
    output[kNetworkOperationOffset] = operation_value;
    output[kNetworkFamilyOffset] = 0;
    WriteU32(
        output, kNetworkDomainLengthOffset,
        static_cast<std::uint32_t>(domain_length));
    std::copy_n(ascii_domain, domain_length, output + kNetworkDomainOffset);
    RewriteFrameChecksum(output, frame_length);
    written = frame_length;
    return FrameEncodeStatus::kSuccess;
}

FrameEncodeStatus EncodeEventsDroppedFrame(
    const std::uint32_t process_id,
    const std::uint64_t dropped_count,
    const std::uint64_t sequence,
    std::uint8_t* const output,
    const std::size_t capacity,
    std::size_t& written) noexcept {
    written = 0;
    if (output == nullptr || dropped_count == 0) {
        return FrameEncodeStatus::kInvalidArgument;
    }
    if (capacity < kEventsDroppedFrameLength) {
        return FrameEncodeStatus::kInsufficientBuffer;
    }
    std::fill_n(output, kEventsDroppedFrameLength, std::uint8_t{0});
    std::copy(kMagic.begin(), kMagic.end(), output);
    WriteU16(output, kVersionOffset, kProtocolVersion);
    WriteU16(output, kKindOffset, kEventsDroppedKind);
    WriteU32(output, kLengthOffset, 12);
    WriteU64(output, kSequenceOffset, sequence);
    WriteU32(output, kEventsDroppedProcessIdOffset, process_id);
    WriteU64(output, kEventsDroppedCountOffset, dropped_count);
    RewriteFrameChecksum(output, kEventsDroppedFrameLength);
    written = kEventsDroppedFrameLength;
    return FrameEncodeStatus::kSuccess;
}

void RewriteFrameChecksum(std::uint8_t* encoded, const std::size_t length) noexcept {
    if (encoded != nullptr && length >= kEventHeaderLength) {
        WriteU32(encoded, kChecksumOffset, FrameChecksum(encoded, length));
    }
}

}  // namespace bolt::protocol
