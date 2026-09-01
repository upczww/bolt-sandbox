#include "protocol/inherited_handle_payload.h"

#include "protocol/version.h"

#include <algorithm>
#include <limits>

namespace bolt::protocol {
namespace {

constexpr std::uint8_t kMagic[] = {'B', 'L', 'H', '1'};

void WriteU16(std::uint8_t* output, const std::size_t offset,
              const std::uint16_t value) noexcept {
    output[offset] = static_cast<std::uint8_t>(value);
    output[offset + 1] = static_cast<std::uint8_t>(value >> 8);
}

void WriteU32(std::uint8_t* output, const std::size_t offset,
              const std::uint32_t value) noexcept {
    for (std::size_t index = 0; index < 4; ++index) {
        output[offset + index] =
            static_cast<std::uint8_t>(value >> (index * 8));
    }
}

void WriteU64(std::uint8_t* output, const std::size_t offset,
              const std::uint64_t value) noexcept {
    for (std::size_t index = 0; index < 8; ++index) {
        output[offset + index] =
            static_cast<std::uint8_t>(value >> (index * 8));
    }
}

std::uint16_t ReadU16(const std::uint8_t* input,
                      const std::size_t offset) noexcept {
    return static_cast<std::uint16_t>(input[offset]) |
           static_cast<std::uint16_t>(input[offset + 1]) << 8;
}

std::uint32_t ReadU32(const std::uint8_t* input,
                      const std::size_t offset) noexcept {
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < 4; ++index) {
        value |= static_cast<std::uint32_t>(input[offset + index]) <<
                 (index * 8);
    }
    return value;
}

std::uint64_t ReadU64(const std::uint8_t* input,
                      const std::size_t offset) noexcept {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < 8; ++index) {
        value |= static_cast<std::uint64_t>(input[offset + index]) <<
                 (index * 8);
    }
    return value;
}

bool IsValidHandle(const std::uint64_t handle) noexcept {
    if (handle == 0 || handle == (std::numeric_limits<std::uint64_t>::max)()) {
        return false;
    }
#if !defined(_WIN64)
    return handle <= (std::numeric_limits<std::uint32_t>::max)();
#else
    return true;
#endif
}

}  // namespace

std::vector<std::uint8_t> EncodeInheritedHandlePayload(
    const std::vector<std::uint64_t>& handles) {
    if (handles.size() > kMaximumInheritedHandleCount ||
        std::any_of(handles.begin(), handles.end(),
                    [](const std::uint64_t handle) {
                        return !IsValidHandle(handle);
                    })) {
        return {};
    }
    std::vector<std::uint8_t> encoded(
        kInheritedHandlePayloadHeaderLength +
        handles.size() * sizeof(std::uint64_t));
    std::copy(std::begin(kMagic), std::end(kMagic), encoded.begin());
    WriteU16(encoded.data(), 4, kProtocolVersion);
    WriteU16(
        encoded.data(), 6,
        static_cast<std::uint16_t>(kInheritedHandlePayloadHeaderLength));
    WriteU32(encoded.data(), 8, static_cast<std::uint32_t>(handles.size()));
    for (std::size_t index = 0; index < handles.size(); ++index) {
        WriteU64(encoded.data(), kInheritedHandlePayloadHeaderLength +
                                    index * sizeof(std::uint64_t),
                 handles[index]);
    }
    return encoded;
}

InheritedHandlePayloadStatus DecodeInheritedHandlePayload(
    const std::uint8_t* encoded,
    const std::size_t length,
    std::vector<std::uint64_t>& handles) {
    handles.clear();
    if (encoded == nullptr) {
        return InheritedHandlePayloadStatus::kInvalidArgument;
    }
    if (length < kInheritedHandlePayloadHeaderLength) {
        return InheritedHandlePayloadStatus::kInvalidLength;
    }
    if (!std::equal(std::begin(kMagic), std::end(kMagic), encoded)) {
        return InheritedHandlePayloadStatus::kInvalidMagic;
    }
    if (ReadU16(encoded, 4) != kProtocolVersion) {
        return InheritedHandlePayloadStatus::kUnsupportedVersion;
    }
    if (ReadU16(encoded, 6) != kInheritedHandlePayloadHeaderLength) {
        return InheritedHandlePayloadStatus::kInvalidHeaderLength;
    }
    const std::size_t count = ReadU32(encoded, 8);
    if (count > kMaximumInheritedHandleCount) {
        return InheritedHandlePayloadStatus::kInvalidCount;
    }
    const std::size_t expected_length =
        kInheritedHandlePayloadHeaderLength + count * sizeof(std::uint64_t);
    if (length != expected_length) {
        return InheritedHandlePayloadStatus::kInvalidLength;
    }
    if (encoded[12] != 0 || encoded[13] != 0 || encoded[14] != 0 ||
        encoded[15] != 0) {
        return InheritedHandlePayloadStatus::kNonCanonicalReservedBytes;
    }
    try {
        handles.reserve(count);
        for (std::size_t index = 0; index < count; ++index) {
            const std::uint64_t handle = ReadU64(
                encoded, kInheritedHandlePayloadHeaderLength +
                             index * sizeof(std::uint64_t));
            if (!IsValidHandle(handle)) {
                handles.clear();
                return InheritedHandlePayloadStatus::kInvalidHandle;
            }
            if (std::find(handles.begin(), handles.end(), handle) !=
                handles.end()) {
                handles.clear();
                return InheritedHandlePayloadStatus::kInvalidHandle;
            }
            handles.push_back(handle);
        }
    } catch (...) {
        handles.clear();
        return InheritedHandlePayloadStatus::kInvalidCount;
    }
    return InheritedHandlePayloadStatus::kSuccess;
}

}  // namespace bolt::protocol
