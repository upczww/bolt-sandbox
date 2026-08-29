#pragma once

#include <cstddef>
#include <cstdint>

namespace bolt::protocol {

enum class PolicyPayloadStatus : std::uint8_t {
    kValid,
    kTruncatedHeader,
    kInvalidMagic,
    kUnsupportedVersion,
    kInvalidHeaderLength,
    kBodyTooLarge,
    kLengthMismatch,
    kDigestFailure,
    kDigestMismatch,
    kInvalidBody,
};

PolicyPayloadStatus ValidatePolicyPayload(
    const std::uint8_t* payload,
    std::size_t length) noexcept;

}  // namespace bolt::protocol
