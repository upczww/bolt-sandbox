#include "protocol/policy_payload.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace {

using bolt::protocol::PolicyPayloadStatus;

constexpr std::array<std::uint8_t, 54> kMinimalPayload = {
    0x42, 0x4c, 0x50, 0x31, 0x01, 0x00, 0x2c, 0x00, 0x0a, 0x00, 0x00, 0x00,
    0x0c, 0xee, 0x19, 0x24, 0xbb, 0x11, 0x38, 0x05, 0x95, 0x58, 0xbc, 0x22,
    0x1f, 0x5a, 0x7a, 0x1c, 0xf1, 0x59, 0x59, 0x20, 0x23, 0x31, 0x0c, 0x7d,
    0x00, 0xcd, 0xa8, 0x2e, 0xed, 0x90, 0xbb, 0xeb, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
};

constexpr std::array<std::uint8_t, 32> kInvalidBodyDigest = {
    0x0e, 0x5e, 0xc4, 0xe1, 0xbe, 0xec, 0x30, 0xda, 0x00, 0x70, 0x64,
    0x1f, 0xfc, 0xa2, 0x8d, 0x8f, 0xbd, 0xc9, 0xa7, 0xec, 0x9d, 0x5a,
    0xd4, 0x71, 0xd8, 0xd5, 0xf7, 0x14, 0x24, 0x82, 0x1a, 0x3d,
};

bool expect_status(
    const std::vector<std::uint8_t>& payload,
    const PolicyPayloadStatus expected) {
    return bolt::protocol::ValidatePolicyPayload(payload.data(), payload.size()) == expected;
}

}  // namespace

bool RunPolicyPayloadTests() {
    const std::vector<std::uint8_t> valid(kMinimalPayload.begin(), kMinimalPayload.end());
    if (!expect_status(valid, PolicyPayloadStatus::kValid)) {
        return false;
    }

    auto tampered = valid;
    tampered.back() ^= 1;
    if (!expect_status(tampered, PolicyPayloadStatus::kDigestMismatch)) {
        return false;
    }

    auto invalid_magic = valid;
    invalid_magic[0] = 0;
    if (!expect_status(invalid_magic, PolicyPayloadStatus::kInvalidMagic)) {
        return false;
    }

    auto unknown_version = valid;
    unknown_version[4] = 2;
    if (!expect_status(unknown_version, PolicyPayloadStatus::kUnsupportedVersion)) {
        return false;
    }

    auto invalid_header = valid;
    invalid_header[6] = 0;
    if (!expect_status(invalid_header, PolicyPayloadStatus::kInvalidHeaderLength)) {
        return false;
    }

    auto truncated = valid;
    truncated.pop_back();
    if (!expect_status(truncated, PolicyPayloadStatus::kLengthMismatch)) {
        return false;
    }

    auto oversized = valid;
    oversized[8] = 1;
    oversized[9] = 0;
    oversized[10] = 0x10;
    oversized[11] = 0;
    if (!expect_status(oversized, PolicyPayloadStatus::kBodyTooLarge)) {
        return false;
    }

    auto invalid_body = valid;
    invalid_body[44] = 4;
    for (std::size_t index = 0; index < kInvalidBodyDigest.size(); ++index) {
        invalid_body[12 + index] = kInvalidBodyDigest[index];
    }
    return expect_status(invalid_body, PolicyPayloadStatus::kInvalidBody);
}
