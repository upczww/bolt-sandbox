#include "common/immutable_policy_mapping.h"

#include <array>
#include <cstdint>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

bool RunPolicyMappingTests() {
    constexpr std::array<std::uint8_t, 54> payload = {
        0x42, 0x4c, 0x50, 0x31, 0x01, 0x00, 0x2c, 0x00, 0x0a, 0x00, 0x00, 0x00,
        0x0c, 0xee, 0x19, 0x24, 0xbb, 0x11, 0x38, 0x05, 0x95, 0x58, 0xbc, 0x22,
        0x1f, 0x5a, 0x7a, 0x1c, 0xf1, 0x59, 0x59, 0x20, 0x23, 0x31, 0x0c, 0x7d,
        0x00, 0xcd, 0xa8, 0x2e, 0xed, 0x90, 0xbb, 0xeb, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    };

    bolt::common::ImmutablePolicyMapping mapping;
    if (bolt::common::ImmutablePolicyMapping::Create(
            payload.data(), payload.size(), mapping) !=
            bolt::common::PolicyMappingStatus::kSuccess ||
        mapping.Validate() != bolt::common::PolicyMappingStatus::kSuccess) {
        return false;
    }

    DWORD handle_flags = 0;
    if (!GetHandleInformation(mapping.handle(), &handle_flags) ||
        (handle_flags & HANDLE_FLAG_INHERIT) == 0) {
        return false;
    }
    void* writable = MapViewOfFile(mapping.handle(), FILE_MAP_WRITE, 0, 0, payload.size());
    if (writable != nullptr) {
        UnmapViewOfFile(writable);
        return false;
    }

    auto tampered = payload;
    tampered.back() ^= 1;
    bolt::common::ImmutablePolicyMapping rejected;
    return bolt::common::ImmutablePolicyMapping::Create(
               tampered.data(), tampered.size(), rejected) ==
               bolt::common::PolicyMappingStatus::kInvalidPayload &&
           rejected.handle() == nullptr;
}
