#include "protocol/inherited_handle_payload.h"

#include <cstdint>
#include <vector>

bool RunInheritedHandlePayloadTests() {
    const std::vector<std::uint64_t> expected = {0x111, 0x222, 0x333};
    const auto encoded =
        bolt::protocol::EncodeInheritedHandlePayload(expected);
    std::vector<std::uint64_t> decoded;
    if (bolt::protocol::DecodeInheritedHandlePayload(
            encoded.data(), encoded.size(), decoded) !=
            bolt::protocol::InheritedHandlePayloadStatus::kSuccess ||
        decoded != expected) {
        return false;
    }

    const auto empty = bolt::protocol::EncodeInheritedHandlePayload({});
    if (bolt::protocol::DecodeInheritedHandlePayload(
            empty.data(), empty.size(), decoded) !=
            bolt::protocol::InheritedHandlePayloadStatus::kSuccess ||
        !decoded.empty()) {
        return false;
    }

    auto invalid_magic = encoded;
    invalid_magic[0] ^= 0xff;
    auto invalid_count = encoded;
    invalid_count[8] = 0xff;
    auto invalid_handle = encoded;
    for (std::size_t index = 16; index < 24; ++index) {
        invalid_handle[index] = 0;
    }
    auto trailing = encoded;
    trailing.push_back(0);
    std::vector<std::uint64_t> excessive(
        bolt::protocol::kMaximumInheritedHandleCount + 1, 1);

    return bolt::protocol::DecodeInheritedHandlePayload(
               nullptr, encoded.size(), decoded) ==
               bolt::protocol::InheritedHandlePayloadStatus::kInvalidArgument &&
           bolt::protocol::DecodeInheritedHandlePayload(
               encoded.data(), encoded.size() - 1, decoded) ==
               bolt::protocol::InheritedHandlePayloadStatus::kInvalidLength &&
           bolt::protocol::DecodeInheritedHandlePayload(
               trailing.data(), trailing.size(), decoded) ==
               bolt::protocol::InheritedHandlePayloadStatus::kInvalidLength &&
           bolt::protocol::DecodeInheritedHandlePayload(
               invalid_magic.data(), invalid_magic.size(), decoded) ==
               bolt::protocol::InheritedHandlePayloadStatus::kInvalidMagic &&
           bolt::protocol::DecodeInheritedHandlePayload(
               invalid_count.data(), invalid_count.size(), decoded) ==
               bolt::protocol::InheritedHandlePayloadStatus::kInvalidCount &&
           bolt::protocol::DecodeInheritedHandlePayload(
               invalid_handle.data(), invalid_handle.size(), decoded) ==
               bolt::protocol::InheritedHandlePayloadStatus::kInvalidHandle &&
           bolt::protocol::EncodeInheritedHandlePayload(excessive).empty();
}
