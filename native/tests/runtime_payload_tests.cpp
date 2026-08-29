#include "protocol/runtime_payload.h"

#include <array>
#include <cstdint>

bool RunRuntimePayloadTests() {
    bolt::protocol::RuntimePayload expected{};
    expected.target_process_id = 42;
    expected.policy_length = 54;
    expected.policy_handle = 0x111;
    expected.event_handle = 0x222;
    expected.release_handle = 0x333;
    expected.handshake_nonce.fill(0xA5);

    const auto encoded = bolt::protocol::EncodeRuntimePayload(expected);
    bolt::protocol::RuntimePayload decoded{};
    if (bolt::protocol::DecodeRuntimePayload(encoded.data(), encoded.size(), decoded) !=
            bolt::protocol::RuntimePayloadStatus::kSuccess ||
        decoded != expected) {
        return false;
    }

    auto invalid_magic = encoded;
    invalid_magic[0] ^= 0xFF;
    if (bolt::protocol::DecodeRuntimePayload(
            invalid_magic.data(), invalid_magic.size(), decoded) !=
        bolt::protocol::RuntimePayloadStatus::kInvalidMagic) {
        return false;
    }
    return bolt::protocol::DecodeRuntimePayload(encoded.data(), encoded.size() - 1, decoded) ==
               bolt::protocol::RuntimePayloadStatus::kInvalidLength &&
           bolt::protocol::DecodeRuntimePayload(nullptr, encoded.size(), decoded) ==
               bolt::protocol::RuntimePayloadStatus::kInvalidArgument;
}
