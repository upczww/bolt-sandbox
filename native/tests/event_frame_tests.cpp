#include "protocol/event_frame.h"

#include <array>
#include <cstdint>

bool RunEventFrameTests() {
    constexpr std::array<std::uint8_t, 16> nonce = {
        0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
        0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
    };
    constexpr std::array<std::uint8_t, 40> golden = {
        0x42, 0x4C, 0x54, 0x31,  // magic
        0x01, 0x00,              // version
        0x01, 0x00,              // Ready
        0x10, 0x00, 0x00, 0x00,  // payload length
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // sequence
        0x29, 0xC3, 0xD4, 0x29,                          // CRC-32
        0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
        0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
    };

    const auto encoded = bolt::protocol::EncodeReadyFrame(nonce);
    if (encoded != golden ||
        bolt::protocol::ValidateReadyFrame(encoded.data(), encoded.size(), nonce) !=
            bolt::protocol::ReadyFrameStatus::kSuccess) {
        return false;
    }

    auto tampered = encoded;
    tampered.back() ^= 0xFF;
    if (bolt::protocol::ValidateReadyFrame(tampered.data(), tampered.size(), nonce) !=
        bolt::protocol::ReadyFrameStatus::kChecksumMismatch) {
        return false;
    }

    auto wrong_sequence = encoded;
    wrong_sequence[12] = 1;
    bolt::protocol::RewriteFrameChecksum(wrong_sequence.data(), wrong_sequence.size());
    if (bolt::protocol::ValidateReadyFrame(
            wrong_sequence.data(), wrong_sequence.size(), nonce) !=
        bolt::protocol::ReadyFrameStatus::kUnexpectedSequence) {
        return false;
    }

    auto wrong_nonce = nonce;
    wrong_nonce[0] ^= 0xFF;
    return bolt::protocol::ValidateReadyFrame(encoded.data(), encoded.size(), wrong_nonce) ==
               bolt::protocol::ReadyFrameStatus::kNonceMismatch &&
           bolt::protocol::ValidateReadyFrame(encoded.data(), encoded.size() - 1, nonce) ==
               bolt::protocol::ReadyFrameStatus::kInvalidLength &&
           bolt::protocol::ValidateReadyFrame(nullptr, encoded.size(), nonce) ==
               bolt::protocol::ReadyFrameStatus::kInvalidArgument;
}
