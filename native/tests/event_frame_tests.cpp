#include "protocol/event_frame.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

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
    if (bolt::protocol::ValidateReadyFrame(encoded.data(), encoded.size(), wrong_nonce) !=
               bolt::protocol::ReadyFrameStatus::kNonceMismatch ||
        bolt::protocol::ValidateReadyFrame(encoded.data(), encoded.size() - 1, nonce) !=
               bolt::protocol::ReadyFrameStatus::kInvalidLength ||
        bolt::protocol::ValidateReadyFrame(nullptr, encoded.size(), nonce) !=
            bolt::protocol::ReadyFrameStatus::kInvalidArgument) {
        return false;
    }

    constexpr std::array<std::uint8_t, 41> filesystem_golden = {
        0x42, 0x4C, 0x54, 0x31, 0x01, 0x00, 0x02, 0x00,
        0x11, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x78, 0xED, 0xED, 0x77,
        0x04, 0x03, 0x02, 0x01, 0x04, 0x04, 0x00, 0x00,
        0x00, 0x43, 0x00, 0x3A, 0x00, 0x5C, 0x00, 0x78,
        0x00,
    };
    std::array<std::uint8_t, filesystem_golden.size()> filesystem_frame{};
    std::size_t filesystem_length = 0;
    if (bolt::protocol::EncodeFilesystemViolationFrame(
            0x01020304U, bolt::protocol::FilesystemOperation::kDelete, L"C:\\x", 7,
            filesystem_frame.data(), filesystem_frame.size(), filesystem_length) !=
            bolt::protocol::FrameEncodeStatus::kSuccess ||
        filesystem_length != filesystem_frame.size() ||
        filesystem_frame != filesystem_golden) {
        return false;
    }

    std::wstring maximum_path(32'767, L'x');
    std::array<std::uint8_t, 1> too_small{};
    return bolt::protocol::FilesystemViolationFrameLength(maximum_path.c_str()) ==
               bolt::protocol::kEventHeaderLength + 9U + maximum_path.size() * 2U &&
           bolt::protocol::EncodeFilesystemViolationFrame(
               1, bolt::protocol::FilesystemOperation::kWrite, L"", 1, too_small.data(),
               too_small.size(), filesystem_length) ==
               bolt::protocol::FrameEncodeStatus::kInvalidPath &&
           bolt::protocol::EncodeFilesystemViolationFrame(
               1, bolt::protocol::FilesystemOperation::kWrite, maximum_path.c_str(), 1,
               too_small.data(), too_small.size(), filesystem_length) ==
               bolt::protocol::FrameEncodeStatus::kInsufficientBuffer;
}
