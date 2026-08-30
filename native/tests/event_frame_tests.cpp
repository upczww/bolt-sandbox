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

    constexpr std::array<std::uint8_t, 29> process_golden = {
        0x42, 0x4C, 0x54, 0x31, 0x01, 0x00, 0x08, 0x00,
        0x05, 0x00, 0x00, 0x00, 0x69, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xF2, 0x27, 0xEE, 0x7B,
        0x04, 0x03, 0x02, 0x01, 0x00,
    };
    std::array<std::uint8_t, process_golden.size()> process_frame{};
    std::size_t process_length = 0;
    if (bolt::protocol::EncodeProcessViolationFrame(
            0x01020304U,
            bolt::protocol::ProcessOperation::kCreateWithToken, 105,
            process_frame.data(), process_frame.size(), process_length) !=
            bolt::protocol::FrameEncodeStatus::kSuccess ||
        process_length != process_frame.size() ||
        process_frame != process_golden) {
        return false;
    }

    std::array<std::uint8_t, process_golden.size()> invalid_process_frame{};
    std::size_t invalid_process_length = 1;
    if (bolt::protocol::EncodeProcessViolationFrame(
            1, static_cast<bolt::protocol::ProcessOperation>(0xFF), 1,
            invalid_process_frame.data(), invalid_process_frame.size(),
            invalid_process_length) !=
            bolt::protocol::FrameEncodeStatus::kInvalidOperation ||
        invalid_process_length != 0 ||
        bolt::protocol::EncodeProcessViolationFrame(
            1, bolt::protocol::ProcessOperation::kCreateWithToken, 1, nullptr,
            invalid_process_frame.size(), invalid_process_length) !=
            bolt::protocol::FrameEncodeStatus::kInvalidArgument ||
        bolt::protocol::EncodeProcessViolationFrame(
            1, bolt::protocol::ProcessOperation::kCreateWithToken, 1,
            invalid_process_frame.data(), invalid_process_frame.size() - 1,
            invalid_process_length) !=
            bolt::protocol::FrameEncodeStatus::kInsufficientBuffer) {
        return false;
    }

    bolt::protocol::NetworkEndpoint ipv4_endpoint{};
    ipv4_endpoint.family = bolt::protocol::NetworkAddressFamily::kIpv4;
    ipv4_endpoint.address[0] = 127;
    ipv4_endpoint.address[1] = 0;
    ipv4_endpoint.address[2] = 0;
    ipv4_endpoint.address[3] = 1;
    ipv4_endpoint.port = 8'443;
    std::array<std::uint8_t, bolt::protocol::kIpv4NetworkViolationFrameLength>
        network_frame{};
    std::array<std::uint8_t, bolt::protocol::kIpv4NetworkViolationFrameLength>
        expected_network_frame = {
            0x42, 0x4C, 0x54, 0x31, 0x01, 0x00, 0x04, 0x00,
            0x0C, 0x00, 0x00, 0x00, 0x6A, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x04, 0x03, 0x02, 0x01, 0x01, 0x04, 0x7F, 0x00,
            0x00, 0x01, 0xFB, 0x20,
        };
    bolt::protocol::RewriteFrameChecksum(
        expected_network_frame.data(), expected_network_frame.size());
    std::size_t network_length = 0;
    if (bolt::protocol::EncodeNetworkViolationFrame(
            0x01020304U, bolt::protocol::NetworkOperation::kConnect,
            ipv4_endpoint, 106, network_frame.data(), network_frame.size(),
            network_length) != bolt::protocol::FrameEncodeStatus::kSuccess ||
        network_length != network_frame.size() ||
        network_frame != expected_network_frame) {
        return false;
    }

    bolt::protocol::NetworkEndpoint invalid_endpoint = ipv4_endpoint;
    invalid_endpoint.family =
        static_cast<bolt::protocol::NetworkAddressFamily>(0xFF);
    if (bolt::protocol::EncodeNetworkViolationFrame(
            1, bolt::protocol::NetworkOperation::kConnect, invalid_endpoint, 1,
            network_frame.data(), network_frame.size(), network_length) !=
            bolt::protocol::FrameEncodeStatus::kInvalidAddress ||
        network_length != 0 ||
        bolt::protocol::EncodeNetworkViolationFrame(
            1, static_cast<bolt::protocol::NetworkOperation>(0xFF), ipv4_endpoint,
            1, network_frame.data(), network_frame.size(), network_length) !=
            bolt::protocol::FrameEncodeStatus::kInvalidOperation) {
        return false;
    }

    constexpr std::array<std::uint8_t, 43> domain_network_payload = {
        0x42, 0x4C, 0x54, 0x31, 0x01, 0x00, 0x04, 0x00,
        0x13, 0x00, 0x00, 0x00, 0x6B, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x03, 0x02, 0x01, 0x00, 0x00, 0x09, 0x00,
        0x00, 0x00, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x68,
        0x6F, 0x73, 0x74,
    };
    auto expected_domain_network_frame = domain_network_payload;
    bolt::protocol::RewriteFrameChecksum(
        expected_domain_network_frame.data(),
        expected_domain_network_frame.size());
    std::array<std::uint8_t, domain_network_payload.size()>
        domain_network_frame{};
    std::size_t domain_network_length = 0;
    if (bolt::protocol::DomainNetworkViolationFrameLength("localhost") !=
            domain_network_frame.size() ||
        bolt::protocol::EncodeDomainNetworkViolationFrame(
            0x01020304U, bolt::protocol::NetworkOperation::kResolve,
            "localhost", 107, domain_network_frame.data(),
            domain_network_frame.size(), domain_network_length) !=
            bolt::protocol::FrameEncodeStatus::kSuccess ||
        domain_network_length != domain_network_frame.size() ||
        domain_network_frame != expected_domain_network_frame ||
        bolt::protocol::DomainNetworkViolationFrameLength("") != 0 ||
        bolt::protocol::DomainNetworkViolationFrameLength("bad\nname") != 0 ||
        bolt::protocol::EncodeDomainNetworkViolationFrame(
            1, bolt::protocol::NetworkOperation::kResolve, "", 1,
            domain_network_frame.data(), domain_network_frame.size(),
            domain_network_length) !=
            bolt::protocol::FrameEncodeStatus::kInvalidDomain) {
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
