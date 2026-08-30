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
    expected.descendant_ready_handle = 0x444;
    expected.handshake_nonce.fill(0xA5);
    expected.dns_request_handle = 0x555;
    expected.dns_response_handle = 0x666;
    expected.dns_authentication_key.fill(0x5A);
    expected.dns_maximum_frame_length = 1'024;
    expected.tcp_proxy_port = 32'123;
    expected.tcp_proxy_ipv6_port = 32'124;

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

    auto invalid_descendant_ready_handle = encoded;
    for (std::size_t index = 40; index < 48; ++index) {
        invalid_descendant_ready_handle[index] = 0xFF;
    }
    if (bolt::protocol::DecodeRuntimePayload(
            invalid_descendant_ready_handle.data(),
            invalid_descendant_ready_handle.size(), decoded) !=
        bolt::protocol::RuntimePayloadStatus::kInvalidHandle) {
        return false;
    }

    expected.descendant_ready_handle = 0;
    const auto initial_process_payload =
        bolt::protocol::EncodeRuntimePayload(expected);
    if (bolt::protocol::DecodeRuntimePayload(
            initial_process_payload.data(), initial_process_payload.size(), decoded) !=
            bolt::protocol::RuntimePayloadStatus::kSuccess ||
        decoded != expected) {
        return false;
    }
    auto incomplete_proxy = expected;
    incomplete_proxy.tcp_proxy_port = 0;
    const auto incomplete_proxy_bytes =
        bolt::protocol::EncodeRuntimePayload(incomplete_proxy);
    if (bolt::protocol::DecodeRuntimePayload(
            incomplete_proxy_bytes.data(), incomplete_proxy_bytes.size(),
            decoded) !=
        bolt::protocol::RuntimePayloadStatus::kInvalidDnsProxy) {
        return false;
    }
    incomplete_proxy = expected;
    incomplete_proxy.tcp_proxy_ipv6_port = 0;
    const auto incomplete_ipv6_bytes =
        bolt::protocol::EncodeRuntimePayload(incomplete_proxy);
    if (bolt::protocol::DecodeRuntimePayload(
            incomplete_ipv6_bytes.data(), incomplete_ipv6_bytes.size(),
            decoded) !=
        bolt::protocol::RuntimePayloadStatus::kInvalidDnsProxy) {
        return false;
    }
    return bolt::protocol::DecodeRuntimePayload(encoded.data(), encoded.size() - 1, decoded) ==
               bolt::protocol::RuntimePayloadStatus::kInvalidLength &&
           bolt::protocol::DecodeRuntimePayload(nullptr, encoded.size(), decoded) ==
               bolt::protocol::RuntimePayloadStatus::kInvalidArgument;
}
