#include "protocol/launcher_control.h"
#include "protocol/launcher_startup.h"
#include "protocol/launcher_transport.h"

#include <algorithm>

bool RunLauncherStartupTests() {
    const auto cancel = bolt::protocol::EncodeLauncherControl(
        bolt::protocol::LauncherControlKind::kCancel);
    bolt::protocol::LauncherControlKind decoded_control{};
    if (cancel != std::array<std::uint8_t, 8>{
                      'B', 'L', 'C', '1', 1, 0, 1, 0} ||
        bolt::protocol::DecodeLauncherControl(
            cancel.data(), cancel.size(), decoded_control) !=
            bolt::protocol::LauncherControlStatus::kSuccess ||
        decoded_control != bolt::protocol::LauncherControlKind::kCancel) {
        return false;
    }

    std::array<std::uint8_t, bolt::protocol::kLauncherTransportHeaderLength>
        transport_header{};
    if (bolt::protocol::EncodeLauncherTransportHeader(
            bolt::protocol::LauncherTransportKind::kStdout, 3,
            transport_header) !=
            bolt::protocol::LauncherTransportStatus::kSuccess ||
        transport_header !=
            std::array<std::uint8_t, 12>{
                'B', 'L', 'X', '1', 1, 0, 1, 0, 3, 0, 0, 0}) {
        return false;
    }
    bolt::protocol::LauncherTransportKind transport_kind{};
    std::uint32_t transport_length = 0;
    if (bolt::protocol::DecodeLauncherTransportHeader(
            transport_header.data(), transport_header.size(), transport_kind,
            transport_length) !=
            bolt::protocol::LauncherTransportStatus::kSuccess ||
        transport_kind != bolt::protocol::LauncherTransportKind::kStdout ||
        transport_length != 3) {
        return false;
    }
    transport_header[6] = 99;
    if (bolt::protocol::DecodeLauncherTransportHeader(
            transport_header.data(), transport_header.size(), transport_kind,
            transport_length) !=
        bolt::protocol::LauncherTransportStatus::kUnknownKind) {
        return false;
    }

    bolt::protocol::LauncherStartRequest expected{};
    expected.program = L"C:\\tool.exe";
    expected.cwd = L"C:\\work";
    expected.command_line = {
        L't', L'o', L'o', L'l', L' ', L'a', L'r', L'g', L'\0'};
    expected.environment_block = {L'A', L'=', L'B', L'\0', L'\0'};
    expected.policy = {'p', 'o', 'l', 'i', 'c', 'y'};
    expected.hook_path = L"C:\\hook.dll";
    expected.has_timeout = true;
    expected.timeout_milliseconds = 5'000;
    expected.nonce.fill(0xA5);

    auto truncated_command = expected;
    truncated_command.command_line = {
        L't', L'o', L'o', L'l', L'\0', L'h', L'i', L'd', L'd', L'e', L'n',
        L'\0'};
    std::vector<std::uint8_t> rejected;
    if (bolt::protocol::EncodeLauncherStartRequest(
            truncated_command, rejected) !=
        bolt::protocol::LauncherStartStatus::kInvalidField) {
        return false;
    }

    std::vector<std::uint8_t> encoded;
    bolt::protocol::LauncherStartRequest decoded{};
    if (bolt::protocol::EncodeLauncherStartRequest(expected, encoded) !=
            bolt::protocol::LauncherStartStatus::kSuccess ||
        bolt::protocol::DecodeLauncherStartRequest(
            encoded.data(), encoded.size(), decoded) !=
            bolt::protocol::LauncherStartStatus::kSuccess ||
        !(decoded == expected)) {
        return false;
    }

    auto tampered = encoded;
    tampered.back() ^= 1;
    if (bolt::protocol::DecodeLauncherStartRequest(
            tampered.data(), tampered.size(), decoded) !=
        bolt::protocol::LauncherStartStatus::kDigestMismatch) {
        return false;
    }
    auto invalid_flags = encoded;
    invalid_flags[60] = 2;
    return bolt::protocol::DecodeLauncherStartRequest(
               invalid_flags.data(), invalid_flags.size(), decoded) ==
           bolt::protocol::LauncherStartStatus::kInvalidFlags;
}
