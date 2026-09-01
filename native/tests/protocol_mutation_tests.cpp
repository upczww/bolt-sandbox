#include "protocol/event_frame.h"
#include "protocol/launcher_control.h"
#include "protocol/launcher_startup.h"
#include "protocol/launcher_transport.h"
#include "protocol/policy_payload.h"
#include "protocol/recovery_protocol.h"
#include "protocol/runtime_payload.h"
#include "protocol/version.h"
#include "tests/policy_fixture.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>

namespace {

constexpr std::size_t kMaximumMutationCases = 4'096;

std::vector<std::vector<std::uint8_t>> Mutations(
    const std::vector<std::uint8_t>& seed) {
    std::vector<std::vector<std::uint8_t>> cases;
    cases.reserve((std::min)(
        kMaximumMutationCases, seed.size() * 3 + seed.size() + 8));
    for (std::size_t length = 0;
         length <= seed.size() && cases.size() < kMaximumMutationCases;
         ++length) {
        cases.emplace_back(seed.begin(), seed.begin() + length);
    }
    for (std::size_t offset = 0;
         offset < seed.size() && cases.size() < kMaximumMutationCases;
         ++offset) {
        for (const std::uint8_t mask :
             std::array<std::uint8_t, 3>{0x01U, 0x80U, 0xffU}) {
            auto mutated = seed;
            mutated[offset] ^= mask;
            cases.push_back(std::move(mutated));
            if (cases.size() == kMaximumMutationCases) {
                break;
            }
        }
    }
    for (const std::size_t suffix_length : {1U, 2U, 4U, 8U, 16U}) {
        if (cases.size() == kMaximumMutationCases) {
            break;
        }
        auto mutated = seed;
        mutated.insert(mutated.end(), suffix_length, 0xffU);
        cases.push_back(std::move(mutated));
    }
    return cases;
}

template <typename Parser>
bool RunCampaign(
    const std::vector<std::uint8_t>& seed,
    Parser&& parser) noexcept {
    if (seed.empty()) {
        return false;
    }
    try {
        const auto cases = Mutations(seed);
        if (cases.empty() || cases.size() > kMaximumMutationCases) {
            return false;
        }
        for (const auto& input : cases) {
            parser(input.data(), input.size());
        }
        parser(nullptr, seed.size());
        return true;
    } catch (...) {
        return false;
    }
}

template <typename T>
void Write(
    std::vector<std::uint8_t>& output,
    const std::size_t offset,
    const T value) noexcept {
    std::memcpy(output.data() + offset, &value, sizeof(value));
}

std::vector<std::uint8_t> LauncherSeed() {
    bolt::protocol::LauncherStartRequest request{};
    request.program = L"C:\\tool.exe";
    request.cwd = L"C:\\work";
    request.command_line = {L't', L'o', L'o', L'l', L'\0'};
    request.environment_block = {L'A', L'=', L'B', L'\0', L'\0'};
    request.policy = {'p', 'o', 'l', 'i', 'c', 'y'};
    request.hook_path = L"C:\\hook.dll";
    request.has_timeout = true;
    request.timeout_milliseconds = 5'000;
    request.nonce.fill(0xa5U);
    std::vector<std::uint8_t> encoded;
    if (bolt::protocol::EncodeLauncherStartRequest(request, encoded) !=
        bolt::protocol::LauncherStartStatus::kSuccess) {
        return {};
    }
    return encoded;
}

std::vector<std::uint8_t> RuntimeSeed() {
    bolt::protocol::RuntimePayload payload{};
    payload.target_process_id = 42;
    payload.policy_length = 54;
    payload.policy_handle = 0x111;
    payload.event_handle = 0x222;
    payload.release_handle = 0x333;
    payload.handshake_nonce.fill(0xa5U);
    const auto encoded = bolt::protocol::EncodeRuntimePayload(payload);
    return {encoded.begin(), encoded.end()};
}

std::vector<std::uint8_t> RecoveryResponseSeed() {
    std::vector<std::uint8_t> encoded(
        bolt::protocol::kRecoveryResponseLength, 0);
    std::memcpy(encoded.data(), "BRP1", 4);
    Write(encoded, 4, bolt::protocol::kProtocolVersion);
    Write(
        encoded, 6,
        static_cast<std::uint16_t>(
            bolt::protocol::kRecoveryResponseLength));
    Write(
        encoded, 8,
        static_cast<std::uint32_t>(
            bolt::protocol::kRecoveryResponseLength));
    Write(encoded, 12, std::uint64_t{1});
    Write(encoded, 24, std::uint64_t{1});
    return encoded;
}

}  // namespace

bool RunProtocolMutationTests() {
    const auto policy = bolt::tests::SealPolicy({
        {bolt::tests::FilesystemRuleKind::kReadWrite, L"C:\\work"}});
    const auto ready_array = bolt::protocol::EncodeReadyFrame({
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});
    const std::vector<std::uint8_t> ready(
        ready_array.begin(), ready_array.end());
    const auto control_array = bolt::protocol::EncodeLauncherControl(
        bolt::protocol::LauncherControlKind::kCancel);
    const std::vector<std::uint8_t> control(
        control_array.begin(), control_array.end());
    std::array<
        std::uint8_t,
        bolt::protocol::kLauncherTransportHeaderLength> transport_array{};
    if (bolt::protocol::EncodeLauncherTransportHeader(
            bolt::protocol::LauncherTransportKind::kStdout, 16,
            transport_array) !=
        bolt::protocol::LauncherTransportStatus::kSuccess) {
        return false;
    }
    const std::vector<std::uint8_t> transport(
        transport_array.begin(), transport_array.end());

    return RunCampaign(policy, [](const std::uint8_t* bytes, const std::size_t length) {
               static_cast<void>(
                   bolt::protocol::ValidatePolicyPayload(bytes, length));
           }) &&
           RunCampaign(ready, [](const std::uint8_t* bytes, const std::size_t length) {
               static_cast<void>(
                   bolt::protocol::ValidateEventFrame(bytes, length));
           }) &&
           RunCampaign(LauncherSeed(), [](const std::uint8_t* bytes, const std::size_t length) {
               bolt::protocol::LauncherStartRequest decoded{};
               static_cast<void>(bolt::protocol::DecodeLauncherStartRequest(
                   bytes, length, decoded));
           }) &&
           RunCampaign(RuntimeSeed(), [](const std::uint8_t* bytes, const std::size_t length) {
               bolt::protocol::RuntimePayload decoded{};
               static_cast<void>(bolt::protocol::DecodeRuntimePayload(
                   bytes, length, decoded));
           }) &&
           RunCampaign(RecoveryResponseSeed(), [](const std::uint8_t* bytes, const std::size_t length) {
               bolt::protocol::RecoveryResponse decoded{};
               static_cast<void>(bolt::protocol::DecodeRecoveryResponse(
                   bytes, length, decoded));
           }) &&
           RunCampaign(control, [](const std::uint8_t* bytes, const std::size_t length) {
               bolt::protocol::LauncherControlKind decoded{};
               static_cast<void>(bolt::protocol::DecodeLauncherControl(
                   bytes, length, decoded));
           }) &&
           RunCampaign(transport, [](const std::uint8_t* bytes, const std::size_t length) {
               bolt::protocol::LauncherTransportKind kind{};
               std::uint32_t payload_length = 0;
               static_cast<void>(
                   bolt::protocol::DecodeLauncherTransportHeader(
                       bytes, length, kind, payload_length));
           });
}
