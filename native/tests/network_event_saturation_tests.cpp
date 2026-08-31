#include "hook/event_sink.h"
#include "protocol/event_frame.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace {

constexpr std::uint16_t kNetworkViolationKind = 4;
constexpr std::uint16_t kEventsDroppedKind = 9;

std::uint16_t ReadU16(const std::uint8_t* bytes) noexcept {
    return static_cast<std::uint16_t>(bytes[0]) |
           static_cast<std::uint16_t>(bytes[1]) << 8U;
}

std::uint32_t ReadU32(const std::uint8_t* bytes) noexcept {
    return static_cast<std::uint32_t>(bytes[0]) |
           static_cast<std::uint32_t>(bytes[1]) << 8U |
           static_cast<std::uint32_t>(bytes[2]) << 16U |
           static_cast<std::uint32_t>(bytes[3]) << 24U;
}

std::uint64_t ReadU64(const std::uint8_t* bytes) noexcept {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < 8; ++index) {
        value |= static_cast<std::uint64_t>(bytes[index]) << (index * 8U);
    }
    return value;
}

bool ReadExact(
    const HANDLE pipe,
    std::uint8_t* const bytes,
    const std::size_t length) noexcept {
    std::size_t offset = 0;
    while (offset < length) {
        DWORD read = 0;
        if (!ReadFile(
                pipe, bytes + offset, static_cast<DWORD>(length - offset),
                &read, nullptr) ||
            read == 0) {
            return false;
        }
        offset += read;
    }
    return true;
}

}  // namespace

bool RunNetworkEventSaturationTests() {
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = FALSE;
    HANDLE read_pipe = nullptr;
    HANDLE write_pipe = nullptr;
    constexpr DWORD pipe_capacity = 4'096;
    if (!CreatePipe(
            &read_pipe, &write_pipe, &inheritable, pipe_capacity) ||
        bolt::hook::InitializeEventSink(write_pipe) !=
            bolt::hook::EventSinkStatus::kSuccess) {
        if (read_pipe != nullptr) {
            CloseHandle(read_pipe);
        }
        if (write_pipe != nullptr) {
            CloseHandle(write_pipe);
        }
        return false;
    }

    bolt::protocol::NetworkEndpoint endpoint{};
    endpoint.family = bolt::protocol::NetworkAddressFamily::kIpv4;
    endpoint.address[0] = 203;
    endpoint.address[1] = 0;
    endpoint.address[2] = 113;
    endpoint.address[3] = 7;
    endpoint.port = 443;
    constexpr std::size_t attempts = 50'000;
    std::size_t queued = 0;
    const ULONGLONG producer_started = GetTickCount64();
    for (std::size_t index = 0; index < attempts; ++index) {
        if (bolt::hook::TryReportNetworkViolation(
                bolt::protocol::NetworkOperation::kConnect, endpoint)) {
            ++queued;
        }
    }
    const ULONGLONG producer_elapsed = GetTickCount64() - producer_started;

    std::size_t network_frames = 0;
    std::uint64_t dropped_count = 0;
    bool first_preserved = false;
    const ULONGLONG deadline = GetTickCount64() + 5'000;
    while (GetTickCount64() < deadline) {
        DWORD available = 0;
        if (!PeekNamedPipe(
                read_pipe, nullptr, 0, nullptr, &available, nullptr)) {
            break;
        }
        if (available < bolt::protocol::kEventHeaderLength) {
            if (bolt::hook::WaitForEventSinkIdle(0)) {
                break;
            }
            Sleep(1);
            continue;
        }
        std::array<std::uint8_t, bolt::protocol::kEventHeaderLength> header{};
        if (!ReadExact(read_pipe, header.data(), header.size())) {
            break;
        }
        const std::uint16_t kind = ReadU16(header.data() + 6);
        const std::size_t payload_length = ReadU32(header.data() + 8);
        std::vector<std::uint8_t> frame(header.begin(), header.end());
        frame.resize(header.size() + payload_length);
        if (!ReadExact(
                read_pipe, frame.data() + header.size(), payload_length)) {
            break;
        }
        if (kind == kNetworkViolationKind) {
            ++network_frames;
            if (network_frames == 1) {
                std::array<
                    std::uint8_t,
                    bolt::protocol::kIpv4NetworkViolationFrameLength>
                    expected{};
                std::size_t written = 0;
                first_preserved = frame.size() == expected.size() &&
                    bolt::protocol::EncodeNetworkViolationFrame(
                        GetCurrentProcessId(),
                        bolt::protocol::NetworkOperation::kConnect, endpoint,
                        1, expected.data(), expected.size(), written) ==
                        bolt::protocol::FrameEncodeStatus::kSuccess &&
                    written == expected.size() &&
                    std::equal(frame.begin(), frame.end(), expected.begin());
            }
        } else if (kind == kEventsDroppedKind && payload_length == 12) {
            dropped_count = ReadU64(
                frame.data() + bolt::protocol::kEventHeaderLength + 4);
        }
    }

    const bool idle = bolt::hook::WaitForEventSinkIdle(1'000);
    CloseHandle(read_pipe);
    const bool passed = producer_elapsed < 2'000 && queued < attempts &&
        queued == network_frames && dropped_count == attempts - queued &&
        dropped_count != 0 && first_preserved && idle;
    if (!passed) {
        std::fprintf(
            stderr,
            "network saturation failed: elapsed=%llu queued=%zu frames=%zu "
            "dropped=%llu first=%d idle=%d\n",
            static_cast<unsigned long long>(producer_elapsed), queued,
            network_frames, static_cast<unsigned long long>(dropped_count),
            first_preserved ? 1 : 0, idle ? 1 : 0);
    }
    return passed;
}
