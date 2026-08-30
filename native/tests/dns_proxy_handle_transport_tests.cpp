#include "hook/network/dns_proxy_handle_transport.h"

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace {

bool WriteExact(HANDLE handle, const std::uint8_t* bytes, std::size_t length) {
    DWORD written = 0;
    return WriteFile(handle, bytes, static_cast<DWORD>(length), &written, nullptr) &&
           written == length;
}

}  // namespace

bool RunDnsProxyHandleTransportTests() {
    HANDLE input_read = nullptr;
    HANDLE input_write = nullptr;
    HANDLE output_read = nullptr;
    HANDLE output_write = nullptr;
    if (!CreatePipe(&input_read, &input_write, nullptr, 0) ||
        !CreatePipe(&output_read, &output_write, nullptr, 0)) {
        return false;
    }
    std::unique_ptr<bolt::network::DnsProxyHandleTransport> transport;
    if (bolt::network::DnsProxyHandleTransport::Create(
            input_read, output_write, 512, transport) !=
            bolt::network::HandleTransportStatus::kSuccess) {
        return false;
    }
    std::unique_ptr<bolt::network::DnsProxyHandleTransport> invalid_maximum;
    const bool invalid_maximum_rejected =
        bolt::network::DnsProxyHandleTransport::Create(
            input_read, output_write, 0, invalid_maximum) ==
        bolt::network::HandleTransportStatus::kInvalidMaximumFrame;
    const std::array<std::uint8_t, 4> prefix = {3, 0, 0, 0};
    const std::array<std::uint8_t, 3> payload = {1, 2, 3};
    if (!WriteExact(input_write, prefix.data(), prefix.size()) ||
        !WriteExact(input_write, payload.data(), payload.size())) {
        return false;
    }
    std::vector<std::uint8_t> frame;
    if (transport->ReadFrame(frame) != bolt::network::TransportReadStatus::kFrame ||
        frame != std::vector<std::uint8_t>(payload.begin(), payload.end()) ||
        !transport->WriteFrame(frame)) {
        return false;
    }
    std::array<std::uint8_t, 7> output{};
    DWORD read = 0;
    if (!ReadFile(output_read, output.data(), static_cast<DWORD>(output.size()), &read, nullptr) ||
        read != output.size() ||
        output != std::array<std::uint8_t, 7>{3, 0, 0, 0, 1, 2, 3}) {
        return false;
    }
    CloseHandle(input_write);
    const bool eof = transport->ReadFrame(frame) == bolt::network::TransportReadStatus::kEof;
    CloseHandle(input_read);
    CloseHandle(output_read);
    CloseHandle(output_write);
    HANDLE oversized_read = nullptr;
    HANDLE oversized_write = nullptr;
    if (!CreatePipe(&oversized_read, &oversized_write, nullptr, 0)) {
        return false;
    }
    std::unique_ptr<bolt::network::DnsProxyHandleTransport> oversized_transport;
    const std::array<std::uint8_t, 4> oversized_prefix = {1, 2, 0, 0};
    const bool oversized_rejected =
        bolt::network::DnsProxyHandleTransport::Create(
            oversized_read, oversized_write, 512, oversized_transport) ==
            bolt::network::HandleTransportStatus::kSuccess &&
        WriteExact(
            oversized_write, oversized_prefix.data(), oversized_prefix.size()) &&
        oversized_transport->ReadFrame(frame) ==
            bolt::network::TransportReadStatus::kFailure;
    CloseHandle(oversized_read);
    CloseHandle(oversized_write);
    std::unique_ptr<bolt::network::DnsProxyHandleTransport> invalid;
    return eof && oversized_rejected && invalid_maximum_rejected &&
           bolt::network::DnsProxyHandleTransport::Create(
                      INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE, 512, invalid) ==
                      bolt::network::HandleTransportStatus::kInvalidHandle;
}
