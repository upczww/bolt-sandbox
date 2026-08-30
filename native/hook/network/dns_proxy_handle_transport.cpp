#include "hook/network/dns_proxy_handle_transport.h"

#include <array>
#include <limits>
#include <new>

namespace bolt::network {
namespace {

constexpr std::size_t kAbsoluteMaximumFrameLength = 1'048'576;

bool ValidHandle(const HANDLE handle) noexcept {
    DWORD flags = 0;
    return handle != nullptr && handle != INVALID_HANDLE_VALUE &&
           GetHandleInformation(handle, &flags) != FALSE;
}

bool ReadExact(
    const HANDLE handle,
    std::uint8_t* bytes,
    const std::size_t length,
    std::size_t& completed) noexcept {
    completed = 0;
    while (completed < length) {
        DWORD read = 0;
        if (!ReadFile(
                handle, bytes + completed, static_cast<DWORD>(length - completed),
                &read, nullptr) || read == 0) {
            return false;
        }
        completed += read;
    }
    return true;
}

bool WriteExact(
    const HANDLE handle,
    const std::uint8_t* bytes,
    const std::size_t length) noexcept {
    std::size_t completed = 0;
    while (completed < length) {
        DWORD written = 0;
        if (!WriteFile(
                handle, bytes + completed,
                static_cast<DWORD>(length - completed), &written, nullptr) ||
            written == 0) {
            return false;
        }
        completed += written;
    }
    return true;
}

}  // namespace

DnsProxyHandleTransport::DnsProxyHandleTransport(
    const HANDLE read_handle,
    const HANDLE write_handle,
    const std::size_t maximum_frame_length) noexcept
    : read_handle_(read_handle),
      write_handle_(write_handle),
      maximum_frame_length_(maximum_frame_length) {}

HandleTransportStatus DnsProxyHandleTransport::Create(
    const HANDLE read_handle,
    const HANDLE write_handle,
    const std::size_t maximum_frame_length,
    std::unique_ptr<DnsProxyHandleTransport>& transport) noexcept {
    transport.reset();
    if (!ValidHandle(read_handle) || !ValidHandle(write_handle)) {
        return HandleTransportStatus::kInvalidHandle;
    }
    if (maximum_frame_length == 0 ||
        maximum_frame_length > kAbsoluteMaximumFrameLength ||
        maximum_frame_length > std::numeric_limits<DWORD>::max()) {
        return HandleTransportStatus::kInvalidMaximumFrame;
    }
    try {
        transport = std::unique_ptr<DnsProxyHandleTransport>(
            new DnsProxyHandleTransport(
                read_handle, write_handle, maximum_frame_length));
        return HandleTransportStatus::kSuccess;
    } catch (...) {
        return HandleTransportStatus::kAllocationFailed;
    }
}

TransportReadStatus DnsProxyHandleTransport::ReadFrame(
    std::vector<std::uint8_t>& frame) noexcept {
    frame.clear();
    std::array<std::uint8_t, 4> prefix{};
    std::size_t completed = 0;
    if (!ReadExact(read_handle_, prefix.data(), prefix.size(), completed)) {
        return completed == 0 ? TransportReadStatus::kEof
                              : TransportReadStatus::kFailure;
    }
    const std::size_t length = static_cast<std::size_t>(prefix[0]) |
                               (static_cast<std::size_t>(prefix[1]) << 8U) |
                               (static_cast<std::size_t>(prefix[2]) << 16U) |
                               (static_cast<std::size_t>(prefix[3]) << 24U);
    if (length == 0 || length > maximum_frame_length_) {
        return TransportReadStatus::kFailure;
    }
    try {
        frame.resize(length);
        if (!ReadExact(read_handle_, frame.data(), frame.size(), completed)) {
            frame.clear();
            return TransportReadStatus::kFailure;
        }
        return TransportReadStatus::kFrame;
    } catch (...) {
        frame.clear();
        return TransportReadStatus::kFailure;
    }
}

bool DnsProxyHandleTransport::WriteFrame(
    const std::vector<std::uint8_t>& frame) noexcept {
    if (frame.empty() || frame.size() > maximum_frame_length_ ||
        frame.size() > std::numeric_limits<std::uint32_t>::max()) {
        return false;
    }
    const std::uint32_t length = static_cast<std::uint32_t>(frame.size());
    const std::array<std::uint8_t, 4> prefix = {
        static_cast<std::uint8_t>(length),
        static_cast<std::uint8_t>(length >> 8U),
        static_cast<std::uint8_t>(length >> 16U),
        static_cast<std::uint8_t>(length >> 24U),
    };
    return WriteExact(write_handle_, prefix.data(), prefix.size()) &&
           WriteExact(write_handle_, frame.data(), frame.size());
}

}  // namespace bolt::network
