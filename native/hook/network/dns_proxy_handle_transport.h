#pragma once

#include "hook/network/dns_proxy_session.h"

#include <cstddef>
#include <cstdint>
#include <memory>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace bolt::network {

enum class HandleTransportStatus : std::uint8_t {
    kSuccess,
    kInvalidHandle,
    kInvalidMaximumFrame,
    kAllocationFailed,
};

class DnsProxyHandleTransport final : public DnsProxyTransport {
  public:
    static HandleTransportStatus Create(
        HANDLE read_handle,
        HANDLE write_handle,
        std::size_t maximum_frame_length,
        std::unique_ptr<DnsProxyHandleTransport>& transport) noexcept;

    TransportReadStatus ReadFrame(std::vector<std::uint8_t>& frame) noexcept override;
    bool WriteFrame(const std::vector<std::uint8_t>& frame) noexcept override;

  private:
    DnsProxyHandleTransport(
        HANDLE read_handle,
        HANDLE write_handle,
        std::size_t maximum_frame_length) noexcept;

    HANDLE read_handle_;
    HANDLE write_handle_;
    std::size_t maximum_frame_length_;
};

}  // namespace bolt::network
