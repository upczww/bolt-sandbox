#pragma once

#include "protocol/dns_proxy_protocol.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace bolt::network {

enum class DnsProxyProcessStatus : std::uint8_t {
    kSuccess,
    kInvalidArgument,
    kResourceFailed,
    kCreateFailed,
    kWaitTimeout,
    kWaitFailed,
    kProcessFailed,
};

class DnsProxyProcess final {
  public:
    ~DnsProxyProcess() noexcept;
    DnsProxyProcess(const DnsProxyProcess&) = delete;
    DnsProxyProcess& operator=(const DnsProxyProcess&) = delete;

    static DnsProxyProcessStatus Start(
        const std::filesystem::path& executable,
        const std::uint8_t* policy,
        std::size_t policy_length,
        const protocol::DnsProxySession& session,
        std::uint32_t maximum_frame_length,
        std::uint32_t maximum_requests,
        std::unique_ptr<DnsProxyProcess>& process) noexcept;

    void CloseClientHandles() noexcept;
    DnsProxyProcessStatus Wait(DWORD timeout_milliseconds) noexcept;
    HANDLE request_write_handle() const noexcept { return request_write_; }
    HANDLE response_read_handle() const noexcept { return response_read_; }

  private:
    DnsProxyProcess() noexcept = default;
    void Close() noexcept;
    HANDLE process_ = nullptr;
    HANDLE request_write_ = nullptr;
    HANDLE response_read_ = nullptr;
};

}  // namespace bolt::network
