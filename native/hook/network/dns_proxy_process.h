#pragma once

#include "protocol/dns_proxy_protocol.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
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
    bool ExitCode(DWORD& exit_code) const noexcept;
    HANDLE request_write_handle() const noexcept { return request_write_; }
    HANDLE response_read_handle() const noexcept { return response_read_; }
    std::uint16_t tcp_proxy_port() const noexcept { return tcp_proxy_port_; }
    std::uint16_t tcp_proxy_ipv6_port() const noexcept {
        return tcp_proxy_ipv6_port_;
    }

  private:
    DnsProxyProcess() noexcept = default;
    void Close() noexcept;
    HANDLE process_ = nullptr;
    HANDLE request_write_ = nullptr;
    HANDLE response_read_ = nullptr;
    std::uint16_t tcp_proxy_port_ = 0;
    std::uint16_t tcp_proxy_ipv6_port_ = 0;
};

}  // namespace bolt::network
