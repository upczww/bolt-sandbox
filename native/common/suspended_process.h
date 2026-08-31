#pragma once

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN

#include "common/execution_job.h"
#include "protocol/runtime_payload.h"

#include <cstddef>
#include <cstdint>
#include <array>
#include <string_view>

#include <windows.h>

namespace bolt::common {

struct ProcessLaunchOptions {
    std::wstring_view application;
    std::wstring_view command_line;
    std::wstring_view current_directory;
    void* environment;
    const HANDLE* inherited_handles;
    std::size_t inherited_handle_count;
    DWORD creation_flags;
    HANDLE standard_input = nullptr;
    HANDLE standard_output = nullptr;
    HANDLE standard_error = nullptr;
    HANDLE recovery_request = nullptr;
    HANDLE recovery_response = nullptr;
    HANDLE recovery_mutex = nullptr;
    HANDLE recovery_counter = nullptr;
};

enum class ProcessStatus : std::uint8_t {
    kSuccess,
    kInvalidArgument,
    kUnsupportedFlags,
    kAllocationFailed,
    kInvalidInheritedHandle,
    kAttributeListFailed,
    kCreateFailed,
    kInvalidState,
    kAssignFailed,
    kInvalidRuntimePayload,
    kPayloadCopyFailed,
    kInvalidDllPath,
    kInjectFailed,
    kInitializationFailed,
    kReleaseFailed,
    kResumeFailed,
    kWaitTimeout,
    kWaitFailed,
    kExitCodeFailed,
};

class SuspendedProcess final {
  public:
    SuspendedProcess() noexcept = default;
    ~SuspendedProcess() noexcept;

    SuspendedProcess(const SuspendedProcess&) = delete;
    SuspendedProcess& operator=(const SuspendedProcess&) = delete;
    SuspendedProcess(SuspendedProcess&&) = delete;
    SuspendedProcess& operator=(SuspendedProcess&&) = delete;

    static ProcessStatus Create(
        const ProcessLaunchOptions& options,
        SuspendedProcess& output) noexcept;

    ProcessStatus AssignTo(ExecutionJob& job) noexcept;
    ProcessStatus InstallRuntimePayload(
        HANDLE policy_handle,
        std::size_t policy_length,
        HANDLE event_handle,
        HANDLE release_handle,
        const std::array<std::uint8_t, 16>& nonce,
        HANDLE dns_request_handle = nullptr,
        HANDLE dns_response_handle = nullptr,
        const std::array<std::uint8_t, 32>* dns_authentication_key = nullptr,
        std::uint32_t dns_maximum_frame_length = 0,
        std::uint16_t tcp_proxy_port = 0,
        std::uint16_t tcp_proxy_ipv6_port = 0,
        protocol::RuntimeStartupFault descendant_startup_fault =
            protocol::RuntimeStartupFault::kNone) noexcept;
    ProcessStatus Inject(std::string_view dll_path) noexcept;
    ProcessStatus BeginHookInitialization() noexcept;
    ProcessStatus ReleaseAfterReady() noexcept;
    ProcessStatus Resume() noexcept;
    ProcessStatus Wait(DWORD milliseconds) noexcept;
    ProcessStatus ExitCode(DWORD& exit_code) const noexcept;
    void Close() noexcept;

    HANDLE process_handle() const noexcept { return process_; }
    HANDLE thread_handle() const noexcept { return thread_; }

  private:
    HANDLE process_ = nullptr;
    HANDLE thread_ = nullptr;
    bool assigned_ = false;
    bool payload_installed_ = false;
    bool injected_ = false;
    bool initialization_started_ = false;
    bool resumed_ = false;
    HANDLE release_event_ = nullptr;
    HANDLE standard_output_ = nullptr;
    HANDLE standard_error_ = nullptr;
    HANDLE recovery_request_ = nullptr;
    HANDLE recovery_response_ = nullptr;
    HANDLE recovery_mutex_ = nullptr;
    HANDLE recovery_counter_ = nullptr;
};

}  // namespace bolt::common
