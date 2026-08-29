#pragma once

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN

#include "common/execution_job.h"

#include <cstddef>
#include <cstdint>
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
    kInvalidDllPath,
    kInjectFailed,
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
    ProcessStatus Inject(std::string_view dll_path) noexcept;
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
    bool injected_ = false;
    bool resumed_ = false;
};

}  // namespace bolt::common
