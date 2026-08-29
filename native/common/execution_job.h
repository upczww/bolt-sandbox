#pragma once

#include <atomic>
#include <cstdint>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace bolt::common {

enum class JobStatus : std::uint8_t {
    kSuccess,
    kInvalidArgument,
    kCreateFailed,
    kConfigureFailed,
    kAssignFailed,
    kTerminateFailed,
};

class ExecutionJob final {
  public:
    ExecutionJob() noexcept = default;
    ~ExecutionJob() noexcept;

    ExecutionJob(const ExecutionJob&) = delete;
    ExecutionJob& operator=(const ExecutionJob&) = delete;
    ExecutionJob(ExecutionJob&&) = delete;
    ExecutionJob& operator=(ExecutionJob&&) = delete;

    static JobStatus Create(ExecutionJob& output) noexcept;

    JobStatus Assign(HANDLE process) noexcept;
    JobStatus Terminate(std::uint32_t exit_code) noexcept;
    void Close() noexcept;

    HANDLE handle() const noexcept { return handle_; }

  private:
    HANDLE handle_ = nullptr;
    std::atomic_bool termination_requested_ = false;
};

}  // namespace bolt::common
