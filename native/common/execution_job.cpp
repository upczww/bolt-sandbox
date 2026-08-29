#include "common/execution_job.h"

namespace bolt::common {

ExecutionJob::~ExecutionJob() noexcept {
    Close();
}

JobStatus ExecutionJob::Create(ExecutionJob& output) noexcept {
    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (job == nullptr) {
        return JobStatus::kCreateFailed;
    }

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(
            job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
        CloseHandle(job);
        return JobStatus::kConfigureFailed;
    }

    output.Close();
    output.handle_ = job;
    output.termination_requested_.store(false, std::memory_order_release);
    return JobStatus::kSuccess;
}

JobStatus ExecutionJob::Assign(const HANDLE process) noexcept {
    if (handle_ == nullptr || process == nullptr || process == INVALID_HANDLE_VALUE) {
        return JobStatus::kInvalidArgument;
    }
    if (!AssignProcessToJobObject(handle_, process)) {
        return JobStatus::kAssignFailed;
    }
    return JobStatus::kSuccess;
}

JobStatus ExecutionJob::Terminate(const std::uint32_t exit_code) noexcept {
    if (handle_ == nullptr) {
        return JobStatus::kInvalidArgument;
    }
    bool expected = false;
    if (!termination_requested_.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel)) {
        return JobStatus::kSuccess;
    }
    if (!TerminateJobObject(handle_, exit_code)) {
        termination_requested_.store(false, std::memory_order_release);
        return JobStatus::kTerminateFailed;
    }
    return JobStatus::kSuccess;
}

void ExecutionJob::Close() noexcept {
    HANDLE handle = handle_;
    handle_ = nullptr;
    termination_requested_.store(false, std::memory_order_release);
    if (handle != nullptr) {
        CloseHandle(handle);
    }
}

}  // namespace bolt::common
