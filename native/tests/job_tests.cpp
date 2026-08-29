#include "common/execution_job.h"

#include <filesystem>
#include <string>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace {

bool HasRequiredLimits(const bolt::common::ExecutionJob& job) {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    if (!QueryInformationJobObject(
            job.handle(), JobObjectExtendedLimitInformation, &limits, sizeof(limits), nullptr)) {
        return false;
    }
    const DWORD flags = limits.BasicLimitInformation.LimitFlags;
    return (flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) != 0 &&
           (flags & JOB_OBJECT_LIMIT_BREAKAWAY_OK) == 0 &&
           (flags & JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK) == 0;
}

bool CreateSuspendedJobChild(PROCESS_INFORMATION& process) {
    std::wstring executable(32'768, L'\0');
    const DWORD length =
        GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
    if (length == 0 || length == executable.size()) {
        return false;
    }
    executable.resize(length);
    std::wstring command_line = L"\"" + executable + L"\" --job-child";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    return CreateProcessW(
               executable.c_str(), command_line.data(), nullptr, nullptr, FALSE, CREATE_SUSPENDED,
               nullptr, nullptr, &startup, &process) != FALSE;
}

void CloseProcessInformation(PROCESS_INFORMATION& process) {
    if (process.hThread != nullptr) {
        CloseHandle(process.hThread);
    }
    if (process.hProcess != nullptr) {
        CloseHandle(process.hProcess);
    }
}

}  // namespace

bool RunJobTests() {
    bolt::common::ExecutionJob limits_job;
    if (bolt::common::ExecutionJob::Create(limits_job) != bolt::common::JobStatus::kSuccess ||
        !HasRequiredLimits(limits_job)) {
        return false;
    }

    bolt::common::ExecutionJob close_job;
    if (bolt::common::ExecutionJob::Create(close_job) != bolt::common::JobStatus::kSuccess) {
        return false;
    }
    PROCESS_INFORMATION child{};
    if (!CreateSuspendedJobChild(child)) {
        return false;
    }
    if (close_job.Assign(child.hProcess) != bolt::common::JobStatus::kSuccess ||
        ResumeThread(child.hThread) == static_cast<DWORD>(-1)) {
        TerminateProcess(child.hProcess, 91);
        CloseProcessInformation(child);
        return false;
    }
    close_job.Close();
    const bool killed_on_close = WaitForSingleObject(child.hProcess, 5'000) == WAIT_OBJECT_0;
    CloseProcessInformation(child);
    if (!killed_on_close) {
        return false;
    }

    bolt::common::ExecutionJob terminate_job;
    return bolt::common::ExecutionJob::Create(terminate_job) == bolt::common::JobStatus::kSuccess &&
           terminate_job.Terminate(92) == bolt::common::JobStatus::kSuccess &&
           terminate_job.Terminate(92) == bolt::common::JobStatus::kSuccess;
}
