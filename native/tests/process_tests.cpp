#include "common/execution_job.h"
#include "common/suspended_process.h"

#include <cstdint>
#include <string>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace {

std::wstring CurrentExecutable() {
    std::wstring path(32'768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (length == 0 || length == path.size()) {
        return {};
    }
    path.resize(length);
    return path;
}

std::wstring HandleText(const HANDLE handle) {
    return std::to_wstring(reinterpret_cast<std::uintptr_t>(handle));
}

}  // namespace

int RunProcessChild(const int argument_count, wchar_t** arguments) {
    if (argument_count != 4) {
        return 80;
    }
    const auto allowed = reinterpret_cast<HANDLE>(_wcstoui64(arguments[2], nullptr, 10));
    const auto denied = reinterpret_cast<HANDLE>(_wcstoui64(arguments[3], nullptr, 10));
    DWORD flags = 0;
    if (!GetHandleInformation(allowed, &flags)) {
        return 81;
    }
    if (GetHandleInformation(denied, &flags)) {
        return 82;
    }
    return 0;
}

bool RunProcessTests() {
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    const HANDLE allowed = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    const HANDLE denied = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    if (allowed == nullptr || denied == nullptr) {
        return false;
    }

    const std::wstring executable = CurrentExecutable();
    const std::wstring command_line = L"\"" + executable + L"\" --process-child " +
                                      HandleText(allowed) + L" " + HandleText(denied);
    const HANDLE inherited[] = {allowed};
    bolt::common::ProcessLaunchOptions options{
        executable,
        command_line,
        L"",
        nullptr,
        inherited,
        1,
        0,
    };
    bolt::common::SuspendedProcess process;
    bolt::common::ExecutionJob job;
    const bool created = bolt::common::ExecutionJob::Create(job) ==
                             bolt::common::JobStatus::kSuccess &&
                         bolt::common::SuspendedProcess::Create(options, process) ==
                             bolt::common::ProcessStatus::kSuccess;
    if (!created || process.Wait(100) != bolt::common::ProcessStatus::kWaitTimeout ||
        job.Assign(process.process_handle()) != bolt::common::JobStatus::kSuccess ||
        process.Resume() != bolt::common::ProcessStatus::kSuccess ||
        process.Wait(5'000) != bolt::common::ProcessStatus::kSuccess) {
        CloseHandle(allowed);
        CloseHandle(denied);
        return false;
    }
    DWORD exit_code = 0;
    const bool exact_exit = process.ExitCode(exit_code) == bolt::common::ProcessStatus::kSuccess &&
                            exit_code == 0;
    CloseHandle(allowed);
    CloseHandle(denied);
    if (!exact_exit) {
        return false;
    }

    auto breakaway = options;
    breakaway.creation_flags = CREATE_BREAKAWAY_FROM_JOB;
    bolt::common::SuspendedProcess rejected;
    return bolt::common::SuspendedProcess::Create(breakaway, rejected) ==
           bolt::common::ProcessStatus::kUnsupportedFlags;
}
