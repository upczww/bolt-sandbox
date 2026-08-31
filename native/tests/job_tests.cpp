#include "common/execution_job.h"

#include <cstdint>
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

std::wstring HandleText(const HANDLE handle) {
    return std::to_wstring(reinterpret_cast<std::uintptr_t>(handle));
}

bool RunJobTreeTermination(const bool close_job) {
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    const HANDLE ready = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    const HANDLE mapping = CreateFileMappingW(
        INVALID_HANDLE_VALUE, &inheritable, PAGE_READWRITE, 0, sizeof(DWORD),
        nullptr);
    auto* child_id = mapping == nullptr
                         ? nullptr
                         : static_cast<volatile LONG*>(MapViewOfFile(
                               mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0,
                               sizeof(DWORD)));
    if (ready == nullptr || mapping == nullptr || child_id == nullptr) {
        if (child_id != nullptr) {
            UnmapViewOfFile(const_cast<LONG*>(child_id));
        }
        if (mapping != nullptr) {
            CloseHandle(mapping);
        }
        if (ready != nullptr) {
            CloseHandle(ready);
        }
        return false;
    }
    InterlockedExchange(child_id, 0);

    std::wstring executable(32'768, L'\0');
    const DWORD length = GetModuleFileNameW(
        nullptr, executable.data(), static_cast<DWORD>(executable.size()));
    if (length == 0 || length == executable.size()) {
        return false;
    }
    executable.resize(length);
    std::wstring command =
        L"\"" + executable + L"\" --job-tree-parent " + HandleText(ready) +
        L" " + HandleText(mapping);
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION parent{};
    bolt::common::ExecutionJob job;
    const bool started =
        bolt::common::ExecutionJob::Create(job) ==
            bolt::common::JobStatus::kSuccess &&
        CreateProcessW(
            executable.c_str(), command.data(), nullptr, nullptr, TRUE,
            CREATE_SUSPENDED, nullptr, nullptr, &startup, &parent) != FALSE &&
        job.Assign(parent.hProcess) == bolt::common::JobStatus::kSuccess &&
        ResumeThread(parent.hThread) != static_cast<DWORD>(-1) &&
        WaitForSingleObject(ready, 5'000) == WAIT_OBJECT_0;
    const DWORD descendant_id =
        static_cast<DWORD>(InterlockedCompareExchange(child_id, 0, 0));
    const HANDLE descendant = descendant_id == 0
                                  ? nullptr
                                  : OpenProcess(SYNCHRONIZE, FALSE, descendant_id);
    const bool requested =
        started && descendant != nullptr &&
        (close_job
             ? (job.Close(), true)
             : job.Terminate(293) == bolt::common::JobStatus::kSuccess);
    const bool stopped =
        requested && WaitForSingleObject(parent.hProcess, 5'000) == WAIT_OBJECT_0 &&
        WaitForSingleObject(descendant, 5'000) == WAIT_OBJECT_0;
    if (!stopped && parent.hProcess != nullptr) {
        TerminateProcess(parent.hProcess, 294);
    }
    if (descendant != nullptr) {
        CloseHandle(descendant);
    }
    CloseProcessInformation(parent);
    UnmapViewOfFile(const_cast<LONG*>(child_id));
    CloseHandle(mapping);
    CloseHandle(ready);
    return stopped;
}

bool RunIgnoredGracefulTermination() {
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    const HANDLE request = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    const HANDLE acknowledged =
        CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    std::wstring executable(32'768, L'\0');
    const DWORD length = GetModuleFileNameW(
        nullptr, executable.data(), static_cast<DWORD>(executable.size()));
    if (request == nullptr || acknowledged == nullptr || length == 0 ||
        length == executable.size()) {
        return false;
    }
    executable.resize(length);
    std::wstring command =
        L"\"" + executable + L"\" --ignore-graceful " +
        HandleText(request) + L" " + HandleText(acknowledged);
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    bolt::common::ExecutionJob job;
    const bool started =
        bolt::common::ExecutionJob::Create(job) ==
            bolt::common::JobStatus::kSuccess &&
        CreateProcessW(
            executable.c_str(), command.data(), nullptr, nullptr, TRUE,
            CREATE_SUSPENDED, nullptr, nullptr, &startup, &process) != FALSE &&
        job.Assign(process.hProcess) == bolt::common::JobStatus::kSuccess &&
        ResumeThread(process.hThread) != static_cast<DWORD>(-1);
    const bool ignored =
        started && SetEvent(request) != FALSE &&
        WaitForSingleObject(acknowledged, 5'000) == WAIT_OBJECT_0 &&
        WaitForSingleObject(process.hProcess, 0) == WAIT_TIMEOUT;
    const bool forced =
        ignored && job.Terminate(307) == bolt::common::JobStatus::kSuccess &&
        WaitForSingleObject(process.hProcess, 5'000) == WAIT_OBJECT_0;
    if (!forced && process.hProcess != nullptr) {
        TerminateProcess(process.hProcess, 308);
    }
    CloseProcessInformation(process);
    CloseHandle(acknowledged);
    CloseHandle(request);
    return forced;
}

bool RunSingleProcessTimeout() {
    return false;
}

bool RunIdempotentCancellationTree() {
    return false;
}

}  // namespace

int RunJobTreeParent(const int argument_count, wchar_t** arguments) {
    if (argument_count != 4) {
        return 295;
    }
    const HANDLE ready = reinterpret_cast<HANDLE>(
        _wcstoui64(arguments[2], nullptr, 10));
    const HANDLE mapping = reinterpret_cast<HANDLE>(
        _wcstoui64(arguments[3], nullptr, 10));
    auto* child_id = static_cast<volatile LONG*>(
        MapViewOfFile(mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(DWORD)));
    if (child_id == nullptr) {
        return 296;
    }
    std::wstring executable(32'768, L'\0');
    const DWORD length = GetModuleFileNameW(
        nullptr, executable.data(), static_cast<DWORD>(executable.size()));
    if (length == 0 || length == executable.size()) {
        return 297;
    }
    executable.resize(length);
    std::wstring command = L"\"" + executable + L"\" --job-child";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION child{};
    if (!CreateProcessW(
            executable.c_str(), command.data(), nullptr, nullptr, FALSE, 0,
            nullptr, nullptr, &startup, &child)) {
        return 298;
    }
    InterlockedExchange(child_id, static_cast<LONG>(child.dwProcessId));
    const bool ready_set = SetEvent(ready) != FALSE;
    CloseProcessInformation(child);
    UnmapViewOfFile(const_cast<LONG*>(child_id));
    if (!ready_set) {
        return 299;
    }
    Sleep(INFINITE);
    return 0;
}

int RunIgnoreGracefulChild(const int argument_count, wchar_t** arguments) {
    if (argument_count != 4) {
        return 309;
    }
    const HANDLE request = reinterpret_cast<HANDLE>(
        _wcstoui64(arguments[2], nullptr, 10));
    const HANDLE acknowledged = reinterpret_cast<HANDLE>(
        _wcstoui64(arguments[3], nullptr, 10));
    if (WaitForSingleObject(request, 5'000) != WAIT_OBJECT_0 ||
        !SetEvent(acknowledged)) {
        return 310;
    }
    Sleep(INFINITE);
    return 0;
}

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
           terminate_job.Terminate(92) == bolt::common::JobStatus::kSuccess &&
           RunJobTreeTermination(true) && RunJobTreeTermination(false) &&
           RunIgnoredGracefulTermination() && RunSingleProcessTimeout() &&
           RunIdempotentCancellationTree();
}
