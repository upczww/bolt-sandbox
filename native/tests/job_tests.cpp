#include "common/execution_job.h"
#include "common/suspended_process.h"

#include <cstdint>
#include <filesystem>
#include <string>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace {

std::wstring CurrentExecutable() {
    std::wstring executable(32'768, L'\0');
    const DWORD length = GetModuleFileNameW(
        nullptr, executable.data(), static_cast<DWORD>(executable.size()));
    if (length == 0 || length == executable.size()) {
        return {};
    }
    executable.resize(length);
    return executable;
}

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

bool RunJobTreeTermination(
    const bool close_job,
    const bool repeat_termination = false) {
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
    const HANDLE descendant =
        descendant_id == 0
            ? nullptr
            : OpenProcess(
                  SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                  descendant_id);
    const bool requested =
        started && descendant != nullptr &&
        (close_job
             ? (job.Close(), true)
             : job.Terminate(293) == bolt::common::JobStatus::kSuccess &&
                   (!repeat_termination ||
                    job.Terminate(293) == bolt::common::JobStatus::kSuccess));
    const bool stopped =
        requested && WaitForSingleObject(parent.hProcess, 5'000) == WAIT_OBJECT_0 &&
        WaitForSingleObject(descendant, 5'000) == WAIT_OBJECT_0;
    DWORD parent_exit_code = 0;
    DWORD descendant_exit_code = 0;
    const bool exact_termination =
        close_job ||
        (stopped && GetExitCodeProcess(parent.hProcess, &parent_exit_code) &&
         GetExitCodeProcess(descendant, &descendant_exit_code) &&
         parent_exit_code == 293 && descendant_exit_code == 293);
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
    return stopped && exact_termination;
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
    bolt::common::ExecutionJob job;
    PROCESS_INFORMATION process{};
    const bool started =
        bolt::common::ExecutionJob::Create(job) ==
            bolt::common::JobStatus::kSuccess &&
        CreateSuspendedJobChild(process) &&
        job.Assign(process.hProcess) == bolt::common::JobStatus::kSuccess &&
        ResumeThread(process.hThread) != static_cast<DWORD>(-1);
    const bool timed_out =
        started && WaitForSingleObject(process.hProcess, 100) == WAIT_TIMEOUT;
    const bool terminated =
        timed_out &&
        job.Terminate(408) == bolt::common::JobStatus::kSuccess &&
        job.Terminate(408) == bolt::common::JobStatus::kSuccess &&
        WaitForSingleObject(process.hProcess, 5'000) == WAIT_OBJECT_0;
    DWORD exit_code = 0;
    const bool exact_exit =
        terminated && GetExitCodeProcess(process.hProcess, &exit_code) &&
        exit_code == 408;
    if (!terminated && process.hProcess != nullptr) {
        TerminateProcess(process.hProcess, 409);
        WaitForSingleObject(process.hProcess, 5'000);
    }
    CloseProcessInformation(process);
    return exact_exit;
}

bool RunIdempotentCancellationTree() {
    return RunJobTreeTermination(false, true);
}

bool RunCrashCleanupIteration() {
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

    const std::wstring executable = CurrentExecutable();
    std::wstring command =
        L"\"" + executable + L"\" --crash-tree-parent " +
        HandleText(ready) + L" " + HandleText(mapping);
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION parent{};
    bolt::common::ExecutionJob job;
    const bool started =
        !executable.empty() &&
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
    const HANDLE descendant =
        descendant_id == 0
            ? nullptr
            : OpenProcess(
                  SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                  descendant_id);
    const bool parent_crashed =
        started && descendant != nullptr &&
        WaitForSingleObject(parent.hProcess, 5'000) == WAIT_OBJECT_0;
    DWORD parent_exit_code = 0;
    const bool typed_crash =
        parent_crashed &&
        GetExitCodeProcess(parent.hProcess, &parent_exit_code) != FALSE &&
        (parent_exit_code & 0xC000'0000U) == 0xC000'0000U;
    const bool descendant_confined =
        typed_crash && WaitForSingleObject(descendant, 0) == WAIT_TIMEOUT;
    const bool cleanup_requested =
        descendant_confined &&
        job.Terminate(319) == bolt::common::JobStatus::kSuccess;
    const bool descendant_stopped =
        cleanup_requested &&
        WaitForSingleObject(descendant, 5'000) == WAIT_OBJECT_0;
    DWORD descendant_exit_code = 0;
    const bool exact_cleanup =
        descendant_stopped &&
        GetExitCodeProcess(descendant, &descendant_exit_code) != FALSE &&
        descendant_exit_code == 319;
    if (!parent_crashed && parent.hProcess != nullptr) {
        TerminateProcess(parent.hProcess, 320);
        WaitForSingleObject(parent.hProcess, 5'000);
    }
    if (!descendant_stopped && descendant != nullptr) {
        job.Terminate(320);
        WaitForSingleObject(descendant, 5'000);
    }
    if (descendant != nullptr) {
        CloseHandle(descendant);
    }
    CloseProcessInformation(parent);
    UnmapViewOfFile(const_cast<LONG*>(child_id));
    CloseHandle(mapping);
    CloseHandle(ready);
    return typed_crash && exact_cleanup;
}

bool RunCrashCleanupTests() {
    DWORD handles_before = 0;
    if (!GetProcessHandleCount(GetCurrentProcess(), &handles_before) ||
        !RunCrashCleanupIteration()) {
        return false;
    }
    DWORD handles_after = 0;
    return GetProcessHandleCount(GetCurrentProcess(), &handles_after) != FALSE &&
           handles_after == handles_before;
}

#if defined(_WIN64)
bool DuplicateInheritableHandle(
    const HANDLE source,
    const DWORD access,
    HANDLE& output) {
    return DuplicateHandle(
               GetCurrentProcess(), source, GetCurrentProcess(), &output,
               access, TRUE, access == 0 ? DUPLICATE_SAME_ACCESS : 0) != FALSE;
}

bool StartLauncherSupervisor(
    bolt::common::ExecutionJob& job,
    const HANDLE target_ready,
    const HANDLE host_ready,
    const HANDLE release,
    const HANDLE shutdown,
    bolt::common::SuspendedProcess& launcher) {
    HANDLE inherited_job = nullptr;
    HANDLE inherited_owner = nullptr;
    const bool duplicated =
        DuplicateInheritableHandle(job.handle(), 0, inherited_job) &&
        DuplicateInheritableHandle(
            GetCurrentProcess(), SYNCHRONIZE, inherited_owner);
    if (!duplicated) {
        if (inherited_job != nullptr) {
            CloseHandle(inherited_job);
        }
        if (inherited_owner != nullptr) {
            CloseHandle(inherited_owner);
        }
        return false;
    }
    const std::filesystem::path launcher_path =
        std::filesystem::path(CurrentExecutable()).parent_path() /
        L"bolt-sandbox-launcher.exe";
    const std::wstring launcher_string = launcher_path.wstring();
    const std::wstring launcher_directory =
        launcher_path.parent_path().wstring();
    std::wstring command =
        L"\"" + launcher_string + L"\" --supervise-job " +
        HandleText(inherited_job) + L" " + HandleText(target_ready) + L" " +
        HandleText(host_ready) + L" " + HandleText(release) + L" " +
        HandleText(shutdown) + L" " + HandleText(inherited_owner);
    const HANDLE inherited[] = {
        inherited_job, target_ready, host_ready, release, shutdown,
        inherited_owner};
    const bolt::common::ProcessLaunchOptions options{
        launcher_string, command, launcher_directory, nullptr, inherited,
        std::size(inherited), 0};
    const bool started =
        bolt::common::SuspendedProcess::Create(options, launcher) ==
            bolt::common::ProcessStatus::kSuccess &&
        ResumeThread(launcher.thread_handle()) != static_cast<DWORD>(-1);
    CloseHandle(inherited_owner);
    CloseHandle(inherited_job);
    return started;
}

bool RunLauncherDeathBeforeHandshake() {
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    const HANDLE target_ready =
        CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    const HANDLE host_ready = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    const HANDLE release = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    const HANDLE shutdown = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    PROCESS_INFORMATION target{};
    bolt::common::ExecutionJob job;
    bolt::common::SuspendedProcess launcher;
    const bool target_created =
        target_ready != nullptr && host_ready != nullptr && release != nullptr &&
        shutdown != nullptr &&
        bolt::common::ExecutionJob::Create(job) ==
            bolt::common::JobStatus::kSuccess &&
        CreateSuspendedJobChild(target) &&
        job.Assign(target.hProcess) == bolt::common::JobStatus::kSuccess;
    const bool launcher_started =
        target_created &&
        StartLauncherSupervisor(
            job, target_ready, host_ready, release, shutdown, launcher);
    if (launcher_started) {
        job.Close();
    }
    const bool handshake_absent =
        launcher_started && WaitForSingleObject(host_ready, 0) == WAIT_TIMEOUT;
    const bool launcher_stopped =
        handshake_absent &&
        TerminateProcess(launcher.process_handle(), 326) != FALSE &&
        launcher.Wait(5'000) == bolt::common::ProcessStatus::kSuccess;
    const bool target_stopped =
        launcher_stopped &&
        WaitForSingleObject(target.hProcess, 5'000) == WAIT_OBJECT_0;
    if (!target_stopped && target.hProcess != nullptr) {
        TerminateProcess(target.hProcess, 327);
        WaitForSingleObject(target.hProcess, 5'000);
    }
    launcher.Close();
    CloseProcessInformation(target);
    if (shutdown != nullptr) {
        CloseHandle(shutdown);
    }
    if (release != nullptr) {
        CloseHandle(release);
    }
    if (host_ready != nullptr) {
        CloseHandle(host_ready);
    }
    if (target_ready != nullptr) {
        CloseHandle(target_ready);
    }
    return handshake_absent && target_stopped;
}

bool RunLauncherDeathAfterHandshake() {
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    const HANDLE target_ready =
        CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    const HANDLE host_ready = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    const HANDLE release = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    const HANDLE shutdown = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    const HANDLE mapping = CreateFileMappingW(
        INVALID_HANDLE_VALUE, &inheritable, PAGE_READWRITE, 0, sizeof(DWORD),
        nullptr);
    auto* child_id = mapping == nullptr
                         ? nullptr
                         : static_cast<volatile LONG*>(MapViewOfFile(
                               mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0,
                               sizeof(DWORD)));
    if (target_ready == nullptr || host_ready == nullptr || release == nullptr ||
        shutdown == nullptr || mapping == nullptr || child_id == nullptr) {
        if (child_id != nullptr) {
            UnmapViewOfFile(const_cast<LONG*>(child_id));
        }
        if (mapping != nullptr) {
            CloseHandle(mapping);
        }
        for (const HANDLE handle :
             {target_ready, host_ready, release, shutdown}) {
            if (handle != nullptr) {
                CloseHandle(handle);
            }
        }
        return false;
    }
    InterlockedExchange(child_id, 0);
    const std::wstring executable = CurrentExecutable();
    std::wstring command =
        L"\"" + executable + L"\" --job-tree-parent " +
        HandleText(target_ready) + L" " + HandleText(mapping);
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION target{};
    bolt::common::ExecutionJob job;
    bolt::common::SuspendedProcess launcher;
    const bool target_created =
        bolt::common::ExecutionJob::Create(job) ==
            bolt::common::JobStatus::kSuccess &&
        CreateProcessW(
            executable.c_str(), command.data(), nullptr, nullptr, TRUE,
            CREATE_SUSPENDED, nullptr, nullptr, &startup, &target) != FALSE &&
        job.Assign(target.hProcess) == bolt::common::JobStatus::kSuccess;
    const bool launcher_started =
        target_created &&
        StartLauncherSupervisor(
            job, target_ready, host_ready, release, shutdown, launcher);
    if (launcher_started) {
        job.Close();
    }
    const bool resumed =
        launcher_started &&
        ResumeThread(target.hThread) != static_cast<DWORD>(-1);
    const bool handshake_complete =
        resumed &&
        WaitForSingleObject(host_ready, 5'000) == WAIT_OBJECT_0 &&
        SetEvent(release) != FALSE;
    const DWORD descendant_id =
        static_cast<DWORD>(InterlockedCompareExchange(child_id, 0, 0));
    const HANDLE descendant =
        descendant_id == 0
            ? nullptr
            : OpenProcess(
                  SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                  descendant_id);
    const bool tree_running =
        handshake_complete && descendant != nullptr &&
        WaitForSingleObject(target.hProcess, 0) == WAIT_TIMEOUT &&
        WaitForSingleObject(descendant, 0) == WAIT_TIMEOUT;
    const bool launcher_stopped =
        tree_running &&
        TerminateProcess(launcher.process_handle(), 328) != FALSE &&
        launcher.Wait(5'000) == bolt::common::ProcessStatus::kSuccess;
    const bool tree_stopped =
        launcher_stopped &&
        WaitForSingleObject(target.hProcess, 5'000) == WAIT_OBJECT_0 &&
        WaitForSingleObject(descendant, 5'000) == WAIT_OBJECT_0;
    if (!tree_stopped && target.hProcess != nullptr) {
        TerminateProcess(target.hProcess, 329);
        WaitForSingleObject(target.hProcess, 5'000);
    }
    if (descendant != nullptr) {
        CloseHandle(descendant);
    }
    launcher.Close();
    CloseProcessInformation(target);
    UnmapViewOfFile(const_cast<LONG*>(child_id));
    CloseHandle(mapping);
    CloseHandle(shutdown);
    CloseHandle(release);
    CloseHandle(host_ready);
    CloseHandle(target_ready);
    return handshake_complete && tree_stopped;
}

bool RunLauncherDeathTests() {
    DWORD handles_before = 0;
    if (!GetProcessHandleCount(GetCurrentProcess(), &handles_before) ||
        !RunLauncherDeathBeforeHandshake() ||
        !RunLauncherDeathAfterHandshake()) {
        return false;
    }
    DWORD handles_after = 0;
    return GetProcessHandleCount(GetCurrentProcess(), &handles_after) != FALSE &&
           handles_after == handles_before;
}
#else
bool RunLauncherDeathTests() {
    return true;
}
#endif

}  // namespace

int RunCrashTreeParent(const int argument_count, wchar_t** arguments) {
    if (argument_count != 4) {
        return 321;
    }
    const HANDLE ready = reinterpret_cast<HANDLE>(
        _wcstoui64(arguments[2], nullptr, 10));
    const HANDLE mapping = reinterpret_cast<HANDLE>(
        _wcstoui64(arguments[3], nullptr, 10));
    auto* child_id = static_cast<volatile LONG*>(
        MapViewOfFile(mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0,
                      sizeof(DWORD)));
    const std::wstring executable = CurrentExecutable();
    if (child_id == nullptr || executable.empty()) {
        return 322;
    }
    std::wstring command = L"\"" + executable + L"\" --job-child";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION child{};
    if (!CreateProcessW(
            executable.c_str(), command.data(), nullptr, nullptr, FALSE, 0,
            nullptr, nullptr, &startup, &child)) {
        UnmapViewOfFile(const_cast<LONG*>(child_id));
        return 323;
    }
    InterlockedExchange(child_id, static_cast<LONG>(child.dwProcessId));
    const bool ready_set = SetEvent(ready) != FALSE;
    CloseProcessInformation(child);
    UnmapViewOfFile(const_cast<LONG*>(child_id));
    if (!ready_set) {
        return 324;
    }
    RaiseFailFastException(nullptr, nullptr, 0);
    return 325;
}

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
           RunIdempotentCancellationTree() && RunCrashCleanupTests() &&
           RunLauncherDeathTests();
}
