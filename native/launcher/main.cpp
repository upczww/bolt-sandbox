#include <array>
#include <cerrno>
#include <cstdint>
#include <cwchar>
#include <limits>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace {

constexpr DWORD kStartupTimeoutMilliseconds = 5'000;

bool ParseHandle(const wchar_t* const text, HANDLE& output) noexcept {
    if (text == nullptr || *text == L'\0' || *text == L'-') {
        return false;
    }
    wchar_t* end = nullptr;
    errno = 0;
    const unsigned long long value = std::wcstoull(text, &end, 10);
    if (errno != 0 || end == text || *end != L'\0' || value == 0 ||
        value > (std::numeric_limits<std::uintptr_t>::max)()) {
        return false;
    }
    output = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(value));
    DWORD flags = 0;
    return GetHandleInformation(output, &flags) != FALSE;
}

bool HasKillOnClose(const HANDLE job) noexcept {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    return QueryInformationJobObject(
               job, JobObjectExtendedLimitInformation, &limits,
               sizeof(limits), nullptr) != FALSE &&
           (limits.BasicLimitInformation.LimitFlags &
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) != 0;
}

DWORD WaitForStartupSignal(
    const HANDLE expected,
    const HANDLE shutdown,
    const HANDLE owner) noexcept {
    const std::array<HANDLE, 3> handles = {expected, shutdown, owner};
    return WaitForMultipleObjects(
        static_cast<DWORD>(handles.size()), handles.data(), FALSE,
        kStartupTimeoutMilliseconds);
}

}  // namespace

int wmain(const int argument_count, wchar_t** arguments) noexcept {
    if (argument_count != 8 ||
        std::wcscmp(arguments[1], L"--supervise-job") != 0) {
        return ERROR_INVALID_HANDLE;
    }
    HANDLE job = nullptr;
    HANDLE target_ready = nullptr;
    HANDLE host_ready = nullptr;
    HANDLE release = nullptr;
    HANDLE shutdown = nullptr;
    HANDLE owner = nullptr;
    if (!ParseHandle(arguments[2], job) ||
        !ParseHandle(arguments[3], target_ready) ||
        !ParseHandle(arguments[4], host_ready) ||
        !ParseHandle(arguments[5], release) ||
        !ParseHandle(arguments[6], shutdown) ||
        !ParseHandle(arguments[7], owner) || !HasKillOnClose(job)) {
        return ERROR_INVALID_HANDLE;
    }

    const DWORD target_status =
        WaitForStartupSignal(target_ready, shutdown, owner);
    if (target_status != WAIT_OBJECT_0) {
        return target_status == WAIT_TIMEOUT ? WAIT_TIMEOUT
                                             : ERROR_PROCESS_ABORTED;
    }
    if (!SetEvent(host_ready)) {
        return GetLastError();
    }
    const DWORD release_status = WaitForStartupSignal(release, shutdown, owner);
    if (release_status != WAIT_OBJECT_0) {
        return release_status == WAIT_TIMEOUT ? WAIT_TIMEOUT
                                              : ERROR_PROCESS_ABORTED;
    }

    const std::array<HANDLE, 2> terminal_handles = {shutdown, owner};
    const DWORD terminal_status = WaitForMultipleObjects(
        static_cast<DWORD>(terminal_handles.size()), terminal_handles.data(),
        FALSE, INFINITE);
    return terminal_status == WAIT_OBJECT_0 ? ERROR_SUCCESS
                                           : ERROR_PROCESS_ABORTED;
}
