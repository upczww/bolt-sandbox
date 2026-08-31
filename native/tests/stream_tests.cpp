#include "common/suspended_process.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cwchar>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace {

constexpr std::size_t kStreamBytes = 256 * 1'024;

std::wstring CurrentExecutable() {
    std::wstring path(32'768, L'\0');
    const DWORD length = GetModuleFileNameW(
        nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (length == 0 || length == path.size()) {
        return {};
    }
    path.resize(length);
    return path;
}

std::uint8_t ExpectedByte(const std::size_t offset, const bool stderr_stream) {
    const auto value = static_cast<std::uint8_t>(offset % 251);
    return stderr_stream ? static_cast<std::uint8_t>(0xffU - value) : value;
}

bool WritePattern(
    const HANDLE stream,
    const std::size_t length,
    const bool stderr_stream) {
    std::array<std::uint8_t, 4'096> chunk{};
    std::size_t offset = 0;
    while (offset < length) {
        const std::size_t count = (std::min)(chunk.size(), length - offset);
        for (std::size_t index = 0; index < count; ++index) {
            chunk[index] = ExpectedByte(offset + index, stderr_stream);
        }
        DWORD written = 0;
        if (!WriteFile(
                stream, chunk.data(), static_cast<DWORD>(count), &written,
                nullptr) ||
            written != static_cast<DWORD>(count)) {
            return false;
        }
        offset += written;
    }
    return true;
}

void DrainPipe(const HANDLE pipe, std::vector<std::uint8_t>& bytes) {
    std::array<std::uint8_t, 4'096> chunk{};
    for (;;) {
        DWORD read = 0;
        if (!ReadFile(
                pipe, chunk.data(), static_cast<DWORD>(chunk.size()), &read,
                nullptr)) {
            break;
        }
        bytes.insert(bytes.end(), chunk.begin(), chunk.begin() + read);
    }
}

bool MatchesPattern(
    const std::vector<std::uint8_t>& bytes,
    const bool stderr_stream) {
    if (bytes.size() != kStreamBytes) {
        return false;
    }
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        if (bytes[index] != ExpectedByte(index, stderr_stream)) {
            return false;
        }
    }
    return true;
}

bool RunDroppedReceiverTest() {
    DWORD handles_before = 0;
    if (!GetProcessHandleCount(GetCurrentProcess(), &handles_before)) {
        return false;
    }
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    HANDLE stdout_read = nullptr;
    HANDLE stdout_write = nullptr;
    HANDLE stderr_read = nullptr;
    HANDLE stderr_write = nullptr;
    const auto close_if_valid = [](const HANDLE handle) {
        if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
        }
    };
    if (!CreatePipe(&stdout_read, &stdout_write, &inheritable, 4'096) ||
        !CreatePipe(&stderr_read, &stderr_write, &inheritable, 4'096) ||
        !SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0) ||
        !SetHandleInformation(stderr_read, HANDLE_FLAG_INHERIT, 0)) {
        close_if_valid(stdout_read);
        close_if_valid(stdout_write);
        close_if_valid(stderr_read);
        close_if_valid(stderr_write);
        return false;
    }
    const std::wstring executable = CurrentExecutable();
    std::wstring command = L"\"" + executable + L"\" --dual-stream-writer " +
                           std::to_wstring(kStreamBytes);
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = stdout_write;
    startup.hStdError = stderr_write;
    PROCESS_INFORMATION process{};
    const bool created = !executable.empty() &&
                         CreateProcessW(
                             executable.c_str(), command.data(), nullptr,
                             nullptr, TRUE, 0, nullptr, nullptr, &startup,
                             &process) != FALSE;
    CloseHandle(stdout_write);
    CloseHandle(stderr_write);
    CloseHandle(stdout_read);
    CloseHandle(stderr_read);
    if (!created) {
        return false;
    }
    const DWORD wait = WaitForSingleObject(process.hProcess, 5'000);
    if (wait != WAIT_OBJECT_0) {
        TerminateProcess(process.hProcess, 315);
        WaitForSingleObject(process.hProcess, 5'000);
    }
    DWORD exit_code = 0;
    const bool exited_on_disconnect =
        wait == WAIT_OBJECT_0 &&
        GetExitCodeProcess(process.hProcess, &exit_code) != FALSE &&
        exit_code == 313;
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    DWORD handles_after = 0;
    return exited_on_disconnect &&
           GetProcessHandleCount(GetCurrentProcess(), &handles_after) &&
           handles_after == handles_before;
}

}  // namespace

int RunDualStreamWriter(const int argument_count, wchar_t** arguments) {
    if (argument_count != 3 || std::wcstoull(arguments[2], nullptr, 10) != kStreamBytes) {
        return 312;
    }
    std::array<bool, 2> results{};
    std::thread stdout_writer([&] {
        results[0] = WritePattern(GetStdHandle(STD_OUTPUT_HANDLE), kStreamBytes, false);
    });
    std::thread stderr_writer([&] {
        results[1] = WritePattern(GetStdHandle(STD_ERROR_HANDLE), kStreamBytes, true);
    });
    stdout_writer.join();
    stderr_writer.join();
    return results[0] && results[1] ? 0 : 313;
}

int RunDescendantDualStreamWriter(
    const int argument_count,
    wchar_t** arguments) {
    if (argument_count != 3 ||
        std::wcstoull(arguments[2], nullptr, 10) != kStreamBytes) {
        return 316;
    }
    const std::wstring executable = CurrentExecutable();
    std::wstring command = L"\"" + executable +
                           L"\" --dual-stream-writer " + arguments[2];
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (executable.empty() ||
        !CreateProcessW(
            executable.c_str(), command.data(), nullptr, nullptr, TRUE, 0,
            nullptr, nullptr, &startup, &process)) {
        return 317;
    }
    const DWORD wait = WaitForSingleObject(process.hProcess, 10'000);
    DWORD exit_code = 318;
    if (wait != WAIT_OBJECT_0 ||
        !GetExitCodeProcess(process.hProcess, &exit_code)) {
        TerminateProcess(process.hProcess, 318);
        WaitForSingleObject(process.hProcess, 5'000);
        exit_code = 318;
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return static_cast<int>(exit_code);
}

int RunBlockingStreamFixture(const int argument_count) {
    if (argument_count != 2) {
        return 319;
    }
    constexpr std::array<std::uint8_t, 5> ready = {'r', 'e', 'a', 'd', 'y'};
    DWORD written = 0;
    if (!WriteFile(
            GetStdHandle(STD_OUTPUT_HANDLE), ready.data(),
            static_cast<DWORD>(ready.size()), &written, nullptr) ||
        written != static_cast<DWORD>(ready.size())) {
        return 320;
    }
    const HANDLE never = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (never == nullptr) {
        return 321;
    }
    WaitForSingleObject(never, INFINITE);
    CloseHandle(never);
    return 322;
}

bool RunStreamTests() {
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    HANDLE stdout_read = nullptr;
    HANDLE stdout_write = nullptr;
    HANDLE stderr_read = nullptr;
    HANDLE stderr_write = nullptr;
    const HANDLE stdin_read = CreateFileW(
        L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        &inheritable, OPEN_EXISTING, 0, nullptr);
    if (!CreatePipe(&stdout_read, &stdout_write, &inheritable, 4'096) ||
        !CreatePipe(&stderr_read, &stderr_write, &inheritable, 4'096) ||
        !SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0) ||
        !SetHandleInformation(stderr_read, HANDLE_FLAG_INHERIT, 0) ||
        stdin_read == INVALID_HANDLE_VALUE) {
        return false;
    }
    const std::wstring executable = CurrentExecutable();
    std::wstring command = L"\"" + executable + L"\" --dual-stream-writer " +
                           std::to_wstring(kStreamBytes);
    const HANDLE inherited[] = {stdin_read, stdout_write, stderr_write};
    const bolt::common::ProcessLaunchOptions options{
        executable,
        command,
        {},
        nullptr,
        inherited,
        std::size(inherited),
        0,
        stdin_read,
        stdout_write,
        stderr_write};
    bolt::common::SuspendedProcess process;
    const bool created = !executable.empty() &&
        bolt::common::SuspendedProcess::Create(options, process) ==
            bolt::common::ProcessStatus::kSuccess &&
        ResumeThread(process.thread_handle()) != static_cast<DWORD>(-1);
    CloseHandle(stdin_read);
    CloseHandle(stdout_write);
    CloseHandle(stderr_write);
    if (!created) {
        CloseHandle(stdout_read);
        CloseHandle(stderr_read);
        return false;
    }
    std::vector<std::uint8_t> stdout_bytes;
    std::vector<std::uint8_t> stderr_bytes;
    stdout_bytes.reserve(kStreamBytes);
    stderr_bytes.reserve(kStreamBytes);
    std::thread stdout_reader(DrainPipe, stdout_read, std::ref(stdout_bytes));
    std::thread stderr_reader(DrainPipe, stderr_read, std::ref(stderr_bytes));
    const DWORD wait = WaitForSingleObject(process.process_handle(), 10'000);
    if (wait != WAIT_OBJECT_0) {
        TerminateProcess(process.process_handle(), 314);
    }
    stdout_reader.join();
    stderr_reader.join();
    DWORD exit_code = 0;
    const bool passed =
        wait == WAIT_OBJECT_0 &&
        GetExitCodeProcess(process.process_handle(), &exit_code) != FALSE &&
        exit_code == 0 && MatchesPattern(stdout_bytes, false) &&
        MatchesPattern(stderr_bytes, true);
    CloseHandle(stdout_read);
    CloseHandle(stderr_read);
    return passed && RunDroppedReceiverTest();
}
