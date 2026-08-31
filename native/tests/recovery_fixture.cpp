#include "protocol/recovery_protocol.h"
#include "protocol/runtime_payload.h"

#include <array>
#include <cstdint>
#include <cwchar>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <detours.h>

namespace {

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

bool WriteExact(
    const HANDLE handle,
    const std::uint8_t* bytes,
    const std::size_t length) noexcept {
    std::size_t offset = 0;
    while (offset < length) {
        DWORD written = 0;
        if (!WriteFile(
                handle, bytes + offset,
                static_cast<DWORD>(length - offset), &written, nullptr) ||
            written == 0) {
            return false;
        }
        offset += written;
    }
    return true;
}

bool ReadExact(
    const HANDLE handle,
    std::uint8_t* bytes,
    const std::size_t length) noexcept {
    std::size_t offset = 0;
    while (offset < length) {
        DWORD read = 0;
        if (!ReadFile(
                handle, bytes + offset,
                static_cast<DWORD>(length - offset), &read, nullptr) ||
            read == 0) {
            return false;
        }
        offset += read;
    }
    return true;
}

HANDLE HandleFromWire(const std::uint64_t value) noexcept {
    return reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(value));
}

}  // namespace

int RunRecoveryDeleteFixture(
    const int argument_count,
    wchar_t** arguments) noexcept {
    if (argument_count != 3 || arguments[2] == nullptr ||
        arguments[2][0] == L'\0') {
        return 334;
    }
    if (!DeleteFileW(arguments[2])) {
        return 335;
    }
    return GetFileAttributesW(arguments[2]) == INVALID_FILE_ATTRIBUTES ? 0
                                                                       : 336;
}

int RunRecoveryTruncateFixture(
    const int argument_count,
    wchar_t** arguments) noexcept {
    if (argument_count != 3 || arguments[2] == nullptr ||
        arguments[2][0] == L'\0') {
        return 337;
    }
    const HANDLE file = CreateFileW(
        arguments[2], GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return 338;
    }
    LARGE_INTEGER offset{};
    offset.QuadPart = 4;
    const bool truncated = SetFilePointerEx(file, offset, nullptr, FILE_BEGIN) &&
                           SetEndOfFile(file);
    CloseHandle(file);
    return truncated ? 0 : 339;
}

int RunRecoveryReplaceRenameFixture(
    const int argument_count,
    wchar_t** arguments) noexcept {
    if (argument_count != 6) {
        return 340;
    }
    if (!ReplaceFileW(
            arguments[2], arguments[3], nullptr, 0, nullptr, nullptr)) {
        return 341;
    }
    if (!MoveFileExW(
            arguments[4], arguments[5], MOVEFILE_REPLACE_EXISTING)) {
        return 342;
    }
    return 0;
}

int RunUnauthorizedRecoveryRequestFixture(
    const int argument_count,
    wchar_t** arguments) noexcept {
    if (argument_count != 3) {
        return 343;
    }
    DWORD payload_length = 0;
    const auto* encoded_payload = static_cast<const std::uint8_t*>(
        DetourFindPayloadEx(
            bolt::protocol::kRuntimePayloadGuid, &payload_length));
    bolt::protocol::RuntimePayload payload{};
    if (bolt::protocol::DecodeRuntimePayload(
            encoded_payload, payload_length, payload) !=
        bolt::protocol::RuntimePayloadStatus::kSuccess) {
        return 344;
    }
    const HANDLE mutex = HandleFromWire(payload.recovery_mutex_handle);
    const DWORD wait = WaitForSingleObject(mutex, 5'000);
    if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED) {
        return 345;
    }
    auto* counter = static_cast<volatile LONG64*>(MapViewOfFile(
        HandleFromWire(payload.recovery_counter_handle),
        FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(LONG64)));
    const LONG64 request_id =
        counter == nullptr ? 0 : InterlockedIncrement64(counter);
    std::vector<std::uint8_t> request;
    const bool encoded = request_id > 0 &&
        bolt::protocol::EncodeRecoveryRequest(
            static_cast<std::uint64_t>(request_id), GetCurrentProcessId(),
            bolt::protocol::RecoveryOperation::kDelete, arguments[2],
            request) == bolt::protocol::RecoveryProtocolStatus::kSuccess;
    std::array<std::uint8_t, bolt::protocol::kRecoveryResponseLength> response{};
    const bool exchanged = encoded &&
        WriteExact(
            HandleFromWire(payload.recovery_request_handle), request.data(),
            request.size()) &&
        ReadExact(
            HandleFromWire(payload.recovery_response_handle), response.data(),
            response.size());
    bolt::protocol::RecoveryResponse decoded{};
    const bool valid = exchanged &&
        bolt::protocol::DecodeRecoveryResponse(
            response.data(), response.size(), decoded) ==
            bolt::protocol::RecoveryProtocolStatus::kSuccess &&
        decoded.request_id == static_cast<std::uint64_t>(request_id);
    if (counter != nullptr) {
        UnmapViewOfFile(const_cast<LONG64*>(counter));
    }
    ReleaseMutex(mutex);
    return valid && !decoded.succeeded ? 0 : 346;
}

int RunRecoveryDeleteTwoFixture(
    const int argument_count,
    wchar_t** arguments) noexcept {
    if (argument_count != 4) {
        return 347;
    }
    if (!DeleteFileW(arguments[2])) {
        return 348;
    }
    return DeleteFileW(arguments[3]) ? 0 : 349;
}

int RunRecoveryHandleAndChildFixture(
    const int argument_count,
    wchar_t** arguments) noexcept {
    if (argument_count != 4) {
        return 350;
    }
    const HANDLE handle = CreateFileW(
        arguments[2], DELETE | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    FILE_DISPOSITION_INFO disposition{};
    disposition.DeleteFile = TRUE;
    const bool disposed = handle != INVALID_HANDLE_VALUE &&
        SetFileInformationByHandle(
            handle, FileDispositionInfo, &disposition, sizeof(disposition));
    if (handle != INVALID_HANDLE_VALUE) {
        CloseHandle(handle);
    }
    if (!disposed) {
        return 351;
    }
    const std::wstring executable = CurrentExecutable();
    std::wstring command = L"\"" + executable +
                           L"\" --recovery-delete-fixture \"" +
                           arguments[3] + L"\"";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (executable.empty() ||
        !CreateProcessW(
            executable.c_str(), command.data(), nullptr, nullptr, TRUE, 0,
            nullptr, nullptr, &startup, &process)) {
        return 352;
    }
    const DWORD wait = WaitForSingleObject(process.hProcess, 10'000);
    DWORD exit_code = 353;
    if (wait != WAIT_OBJECT_0 ||
        !GetExitCodeProcess(process.hProcess, &exit_code)) {
        TerminateProcess(process.hProcess, 353);
        WaitForSingleObject(process.hProcess, 5'000);
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return static_cast<int>(exit_code);
}
