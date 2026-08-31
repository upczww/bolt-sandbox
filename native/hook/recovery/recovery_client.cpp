#include "hook/recovery/recovery_client.h"

#include <array>
#include <atomic>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace bolt::recovery {
namespace {

HANDLE g_request = nullptr;
HANDLE g_response = nullptr;
HANDLE g_mutex = nullptr;
volatile LONG64* g_counter = nullptr;
std::atomic_bool g_configured = false;

HANDLE HandleFromWire(const std::uint64_t value) noexcept {
    return reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(value));
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

}  // namespace

bool ConfigureRecoveryClient(
    const protocol::RuntimePayload& payload) noexcept {
    const bool absent = payload.recovery_request_handle == 0 &&
                        payload.recovery_response_handle == 0 &&
                        payload.recovery_mutex_handle == 0 &&
                        payload.recovery_counter_handle == 0;
    if (absent) {
        return true;
    }
    if (payload.recovery_request_handle == 0 ||
        payload.recovery_response_handle == 0 ||
        payload.recovery_mutex_handle == 0 ||
        payload.recovery_counter_handle == 0 ||
        g_configured.exchange(true, std::memory_order_acq_rel)) {
        return false;
    }
    g_request = HandleFromWire(payload.recovery_request_handle);
    g_response = HandleFromWire(payload.recovery_response_handle);
    g_mutex = HandleFromWire(payload.recovery_mutex_handle);
    g_counter = static_cast<volatile LONG64*>(MapViewOfFile(
        HandleFromWire(payload.recovery_counter_handle),
        FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(LONG64)));
    DWORD flags = 0;
    return g_counter != nullptr && GetHandleInformation(g_request, &flags) &&
           GetHandleInformation(g_response, &flags) &&
           GetHandleInformation(g_mutex, &flags);
}

RecoveryClientStatus BackupPath(
    const wchar_t* const path,
    const protocol::RecoveryOperation operation) noexcept {
    if (!g_configured.load(std::memory_order_acquire)) {
        return RecoveryClientStatus::kDisabled;
    }
    const DWORD wait = WaitForSingleObject(g_mutex, 30'000);
    if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED) {
        return RecoveryClientStatus::kFailed;
    }
    const LONG64 next = InterlockedIncrement64(g_counter);
    std::vector<std::uint8_t> request;
    const bool request_ready = next > 0 &&
        protocol::EncodeRecoveryRequest(
            static_cast<std::uint64_t>(next), GetCurrentProcessId(),
            operation, path, request) ==
            protocol::RecoveryProtocolStatus::kSuccess;
    std::array<std::uint8_t, protocol::kRecoveryResponseLength> response{};
    const bool exchanged = request_ready &&
        WriteExact(g_request, request.data(), request.size()) &&
        ReadExact(g_response, response.data(), response.size());
    protocol::RecoveryResponse decoded{};
    const bool valid = exchanged &&
        protocol::DecodeRecoveryResponse(
            response.data(), response.size(), decoded) ==
            protocol::RecoveryProtocolStatus::kSuccess &&
        decoded.request_id == static_cast<std::uint64_t>(next);
    const bool released = ReleaseMutex(g_mutex) != FALSE;
    return valid && released && decoded.succeeded
               ? RecoveryClientStatus::kSuccess
               : RecoveryClientStatus::kFailed;
}

}  // namespace bolt::recovery
