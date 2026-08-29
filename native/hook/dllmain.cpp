#include "protocol/event_frame.h"
#include "protocol/policy_payload.h"
#include "protocol/runtime_payload.h"
#include "protocol/version.h"

#include <cstdint>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <detours.h>

extern "C" __declspec(dllexport) std::uint16_t BoltSandboxProtocolVersion() noexcept {
    return bolt::protocol::kProtocolVersion;
}

namespace {

volatile LONG g_runtime_initialized = 0;

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
        const DWORD remaining = static_cast<DWORD>(length - offset);
        if (!WriteFile(handle, bytes + offset, remaining, &written, nullptr) || written == 0) {
            return false;
        }
        offset += written;
    }
    return true;
}

bool InitializeRuntime() noexcept {
    DetourRestoreAfterWith();
    DWORD payload_length = 0;
    const auto* encoded = static_cast<const std::uint8_t*>(
        DetourFindPayloadEx(bolt::protocol::kRuntimePayloadGuid, &payload_length));
    bolt::protocol::RuntimePayload payload{};
    if (bolt::protocol::DecodeRuntimePayload(encoded, payload_length, payload) !=
            bolt::protocol::RuntimePayloadStatus::kSuccess ||
        payload.target_process_id != GetCurrentProcessId()) {
        return false;
    }

    const HANDLE policy_handle = HandleFromWire(payload.policy_handle);
    const auto* policy = static_cast<const std::uint8_t*>(
        MapViewOfFile(policy_handle, FILE_MAP_READ, 0, 0, payload.policy_length));
    if (policy == nullptr) {
        return false;
    }
    const auto policy_status =
        bolt::protocol::ValidatePolicyPayload(policy, payload.policy_length);
    UnmapViewOfFile(policy);
    if (policy_status != bolt::protocol::PolicyPayloadStatus::kValid) {
        return false;
    }

    const auto ready = bolt::protocol::EncodeReadyFrame(payload.handshake_nonce);
    InterlockedExchange(&g_runtime_initialized, 1);
    if (!WriteExact(HandleFromWire(payload.event_handle), ready.data(), ready.size())) {
        InterlockedExchange(&g_runtime_initialized, 0);
        return false;
    }
    if (WaitForSingleObject(HandleFromWire(payload.release_handle), 30'000) != WAIT_OBJECT_0) {
        InterlockedExchange(&g_runtime_initialized, 0);
        return false;
    }
    return true;
}

}  // namespace

extern "C" __declspec(dllexport) BOOL BoltSandboxRuntimeInitialized() noexcept {
    return InterlockedCompareExchange(&g_runtime_initialized, 1, 1) == 1;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) noexcept {
    static_cast<void>(reserved);
    if (reason == DLL_PROCESS_ATTACH) {
        if (DetourIsHelperProcess()) {
            return TRUE;
        }
        if (!InitializeRuntime()) {
            return FALSE;
        }
        DisableThreadLibraryCalls(instance);
    }
    return TRUE;
}
