#include "protocol/event_frame.h"
#include "protocol/policy_payload.h"
#include "protocol/runtime_payload.h"
#include "protocol/version.h"
#include "hook/filesystem/file_hooks.h"
#include "hook/event_sink.h"
#include "hook/process/process_hooks.h"
#include "hook/process/process_mitigations.h"

#include <cstdint>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <detours.h>

extern "C" __declspec(dllexport) std::uint16_t BoltSandboxProtocolVersion() noexcept {
    return bolt::protocol::kProtocolVersion;
}

namespace {

constexpr LONG kRuntimeUninitialized = 0;
constexpr LONG kRuntimeInitializing = 1;
constexpr LONG kRuntimeInitialized = 2;
constexpr LONG kRuntimeFailed = 3;

enum class RuntimeInitializationStatus : std::uint32_t {
    kSuccess = 0,
    kAlreadyInitialized = 1,
    kFailed = 2,
};

volatile LONG g_runtime_state = kRuntimeUninitialized;
HINSTANCE g_runtime_instance = nullptr;

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

RuntimeInitializationStatus InitializeRuntime(const HINSTANCE instance) noexcept {
    const LONG prior = InterlockedCompareExchange(
        &g_runtime_state, kRuntimeInitializing, kRuntimeUninitialized);
    if (prior == kRuntimeInitialized) {
        return RuntimeInitializationStatus::kAlreadyInitialized;
    }
    if (prior != kRuntimeUninitialized) {
        return RuntimeInitializationStatus::kFailed;
    }
    const auto failed = [] {
        InterlockedExchange(&g_runtime_state, kRuntimeFailed);
        return RuntimeInitializationStatus::kFailed;
    };
    DetourRestoreAfterWith();
    DWORD payload_length = 0;
    const auto* encoded = static_cast<const std::uint8_t*>(
        DetourFindPayloadEx(bolt::protocol::kRuntimePayloadGuid, &payload_length));
    bolt::protocol::RuntimePayload payload{};
    if (bolt::protocol::DecodeRuntimePayload(encoded, payload_length, payload) !=
            bolt::protocol::RuntimePayloadStatus::kSuccess ||
        payload.target_process_id != GetCurrentProcessId()) {
        return failed();
    }

    const HANDLE policy_handle = HandleFromWire(payload.policy_handle);
    const HANDLE event_handle = HandleFromWire(payload.event_handle);
    std::array<char, 32'768> hook_path{};
    const DWORD hook_path_length = GetModuleFileNameA(
        instance, hook_path.data(), static_cast<DWORD>(hook_path.size()));
    if (hook_path_length == 0 || hook_path_length == hook_path.size() ||
        !bolt::process::ConfigureProcessRuntime(payload, hook_path.data())) {
        return failed();
    }
    if (bolt::hook::InitializeEventSink(event_handle) !=
        bolt::hook::EventSinkStatus::kSuccess) {
        return failed();
    }
    const auto* policy = static_cast<const std::uint8_t*>(
        MapViewOfFile(policy_handle, FILE_MAP_READ, 0, 0, payload.policy_length));
    if (policy == nullptr) {
        return failed();
    }
    const auto hook_status =
        bolt::filesystem::InstallFileHooks(policy, payload.policy_length);
    UnmapViewOfFile(policy);
    if (hook_status != bolt::filesystem::HookInstallStatus::kSuccess) {
        return failed();
    }
    if (bolt::process::ApplyRequiredProcessMitigations() !=
        bolt::process::ProcessMitigationStatus::kSuccess) {
        return failed();
    }

    InterlockedExchange(&g_runtime_state, kRuntimeInitialized);
    if (payload.descendant_ready_handle != 0) {
        const HANDLE descendant_ready =
            HandleFromWire(payload.descendant_ready_handle);
        const HANDLE descendant_release = HandleFromWire(payload.release_handle);
        if (!SetEvent(descendant_ready) ||
            WaitForSingleObject(descendant_release, 30'000) != WAIT_OBJECT_0) {
            InterlockedExchange(&g_runtime_state, kRuntimeFailed);
            return RuntimeInitializationStatus::kFailed;
        }
        CloseHandle(descendant_ready);
        CloseHandle(descendant_release);
        return RuntimeInitializationStatus::kSuccess;
    }

    const auto ready = bolt::protocol::EncodeReadyFrame(payload.handshake_nonce);
    if (!WriteExact(event_handle, ready.data(), ready.size())) {
        InterlockedExchange(&g_runtime_state, kRuntimeFailed);
        return RuntimeInitializationStatus::kFailed;
    }
    if (WaitForSingleObject(HandleFromWire(payload.release_handle), 30'000) != WAIT_OBJECT_0) {
        InterlockedExchange(&g_runtime_state, kRuntimeFailed);
        return RuntimeInitializationStatus::kFailed;
    }
    return RuntimeInitializationStatus::kSuccess;
}

}  // namespace

extern "C" __declspec(dllexport) BOOL BoltSandboxRuntimeInitialized() noexcept {
    return InterlockedCompareExchange(
               &g_runtime_state, kRuntimeInitialized, kRuntimeInitialized) ==
           kRuntimeInitialized;
}

extern "C" __declspec(dllexport) std::uint32_t
BoltSandboxInitializeRuntime() noexcept {
    return static_cast<std::uint32_t>(InitializeRuntime(g_runtime_instance));
}

extern "C" __declspec(dllexport) std::uint32_t
BoltSandboxInstalledFilesystemHookCount() noexcept {
    return bolt::filesystem::InstalledFileHookCount();
}

extern "C" __declspec(dllexport) BOOL BoltSandboxFlushEvents(
    const DWORD timeout_milliseconds) noexcept {
    return bolt::hook::WaitForEventSinkIdle(timeout_milliseconds) ? TRUE : FALSE;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) noexcept {
    static_cast<void>(reserved);
    if (reason == DLL_PROCESS_ATTACH) {
        if (DetourIsHelperProcess()) {
            return TRUE;
        }
        g_runtime_instance = instance;
        const auto status = InitializeRuntime(instance);
        if (status != RuntimeInitializationStatus::kSuccess &&
            status != RuntimeInitializationStatus::kAlreadyInitialized) {
            return FALSE;
        }
        DisableThreadLibraryCalls(instance);
    }
    return TRUE;
}
