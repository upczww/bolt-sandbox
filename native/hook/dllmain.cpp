#include "protocol/version.h"

#include <cstdint>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <detours.h>

extern "C" __declspec(dllexport) std::uint16_t BoltSandboxProtocolVersion() noexcept {
    return bolt::protocol::kProtocolVersion;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) noexcept {
    static_cast<void>(reserved);
    if (reason == DLL_PROCESS_ATTACH) {
        if (DetourIsHelperProcess()) {
            return TRUE;
        }
        DetourRestoreAfterWith();
        DisableThreadLibraryCalls(instance);
    }
    return TRUE;
}
