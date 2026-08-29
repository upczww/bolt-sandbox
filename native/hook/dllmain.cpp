#include "protocol/version.h"

#include <cstdint>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

extern "C" __declspec(dllexport) std::uint16_t BoltSandboxProtocolVersion() noexcept {
    return bolt::protocol::kProtocolVersion;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) noexcept {
    static_cast<void>(instance);
    static_cast<void>(reason);
    static_cast<void>(reserved);
    return TRUE;
}
