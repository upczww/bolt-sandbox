#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <detours.h>

bool RunDetoursTests() {
    const auto address = reinterpret_cast<PVOID>(&RunDetoursTests);
    return DetourGetContainingModule(address) == GetModuleHandleW(nullptr);
}
