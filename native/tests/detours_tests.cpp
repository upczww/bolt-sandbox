#include <detours.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

bool RunDetoursTests() {
    const HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (kernel32 == nullptr) {
        return false;
    }
    const FARPROC function = GetProcAddress(kernel32, "CreateProcessW");
    if (function == nullptr) {
        return false;
    }
    return DetourGetContainingModule(reinterpret_cast<PVOID>(function)) != nullptr;
}
