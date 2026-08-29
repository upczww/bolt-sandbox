#define WIN32_LEAN_AND_MEAN
#include <windows.h>

int wmain() noexcept {
    // The launcher must never run a target without validated inherited resources.
    return ERROR_INVALID_HANDLE;
}
