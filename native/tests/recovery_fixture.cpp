#include <cwchar>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

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
