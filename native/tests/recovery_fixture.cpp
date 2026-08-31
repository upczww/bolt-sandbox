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
