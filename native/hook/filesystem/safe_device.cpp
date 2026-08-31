#include "hook/filesystem/safe_device.h"

#include <array>
#include <cstddef>
#include <cstdint>

#include <winternl.h>

namespace bolt::filesystem {
namespace {

using NtQueryObjectFunction = NTSTATUS(NTAPI*)(
    HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);

bool EqualName(
    const wchar_t* const value,
    const int value_length,
    const wchar_t* const expected) noexcept {
    return value != nullptr && expected != nullptr &&
           CompareStringOrdinal(
               value, value_length, expected, -1, TRUE) == CSTR_EQUAL;
}

}  // namespace

bool IsNullDevicePath(const wchar_t* const path) noexcept {
    if (path == nullptr || *path == L'\0') {
        return false;
    }
    return EqualName(path, -1, L"NUL") ||
           EqualName(path, -1, L"NUL:") ||
           EqualName(path, -1, L"\\\\.\\NUL") ||
           EqualName(path, -1, L"\\??\\NUL") ||
           EqualName(path, -1, L"\\Device\\Null");
}

bool IsConsoleDevicePath(const wchar_t* const path) noexcept {
    if (path == nullptr || *path == L'\0') {
        return false;
    }
    return EqualName(path, -1, L"CONIN$") ||
           EqualName(path, -1, L"CONOUT$") ||
           EqualName(path, -1, L"\\\\.\\CONIN$") ||
           EqualName(path, -1, L"\\\\.\\CONOUT$");
}

bool IsNullDeviceHandle(const HANDLE handle) noexcept {
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE ||
        GetFileType(handle) != FILE_TYPE_CHAR) {
        return false;
    }
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto query_object =
        ntdll == nullptr
            ? nullptr
            : reinterpret_cast<NtQueryObjectFunction>(
                  GetProcAddress(ntdll, "NtQueryObject"));
    if (query_object == nullptr) {
        return false;
    }
    std::array<std::uint8_t, 512> storage{};
    ULONG returned = 0;
    constexpr auto object_name_information =
        static_cast<OBJECT_INFORMATION_CLASS>(1);
    if (query_object(
            handle, object_name_information, storage.data(),
            static_cast<ULONG>(storage.size()), &returned) < 0) {
        return false;
    }
    const auto* information =
        reinterpret_cast<const UNICODE_STRING*>(storage.data());
    if (information->Buffer == nullptr || information->Length == 0 ||
        information->Length % sizeof(wchar_t) != 0) {
        return false;
    }
    const auto storage_begin =
        reinterpret_cast<std::uintptr_t>(storage.data());
    const auto storage_end = storage_begin + storage.size();
    const auto name_begin =
        reinterpret_cast<std::uintptr_t>(information->Buffer);
    const auto name_end = name_begin + information->Length;
    if (name_begin < storage_begin || name_end < name_begin ||
        name_end > storage_end) {
        return false;
    }
    return EqualName(
        information->Buffer,
        static_cast<int>(information->Length / sizeof(wchar_t)),
        L"\\Device\\Null");
}

}  // namespace bolt::filesystem
