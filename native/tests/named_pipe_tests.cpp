#include "common/private_pipe.h"

#include <string>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>

namespace {

std::wstring PipeName(const wchar_t suffix) {
    return std::wstring(L"\\\\.\\pipe\\bolt-sandbox-") + std::wstring(31, L'0') + suffix;
}

bool HasProtectedNonEmptyDacl(const HANDLE handle) {
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const DWORD status = GetSecurityInfo(
        handle, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl, nullptr,
        &descriptor);
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    const bool valid = status == ERROR_SUCCESS && dacl != nullptr && dacl->AceCount >= 1 &&
                       GetSecurityDescriptorControl(descriptor, &control, &revision) != FALSE &&
                       (control & SE_DACL_PROTECTED) != 0;
    if (descriptor != nullptr) {
        LocalFree(descriptor);
    }
    return valid;
}

}  // namespace

bool RunNamedPipeTests() {
    bolt::common::PrivatePipe invalid;
    if (bolt::common::PrivatePipe::Create(L"relative-pipe", invalid) !=
        bolt::common::PipeStatus::kInvalidName) {
        return false;
    }

    const std::wstring first_name = PipeName(L'a');
    const std::wstring second_name = PipeName(L'b');
    bolt::common::PrivatePipe first;
    bolt::common::PrivatePipe second;
    if (bolt::common::PrivatePipe::Create(first_name, first) !=
            bolt::common::PipeStatus::kSuccess ||
        bolt::common::PrivatePipe::Create(second_name, second) !=
            bolt::common::PipeStatus::kSuccess ||
        first.handle() == second.handle() || !HasProtectedNonEmptyDacl(first.handle())) {
        return false;
    }

    bolt::common::PrivatePipe squatter;
    if (bolt::common::PrivatePipe::Create(first_name, squatter) !=
        bolt::common::PipeStatus::kCreateFailed) {
        return false;
    }

    const HANDLE client = CreateFileW(
        first_name.c_str(), GENERIC_READ | FILE_WRITE_DATA, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (client == INVALID_HANDLE_VALUE ||
        first.Accept() != bolt::common::PipeStatus::kSuccess) {
        if (client != INVALID_HANDLE_VALUE) {
            CloseHandle(client);
        }
        return false;
    }
    CloseHandle(client);

    const std::wstring remote_name =
        std::wstring(L"\\\\localhost\\pipe\\bolt-sandbox-") + std::wstring(31, L'0') + L'b';
    const HANDLE remote = CreateFileW(
        remote_name.c_str(), GENERIC_READ | FILE_WRITE_DATA, 0, nullptr, OPEN_EXISTING, 0,
        nullptr);
    if (remote != INVALID_HANDLE_VALUE) {
        CloseHandle(remote);
        return false;
    }
    return true;
}
