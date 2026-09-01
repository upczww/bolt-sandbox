#include "common/workspace_security.h"

#include <filesystem>
#include <string>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>

namespace {

bool SetDaclProtection(
    const std::filesystem::path& path,
    const bool protected_dacl) noexcept {
    std::wstring mutable_path = path.native();
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    PACL dacl = nullptr;
    if (GetNamedSecurityInfoW(
            mutable_path.data(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
            nullptr, nullptr, &dacl, nullptr, &descriptor) != ERROR_SUCCESS ||
        descriptor == nullptr) {
        return false;
    }
    const SECURITY_INFORMATION information = DACL_SECURITY_INFORMATION |
        (protected_dacl ? PROTECTED_DACL_SECURITY_INFORMATION
                        : UNPROTECTED_DACL_SECURITY_INFORMATION);
    const DWORD status = SetNamedSecurityInfoW(
        mutable_path.data(), SE_FILE_OBJECT, information, nullptr, nullptr,
        dacl, nullptr);
    LocalFree(descriptor);
    return status == ERROR_SUCCESS;
}

}  // namespace

bool RunWorkspaceSecurityTests() {
    wchar_t temporary[MAX_PATH]{};
    const DWORD length = GetTempPathW(MAX_PATH, temporary);
    if (length == 0 || length >= MAX_PATH) {
        return false;
    }
    const auto fixture = std::filesystem::path(temporary) /
                         (L"bolt-workspace-security-" +
                          std::to_wstring(GetCurrentProcessId()) + L"-" +
                          std::to_wstring(GetTickCount64()));
    const auto source = fixture / L"source";
    const auto staged = fixture / L"staged";
    std::error_code cleanup_error;
    std::filesystem::remove_all(fixture, cleanup_error);
    if (!std::filesystem::create_directories(source / L"nested") ||
        !std::filesystem::create_directories(staged / L"nested")) {
        return false;
    }
    {
        HANDLE source_file = CreateFileW(
            (source / L"nested" / L"file.txt").c_str(), GENERIC_WRITE, 0,
            nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        HANDLE staged_file = CreateFileW(
            (staged / L"nested" / L"file.txt").c_str(), GENERIC_WRITE, 0,
            nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (source_file == INVALID_HANDLE_VALUE ||
            staged_file == INVALID_HANDLE_VALUE) {
            if (source_file != INVALID_HANDLE_VALUE) {
                CloseHandle(source_file);
            }
            if (staged_file != INVALID_HANDLE_VALUE) {
                CloseHandle(staged_file);
            }
            std::filesystem::remove_all(fixture, cleanup_error);
            return false;
        }
        CloseHandle(source_file);
        CloseHandle(staged_file);
    }
    const bool prepared = SetDaclProtection(source, true) &&
                          SetDaclProtection(source / L"nested", true) &&
                          SetDaclProtection(
                              source / L"nested" / L"file.txt", true);
    const auto before = bolt::common::VerifyWorkspaceAuthorization(
        source, staged, 16);
    const auto copied = bolt::common::CopyWorkspaceAuthorization(
        source, staged, 16);
    const auto after = bolt::common::VerifyWorkspaceAuthorization(
        source, staged, 16);
    const auto created_path = staged / L"created.txt";
    const HANDLE created_file = CreateFileW(
        created_path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    const bool created = created_file != INVALID_HANDLE_VALUE;
    if (created) {
        CloseHandle(created_file);
    }
    const bool created_mutation = created && SetDaclProtection(created_path, true);
    const auto created_changed = bolt::common::VerifyWorkspaceAuthorization(
        source, staged, 16);
    std::filesystem::remove(created_path, cleanup_error);
    const bool mutation = SetDaclProtection(staged / L"nested", false);
    const auto changed = bolt::common::VerifyWorkspaceAuthorization(
        source, staged, 16);
    std::filesystem::remove_all(fixture, cleanup_error);
    return prepared &&
           before == bolt::common::WorkspaceSecurityStatus::kMismatch &&
           copied == bolt::common::WorkspaceSecurityStatus::kSuccess &&
           after == bolt::common::WorkspaceSecurityStatus::kSuccess &&
           created_mutation &&
           created_changed ==
               bolt::common::WorkspaceSecurityStatus::kMismatch &&
           mutation &&
           changed == bolt::common::WorkspaceSecurityStatus::kMismatch &&
           !cleanup_error;
}

int RunWorkspaceAclMutationFixture(
    const int argument_count,
    wchar_t** arguments) noexcept {
    if (argument_count != 3 || arguments == nullptr || arguments[2] == nullptr) {
        return ERROR_INVALID_PARAMETER;
    }
    const std::filesystem::path path(arguments[2]);
    const HANDLE file = CreateFileW(
        path.c_str(), GENERIC_WRITE | READ_CONTROL | WRITE_DAC, 0, nullptr,
        CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return GetLastError();
    }
    CloseHandle(file);
    return SetDaclProtection(path, true) ? ERROR_SUCCESS
                                         : ERROR_ACCESS_DENIED;
}
