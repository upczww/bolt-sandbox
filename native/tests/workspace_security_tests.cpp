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
    const SECURITY_INFORMATION information =
        protected_dacl ? PROTECTED_DACL_SECURITY_INFORMATION
                       : UNPROTECTED_DACL_SECURITY_INFORMATION;
    return SetNamedSecurityInfoW(
               mutable_path.data(), SE_FILE_OBJECT, information, nullptr,
               nullptr, nullptr, nullptr) == ERROR_SUCCESS;
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
    const bool mutation = SetDaclProtection(staged / L"nested", false);
    const auto changed = bolt::common::VerifyWorkspaceAuthorization(
        source, staged, 16);
    std::filesystem::remove_all(fixture, cleanup_error);
    return prepared &&
           before == bolt::common::WorkspaceSecurityStatus::kMismatch &&
           copied == bolt::common::WorkspaceSecurityStatus::kSuccess &&
           after == bolt::common::WorkspaceSecurityStatus::kSuccess &&
           mutation &&
           changed == bolt::common::WorkspaceSecurityStatus::kMismatch &&
           !cleanup_error;
}
