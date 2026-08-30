#include "hook/filesystem/file_hooks.h"

#include "hook/filesystem/filesystem_policy.h"

#include <memory>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <detours.h>

namespace bolt::filesystem {
namespace {

std::unique_ptr<FilesystemPolicy> g_policy;

using CreateFileWFunction = HANDLE(WINAPI*)(
    LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
CreateFileWFunction g_create_file_w = CreateFileW;
using DeleteFileWFunction = BOOL(WINAPI*)(LPCWSTR);
DeleteFileWFunction g_delete_file_w = DeleteFileW;
using CreateDirectoryWFunction = BOOL(WINAPI*)(LPCWSTR, LPSECURITY_ATTRIBUTES);
CreateDirectoryWFunction g_create_directory_w = CreateDirectoryW;
using RemoveDirectoryWFunction = BOOL(WINAPI*)(LPCWSTR);
RemoveDirectoryWFunction g_remove_directory_w = RemoveDirectoryW;
using MoveFileExWFunction = BOOL(WINAPI*)(LPCWSTR, LPCWSTR, DWORD);
MoveFileExWFunction g_move_file_ex_w = MoveFileExW;
using CreateHardLinkWFunction = BOOL(WINAPI*)(LPCWSTR, LPCWSTR, LPSECURITY_ATTRIBUTES);
CreateHardLinkWFunction g_create_hard_link_w = CreateHardLinkW;

Access ClassifyAccess(const DWORD desired_access, const DWORD creation_disposition) noexcept {
    constexpr DWORD write_access = GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA |
                                   FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE |
                                   WRITE_DAC | WRITE_OWNER;
    if ((desired_access & write_access) != 0 || creation_disposition == CREATE_NEW ||
        creation_disposition == CREATE_ALWAYS || creation_disposition == TRUNCATE_EXISTING) {
        return Access::kWrite;
    }
    return desired_access == 0 ? Access::kMetadata : Access::kRead;
}

HANDLE WINAPI DetouredCreateFileW(
    const LPCWSTR filename,
    const DWORD desired_access,
    const DWORD share_mode,
    const LPSECURITY_ATTRIBUTES security_attributes,
    const DWORD creation_disposition,
    const DWORD flags_and_attributes,
    const HANDLE template_file) noexcept {
    const auto* policy = g_policy.get();
    if (policy == nullptr ||
        policy->Decide(filename, ClassifyAccess(desired_access, creation_disposition)) ==
            Decision::kDeny) {
        SetLastError(ERROR_ACCESS_DENIED);
        return INVALID_HANDLE_VALUE;
    }
    return g_create_file_w(
        filename, desired_access, share_mode, security_attributes, creation_disposition,
        flags_and_attributes, template_file);
}

// BuildXL classifies DeleteFileW as a write and preserves the last reparse
// point because the API deletes a link itself rather than its target.
BOOL WINAPI DetouredDeleteFileW(const LPCWSTR filename) noexcept {
    const auto* policy = g_policy.get();
    if (policy == nullptr || policy->Decide(filename, Access::kWrite) == Decision::kDeny) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return g_delete_file_w(filename);
}

BOOL WINAPI DetouredCreateDirectoryW(
    const LPCWSTR path,
    const LPSECURITY_ATTRIBUTES security_attributes) noexcept {
    const auto* policy = g_policy.get();
    if (policy == nullptr || policy->Decide(path, Access::kWrite) == Decision::kDeny) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return g_create_directory_w(path, security_attributes);
}

BOOL WINAPI DetouredRemoveDirectoryW(const LPCWSTR path) noexcept {
    const auto* policy = g_policy.get();
    if (policy == nullptr || policy->Decide(path, Access::kWrite) == Decision::kDeny) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return g_remove_directory_w(path);
}

// BuildXL requires write access to both sides of a move: the source is
// effectively deleted and the destination is created or replaced.
BOOL WINAPI DetouredMoveFileExW(
    const LPCWSTR existing_path,
    const LPCWSTR new_path,
    const DWORD flags) noexcept {
    const auto* policy = g_policy.get();
    if (policy == nullptr ||
        policy->Decide(existing_path, Access::kWrite) == Decision::kDeny ||
        (new_path != nullptr && policy->Decide(new_path, Access::kWrite) == Decision::kDeny)) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return g_move_file_ex_w(existing_path, new_path, flags);
}

// Mirrors BuildXL's two-sided hard-link check: reading the existing object and
// writing the new directory entry are separate policy decisions.
BOOL WINAPI DetouredCreateHardLinkW(
    const LPCWSTR new_path,
    const LPCWSTR existing_path,
    const LPSECURITY_ATTRIBUTES security_attributes) noexcept {
    const auto* policy = g_policy.get();
    if (policy == nullptr || policy->Decide(existing_path, Access::kRead) == Decision::kDeny ||
        policy->Decide(new_path, Access::kWrite) == Decision::kDeny) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return g_create_hard_link_w(new_path, existing_path, security_attributes);
}

}  // namespace

HookInstallStatus InstallFileHooks(
    const std::uint8_t* policy_payload,
    const std::size_t policy_length) noexcept {
    if (g_policy != nullptr) {
        return HookInstallStatus::kTransactionFailed;
    }

    std::unique_ptr<FilesystemPolicy> policy;
    if (FilesystemPolicy::Load(policy_payload, policy_length, policy) != PolicyLoadStatus::kValid) {
        return HookInstallStatus::kInvalidPolicy;
    }
    if (DetourTransactionBegin() != NO_ERROR) {
        return HookInstallStatus::kTransactionFailed;
    }
    if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_create_file_w),
            reinterpret_cast<PVOID>(DetouredCreateFileW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_delete_file_w),
            reinterpret_cast<PVOID>(DetouredDeleteFileW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_create_directory_w),
            reinterpret_cast<PVOID>(DetouredCreateDirectoryW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_remove_directory_w),
            reinterpret_cast<PVOID>(DetouredRemoveDirectoryW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_move_file_ex_w),
            reinterpret_cast<PVOID>(DetouredMoveFileExW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_create_hard_link_w),
            reinterpret_cast<PVOID>(DetouredCreateHardLinkW)) != NO_ERROR ||
        DetourTransactionCommit() != NO_ERROR) {
        DetourTransactionAbort();
        return HookInstallStatus::kTransactionFailed;
    }
    g_policy = std::move(policy);
    return HookInstallStatus::kSuccess;
}

}  // namespace bolt::filesystem
