#include "hook/filesystem/file_hooks.h"

#include "hook/filesystem/access_classifier.h"
#include "hook/filesystem/filesystem_policy.h"
#include "hook/filesystem/path_cache.h"
#include "hook/event_sink.h"

#include "DetouredFunctionTypes.h"

#include <memory>
#include <string>

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
CopyFileW_t g_copy_file_w = CopyFileW;
CopyFileExW_t g_copy_file_ex_w = CopyFileExW;
CopyFileA_t g_copy_file_a = CopyFileA;
CopyFileExA_t g_copy_file_ex_a = CopyFileExA;
CopyFileTransactedW_t g_copy_file_transacted_w = CopyFileTransactedW;
CopyFileTransactedA_t g_copy_file_transacted_a = CopyFileTransactedA;
using CopyFile2Function = HRESULT(WINAPI*)(
    PCWSTR, PCWSTR, const COPYFILE2_EXTENDED_PARAMETERS*);
CopyFile2Function g_copy_file_2 = nullptr;

void ReportDenied(
    const protocol::FilesystemOperation operation,
    const wchar_t* path) noexcept {
    static_cast<void>(hook::TryReportFilesystemViolation(operation, path));
}

const wchar_t* EvaluatedPath(
    const PolicyEvaluation& evaluation,
    const wchar_t* fallback) noexcept {
    return evaluation.normalized_path.empty() ? fallback : evaluation.normalized_path.c_str();
}

bool AuthorizeCopy(const wchar_t* existing_path, const wchar_t* new_path) noexcept {
    const auto* policy = g_policy.get();
    const auto source =
        policy == nullptr ? PolicyEvaluation{} : policy->Evaluate(existing_path, Access::kRead);
    const auto destination =
        policy == nullptr ? PolicyEvaluation{} : policy->Evaluate(new_path, Access::kWrite);
    if (source.decision == Decision::kDeny || destination.decision == Decision::kDeny) {
        const bool source_denied = source.decision == Decision::kDeny;
        ReportDenied(
            source_denied ? protocol::FilesystemOperation::kRead
                          : protocol::FilesystemOperation::kCreate,
            source_denied ? EvaluatedPath(source, existing_path)
                          : EvaluatedPath(destination, new_path));
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }
    InvalidateResolvedPathForMutation(EvaluatedPath(destination, new_path), false);
    return true;
}

bool ConvertAnsiPath(const char* path, std::wstring& converted) noexcept {
    if (path == nullptr) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }
    const int length = MultiByteToWideChar(CP_ACP, 0, path, -1, nullptr, 0);
    if (length <= 1) {
        SetLastError(ERROR_NO_UNICODE_TRANSLATION);
        return false;
    }
    try {
        converted.assign(static_cast<std::size_t>(length), L'\0');
    } catch (...) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return false;
    }
    if (MultiByteToWideChar(CP_ACP, 0, path, -1, converted.data(), length) != length) {
        converted.clear();
        SetLastError(ERROR_NO_UNICODE_TRANSLATION);
        return false;
    }
    converted.pop_back();
    return true;
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
    const auto request = ClassifyCreateFileRequest(desired_access, creation_disposition);
    const auto evaluation =
        policy == nullptr ? PolicyEvaluation{} : policy->Evaluate(filename, request.access);
    if (evaluation.decision == Decision::kDeny) {
        ReportDenied(request.operation, EvaluatedPath(evaluation, filename));
        SetLastError(ERROR_ACCESS_DENIED);
        return INVALID_HANDLE_VALUE;
    }
    if (request.access == Access::kWrite) {
        InvalidateResolvedPathForMutation(EvaluatedPath(evaluation, filename), false);
    }
    return g_create_file_w(
        filename, desired_access, share_mode, security_attributes, creation_disposition,
        flags_and_attributes, template_file);
}

// BuildXL classifies DeleteFileW as a write and preserves the last reparse
// point because the API deletes a link itself rather than its target.
BOOL WINAPI DetouredDeleteFileW(const LPCWSTR filename) noexcept {
    const auto* policy = g_policy.get();
    const auto evaluation =
        policy == nullptr ? PolicyEvaluation{} : policy->Evaluate(filename, Access::kWrite);
    if (evaluation.decision == Decision::kDeny) {
        ReportDenied(
            protocol::FilesystemOperation::kDelete, EvaluatedPath(evaluation, filename));
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    InvalidateResolvedPathForMutation(EvaluatedPath(evaluation, filename), false);
    return g_delete_file_w(filename);
}

BOOL WINAPI DetouredCreateDirectoryW(
    const LPCWSTR path,
    const LPSECURITY_ATTRIBUTES security_attributes) noexcept {
    const auto* policy = g_policy.get();
    const auto evaluation =
        policy == nullptr ? PolicyEvaluation{} : policy->Evaluate(path, Access::kWrite);
    if (evaluation.decision == Decision::kDeny) {
        ReportDenied(protocol::FilesystemOperation::kCreate, EvaluatedPath(evaluation, path));
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    InvalidateResolvedPathForMutation(EvaluatedPath(evaluation, path), true);
    return g_create_directory_w(path, security_attributes);
}

BOOL WINAPI DetouredRemoveDirectoryW(const LPCWSTR path) noexcept {
    const auto* policy = g_policy.get();
    const auto evaluation =
        policy == nullptr ? PolicyEvaluation{} : policy->Evaluate(path, Access::kWrite);
    if (evaluation.decision == Decision::kDeny) {
        ReportDenied(protocol::FilesystemOperation::kDelete, EvaluatedPath(evaluation, path));
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    InvalidateResolvedPathForMutation(EvaluatedPath(evaluation, path), true);
    return g_remove_directory_w(path);
}

// BuildXL requires write access to both sides of a move: the source is
// effectively deleted and the destination is created or replaced.
BOOL WINAPI DetouredMoveFileExW(
    const LPCWSTR existing_path,
    const LPCWSTR new_path,
    const DWORD flags) noexcept {
    const auto* policy = g_policy.get();
    const auto source =
        policy == nullptr ? PolicyEvaluation{} : policy->Evaluate(existing_path, Access::kWrite);
    const auto destination = policy == nullptr || new_path == nullptr
                                 ? PolicyEvaluation{}
                                 : policy->Evaluate(new_path, Access::kWrite);
    if (source.decision == Decision::kDeny ||
        (new_path != nullptr && destination.decision == Decision::kDeny)) {
        const bool source_denied = source.decision == Decision::kDeny;
        ReportDenied(
            protocol::FilesystemOperation::kRename,
            source_denied ? EvaluatedPath(source, existing_path)
                          : EvaluatedPath(destination, new_path));
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    InvalidateResolvedPathForMutation(EvaluatedPath(source, existing_path), true);
    InvalidateResolvedPathForMutation(EvaluatedPath(destination, new_path), true);
    return g_move_file_ex_w(existing_path, new_path, flags);
}

// Mirrors BuildXL's two-sided hard-link check: reading the existing object and
// writing the new directory entry are separate policy decisions.
BOOL WINAPI DetouredCreateHardLinkW(
    const LPCWSTR new_path,
    const LPCWSTR existing_path,
    const LPSECURITY_ATTRIBUTES security_attributes) noexcept {
    const auto* policy = g_policy.get();
    const auto source =
        policy == nullptr ? PolicyEvaluation{} : policy->Evaluate(existing_path, Access::kRead);
    const auto destination =
        policy == nullptr ? PolicyEvaluation{} : policy->Evaluate(new_path, Access::kWrite);
    if (source.decision == Decision::kDeny || destination.decision == Decision::kDeny) {
        const bool source_denied = source.decision == Decision::kDeny;
        ReportDenied(
            source_denied ? protocol::FilesystemOperation::kRead
                          : protocol::FilesystemOperation::kCreate,
            source_denied ? EvaluatedPath(source, existing_path)
                          : EvaluatedPath(destination, new_path));
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    InvalidateResolvedPathForMutation(EvaluatedPath(destination, new_path), false);
    return g_create_hard_link_w(new_path, existing_path, security_attributes);
}

// Adapts BuildXL's CopyFile contract: source and destination are independent
// policy identities requiring read and write access respectively. Bolt checks
// both before invoking Windows so a denied source cannot leave a partial copy.
BOOL WINAPI DetouredCopyFileW(
    const LPCWSTR existing_path,
    const LPCWSTR new_path,
    const BOOL fail_if_exists) noexcept {
    if (!AuthorizeCopy(existing_path, new_path)) {
        return FALSE;
    }
    return g_copy_file_w(existing_path, new_path, fail_if_exists);
}

BOOL WINAPI DetouredCopyFileExW(
    const LPCWSTR existing_path,
    const LPCWSTR new_path,
    const LPPROGRESS_ROUTINE progress_routine,
    const LPVOID data,
    const LPBOOL cancel,
    const DWORD copy_flags) noexcept {
    if (!AuthorizeCopy(existing_path, new_path)) {
        return FALSE;
    }
    return g_copy_file_ex_w(
        existing_path, new_path, progress_routine, data, cancel, copy_flags);
}

BOOL WINAPI DetouredCopyFileA(
    const LPCSTR existing_path,
    const LPCSTR new_path,
    const BOOL fail_if_exists) noexcept {
    std::wstring existing_wide;
    std::wstring new_wide;
    if (!ConvertAnsiPath(existing_path, existing_wide) ||
        !ConvertAnsiPath(new_path, new_wide) ||
        !AuthorizeCopy(existing_wide.c_str(), new_wide.c_str())) {
        return FALSE;
    }
    return g_copy_file_w(existing_wide.c_str(), new_wide.c_str(), fail_if_exists);
}

BOOL WINAPI DetouredCopyFileExA(
    const LPCSTR existing_path,
    const LPCSTR new_path,
    const LPPROGRESS_ROUTINE progress_routine,
    const LPVOID data,
    const LPBOOL cancel,
    const DWORD copy_flags) noexcept {
    std::wstring existing_wide;
    std::wstring new_wide;
    if (!ConvertAnsiPath(existing_path, existing_wide) ||
        !ConvertAnsiPath(new_path, new_wide) ||
        !AuthorizeCopy(existing_wide.c_str(), new_wide.c_str())) {
        return FALSE;
    }
    return g_copy_file_ex_w(
        existing_wide.c_str(), new_wide.c_str(), progress_routine, data, cancel, copy_flags);
}

HRESULT WINAPI DetouredCopyFile2(
    const PCWSTR existing_path,
    const PCWSTR new_path,
    const COPYFILE2_EXTENDED_PARAMETERS* extended_parameters) noexcept {
    if (!AuthorizeCopy(existing_path, new_path)) {
        return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
    }
    return g_copy_file_2(existing_path, new_path, extended_parameters);
}

BOOL WINAPI DetouredCopyFileTransactedW(
    const LPCWSTR existing_path,
    const LPCWSTR new_path,
    const LPPROGRESS_ROUTINE progress_routine,
    const LPVOID data,
    const LPBOOL cancel,
    const DWORD copy_flags,
    const HANDLE transaction) noexcept {
    if (!AuthorizeCopy(existing_path, new_path)) {
        return FALSE;
    }
    return g_copy_file_transacted_w(
        existing_path, new_path, progress_routine, data, cancel, copy_flags, transaction);
}

BOOL WINAPI DetouredCopyFileTransactedA(
    const LPCSTR existing_path,
    const LPCSTR new_path,
    const LPPROGRESS_ROUTINE progress_routine,
    const LPVOID data,
    const LPBOOL cancel,
    const DWORD copy_flags,
    const HANDLE transaction) noexcept {
    std::wstring existing_wide;
    std::wstring new_wide;
    if (!ConvertAnsiPath(existing_path, existing_wide) ||
        !ConvertAnsiPath(new_path, new_wide) ||
        !AuthorizeCopy(existing_wide.c_str(), new_wide.c_str())) {
        return FALSE;
    }
    return g_copy_file_transacted_w(
        existing_wide.c_str(), new_wide.c_str(), progress_routine, data, cancel, copy_flags,
        transaction);
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
    g_copy_file_2 = reinterpret_cast<CopyFile2Function>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CopyFile2"));
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
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_copy_file_w),
            reinterpret_cast<PVOID>(DetouredCopyFileW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_copy_file_ex_w),
            reinterpret_cast<PVOID>(DetouredCopyFileExW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_copy_file_a),
            reinterpret_cast<PVOID>(DetouredCopyFileA)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_copy_file_ex_a),
            reinterpret_cast<PVOID>(DetouredCopyFileExA)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_copy_file_transacted_w),
            reinterpret_cast<PVOID>(DetouredCopyFileTransactedW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_copy_file_transacted_a),
            reinterpret_cast<PVOID>(DetouredCopyFileTransactedA)) != NO_ERROR ||
        (g_copy_file_2 != nullptr &&
         DetourAttach(
             reinterpret_cast<PVOID*>(&g_copy_file_2),
             reinterpret_cast<PVOID>(DetouredCopyFile2)) != NO_ERROR) ||
        DetourTransactionCommit() != NO_ERROR) {
        DetourTransactionAbort();
        return HookInstallStatus::kTransactionFailed;
    }
    g_policy = std::move(policy);
    return HookInstallStatus::kSuccess;
}

}  // namespace bolt::filesystem
