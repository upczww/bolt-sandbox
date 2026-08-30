#include "hook/filesystem/file_hooks.h"

#include "hook/filesystem/access_classifier.h"
#include "hook/filesystem/final_path_resolver.h"
#include "hook/filesystem/filesystem_policy.h"
#include "hook/filesystem/path_cache.h"
#include "hook/event_sink.h"

#include "DetouredFunctionTypes.h"
#include "DetouredScope.h"

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
MoveFileW_t g_move_file_w = MoveFileW;
MoveFileA_t g_move_file_a = MoveFileA;
MoveFileExW_t g_move_file_ex_w = MoveFileExW;
MoveFileExA_t g_move_file_ex_a = MoveFileExA;
MoveFileWithProgressW_t g_move_file_with_progress_w = MoveFileWithProgressW;
MoveFileWithProgressA_t g_move_file_with_progress_a = MoveFileWithProgressA;
MoveFileTransactedW_t g_move_file_transacted_w = MoveFileTransactedW;
MoveFileTransactedA_t g_move_file_transacted_a = MoveFileTransactedA;
ReplaceFileW_t g_replace_file_w = ReplaceFileW;
ReplaceFileA_t g_replace_file_a = ReplaceFileA;
SetFileInformationByHandle_t g_set_file_information_by_handle = SetFileInformationByHandle;
using SetEndOfFileFunction = BOOL(WINAPI*)(HANDLE);
SetEndOfFileFunction g_set_end_of_file = SetEndOfFile;
ZwSetInformationFile_t g_zw_set_information_file = nullptr;
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
    const auto source_text =
        policy == nullptr ? PolicyEvaluation{} : policy->Evaluate(existing_path, Access::kRead);
    const auto destination_text =
        policy == nullptr ? PolicyEvaluation{} : policy->Evaluate(new_path, Access::kWrite);
    if (source_text.decision == Decision::kDeny ||
        destination_text.decision == Decision::kDeny) {
        const bool source_denied = source_text.decision == Decision::kDeny;
        ReportDenied(
            source_denied ? protocol::FilesystemOperation::kRead
                          : protocol::FilesystemOperation::kCreate,
            source_denied ? EvaluatedPath(source_text, existing_path)
                          : EvaluatedPath(destination_text, new_path));
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }

    std::wstring resolved_source;
    std::wstring resolved_destination;
    const wchar_t* source_path = EvaluatedPath(source_text, existing_path);
    const wchar_t* destination_path = EvaluatedPath(destination_text, new_path);
    if (!ResolveFinalPathForPolicy(source_path, g_create_file_w, resolved_source) ||
        !ResolveFinalPathForPolicy(
            destination_path, g_create_file_w, resolved_destination)) {
        ReportDenied(protocol::FilesystemOperation::kRead, source_path);
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }

    const auto source_final = policy->Evaluate(resolved_source.c_str(), Access::kRead);
    const auto destination_final =
        policy->Evaluate(resolved_destination.c_str(), Access::kWrite);
    if (source_final.decision == Decision::kDeny ||
        destination_final.decision == Decision::kDeny) {
        const bool source_denied = source_final.decision == Decision::kDeny;
        ReportDenied(
            source_denied ? protocol::FilesystemOperation::kRead
                          : protocol::FilesystemOperation::kCreate,
            source_denied ? EvaluatedPath(source_final, resolved_source.c_str())
                          : EvaluatedPath(destination_final, resolved_destination.c_str()));
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }
    InvalidateResolvedPathForMutation(resolved_destination.c_str(), false);
    return true;
}

bool AuthorizeMove(const wchar_t* existing_path, const wchar_t* new_path) noexcept {
    if (existing_path == nullptr || new_path == nullptr) {
        return true;
    }
    const auto* policy = g_policy.get();
    const auto source_text =
        policy == nullptr ? PolicyEvaluation{} : policy->Evaluate(existing_path, Access::kWrite);
    const auto destination_text =
        policy == nullptr ? PolicyEvaluation{} : policy->Evaluate(new_path, Access::kWrite);
    if (source_text.decision == Decision::kDeny ||
        destination_text.decision == Decision::kDeny) {
        const bool source_denied = source_text.decision == Decision::kDeny;
        ReportDenied(
            protocol::FilesystemOperation::kRename,
            source_denied ? EvaluatedPath(source_text, existing_path)
                          : EvaluatedPath(destination_text, new_path));
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }

    const wchar_t* source_path = EvaluatedPath(source_text, existing_path);
    const wchar_t* destination_path = EvaluatedPath(destination_text, new_path);
    std::wstring resolved_source;
    std::wstring resolved_destination;
    if (!ResolveFinalPathForPolicy(source_path, g_create_file_w, resolved_source) ||
        !ResolveFinalPathForPolicy(
            destination_path, g_create_file_w, resolved_destination)) {
        ReportDenied(protocol::FilesystemOperation::kRename, source_path);
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }

    const auto source_final = policy->Evaluate(resolved_source.c_str(), Access::kWrite);
    const auto destination_final =
        policy->Evaluate(resolved_destination.c_str(), Access::kWrite);
    if (source_final.decision == Decision::kDeny ||
        destination_final.decision == Decision::kDeny) {
        const bool source_denied = source_final.decision == Decision::kDeny;
        ReportDenied(
            protocol::FilesystemOperation::kRename,
            source_denied ? EvaluatedPath(source_final, resolved_source.c_str())
                          : EvaluatedPath(destination_final, resolved_destination.c_str()));
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }
    InvalidateResolvedPathForMutation(resolved_source.c_str(), true);
    InvalidateResolvedPathForMutation(resolved_destination.c_str(), true);
    return true;
}

bool AuthorizeReplace(
    const wchar_t* replaced_path,
    const wchar_t* replacement_path,
    const wchar_t* backup_path) noexcept {
    if (replaced_path == nullptr || replacement_path == nullptr) {
        return true;
    }
    const auto* policy = g_policy.get();
    const auto replacement_text = policy == nullptr
                                      ? PolicyEvaluation{}
                                      : policy->Evaluate(replacement_path, Access::kWrite);
    const auto replaced_text =
        policy == nullptr ? PolicyEvaluation{} : policy->Evaluate(replaced_path, Access::kWrite);
    const auto backup_text = policy == nullptr || backup_path == nullptr
                                 ? PolicyEvaluation{}
                                 : policy->Evaluate(backup_path, Access::kWrite);
    const PolicyEvaluation* denied_text = nullptr;
    const wchar_t* denied_fallback = nullptr;
    if (replacement_text.decision == Decision::kDeny) {
        denied_text = &replacement_text;
        denied_fallback = replacement_path;
    } else if (replaced_text.decision == Decision::kDeny) {
        denied_text = &replaced_text;
        denied_fallback = replaced_path;
    } else if (backup_text.decision == Decision::kDeny) {
        denied_text = &backup_text;
        denied_fallback = backup_path;
    }
    if (denied_text != nullptr) {
        ReportDenied(
            protocol::FilesystemOperation::kRename,
            EvaluatedPath(*denied_text, denied_fallback));
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }

    std::wstring resolved_replacement;
    std::wstring resolved_replaced;
    std::wstring resolved_backup;
    if (!ResolveFinalPathForPolicy(
            EvaluatedPath(replacement_text, replacement_path), g_create_file_w,
            resolved_replacement) ||
        !ResolveFinalPathForPolicy(
            EvaluatedPath(replaced_text, replaced_path), g_create_file_w,
            resolved_replaced) ||
        (backup_path != nullptr &&
         !ResolveFinalPathForPolicy(
             EvaluatedPath(backup_text, backup_path), g_create_file_w, resolved_backup))) {
        ReportDenied(protocol::FilesystemOperation::kRename, replacement_path);
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }

    const auto replacement_final =
        policy->Evaluate(resolved_replacement.c_str(), Access::kWrite);
    const auto replaced_final = policy->Evaluate(resolved_replaced.c_str(), Access::kWrite);
    const auto backup_final = backup_path == nullptr
                                  ? PolicyEvaluation{}
                                  : policy->Evaluate(resolved_backup.c_str(), Access::kWrite);
    const PolicyEvaluation* denied_final = nullptr;
    const wchar_t* denied_final_path = nullptr;
    if (replacement_final.decision == Decision::kDeny) {
        denied_final = &replacement_final;
        denied_final_path = resolved_replacement.c_str();
    } else if (replaced_final.decision == Decision::kDeny) {
        denied_final = &replaced_final;
        denied_final_path = resolved_replaced.c_str();
    } else if (backup_final.decision == Decision::kDeny) {
        denied_final = &backup_final;
        denied_final_path = resolved_backup.c_str();
    }
    if (denied_final != nullptr) {
        ReportDenied(
            protocol::FilesystemOperation::kRename,
            EvaluatedPath(*denied_final, denied_final_path));
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }

    InvalidateResolvedPathForMutation(resolved_replacement.c_str(), false);
    InvalidateResolvedPathForMutation(resolved_replaced.c_str(), false);
    if (backup_path != nullptr) {
        InvalidateResolvedPathForMutation(resolved_backup.c_str(), false);
    }
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

bool TryGetHandlePath(const HANDLE handle, std::wstring& path) noexcept {
    constexpr DWORD flags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
    const DWORD required = GetFinalPathNameByHandleW(handle, nullptr, 0, flags);
    if (required == 0) {
        return false;
    }
    try {
        path.assign(required, L'\0');
    } catch (...) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return false;
    }
    const DWORD written =
        GetFinalPathNameByHandleW(handle, path.data(), static_cast<DWORD>(path.size()), flags);
    if (written == 0 || written >= path.size()) {
        path.clear();
        return false;
    }
    path.resize(written);
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
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_create_file_w(
            filename, desired_access, share_mode, security_attributes, creation_disposition,
            flags_and_attributes, template_file);
    }
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
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_delete_file_w(filename);
    }
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
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_create_directory_w(path, security_attributes);
    }
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
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_remove_directory_w(path);
    }
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

// BuildXL funnels the move family through one two-sided policy decision. The
// source is effectively deleted and the destination is created or replaced.
BOOL WINAPI DetouredMoveFileW(
    const LPCWSTR existing_path,
    const LPCWSTR new_path) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_move_file_w(existing_path, new_path);
    }
    return AuthorizeMove(existing_path, new_path)
               ? g_move_file_w(existing_path, new_path)
               : FALSE;
}

BOOL WINAPI DetouredMoveFileA(
    const LPCSTR existing_path,
    const LPCSTR new_path) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_move_file_a(existing_path, new_path);
    }
    std::wstring existing_wide;
    std::wstring new_wide;
    if (!ConvertAnsiPath(existing_path, existing_wide) ||
        !ConvertAnsiPath(new_path, new_wide) ||
        !AuthorizeMove(existing_wide.c_str(), new_wide.c_str())) {
        return FALSE;
    }
    return g_move_file_w(existing_wide.c_str(), new_wide.c_str());
}

BOOL WINAPI DetouredMoveFileExW(
    const LPCWSTR existing_path,
    const LPCWSTR new_path,
    const DWORD flags) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_move_file_ex_w(existing_path, new_path, flags);
    }
    return AuthorizeMove(existing_path, new_path)
               ? g_move_file_ex_w(existing_path, new_path, flags)
               : FALSE;
}

BOOL WINAPI DetouredMoveFileExA(
    const LPCSTR existing_path,
    const LPCSTR new_path,
    const DWORD flags) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_move_file_ex_a(existing_path, new_path, flags);
    }
    std::wstring existing_wide;
    std::wstring new_wide;
    if (!ConvertAnsiPath(existing_path, existing_wide) ||
        !ConvertAnsiPath(new_path, new_wide) ||
        !AuthorizeMove(existing_wide.c_str(), new_wide.c_str())) {
        return FALSE;
    }
    return g_move_file_ex_w(existing_wide.c_str(), new_wide.c_str(), flags);
}

BOOL WINAPI DetouredMoveFileWithProgressW(
    const LPCWSTR existing_path,
    const LPCWSTR new_path,
    const LPPROGRESS_ROUTINE progress_routine,
    const LPVOID data,
    const DWORD flags) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_move_file_with_progress_w(
            existing_path, new_path, progress_routine, data, flags);
    }
    return AuthorizeMove(existing_path, new_path)
               ? g_move_file_with_progress_w(
                     existing_path, new_path, progress_routine, data, flags)
               : FALSE;
}

BOOL WINAPI DetouredMoveFileWithProgressA(
    const LPCSTR existing_path,
    const LPCSTR new_path,
    const LPPROGRESS_ROUTINE progress_routine,
    const LPVOID data,
    const DWORD flags) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_move_file_with_progress_a(
            existing_path, new_path, progress_routine, data, flags);
    }
    std::wstring existing_wide;
    std::wstring new_wide;
    if (!ConvertAnsiPath(existing_path, existing_wide) ||
        !ConvertAnsiPath(new_path, new_wide) ||
        !AuthorizeMove(existing_wide.c_str(), new_wide.c_str())) {
        return FALSE;
    }
    return g_move_file_with_progress_w(
        existing_wide.c_str(), new_wide.c_str(), progress_routine, data, flags);
}

BOOL WINAPI DetouredMoveFileTransactedW(
    const LPCWSTR existing_path,
    const LPCWSTR new_path,
    const LPPROGRESS_ROUTINE progress_routine,
    const LPVOID data,
    const DWORD flags,
    const HANDLE transaction) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_move_file_transacted_w(
            existing_path, new_path, progress_routine, data, flags, transaction);
    }
    return AuthorizeMove(existing_path, new_path)
               ? g_move_file_transacted_w(
                     existing_path, new_path, progress_routine, data, flags, transaction)
               : FALSE;
}

BOOL WINAPI DetouredMoveFileTransactedA(
    const LPCSTR existing_path,
    const LPCSTR new_path,
    const LPPROGRESS_ROUTINE progress_routine,
    const LPVOID data,
    const DWORD flags,
    const HANDLE transaction) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_move_file_transacted_a(
            existing_path, new_path, progress_routine, data, flags, transaction);
    }
    std::wstring existing_wide;
    std::wstring new_wide;
    if (!ConvertAnsiPath(existing_path, existing_wide) ||
        !ConvertAnsiPath(new_path, new_wide) ||
        !AuthorizeMove(existing_wide.c_str(), new_wide.c_str())) {
        return FALSE;
    }
    return g_move_file_transacted_w(
        existing_wide.c_str(), new_wide.c_str(), progress_routine, data, flags, transaction);
}

BOOL WINAPI DetouredReplaceFileW(
    const LPCWSTR replaced_path,
    const LPCWSTR replacement_path,
    const LPCWSTR backup_path,
    const DWORD flags,
    const LPVOID exclude,
    const LPVOID reserved) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_replace_file_w(
            replaced_path, replacement_path, backup_path, flags, exclude, reserved);
    }
    return AuthorizeReplace(replaced_path, replacement_path, backup_path)
               ? g_replace_file_w(
                     replaced_path, replacement_path, backup_path, flags, exclude, reserved)
               : FALSE;
}

BOOL WINAPI DetouredReplaceFileA(
    const LPCSTR replaced_path,
    const LPCSTR replacement_path,
    const LPCSTR backup_path,
    const DWORD flags,
    const LPVOID exclude,
    const LPVOID reserved) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_replace_file_a(
            replaced_path, replacement_path, backup_path, flags, exclude, reserved);
    }
    std::wstring replaced_wide;
    std::wstring replacement_wide;
    std::wstring backup_wide;
    if (!ConvertAnsiPath(replaced_path, replaced_wide) ||
        !ConvertAnsiPath(replacement_path, replacement_wide) ||
        (backup_path != nullptr && !ConvertAnsiPath(backup_path, backup_wide)) ||
        !AuthorizeReplace(
            replaced_wide.c_str(), replacement_wide.c_str(),
            backup_path == nullptr ? nullptr : backup_wide.c_str())) {
        return FALSE;
    }
    return g_replace_file_w(
        replaced_wide.c_str(), replacement_wide.c_str(),
        backup_path == nullptr ? nullptr : backup_wide.c_str(), flags, exclude, reserved);
}

BOOL WINAPI DetouredSetFileInformationByHandle(
    const HANDLE file,
    const FILE_INFO_BY_HANDLE_CLASS information_class,
    const LPVOID information,
    const DWORD information_size) noexcept {
    const bool is_rename = information_class == FileRenameInfo;
    const bool is_disposition = information_class == FileDispositionInfo ||
                                information_class == FileDispositionInfoEx;
    if (!is_rename && !is_disposition) {
        return g_set_file_information_by_handle(
            file, information_class, information, information_size);
    }
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_set_file_information_by_handle(
            file, information_class, information, information_size);
    }

    if (is_disposition) {
        bool requests_delete = false;
        if (information_class == FileDispositionInfo) {
            if (information == nullptr || information_size < sizeof(FILE_DISPOSITION_INFO)) {
                return g_set_file_information_by_handle(
                    file, information_class, information, information_size);
            }
            requests_delete =
                static_cast<const FILE_DISPOSITION_INFO*>(information)->DeleteFile != FALSE;
        } else {
            if (information == nullptr || information_size < sizeof(FILE_DISPOSITION_INFO_EX)) {
                return g_set_file_information_by_handle(
                    file, information_class, information, information_size);
            }
            requests_delete =
                (static_cast<const FILE_DISPOSITION_INFO_EX*>(information)->Flags &
                 FILE_DISPOSITION_FLAG_DELETE) != 0;
        }
        if (!requests_delete) {
            return g_set_file_information_by_handle(
                file, information_class, information, information_size);
        }

        std::wstring source_path;
        if (!TryGetHandlePath(file, source_path)) {
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
        const auto* policy = g_policy.get();
        const auto evaluation = policy == nullptr
                                    ? PolicyEvaluation{}
                                    : policy->Evaluate(source_path.c_str(), Access::kWrite);
        if (evaluation.decision == Decision::kDeny) {
            ReportDenied(
                protocol::FilesystemOperation::kDelete,
                EvaluatedPath(evaluation, source_path.c_str()));
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
        InvalidateResolvedPathForMutation(EvaluatedPath(evaluation, source_path.c_str()), false);
        return g_set_file_information_by_handle(
            file, information_class, information, information_size);
    }

    constexpr std::size_t header_size = offsetof(FILE_RENAME_INFO, FileName);
    if (information == nullptr || information_size < header_size) {
        return g_set_file_information_by_handle(
            file, information_class, information, information_size);
    }
    const auto* rename = static_cast<const FILE_RENAME_INFO*>(information);
    if (rename->RootDirectory != nullptr || rename->FileNameLength == 0 ||
        rename->FileNameLength % sizeof(wchar_t) != 0 ||
        rename->FileNameLength > information_size - header_size) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }

    std::wstring source_path;
    std::wstring destination_path;
    if (!TryGetHandlePath(file, source_path)) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    try {
        destination_path.assign(
            rename->FileName, rename->FileNameLength / sizeof(wchar_t));
    } catch (...) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    if (!AuthorizeMove(source_path.c_str(), destination_path.c_str())) {
        return FALSE;
    }
    return g_set_file_information_by_handle(
        file, information_class, information, information_size);
}

BOOL WINAPI DetouredSetEndOfFile(const HANDLE file) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_set_end_of_file(file);
    }
    std::wstring source_path;
    if (!TryGetHandlePath(file, source_path)) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    const auto* policy = g_policy.get();
    const auto evaluation = policy == nullptr
                                ? PolicyEvaluation{}
                                : policy->Evaluate(source_path.c_str(), Access::kWrite);
    if (evaluation.decision == Decision::kDeny) {
        ReportDenied(
            protocol::FilesystemOperation::kWrite,
            EvaluatedPath(evaluation, source_path.c_str()));
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    InvalidateResolvedPathForMutation(EvaluatedPath(evaluation, source_path.c_str()), false);
    return g_set_end_of_file(file);
}

NTSTATUS NTAPI DetouredZwSetInformationFile(
    const HANDLE file,
    const PIO_STATUS_BLOCK io_status,
    const PVOID information,
    const ULONG information_size,
    const FILE_INFORMATION_CLASS information_class) noexcept {
    constexpr FILE_INFORMATION_CLASS file_allocation_information =
        static_cast<FILE_INFORMATION_CLASS>(19);
    constexpr FILE_INFORMATION_CLASS file_end_of_file_information =
        static_cast<FILE_INFORMATION_CLASS>(20);
    constexpr FILE_INFORMATION_CLASS file_disposition_information =
        static_cast<FILE_INFORMATION_CLASS>(13);
    constexpr FILE_INFORMATION_CLASS file_disposition_information_ex =
        static_cast<FILE_INFORMATION_CLASS>(64);
    constexpr FILE_INFORMATION_CLASS file_rename_information =
        static_cast<FILE_INFORMATION_CLASS>(10);
    constexpr FILE_INFORMATION_CLASS file_rename_information_ex =
        static_cast<FILE_INFORMATION_CLASS>(65);
    const bool is_truncation = information_class == file_allocation_information ||
                               information_class == file_end_of_file_information;
    const bool is_disposition = information_class == file_disposition_information ||
                                information_class == file_disposition_information_ex;
    const bool is_rename = information_class == file_rename_information ||
                           information_class == file_rename_information_ex;
    if (!is_truncation && !is_disposition && !is_rename) {
        return g_zw_set_information_file(
            file, io_status, information, information_size, information_class);
    }
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_zw_set_information_file(
            file, io_status, information, information_size, information_class);
    }

    if (is_disposition) {
        bool requests_delete = false;
        if (information_class == file_disposition_information) {
            if (information == nullptr || information_size < sizeof(FILE_DISPOSITION_INFO)) {
                return g_zw_set_information_file(
                    file, io_status, information, information_size, information_class);
            }
            requests_delete =
                static_cast<const FILE_DISPOSITION_INFO*>(information)->DeleteFile != FALSE;
        } else {
            if (information == nullptr || information_size < sizeof(FILE_DISPOSITION_INFO_EX)) {
                return g_zw_set_information_file(
                    file, io_status, information, information_size, information_class);
            }
            requests_delete =
                (static_cast<const FILE_DISPOSITION_INFO_EX*>(information)->Flags &
                 FILE_DISPOSITION_FLAG_DELETE) != 0;
        }
        if (!requests_delete) {
            return g_zw_set_information_file(
                file, io_status, information, information_size, information_class);
        }
    }

    constexpr NTSTATUS status_access_denied = static_cast<NTSTATUS>(0xC0000022UL);
    if (is_rename) {
        struct NtFileRenameInformation {
            BOOLEAN replace_or_flags;
            HANDLE root_directory;
            ULONG file_name_length;
            WCHAR file_name[1];
        };
        constexpr std::size_t header_size =
            offsetof(NtFileRenameInformation, file_name);
        if (information == nullptr || information_size < header_size) {
            return g_zw_set_information_file(
                file, io_status, information, information_size, information_class);
        }
        const auto* rename = static_cast<const NtFileRenameInformation*>(information);
        if (rename->root_directory != nullptr || rename->file_name_length == 0 ||
            rename->file_name_length % sizeof(wchar_t) != 0 ||
            rename->file_name_length > information_size - header_size) {
            if (io_status != nullptr) {
                io_status->Status = status_access_denied;
                io_status->Information = 0;
            }
            return status_access_denied;
        }
        std::wstring source_path;
        std::wstring destination_path;
        if (!TryGetHandlePath(file, source_path)) {
            if (io_status != nullptr) {
                io_status->Status = status_access_denied;
                io_status->Information = 0;
            }
            return status_access_denied;
        }
        try {
            destination_path.assign(
                rename->file_name, rename->file_name_length / sizeof(wchar_t));
        } catch (...) {
            if (io_status != nullptr) {
                io_status->Status = status_access_denied;
                io_status->Information = 0;
            }
            return status_access_denied;
        }
        if (!AuthorizeMove(source_path.c_str(), destination_path.c_str())) {
            if (io_status != nullptr) {
                io_status->Status = status_access_denied;
                io_status->Information = 0;
            }
            return status_access_denied;
        }
        return g_zw_set_information_file(
            file, io_status, information, information_size, information_class);
    }

    std::wstring source_path;
    if (!TryGetHandlePath(file, source_path)) {
        if (io_status != nullptr) {
            io_status->Status = status_access_denied;
            io_status->Information = 0;
        }
        return status_access_denied;
    }
    const auto* policy = g_policy.get();
    const auto evaluation = policy == nullptr
                                ? PolicyEvaluation{}
                                : policy->Evaluate(source_path.c_str(), Access::kWrite);
    if (evaluation.decision == Decision::kDeny) {
        ReportDenied(
            is_disposition ? protocol::FilesystemOperation::kDelete
                           : protocol::FilesystemOperation::kWrite,
            EvaluatedPath(evaluation, source_path.c_str()));
        if (io_status != nullptr) {
            io_status->Status = status_access_denied;
            io_status->Information = 0;
        }
        return status_access_denied;
    }
    InvalidateResolvedPathForMutation(EvaluatedPath(evaluation, source_path.c_str()), false);
    return g_zw_set_information_file(
        file, io_status, information, information_size, information_class);
}

// Mirrors BuildXL's two-sided hard-link check: reading the existing object and
// writing the new directory entry are separate policy decisions.
BOOL WINAPI DetouredCreateHardLinkW(
    const LPCWSTR new_path,
    const LPCWSTR existing_path,
    const LPSECURITY_ATTRIBUTES security_attributes) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_create_hard_link_w(new_path, existing_path, security_attributes);
    }
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
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_copy_file_w(existing_path, new_path, fail_if_exists);
    }
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
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_copy_file_ex_w(
            existing_path, new_path, progress_routine, data, cancel, copy_flags);
    }
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
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_copy_file_a(existing_path, new_path, fail_if_exists);
    }
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
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_copy_file_ex_a(
            existing_path, new_path, progress_routine, data, cancel, copy_flags);
    }
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
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_copy_file_2(existing_path, new_path, extended_parameters);
    }
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
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_copy_file_transacted_w(
            existing_path, new_path, progress_routine, data, cancel, copy_flags, transaction);
    }
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
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_copy_file_transacted_a(
            existing_path, new_path, progress_routine, data, cancel, copy_flags, transaction);
    }
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
    g_zw_set_information_file = reinterpret_cast<ZwSetInformationFile_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "ZwSetInformationFile"));
    if (g_zw_set_information_file == nullptr) {
        return HookInstallStatus::kTransactionFailed;
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
            reinterpret_cast<PVOID*>(&g_move_file_w),
            reinterpret_cast<PVOID>(DetouredMoveFileW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_move_file_a),
            reinterpret_cast<PVOID>(DetouredMoveFileA)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_move_file_ex_w),
            reinterpret_cast<PVOID>(DetouredMoveFileExW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_move_file_ex_a),
            reinterpret_cast<PVOID>(DetouredMoveFileExA)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_move_file_with_progress_w),
            reinterpret_cast<PVOID>(DetouredMoveFileWithProgressW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_move_file_with_progress_a),
            reinterpret_cast<PVOID>(DetouredMoveFileWithProgressA)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_move_file_transacted_w),
            reinterpret_cast<PVOID>(DetouredMoveFileTransactedW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_move_file_transacted_a),
            reinterpret_cast<PVOID>(DetouredMoveFileTransactedA)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_replace_file_w),
            reinterpret_cast<PVOID>(DetouredReplaceFileW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_replace_file_a),
            reinterpret_cast<PVOID>(DetouredReplaceFileA)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_set_file_information_by_handle),
            reinterpret_cast<PVOID>(DetouredSetFileInformationByHandle)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_set_end_of_file),
            reinterpret_cast<PVOID>(DetouredSetEndOfFile)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_zw_set_information_file),
            reinterpret_cast<PVOID>(DetouredZwSetInformationFile)) != NO_ERROR ||
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
