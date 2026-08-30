#include "hook/filesystem/file_hooks.h"

#include "hook/filesystem/access_classifier.h"
#include "hook/filesystem/final_path_resolver.h"
#include "hook/filesystem/filesystem_policy.h"
#include "hook/filesystem/path_cache.h"
#include "hook/event_sink.h"
#include "hook/process/process_hooks.h"

#include "DetouredFunctionTypes.h"
#include "DetouredScope.h"

#include <cstring>
#include <cwchar>
#include <filesystem>
#include <memory>
#include <string>
#include <utility>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#include <shellapi.h>

#include <detours.h>

namespace bolt::filesystem {
namespace {

std::unique_ptr<FilesystemPolicy> g_policy;

CreateFileW_t g_create_file_w = CreateFileW;
CreateFileA_t g_create_file_a = CreateFileA;
DeleteFileW_t g_delete_file_w = DeleteFileW;
DeleteFileA_t g_delete_file_a = DeleteFileA;
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
using CreateFileMappingWFunction = HANDLE(WINAPI*)(
    HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
using CreateFileMappingAFunction = HANDLE(WINAPI*)(
    HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
CreateFileMappingWFunction g_create_file_mapping_w = CreateFileMappingW;
CreateFileMappingAFunction g_create_file_mapping_a = CreateFileMappingA;
using NtCreateSectionFunction = NTSTATUS(NTAPI*)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
NtCreateSectionFunction g_nt_create_section = nullptr;
DeviceIoControl_t g_device_io_control = DeviceIoControl;
FindFirstFileW_t g_find_first_file_w = FindFirstFileW;
FindFirstFileA_t g_find_first_file_a = FindFirstFileA;
FindFirstFileExW_t g_find_first_file_ex_w = FindFirstFileExW;
FindFirstFileExA_t g_find_first_file_ex_a = FindFirstFileExA;
GetFileAttributesW_t g_get_file_attributes_w = GetFileAttributesW;
GetFileAttributesA_t g_get_file_attributes_a = GetFileAttributesA;
GetFileAttributesExW_t g_get_file_attributes_ex_w = GetFileAttributesExW;
GetFileAttributesExA_t g_get_file_attributes_ex_a = GetFileAttributesExA;
GetFileInformationByHandle_t g_get_file_information_by_handle =
    GetFileInformationByHandle;
GetFileInformationByHandleEx_t g_get_file_information_by_handle_ex =
    GetFileInformationByHandleEx;
using NtQueryInformationFileFunction = NTSTATUS(NTAPI*)(
    HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
NtQueryInformationFileFunction g_nt_query_information_file = nullptr;
using NtQueryAttributesFileFunction = NTSTATUS(NTAPI*)(POBJECT_ATTRIBUTES, PVOID);
NtQueryAttributesFileFunction g_nt_query_attributes_file = nullptr;
NtQueryAttributesFileFunction g_nt_query_full_attributes_file = nullptr;
NtQueryDirectoryFile_t g_nt_query_directory_file = nullptr;
using NtQueryDirectoryFileExFunction = NTSTATUS(NTAPI*)(
    HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG,
    FILE_INFORMATION_CLASS, ULONG, PUNICODE_STRING);
NtQueryDirectoryFileExFunction g_nt_query_directory_file_ex = nullptr;
using SetFileAttributesWFunction = BOOL(WINAPI*)(LPCWSTR, DWORD);
using SetFileAttributesAFunction = BOOL(WINAPI*)(LPCSTR, DWORD);
SetFileAttributesWFunction g_set_file_attributes_w = SetFileAttributesW;
SetFileAttributesAFunction g_set_file_attributes_a = SetFileAttributesA;
using SetFileSecurityWFunction = BOOL(WINAPI*)(
    LPCWSTR, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR);
using SetFileSecurityAFunction = BOOL(WINAPI*)(
    LPCSTR, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR);
SetFileSecurityWFunction g_set_file_security_w = SetFileSecurityW;
SetFileSecurityAFunction g_set_file_security_a = SetFileSecurityA;
DecryptFileW_t g_decrypt_file_w = DecryptFileW;
DecryptFileA_t g_decrypt_file_a = DecryptFileA;
EncryptFileW_t g_encrypt_file_w = EncryptFileW;
EncryptFileA_t g_encrypt_file_a = EncryptFileA;
using SetFileTimeFunction = BOOL(WINAPI*)(
    HANDLE, const FILETIME*, const FILETIME*, const FILETIME*);
SetFileTimeFunction g_set_file_time = SetFileTime;
CreateHardLinkW_t g_create_hard_link_w = CreateHardLinkW;
CreateHardLinkA_t g_create_hard_link_a = CreateHardLinkA;
CreateSymbolicLinkW_t g_create_symbolic_link_w = CreateSymbolicLinkW;
CreateSymbolicLinkA_t g_create_symbolic_link_a = CreateSymbolicLinkA;
CopyFileW_t g_copy_file_w = CopyFileW;
CopyFileExW_t g_copy_file_ex_w = CopyFileExW;
CopyFileA_t g_copy_file_a = CopyFileA;
CopyFileExA_t g_copy_file_ex_a = CopyFileExA;
CopyFileTransactedW_t g_copy_file_transacted_w = CopyFileTransactedW;
CopyFileTransactedA_t g_copy_file_transacted_a = CopyFileTransactedA;
using CopyFile2Function = HRESULT(WINAPI*)(
    PCWSTR, PCWSTR, const COPYFILE2_EXTENDED_PARAMETERS*);
CopyFile2Function g_copy_file_2 = nullptr;
using SHFileOperationWFunction = int(WINAPI*)(LPSHFILEOPSTRUCTW);
using SHFileOperationAFunction = int(WINAPI*)(LPSHFILEOPSTRUCTA);
SHFileOperationWFunction g_sh_file_operation_w = SHFileOperationW;
SHFileOperationAFunction g_sh_file_operation_a = SHFileOperationA;
using ReadFileFunction = BOOL(WINAPI*)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
using WriteFileFunction = BOOL(WINAPI*)(
    HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
ReadFileFunction g_read_file = ReadFile;
WriteFileFunction g_write_file = WriteFile;
using NtReadWriteFileFunction = NTSTATUS(NTAPI*)(
    HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG,
    PLARGE_INTEGER, PULONG);
NtReadWriteFileFunction g_nt_read_file = nullptr;
NtReadWriteFileFunction g_nt_write_file = nullptr;
NtCreateFile_t g_nt_create_file = nullptr;
NtOpenFile_t g_nt_open_file = nullptr;
using ReadDirectoryChangesWFunction = BOOL(WINAPI*)(
    HANDLE, LPVOID, DWORD, BOOL, DWORD, LPDWORD, LPOVERLAPPED,
    LPOVERLAPPED_COMPLETION_ROUTINE);
ReadDirectoryChangesWFunction g_read_directory_changes_w =
    ReadDirectoryChangesW;
using NtNotifyChangeDirectoryFileFunction = NTSTATUS(NTAPI*)(
    HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG,
    ULONG, BOOLEAN);
using NtNotifyChangeDirectoryFileExFunction = NTSTATUS(NTAPI*)(
    HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG,
    ULONG, BOOLEAN, ULONG);
NtNotifyChangeDirectoryFileFunction g_nt_notify_change_directory_file = nullptr;
NtNotifyChangeDirectoryFileExFunction g_nt_notify_change_directory_file_ex =
    nullptr;
OpenFileById_t g_open_file_by_id = OpenFileById;

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

bool AuthorizeSymbolicLink(
    const wchar_t* link_path,
    const wchar_t* target_path) noexcept {
    const auto* policy = g_policy.get();
    const auto link_text =
        policy == nullptr ? PolicyEvaluation{} : policy->Evaluate(link_path, Access::kWrite);
    const auto target_text = policy == nullptr
                                 ? PolicyEvaluation{}
                                 : policy->Evaluate(target_path, Access::kMetadata);
    if (link_text.decision == Decision::kDeny ||
        target_text.decision == Decision::kDeny) {
        const bool link_denied = link_text.decision == Decision::kDeny;
        ReportDenied(
            protocol::FilesystemOperation::kCreate,
            link_denied ? EvaluatedPath(link_text, link_path)
                        : EvaluatedPath(target_text, target_path));
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }

    std::wstring resolved_link;
    std::wstring resolved_target;
    if (!ResolveFinalPathForPolicy(
            EvaluatedPath(link_text, link_path), g_create_file_w, resolved_link) ||
        !ResolveFinalPathForPolicy(
            EvaluatedPath(target_text, target_path), g_create_file_w,
            resolved_target)) {
        ReportDenied(protocol::FilesystemOperation::kCreate, target_path);
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }
    const auto link_final = policy->Evaluate(resolved_link.c_str(), Access::kWrite);
    const auto target_final =
        policy->Evaluate(resolved_target.c_str(), Access::kMetadata);
    if (link_final.decision == Decision::kDeny ||
        target_final.decision == Decision::kDeny) {
        const bool link_denied = link_final.decision == Decision::kDeny;
        ReportDenied(
            protocol::FilesystemOperation::kCreate,
            link_denied ? EvaluatedPath(link_final, resolved_link.c_str())
                        : EvaluatedPath(target_final, resolved_target.c_str()));
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }
    InvalidateResolvedPathForMutation(resolved_link.c_str(), false);
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

bool AuthorizeFileMapping(const HANDLE file, const DWORD protection) noexcept {
    if (file == nullptr || file == INVALID_HANDLE_VALUE) {
        return true;
    }
    std::wstring source_path;
    if (!TryGetHandlePath(file, source_path)) {
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }
    const DWORD base_protection = protection & 0xffU;
    const bool writes_file = base_protection == PAGE_READWRITE ||
                             base_protection == PAGE_EXECUTE_READWRITE;
    const Access access = writes_file ? Access::kWrite : Access::kRead;
    const auto* policy = g_policy.get();
    const auto evaluation = policy == nullptr
                                ? PolicyEvaluation{}
                                : policy->Evaluate(source_path.c_str(), access);
    if (evaluation.decision == Decision::kDeny) {
        ReportDenied(
            writes_file ? protocol::FilesystemOperation::kWrite
                        : protocol::FilesystemOperation::kRead,
            EvaluatedPath(evaluation, source_path.c_str()));
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }
    return true;
}

bool ReadReparseTarget(
    const void* buffer,
    const DWORD buffer_size,
    std::wstring& target) noexcept {
    struct ReparseDataBuffer {
        ULONG tag;
        USHORT data_length;
        USHORT reserved;
        union {
            struct {
                USHORT substitute_offset;
                USHORT substitute_length;
                USHORT print_offset;
                USHORT print_length;
                WCHAR path_buffer[1];
            } mount_point;
            struct {
                USHORT substitute_offset;
                USHORT substitute_length;
                USHORT print_offset;
                USHORT print_length;
                ULONG flags;
                WCHAR path_buffer[1];
            } symbolic_link;
        } data;
    };
    constexpr DWORD header_size = 8;
    if (buffer == nullptr || buffer_size < header_size) {
        return false;
    }
    const auto* reparse = static_cast<const ReparseDataBuffer*>(buffer);
    if (static_cast<DWORD>(reparse->data_length) + header_size > buffer_size) {
        return false;
    }

    const wchar_t* path_buffer = nullptr;
    USHORT offset = 0;
    USHORT length = 0;
    std::size_t path_capacity = 0;
    if (reparse->tag == IO_REPARSE_TAG_MOUNT_POINT) {
        path_buffer = reparse->data.mount_point.path_buffer;
        offset = reparse->data.mount_point.substitute_offset;
        length = reparse->data.mount_point.substitute_length;
        path_capacity = reparse->data_length >= 8
                            ? reparse->data_length - 8
                            : 0;
    } else if (reparse->tag == IO_REPARSE_TAG_SYMLINK) {
        path_buffer = reparse->data.symbolic_link.path_buffer;
        offset = reparse->data.symbolic_link.substitute_offset;
        length = reparse->data.symbolic_link.substitute_length;
        path_capacity = reparse->data_length >= 12
                            ? reparse->data_length - 12
                            : 0;
    } else {
        return false;
    }
    if (length == 0 || length % sizeof(wchar_t) != 0 ||
        static_cast<std::size_t>(offset) + length > path_capacity) {
        return false;
    }
    try {
        target.assign(
            reinterpret_cast<const wchar_t*>(
                reinterpret_cast<const std::uint8_t*>(path_buffer) + offset),
            length / sizeof(wchar_t));
        constexpr wchar_t nt_prefix[] = L"\\??\\";
        if (target.rfind(nt_prefix, 0) == 0) {
            target.erase(0, std::size(nt_prefix) - 1);
            if (target.rfind(L"UNC\\", 0) == 0) {
                target.replace(0, 4, L"\\\\");
            }
        }
    } catch (...) {
        target.clear();
        return false;
    }
    return !target.empty();
}

bool ResolveParentFinalIdentity(
    const wchar_t* path,
    std::wstring& resolved_path) noexcept;

bool AuthorizeEnumeration(const wchar_t* path) noexcept {
    const auto* policy = g_policy.get();
    const auto text_evaluation =
        policy == nullptr ? PolicyEvaluation{} : policy->Evaluate(path, Access::kMetadata);
    if (text_evaluation.decision == Decision::kDeny) {
        ReportDenied(
            protocol::FilesystemOperation::kEnumerate,
            EvaluatedPath(text_evaluation, path));
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }
    std::wstring resolved_path;
    if (!ResolveParentFinalIdentity(
            EvaluatedPath(text_evaluation, path), resolved_path)) {
        ReportDenied(
            protocol::FilesystemOperation::kEnumerate,
            EvaluatedPath(text_evaluation, path));
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }
    const auto final_evaluation =
        policy->Evaluate(resolved_path.c_str(), Access::kMetadata);
    if (final_evaluation.decision == Decision::kDeny) {
        ReportDenied(
            protocol::FilesystemOperation::kEnumerate,
            EvaluatedPath(final_evaluation, resolved_path.c_str()));
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }
    return true;
}

bool ResolveParentFinalIdentity(
    const wchar_t* path,
    std::wstring& resolved_path) noexcept {
    try {
        const std::filesystem::path candidate{path};
        const auto parent = candidate.parent_path();
        if (candidate.filename().empty()) {
            return ResolveFinalPathForPolicy(
                candidate.c_str(), g_create_file_w, resolved_path);
        }
        std::wstring resolved_parent;
        if (parent.empty() ||
            !ResolveFinalPathForPolicy(
                parent.c_str(), g_create_file_w, resolved_parent)) {
            return false;
        }
        resolved_path =
            (std::filesystem::path(resolved_parent) / candidate.filename())
                .lexically_normal()
                .wstring();
        return true;
    } catch (...) {
        resolved_path.clear();
        return false;
    }
}

bool AuthorizeMetadata(const wchar_t* path) noexcept {
    const auto* policy = g_policy.get();
    const auto evaluation =
        policy == nullptr ? PolicyEvaluation{} : policy->Evaluate(path, Access::kMetadata);
    if (evaluation.decision == Decision::kDeny) {
        ReportDenied(
            protocol::FilesystemOperation::kMetadata, EvaluatedPath(evaluation, path));
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }
    std::wstring resolved_path;
    if (!ResolveParentFinalIdentity(
            EvaluatedPath(evaluation, path), resolved_path)) {
        ReportDenied(
            protocol::FilesystemOperation::kMetadata,
            EvaluatedPath(evaluation, path));
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }
    const auto final_evaluation =
        policy->Evaluate(resolved_path.c_str(), Access::kMetadata);
    if (final_evaluation.decision == Decision::kDeny) {
        ReportDenied(
            protocol::FilesystemOperation::kMetadata,
            EvaluatedPath(final_evaluation, resolved_path.c_str()));
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }
    return true;
}

bool AuthorizeHandleMetadata(const HANDLE file) noexcept {
    std::wstring source_path;
    if (!TryGetHandlePath(file, source_path)) {
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }
    const auto* policy = g_policy.get();
    const auto evaluation = policy == nullptr
                                ? PolicyEvaluation{}
                                : policy->Evaluate(source_path.c_str(), Access::kMetadata);
    if (evaluation.decision == Decision::kDeny) {
        ReportDenied(
            protocol::FilesystemOperation::kMetadata,
            EvaluatedPath(evaluation, source_path.c_str()));
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }
    return true;
}

bool AuthorizeHandleEnumeration(const HANDLE directory) noexcept {
    std::wstring source_path;
    if (!TryGetHandlePath(directory, source_path)) {
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }
    const auto* policy = g_policy.get();
    const auto evaluation = policy == nullptr
                                ? PolicyEvaluation{}
                                : policy->Evaluate(source_path.c_str(), Access::kMetadata);
    if (evaluation.decision == Decision::kDeny) {
        ReportDenied(
            protocol::FilesystemOperation::kEnumerate,
            EvaluatedPath(evaluation, source_path.c_str()));
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }
    return true;
}

bool AuthorizeHandleIo(
    const HANDLE file,
    const Access access,
    const protocol::FilesystemOperation operation) noexcept {
    if (access == Access::kWrite && hook::IsEventSinkHandle(file)) {
        return true;
    }
    std::wstring source_path;
    if (!TryGetHandlePath(file, source_path)) {
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }
    const auto* policy = g_policy.get();
    const auto evaluation = policy == nullptr
                                ? PolicyEvaluation{}
                                : policy->Evaluate(source_path.c_str(), access);
    if (evaluation.decision == Decision::kDeny) {
        ReportDenied(operation, EvaluatedPath(evaluation, source_path.c_str()));
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }
    if (access == Access::kWrite) {
        InvalidateResolvedPathForMutation(
            EvaluatedPath(evaluation, source_path.c_str()), false);
    }
    return true;
}

bool TryGetObjectAttributesPath(
    const POBJECT_ATTRIBUTES object_attributes,
    std::wstring& path) noexcept {
    if (object_attributes == nullptr || object_attributes->ObjectName == nullptr ||
        object_attributes->ObjectName->Buffer == nullptr ||
        object_attributes->ObjectName->Length == 0 ||
        object_attributes->ObjectName->Length % sizeof(wchar_t) != 0) {
        return false;
    }
    try {
        std::wstring object_path(
            object_attributes->ObjectName->Buffer,
            object_attributes->ObjectName->Length / sizeof(wchar_t));
        if (object_path.find(L'\0') != std::wstring::npos) {
            return false;
        }
        if (object_attributes->RootDirectory != nullptr) {
            if (object_path.front() == L'\\' ||
                std::filesystem::path(object_path).is_absolute()) {
                return false;
            }
            std::wstring root_path;
            if (!TryGetHandlePath(
                    object_attributes->RootDirectory, root_path)) {
                return false;
            }
            path = (std::filesystem::path(root_path) / object_path)
                       .lexically_normal()
                       .wstring();
            return !path.empty();
        }
        path = std::move(object_path);
        constexpr wchar_t nt_prefix[] = L"\\??\\";
        if (path.rfind(nt_prefix, 0) == 0) {
            path.erase(0, std::size(nt_prefix) - 1);
            if (path.rfind(L"UNC\\", 0) == 0) {
                path.replace(0, 4, L"\\\\");
            }
        }
    } catch (...) {
        path.clear();
        return false;
    }
    return !path.empty();
}

DWORD MapNtCreateDisposition(const ULONG disposition) noexcept {
    switch (disposition) {
        case FILE_SUPERSEDE:
        case FILE_OVERWRITE_IF:
            return CREATE_ALWAYS;
        case FILE_OPEN:
            return OPEN_EXISTING;
        case FILE_CREATE:
            return CREATE_NEW;
        case FILE_OPEN_IF:
            return OPEN_ALWAYS;
        case FILE_OVERWRITE:
            return TRUNCATE_EXISTING;
        default:
            return 0;
    }
}

bool AuthorizeCreateFile(
    const wchar_t* path,
    const ClassifiedAccess& request,
    DWORD flags_and_attributes) noexcept;

bool AuthorizeNativeFileOpen(
    const ACCESS_MASK desired_access,
    const POBJECT_ATTRIBUTES object_attributes,
    const ULONG create_disposition,
    const ULONG create_options) noexcept {
    std::wstring path;
    if (!TryGetObjectAttributesPath(object_attributes, path)) {
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }
    auto request = ClassifyCreateFileRequest(
        desired_access, MapNtCreateDisposition(create_disposition));
    if ((create_options & FILE_DELETE_ON_CLOSE) != 0) {
        request = {Access::kWrite, protocol::FilesystemOperation::kDelete};
    }
    const DWORD flags = (create_options & FILE_OPEN_REPARSE_POINT) != 0
                            ? FILE_FLAG_OPEN_REPARSE_POINT
                            : 0;
    return AuthorizeCreateFile(path.c_str(), request, flags);
}

NTSTATUS DenyNativeFileOpen(
    const PHANDLE file,
    const PIO_STATUS_BLOCK io_status) noexcept {
    constexpr NTSTATUS status_access_denied = static_cast<NTSTATUS>(0xC0000022UL);
    if (file != nullptr) {
        *file = nullptr;
    }
    if (io_status != nullptr) {
        io_status->Status = status_access_denied;
        io_status->Information = 0;
    }
    return status_access_denied;
}

bool AuthorizeAttributeMutation(const wchar_t* path) noexcept {
    const auto* policy = g_policy.get();
    const auto evaluation =
        policy == nullptr ? PolicyEvaluation{} : policy->Evaluate(path, Access::kWrite);
    if (evaluation.decision == Decision::kDeny) {
        ReportDenied(
            protocol::FilesystemOperation::kWrite, EvaluatedPath(evaluation, path));
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }
    std::wstring resolved_path;
    if (!ResolveFinalPathForPolicy(
            EvaluatedPath(evaluation, path), g_create_file_w, resolved_path)) {
        ReportDenied(
            protocol::FilesystemOperation::kWrite, EvaluatedPath(evaluation, path));
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }
    const auto final_evaluation =
        policy->Evaluate(resolved_path.c_str(), Access::kWrite);
    if (final_evaluation.decision == Decision::kDeny) {
        ReportDenied(
            protocol::FilesystemOperation::kWrite,
            EvaluatedPath(final_evaluation, resolved_path.c_str()));
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }
    InvalidateResolvedPathForMutation(resolved_path.c_str(), false);
    return true;
}

bool AuthorizeDeletion(
    const wchar_t* path,
    const bool invalidate_descendants = false) noexcept {
    const auto* policy = g_policy.get();
    const auto evaluation =
        policy == nullptr ? PolicyEvaluation{} : policy->Evaluate(path, Access::kWrite);
    if (evaluation.decision == Decision::kDeny) {
        ReportDenied(
            protocol::FilesystemOperation::kDelete, EvaluatedPath(evaluation, path));
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }

    std::wstring resolved_path;
    if (!ResolveParentFinalIdentity(
            EvaluatedPath(evaluation, path), resolved_path)) {
        ReportDenied(protocol::FilesystemOperation::kDelete, path);
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }
    const auto final_evaluation =
        policy->Evaluate(resolved_path.c_str(), Access::kWrite);
    if (final_evaluation.decision == Decision::kDeny) {
        ReportDenied(
            protocol::FilesystemOperation::kDelete,
            EvaluatedPath(final_evaluation, resolved_path.c_str()));
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }
    InvalidateResolvedPathForMutation(
        resolved_path.c_str(), invalidate_descendants);
    return true;
}

bool ResolveCreateFileIdentity(
    const wchar_t* path,
    const DWORD flags_and_attributes,
    std::wstring& resolved_path) noexcept {
    if ((flags_and_attributes & FILE_FLAG_OPEN_REPARSE_POINT) == 0) {
        return ResolveFinalPathForPolicy(path, g_create_file_w, resolved_path);
    }
    try {
        return ResolveParentFinalIdentity(path, resolved_path);
    } catch (...) {
        resolved_path.clear();
        return false;
    }
}

bool AuthorizeCreateFile(
    const wchar_t* path,
    const ClassifiedAccess& request,
    const DWORD flags_and_attributes) noexcept {
    const auto* policy = g_policy.get();
    const auto text_evaluation =
        policy == nullptr ? PolicyEvaluation{} : policy->Evaluate(path, request.access);
    if (text_evaluation.decision == Decision::kDeny) {
        ReportDenied(request.operation, EvaluatedPath(text_evaluation, path));
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }
    std::wstring resolved_path;
    if (!ResolveCreateFileIdentity(
            EvaluatedPath(text_evaluation, path), flags_and_attributes,
            resolved_path)) {
        ReportDenied(request.operation, EvaluatedPath(text_evaluation, path));
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }
    const auto final_evaluation =
        policy->Evaluate(resolved_path.c_str(), request.access);
    if (final_evaluation.decision == Decision::kDeny) {
        ReportDenied(
            request.operation,
            EvaluatedPath(final_evaluation, resolved_path.c_str()));
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }
    if (request.access == Access::kWrite) {
        InvalidateResolvedPathForMutation(resolved_path.c_str(), false);
    }
    return true;
}

NTSTATUS NTAPI DetouredNtCreateFile(
    const PHANDLE file,
    const ACCESS_MASK desired_access,
    const POBJECT_ATTRIBUTES object_attributes,
    const PIO_STATUS_BLOCK io_status,
    const PLARGE_INTEGER allocation_size,
    const ULONG file_attributes,
    const ULONG share_access,
    const ULONG create_disposition,
    const ULONG create_options,
    const PVOID ea_buffer,
    const ULONG ea_length) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_nt_create_file(
            file, desired_access, object_attributes, io_status, allocation_size,
            file_attributes, share_access, create_disposition, create_options,
            ea_buffer, ea_length);
    }
    if (!AuthorizeNativeFileOpen(
            desired_access, object_attributes, create_disposition,
            create_options)) {
        return DenyNativeFileOpen(file, io_status);
    }
    return g_nt_create_file(
        file, desired_access, object_attributes, io_status, allocation_size,
        file_attributes, share_access, create_disposition, create_options,
        ea_buffer, ea_length);
}

NTSTATUS NTAPI DetouredNtOpenFile(
    const PHANDLE file,
    const ACCESS_MASK desired_access,
    const POBJECT_ATTRIBUTES object_attributes,
    const PIO_STATUS_BLOCK io_status,
    const ULONG share_access,
    const ULONG open_options) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_nt_open_file(
            file, desired_access, object_attributes, io_status, share_access,
            open_options);
    }
    if (!AuthorizeNativeFileOpen(
            desired_access, object_attributes, FILE_OPEN, open_options)) {
        return DenyNativeFileOpen(file, io_status);
    }
    return g_nt_open_file(
        file, desired_access, object_attributes, io_status, share_access,
        open_options);
}

bool AuthorizeShellDelete(const wchar_t* paths) noexcept {
    if (paths == nullptr) {
        return true;
    }
    for (const wchar_t* path = paths; *path != L'\0';
         path += std::wcslen(path) + 1) {
        if (!AuthorizeDeletion(path)) {
            return false;
        }
    }
    return true;
}

bool AuthorizeShellDelete(const char* paths) noexcept {
    if (paths == nullptr) {
        return true;
    }
    for (const char* path = paths; *path != '\0'; path += std::strlen(path) + 1) {
        std::wstring path_wide;
        if (!ConvertAnsiPath(path, path_wide) ||
            !AuthorizeDeletion(path_wide.c_str())) {
            return false;
        }
    }
    return true;
}

bool AuthorizeShellTransfer(
    const wchar_t* sources,
    const wchar_t* destinations,
    const bool move,
    const bool multiple_destinations) noexcept {
    if (sources == nullptr || destinations == nullptr) {
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }
    const wchar_t* destination = destinations;
    for (const wchar_t* source = sources; *source != L'\0';
         source += std::wcslen(source) + 1) {
        if (*destination == L'\0' ||
            !(move ? AuthorizeMove(source, destination)
                   : AuthorizeCopy(source, destination))) {
            SetLastError(ERROR_ACCESS_DENIED);
            return false;
        }
        if (multiple_destinations) {
            destination += std::wcslen(destination) + 1;
        }
    }
    return true;
}

bool AuthorizeShellTransfer(
    const char* sources,
    const char* destinations,
    const bool move,
    const bool multiple_destinations) noexcept {
    if (sources == nullptr || destinations == nullptr) {
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }
    const char* destination = destinations;
    for (const char* source = sources; *source != '\0';
         source += std::strlen(source) + 1) {
        if (*destination == '\0') {
            SetLastError(ERROR_ACCESS_DENIED);
            return false;
        }
        std::wstring source_wide;
        std::wstring destination_wide;
        if (!ConvertAnsiPath(source, source_wide) ||
            !ConvertAnsiPath(destination, destination_wide) ||
            !(move ? AuthorizeMove(source_wide.c_str(), destination_wide.c_str())
                   : AuthorizeCopy(source_wide.c_str(), destination_wide.c_str()))) {
            SetLastError(ERROR_ACCESS_DENIED);
            return false;
        }
        if (multiple_destinations) {
            destination += std::strlen(destination) + 1;
        }
    }
    return true;
}

HANDLE WINAPI DetouredFindFirstFileW(
    const LPCWSTR path,
    const LPWIN32_FIND_DATAW find_data) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_find_first_file_w(path, find_data);
    }
    return AuthorizeEnumeration(path) ? g_find_first_file_w(path, find_data)
                                      : INVALID_HANDLE_VALUE;
}

HANDLE WINAPI DetouredFindFirstFileA(
    const LPCSTR path,
    const LPWIN32_FIND_DATAA find_data) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_find_first_file_a(path, find_data);
    }
    std::wstring path_wide;
    if (!ConvertAnsiPath(path, path_wide) || !AuthorizeEnumeration(path_wide.c_str())) {
        return INVALID_HANDLE_VALUE;
    }
    return g_find_first_file_a(path, find_data);
}

HANDLE WINAPI DetouredFindFirstFileExW(
    const LPCWSTR path,
    const FINDEX_INFO_LEVELS info_level,
    const LPVOID find_data,
    const FINDEX_SEARCH_OPS search_operation,
    const LPVOID search_filter,
    const DWORD flags) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_find_first_file_ex_w(
            path, info_level, find_data, search_operation, search_filter, flags);
    }
    return AuthorizeEnumeration(path)
               ? g_find_first_file_ex_w(
                     path, info_level, find_data, search_operation, search_filter, flags)
               : INVALID_HANDLE_VALUE;
}

HANDLE WINAPI DetouredFindFirstFileExA(
    const LPCSTR path,
    const FINDEX_INFO_LEVELS info_level,
    const LPVOID find_data,
    const FINDEX_SEARCH_OPS search_operation,
    const LPVOID search_filter,
    const DWORD flags) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_find_first_file_ex_a(
            path, info_level, find_data, search_operation, search_filter, flags);
    }
    std::wstring path_wide;
    if (!ConvertAnsiPath(path, path_wide) || !AuthorizeEnumeration(path_wide.c_str())) {
        return INVALID_HANDLE_VALUE;
    }
    return g_find_first_file_ex_a(
        path, info_level, find_data, search_operation, search_filter, flags);
}

DWORD WINAPI DetouredGetFileAttributesW(const LPCWSTR path) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_get_file_attributes_w(path);
    }
    return AuthorizeMetadata(path) ? g_get_file_attributes_w(path)
                                   : INVALID_FILE_ATTRIBUTES;
}

DWORD WINAPI DetouredGetFileAttributesA(const LPCSTR path) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_get_file_attributes_a(path);
    }
    std::wstring path_wide;
    if (!ConvertAnsiPath(path, path_wide) || !AuthorizeMetadata(path_wide.c_str())) {
        return INVALID_FILE_ATTRIBUTES;
    }
    return g_get_file_attributes_a(path);
}

BOOL WINAPI DetouredGetFileAttributesExW(
    const LPCWSTR path,
    const GET_FILEEX_INFO_LEVELS info_level,
    const LPVOID information) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_get_file_attributes_ex_w(path, info_level, information);
    }
    return AuthorizeMetadata(path)
               ? g_get_file_attributes_ex_w(path, info_level, information)
               : FALSE;
}

BOOL WINAPI DetouredGetFileAttributesExA(
    const LPCSTR path,
    const GET_FILEEX_INFO_LEVELS info_level,
    const LPVOID information) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_get_file_attributes_ex_a(path, info_level, information);
    }
    std::wstring path_wide;
    if (!ConvertAnsiPath(path, path_wide) || !AuthorizeMetadata(path_wide.c_str())) {
        return FALSE;
    }
    return g_get_file_attributes_ex_a(path, info_level, information);
}

BOOL WINAPI DetouredGetFileInformationByHandle(
    const HANDLE file,
    const LPBY_HANDLE_FILE_INFORMATION information) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_get_file_information_by_handle(file, information);
    }
    return AuthorizeHandleMetadata(file)
               ? g_get_file_information_by_handle(file, information)
               : FALSE;
}

BOOL WINAPI DetouredGetFileInformationByHandleEx(
    const HANDLE file,
    const FILE_INFO_BY_HANDLE_CLASS information_class,
    const LPVOID information,
    const DWORD information_size) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_get_file_information_by_handle_ex(
            file, information_class, information, information_size);
    }
    return AuthorizeHandleMetadata(file)
               ? g_get_file_information_by_handle_ex(
                     file, information_class, information, information_size)
               : FALSE;
}

NTSTATUS NTAPI DetouredNtQueryInformationFile(
    const HANDLE file,
    const PIO_STATUS_BLOCK io_status,
    const PVOID information,
    const ULONG information_size,
    const FILE_INFORMATION_CLASS information_class) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_nt_query_information_file(
            file, io_status, information, information_size, information_class);
    }
    if (AuthorizeHandleMetadata(file)) {
        return g_nt_query_information_file(
            file, io_status, information, information_size, information_class);
    }
    constexpr NTSTATUS status_access_denied = static_cast<NTSTATUS>(0xC0000022UL);
    if (io_status != nullptr) {
        io_status->Status = status_access_denied;
        io_status->Information = 0;
    }
    return status_access_denied;
}

NTSTATUS NTAPI DetouredNtQueryAttributesFile(
    const POBJECT_ATTRIBUTES object_attributes,
    const PVOID information) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_nt_query_attributes_file(object_attributes, information);
    }
    std::wstring path;
    if (TryGetObjectAttributesPath(object_attributes, path) &&
        AuthorizeMetadata(path.c_str())) {
        return g_nt_query_attributes_file(object_attributes, information);
    }
    constexpr NTSTATUS status_access_denied = static_cast<NTSTATUS>(0xC0000022UL);
    return status_access_denied;
}

NTSTATUS NTAPI DetouredNtQueryFullAttributesFile(
    const POBJECT_ATTRIBUTES object_attributes,
    const PVOID information) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_nt_query_full_attributes_file(object_attributes, information);
    }
    std::wstring path;
    if (TryGetObjectAttributesPath(object_attributes, path) &&
        AuthorizeMetadata(path.c_str())) {
        return g_nt_query_full_attributes_file(object_attributes, information);
    }
    constexpr NTSTATUS status_access_denied = static_cast<NTSTATUS>(0xC0000022UL);
    return status_access_denied;
}

NTSTATUS NTAPI DetouredNtQueryDirectoryFile(
    const HANDLE directory,
    const HANDLE event,
    const PIO_APC_ROUTINE apc_routine,
    const PVOID apc_context,
    const PIO_STATUS_BLOCK io_status,
    const PVOID information,
    const ULONG information_size,
    const FILE_INFORMATION_CLASS information_class,
    const BOOLEAN return_single_entry,
    const PUNICODE_STRING name,
    const BOOLEAN restart_scan) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_nt_query_directory_file(
            directory, event, apc_routine, apc_context, io_status, information,
            information_size, information_class, return_single_entry, name,
            restart_scan);
    }
    if (AuthorizeHandleEnumeration(directory)) {
        return g_nt_query_directory_file(
            directory, event, apc_routine, apc_context, io_status, information,
            information_size, information_class, return_single_entry, name,
            restart_scan);
    }
    constexpr NTSTATUS status_access_denied = static_cast<NTSTATUS>(0xC0000022UL);
    if (io_status != nullptr) {
        io_status->Status = status_access_denied;
        io_status->Information = 0;
    }
    return status_access_denied;
}

NTSTATUS NTAPI DetouredNtQueryDirectoryFileEx(
    const HANDLE directory,
    const HANDLE event,
    const PIO_APC_ROUTINE apc_routine,
    const PVOID apc_context,
    const PIO_STATUS_BLOCK io_status,
    const PVOID information,
    const ULONG information_size,
    const FILE_INFORMATION_CLASS information_class,
    const ULONG query_flags,
    const PUNICODE_STRING name) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_nt_query_directory_file_ex(
            directory, event, apc_routine, apc_context, io_status, information,
            information_size, information_class, query_flags, name);
    }
    if (AuthorizeHandleEnumeration(directory)) {
        return g_nt_query_directory_file_ex(
            directory, event, apc_routine, apc_context, io_status, information,
            information_size, information_class, query_flags, name);
    }
    constexpr NTSTATUS status_access_denied = static_cast<NTSTATUS>(0xC0000022UL);
    if (io_status != nullptr) {
        io_status->Status = status_access_denied;
        io_status->Information = 0;
    }
    return status_access_denied;
}

BOOL WINAPI DetouredReadDirectoryChangesW(
    const HANDLE directory,
    const LPVOID buffer,
    const DWORD buffer_size,
    const BOOL watch_subtree,
    const DWORD notify_filter,
    const LPDWORD bytes_returned,
    const LPOVERLAPPED overlapped,
    const LPOVERLAPPED_COMPLETION_ROUTINE completion_routine) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_read_directory_changes_w(
            directory, buffer, buffer_size, watch_subtree, notify_filter,
            bytes_returned, overlapped, completion_routine);
    }
    if (!AuthorizeHandleEnumeration(directory)) {
        if (bytes_returned != nullptr) {
            *bytes_returned = 0;
        }
        return FALSE;
    }
    return g_read_directory_changes_w(
        directory, buffer, buffer_size, watch_subtree, notify_filter,
        bytes_returned, overlapped, completion_routine);
}

NTSTATUS DenyNativeDirectoryNotification(
    const PIO_STATUS_BLOCK io_status) noexcept {
    constexpr NTSTATUS status_access_denied = static_cast<NTSTATUS>(0xC0000022UL);
    if (io_status != nullptr) {
        io_status->Status = status_access_denied;
        io_status->Information = 0;
    }
    return status_access_denied;
}

NTSTATUS NTAPI DetouredNtNotifyChangeDirectoryFile(
    const HANDLE directory,
    const HANDLE event,
    const PIO_APC_ROUTINE apc_routine,
    const PVOID apc_context,
    const PIO_STATUS_BLOCK io_status,
    const PVOID buffer,
    const ULONG buffer_size,
    const ULONG completion_filter,
    const BOOLEAN watch_tree) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_nt_notify_change_directory_file(
            directory, event, apc_routine, apc_context, io_status, buffer,
            buffer_size, completion_filter, watch_tree);
    }
    if (!AuthorizeHandleEnumeration(directory)) {
        return DenyNativeDirectoryNotification(io_status);
    }
    return g_nt_notify_change_directory_file(
        directory, event, apc_routine, apc_context, io_status, buffer,
        buffer_size, completion_filter, watch_tree);
}

NTSTATUS NTAPI DetouredNtNotifyChangeDirectoryFileEx(
    const HANDLE directory,
    const HANDLE event,
    const PIO_APC_ROUTINE apc_routine,
    const PVOID apc_context,
    const PIO_STATUS_BLOCK io_status,
    const PVOID buffer,
    const ULONG buffer_size,
    const ULONG completion_filter,
    const BOOLEAN watch_tree,
    const ULONG information_class) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_nt_notify_change_directory_file_ex(
            directory, event, apc_routine, apc_context, io_status, buffer,
            buffer_size, completion_filter, watch_tree, information_class);
    }
    if (!AuthorizeHandleEnumeration(directory)) {
        return DenyNativeDirectoryNotification(io_status);
    }
    return g_nt_notify_change_directory_file_ex(
        directory, event, apc_routine, apc_context, io_status, buffer,
        buffer_size, completion_filter, watch_tree, information_class);
}

HANDLE WINAPI DetouredOpenFileById(
    const HANDLE volume,
    const LPFILE_ID_DESCRIPTOR file_id,
    const DWORD desired_access,
    const DWORD share_mode,
    const LPSECURITY_ATTRIBUTES security_attributes,
    const DWORD flags) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_open_file_by_id(
            volume, file_id, desired_access, share_mode, security_attributes,
            flags);
    }

    auto request =
        ClassifyCreateFileRequest(desired_access, OPEN_EXISTING);
    const bool delete_on_close = (flags & FILE_FLAG_DELETE_ON_CLOSE) != 0;
    if (delete_on_close) {
        request = {Access::kWrite, protocol::FilesystemOperation::kDelete};
    }
    const HANDLE opened = g_open_file_by_id(
        volume, file_id, desired_access, share_mode, security_attributes,
        flags & ~FILE_FLAG_DELETE_ON_CLOSE);
    if (opened == INVALID_HANDLE_VALUE) {
        return INVALID_HANDLE_VALUE;
    }
    if (!AuthorizeHandleIo(opened, request.access, request.operation)) {
        const DWORD error = GetLastError();
        CloseHandle(opened);
        SetLastError(error);
        return INVALID_HANDLE_VALUE;
    }
    if (delete_on_close) {
        FILE_DISPOSITION_INFO disposition{};
        disposition.DeleteFile = TRUE;
        if (!g_set_file_information_by_handle(
                opened, FileDispositionInfo, &disposition,
                sizeof(disposition))) {
            const DWORD error = GetLastError();
            CloseHandle(opened);
            SetLastError(error);
            return INVALID_HANDLE_VALUE;
        }
    }
    return opened;
}

BOOL WINAPI DetouredSetFileAttributesW(
    const LPCWSTR path,
    const DWORD attributes) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_set_file_attributes_w(path, attributes);
    }
    return AuthorizeAttributeMutation(path) ? g_set_file_attributes_w(path, attributes)
                                            : FALSE;
}

BOOL WINAPI DetouredSetFileAttributesA(
    const LPCSTR path,
    const DWORD attributes) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_set_file_attributes_a(path, attributes);
    }
    std::wstring path_wide;
    if (!ConvertAnsiPath(path, path_wide) ||
        !AuthorizeAttributeMutation(path_wide.c_str())) {
        return FALSE;
    }
    return g_set_file_attributes_a(path, attributes);
}

BOOL WINAPI DetouredSetFileSecurityW(
    const LPCWSTR path,
    const SECURITY_INFORMATION security_information,
    const PSECURITY_DESCRIPTOR security_descriptor) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_set_file_security_w(
            path, security_information, security_descriptor);
    }
    return AuthorizeAttributeMutation(path)
               ? g_set_file_security_w(
                     path, security_information, security_descriptor)
               : FALSE;
}

BOOL WINAPI DetouredSetFileSecurityA(
    const LPCSTR path,
    const SECURITY_INFORMATION security_information,
    const PSECURITY_DESCRIPTOR security_descriptor) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_set_file_security_a(
            path, security_information, security_descriptor);
    }
    std::wstring path_wide;
    if (!ConvertAnsiPath(path, path_wide) ||
        !AuthorizeAttributeMutation(path_wide.c_str())) {
        return FALSE;
    }
    return g_set_file_security_a(
        path, security_information, security_descriptor);
}

BOOL WINAPI DetouredEncryptFileW(const LPCWSTR path) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_encrypt_file_w(path);
    }
    return AuthorizeAttributeMutation(path) ? g_encrypt_file_w(path) : FALSE;
}

BOOL WINAPI DetouredEncryptFileA(const LPCSTR path) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_encrypt_file_a(path);
    }
    std::wstring path_wide;
    if (!ConvertAnsiPath(path, path_wide) ||
        !AuthorizeAttributeMutation(path_wide.c_str())) {
        return FALSE;
    }
    return g_encrypt_file_a(path);
}

BOOL WINAPI DetouredDecryptFileW(
    const LPCWSTR path,
    const DWORD reserved) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_decrypt_file_w(path, reserved);
    }
    return AuthorizeAttributeMutation(path)
               ? g_decrypt_file_w(path, reserved)
               : FALSE;
}

BOOL WINAPI DetouredDecryptFileA(
    const LPCSTR path,
    const DWORD reserved) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_decrypt_file_a(path, reserved);
    }
    std::wstring path_wide;
    if (!ConvertAnsiPath(path, path_wide) ||
        !AuthorizeAttributeMutation(path_wide.c_str())) {
        return FALSE;
    }
    return g_decrypt_file_a(path, reserved);
}

BOOL WINAPI DetouredSetFileTime(
    const HANDLE file,
    const FILETIME* creation_time,
    const FILETIME* access_time,
    const FILETIME* write_time) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled() ||
        (creation_time == nullptr && access_time == nullptr && write_time == nullptr)) {
        return g_set_file_time(file, creation_time, access_time, write_time);
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
    return g_set_file_time(file, creation_time, access_time, write_time);
}

BOOL WINAPI DetouredReadFile(
    const HANDLE file,
    const LPVOID buffer,
    const DWORD bytes_to_read,
    const LPDWORD bytes_read,
    const LPOVERLAPPED overlapped) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_read_file(file, buffer, bytes_to_read, bytes_read, overlapped);
    }
    if (!AuthorizeHandleIo(
            file, Access::kRead, protocol::FilesystemOperation::kRead)) {
        if (bytes_read != nullptr) {
            *bytes_read = 0;
        }
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return g_read_file(file, buffer, bytes_to_read, bytes_read, overlapped);
}

BOOL WINAPI DetouredWriteFile(
    const HANDLE file,
    const LPCVOID buffer,
    const DWORD bytes_to_write,
    const LPDWORD bytes_written,
    const LPOVERLAPPED overlapped) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_write_file(
            file, buffer, bytes_to_write, bytes_written, overlapped);
    }
    if (!AuthorizeHandleIo(
            file, Access::kWrite, protocol::FilesystemOperation::kWrite)) {
        if (bytes_written != nullptr) {
            *bytes_written = 0;
        }
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return g_write_file(file, buffer, bytes_to_write, bytes_written, overlapped);
}

NTSTATUS NTAPI DetouredNtReadFile(
    const HANDLE file,
    const HANDLE event,
    const PIO_APC_ROUTINE apc_routine,
    const PVOID apc_context,
    const PIO_STATUS_BLOCK io_status,
    const PVOID buffer,
    const ULONG bytes_to_read,
    const PLARGE_INTEGER byte_offset,
    const PULONG key) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_nt_read_file(
            file, event, apc_routine, apc_context, io_status, buffer,
            bytes_to_read, byte_offset, key);
    }
    if (AuthorizeHandleIo(
            file, Access::kRead, protocol::FilesystemOperation::kRead)) {
        return g_nt_read_file(
            file, event, apc_routine, apc_context, io_status, buffer,
            bytes_to_read, byte_offset, key);
    }
    constexpr NTSTATUS status_access_denied = static_cast<NTSTATUS>(0xC0000022UL);
    if (io_status != nullptr) {
        io_status->Status = status_access_denied;
        io_status->Information = 0;
    }
    return status_access_denied;
}

NTSTATUS NTAPI DetouredNtWriteFile(
    const HANDLE file,
    const HANDLE event,
    const PIO_APC_ROUTINE apc_routine,
    const PVOID apc_context,
    const PIO_STATUS_BLOCK io_status,
    const PVOID buffer,
    const ULONG bytes_to_write,
    const PLARGE_INTEGER byte_offset,
    const PULONG key) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_nt_write_file(
            file, event, apc_routine, apc_context, io_status, buffer,
            bytes_to_write, byte_offset, key);
    }
    if (AuthorizeHandleIo(
            file, Access::kWrite, protocol::FilesystemOperation::kWrite)) {
        return g_nt_write_file(
            file, event, apc_routine, apc_context, io_status, buffer,
            bytes_to_write, byte_offset, key);
    }
    constexpr NTSTATUS status_access_denied = static_cast<NTSTATUS>(0xC0000022UL);
    if (io_status != nullptr) {
        io_status->Status = status_access_denied;
        io_status->Information = 0;
    }
    return status_access_denied;
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
    const auto request = ClassifyCreateFileRequest(desired_access, creation_disposition);
    if (!AuthorizeCreateFile(filename, request, flags_and_attributes)) {
        return INVALID_HANDLE_VALUE;
    }
    return g_create_file_w(
        filename, desired_access, share_mode, security_attributes, creation_disposition,
        flags_and_attributes, template_file);
}

HANDLE WINAPI DetouredCreateFileA(
    const LPCSTR filename,
    const DWORD desired_access,
    const DWORD share_mode,
    const LPSECURITY_ATTRIBUTES security_attributes,
    const DWORD creation_disposition,
    const DWORD flags_and_attributes,
    const HANDLE template_file) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_create_file_a(
            filename, desired_access, share_mode, security_attributes,
            creation_disposition, flags_and_attributes, template_file);
    }
    std::wstring filename_wide;
    const auto request = ClassifyCreateFileRequest(desired_access, creation_disposition);
    if (!ConvertAnsiPath(filename, filename_wide) ||
        !AuthorizeCreateFile(
            filename_wide.c_str(), request, flags_and_attributes)) {
        return INVALID_HANDLE_VALUE;
    }
    return g_create_file_w(
        filename_wide.c_str(), desired_access, share_mode, security_attributes,
        creation_disposition, flags_and_attributes, template_file);
}

// BuildXL classifies DeleteFileW as a write and preserves the last reparse
// point because the API deletes a link itself rather than its target.
BOOL WINAPI DetouredDeleteFileW(const LPCWSTR filename) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_delete_file_w(filename);
    }
    return AuthorizeDeletion(filename) ? g_delete_file_w(filename) : FALSE;
}

BOOL WINAPI DetouredDeleteFileA(const LPCSTR filename) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_delete_file_a(filename);
    }
    std::wstring filename_wide;
    if (!ConvertAnsiPath(filename, filename_wide) ||
        !AuthorizeDeletion(filename_wide.c_str())) {
        return FALSE;
    }
    return g_delete_file_w(filename_wide.c_str());
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
    std::wstring resolved_path;
    if (!ResolveParentFinalIdentity(
            EvaluatedPath(evaluation, path), resolved_path)) {
        ReportDenied(
            protocol::FilesystemOperation::kCreate,
            EvaluatedPath(evaluation, path));
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    const auto final_evaluation =
        policy->Evaluate(resolved_path.c_str(), Access::kWrite);
    if (final_evaluation.decision == Decision::kDeny) {
        ReportDenied(
            protocol::FilesystemOperation::kCreate,
            EvaluatedPath(final_evaluation, resolved_path.c_str()));
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    InvalidateResolvedPathForMutation(resolved_path.c_str(), true);
    return g_create_directory_w(path, security_attributes);
}

BOOL WINAPI DetouredRemoveDirectoryW(const LPCWSTR path) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_remove_directory_w(path);
    }
    return AuthorizeDeletion(path, true) ? g_remove_directory_w(path) : FALSE;
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

HANDLE WINAPI DetouredCreateFileMappingW(
    const HANDLE file,
    const LPSECURITY_ATTRIBUTES security_attributes,
    const DWORD protection,
    const DWORD maximum_size_high,
    const DWORD maximum_size_low,
    const LPCWSTR name) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_create_file_mapping_w(
            file, security_attributes, protection, maximum_size_high, maximum_size_low, name);
    }
    if (!AuthorizeFileMapping(file, protection)) {
        return nullptr;
    }
    return g_create_file_mapping_w(
        file, security_attributes, protection, maximum_size_high, maximum_size_low, name);
}

HANDLE WINAPI DetouredCreateFileMappingA(
    const HANDLE file,
    const LPSECURITY_ATTRIBUTES security_attributes,
    const DWORD protection,
    const DWORD maximum_size_high,
    const DWORD maximum_size_low,
    const LPCSTR name) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_create_file_mapping_a(
            file, security_attributes, protection, maximum_size_high, maximum_size_low, name);
    }
    if (!AuthorizeFileMapping(file, protection)) {
        return nullptr;
    }
    return g_create_file_mapping_a(
        file, security_attributes, protection, maximum_size_high, maximum_size_low, name);
}

NTSTATUS NTAPI DetouredNtCreateSection(
    const PHANDLE section,
    const ACCESS_MASK desired_access,
    const POBJECT_ATTRIBUTES object_attributes,
    const PLARGE_INTEGER maximum_size,
    const ULONG protection,
    const ULONG allocation_attributes,
    const HANDLE file) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled() || file == nullptr || file == INVALID_HANDLE_VALUE) {
        return g_nt_create_section(
            section, desired_access, object_attributes, maximum_size, protection,
            allocation_attributes, file);
    }
    if (!AuthorizeFileMapping(file, protection)) {
        if (section != nullptr) {
            *section = nullptr;
        }
        constexpr NTSTATUS status_access_denied = static_cast<NTSTATUS>(0xC0000022UL);
        return status_access_denied;
    }
    return g_nt_create_section(
        section, desired_access, object_attributes, maximum_size, protection,
        allocation_attributes, file);
}

BOOL WINAPI DetouredDeviceIoControl(
    const HANDLE device,
    const DWORD control_code,
    const LPVOID input,
    const DWORD input_size,
    const LPVOID output,
    const DWORD output_size,
    const LPDWORD bytes_returned,
    const LPOVERLAPPED overlapped) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_device_io_control(
            device, control_code, input, input_size, output, output_size, bytes_returned,
            overlapped);
    }

    if (control_code == FSCTL_SET_COMPRESSION) {
        std::wstring source_path;
        if (!TryGetHandlePath(device, source_path)) {
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
        const auto* policy = g_policy.get();
        const auto source = policy == nullptr
                                ? PolicyEvaluation{}
                                : policy->Evaluate(source_path.c_str(), Access::kWrite);
        if (source.decision == Decision::kDeny) {
            ReportDenied(
                protocol::FilesystemOperation::kWrite,
                EvaluatedPath(source, source_path.c_str()));
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
        const BOOL result = g_device_io_control(
            device, control_code, input, input_size, output, output_size,
            bytes_returned, overlapped);
        if (result) {
            InvalidateResolvedPathForMutation(
                EvaluatedPath(source, source_path.c_str()), false);
        }
        return result;
    }

    if (control_code != FSCTL_SET_REPARSE_POINT) {
        return g_device_io_control(
            device, control_code, input, input_size, output, output_size, bytes_returned,
            overlapped);
    }

    std::wstring source_path;
    std::wstring target_path;
    if (!TryGetHandlePath(device, source_path) ||
        !ReadReparseTarget(input, input_size, target_path)) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    const auto* policy = g_policy.get();
    const auto source = policy == nullptr
                            ? PolicyEvaluation{}
                            : policy->Evaluate(source_path.c_str(), Access::kWrite);
    const auto target = policy == nullptr
                            ? PolicyEvaluation{}
                            : policy->Evaluate(target_path.c_str(), Access::kMetadata);
    if (source.decision == Decision::kDeny || target.decision == Decision::kDeny) {
        const bool source_denied = source.decision == Decision::kDeny;
        ReportDenied(
            protocol::FilesystemOperation::kCreate,
            source_denied ? EvaluatedPath(source, source_path.c_str())
                          : EvaluatedPath(target, target_path.c_str()));
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }

    const BOOL result = g_device_io_control(
        device, control_code, input, input_size, output, output_size, bytes_returned,
        overlapped);
    if (result) {
        InvalidateResolvedPathForMutation(EvaluatedPath(source, source_path.c_str()), true);
    }
    return result;
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
    constexpr FILE_INFORMATION_CLASS file_basic_information =
        static_cast<FILE_INFORMATION_CLASS>(4);
    const bool is_truncation = information_class == file_allocation_information ||
                               information_class == file_end_of_file_information;
    const bool is_disposition = information_class == file_disposition_information ||
                                information_class == file_disposition_information_ex;
    const bool is_rename = information_class == file_rename_information ||
                           information_class == file_rename_information_ex;
    const bool is_basic = information_class == file_basic_information;
    if (!is_truncation && !is_disposition && !is_rename && !is_basic) {
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
    if (!AuthorizeCopy(existing_path, new_path)) {
        return FALSE;
    }
    return g_create_hard_link_w(new_path, existing_path, security_attributes);
}

BOOL WINAPI DetouredCreateHardLinkA(
    const LPCSTR new_path,
    const LPCSTR existing_path,
    const LPSECURITY_ATTRIBUTES security_attributes) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_create_hard_link_a(new_path, existing_path, security_attributes);
    }
    std::wstring existing_wide;
    std::wstring new_wide;
    if (!ConvertAnsiPath(existing_path, existing_wide) ||
        !ConvertAnsiPath(new_path, new_wide) ||
        !AuthorizeCopy(existing_wide.c_str(), new_wide.c_str())) {
        return FALSE;
    }
    return g_create_hard_link_w(
        new_wide.c_str(), existing_wide.c_str(), security_attributes);
}

BOOLEAN WINAPI DetouredCreateSymbolicLinkW(
    const LPCWSTR link_path,
    const LPCWSTR target_path,
    const DWORD flags) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_create_symbolic_link_w(link_path, target_path, flags);
    }
    return AuthorizeSymbolicLink(link_path, target_path)
               ? g_create_symbolic_link_w(link_path, target_path, flags)
               : FALSE;
}

BOOLEAN WINAPI DetouredCreateSymbolicLinkA(
    const LPCSTR link_path,
    const LPCSTR target_path,
    const DWORD flags) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_create_symbolic_link_a(link_path, target_path, flags);
    }
    std::wstring link_wide;
    std::wstring target_wide;
    if (!ConvertAnsiPath(link_path, link_wide) ||
        !ConvertAnsiPath(target_path, target_wide) ||
        !AuthorizeSymbolicLink(link_wide.c_str(), target_wide.c_str())) {
        return FALSE;
    }
    return g_create_symbolic_link_w(link_wide.c_str(), target_wide.c_str(), flags);
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

int WINAPI DetouredSHFileOperationW(
    const LPSHFILEOPSTRUCTW operation) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled() || operation == nullptr) {
        return g_sh_file_operation_w(operation);
    }
    bool authorized = true;
    if (operation->wFunc == FO_DELETE) {
        authorized = AuthorizeShellDelete(operation->pFrom);
    } else if (operation->wFunc == FO_COPY || operation->wFunc == FO_MOVE ||
               operation->wFunc == FO_RENAME) {
        authorized = AuthorizeShellTransfer(
            operation->pFrom, operation->pTo, operation->wFunc != FO_COPY,
            (operation->fFlags & FOF_MULTIDESTFILES) != 0);
    }
    if (!authorized) {
        operation->fAnyOperationsAborted = TRUE;
        SetLastError(ERROR_ACCESS_DENIED);
        return ERROR_ACCESS_DENIED;
    }
    return g_sh_file_operation_w(operation);
}

int WINAPI DetouredSHFileOperationA(
    const LPSHFILEOPSTRUCTA operation) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled() || operation == nullptr) {
        return g_sh_file_operation_a(operation);
    }
    bool authorized = true;
    if (operation->wFunc == FO_DELETE) {
        authorized = AuthorizeShellDelete(operation->pFrom);
    } else if (operation->wFunc == FO_COPY || operation->wFunc == FO_MOVE ||
               operation->wFunc == FO_RENAME) {
        authorized = AuthorizeShellTransfer(
            operation->pFrom, operation->pTo, operation->wFunc != FO_COPY,
            (operation->fFlags & FOF_MULTIDESTFILES) != 0);
    }
    if (!authorized) {
        operation->fAnyOperationsAborted = TRUE;
        SetLastError(ERROR_ACCESS_DENIED);
        return ERROR_ACCESS_DENIED;
    }
    return g_sh_file_operation_a(operation);
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
    if (process::PrepareProcessHooks(policy_payload, policy_length) !=
        process::ProcessHookPrepareStatus::kSuccess) {
        return HookInstallStatus::kInvalidPolicy;
    }
    g_copy_file_2 = reinterpret_cast<CopyFile2Function>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CopyFile2"));
    g_zw_set_information_file = reinterpret_cast<ZwSetInformationFile_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "ZwSetInformationFile"));
    g_nt_create_section = reinterpret_cast<NtCreateSectionFunction>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateSection"));
    g_nt_query_information_file = reinterpret_cast<NtQueryInformationFileFunction>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationFile"));
    g_nt_query_attributes_file = reinterpret_cast<NtQueryAttributesFileFunction>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryAttributesFile"));
    g_nt_query_full_attributes_file = reinterpret_cast<NtQueryAttributesFileFunction>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryFullAttributesFile"));
    g_nt_query_directory_file = reinterpret_cast<NtQueryDirectoryFile_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryDirectoryFile"));
    g_nt_query_directory_file_ex = reinterpret_cast<NtQueryDirectoryFileExFunction>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryDirectoryFileEx"));
    g_nt_read_file = reinterpret_cast<NtReadWriteFileFunction>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtReadFile"));
    g_nt_write_file = reinterpret_cast<NtReadWriteFileFunction>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtWriteFile"));
    g_nt_create_file = reinterpret_cast<NtCreateFile_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateFile"));
    g_nt_open_file = reinterpret_cast<NtOpenFile_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtOpenFile"));
    g_nt_notify_change_directory_file =
        reinterpret_cast<NtNotifyChangeDirectoryFileFunction>(GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), "NtNotifyChangeDirectoryFile"));
    g_nt_notify_change_directory_file_ex =
        reinterpret_cast<NtNotifyChangeDirectoryFileExFunction>(GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), "NtNotifyChangeDirectoryFileEx"));
    if (g_zw_set_information_file == nullptr || g_nt_create_section == nullptr ||
        g_nt_query_information_file == nullptr || g_nt_query_attributes_file == nullptr ||
        g_nt_query_full_attributes_file == nullptr || g_nt_query_directory_file == nullptr ||
        g_nt_query_directory_file_ex == nullptr || g_nt_read_file == nullptr ||
        g_nt_write_file == nullptr || g_nt_create_file == nullptr ||
        g_nt_open_file == nullptr || g_nt_notify_change_directory_file == nullptr ||
        g_nt_notify_change_directory_file_ex == nullptr) {
        return HookInstallStatus::kTransactionFailed;
    }
    if (DetourTransactionBegin() != NO_ERROR) {
        return HookInstallStatus::kTransactionFailed;
    }
    if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR ||
        process::AttachProcessHooks() != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_find_first_file_w),
            reinterpret_cast<PVOID>(DetouredFindFirstFileW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_find_first_file_a),
            reinterpret_cast<PVOID>(DetouredFindFirstFileA)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_find_first_file_ex_w),
            reinterpret_cast<PVOID>(DetouredFindFirstFileExW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_find_first_file_ex_a),
            reinterpret_cast<PVOID>(DetouredFindFirstFileExA)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_get_file_attributes_w),
            reinterpret_cast<PVOID>(DetouredGetFileAttributesW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_get_file_attributes_a),
            reinterpret_cast<PVOID>(DetouredGetFileAttributesA)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_get_file_attributes_ex_w),
            reinterpret_cast<PVOID>(DetouredGetFileAttributesExW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_get_file_attributes_ex_a),
            reinterpret_cast<PVOID>(DetouredGetFileAttributesExA)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_get_file_information_by_handle),
            reinterpret_cast<PVOID>(DetouredGetFileInformationByHandle)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_get_file_information_by_handle_ex),
            reinterpret_cast<PVOID>(DetouredGetFileInformationByHandleEx)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_nt_query_information_file),
            reinterpret_cast<PVOID>(DetouredNtQueryInformationFile)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_nt_query_attributes_file),
            reinterpret_cast<PVOID>(DetouredNtQueryAttributesFile)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_nt_query_full_attributes_file),
            reinterpret_cast<PVOID>(DetouredNtQueryFullAttributesFile)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_nt_query_directory_file),
            reinterpret_cast<PVOID>(DetouredNtQueryDirectoryFile)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_nt_query_directory_file_ex),
            reinterpret_cast<PVOID>(DetouredNtQueryDirectoryFileEx)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_read_directory_changes_w),
            reinterpret_cast<PVOID>(DetouredReadDirectoryChangesW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_nt_notify_change_directory_file),
            reinterpret_cast<PVOID>(DetouredNtNotifyChangeDirectoryFile)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_nt_notify_change_directory_file_ex),
            reinterpret_cast<PVOID>(DetouredNtNotifyChangeDirectoryFileEx)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_open_file_by_id),
            reinterpret_cast<PVOID>(DetouredOpenFileById)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_set_file_attributes_w),
            reinterpret_cast<PVOID>(DetouredSetFileAttributesW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_set_file_attributes_a),
            reinterpret_cast<PVOID>(DetouredSetFileAttributesA)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_set_file_security_w),
            reinterpret_cast<PVOID>(DetouredSetFileSecurityW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_set_file_security_a),
            reinterpret_cast<PVOID>(DetouredSetFileSecurityA)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_encrypt_file_w),
            reinterpret_cast<PVOID>(DetouredEncryptFileW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_encrypt_file_a),
            reinterpret_cast<PVOID>(DetouredEncryptFileA)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_decrypt_file_w),
            reinterpret_cast<PVOID>(DetouredDecryptFileW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_decrypt_file_a),
            reinterpret_cast<PVOID>(DetouredDecryptFileA)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_set_file_time),
            reinterpret_cast<PVOID>(DetouredSetFileTime)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_read_file),
            reinterpret_cast<PVOID>(DetouredReadFile)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_write_file),
            reinterpret_cast<PVOID>(DetouredWriteFile)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_nt_read_file),
            reinterpret_cast<PVOID>(DetouredNtReadFile)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_nt_write_file),
            reinterpret_cast<PVOID>(DetouredNtWriteFile)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_nt_create_file),
            reinterpret_cast<PVOID>(DetouredNtCreateFile)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_nt_open_file),
            reinterpret_cast<PVOID>(DetouredNtOpenFile)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_create_file_w),
            reinterpret_cast<PVOID>(DetouredCreateFileW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_create_file_a),
            reinterpret_cast<PVOID>(DetouredCreateFileA)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_delete_file_w),
            reinterpret_cast<PVOID>(DetouredDeleteFileW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_delete_file_a),
            reinterpret_cast<PVOID>(DetouredDeleteFileA)) != NO_ERROR ||
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
            reinterpret_cast<PVOID*>(&g_create_file_mapping_w),
            reinterpret_cast<PVOID>(DetouredCreateFileMappingW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_create_file_mapping_a),
            reinterpret_cast<PVOID>(DetouredCreateFileMappingA)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_nt_create_section),
            reinterpret_cast<PVOID>(DetouredNtCreateSection)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_device_io_control),
            reinterpret_cast<PVOID>(DetouredDeviceIoControl)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_zw_set_information_file),
            reinterpret_cast<PVOID>(DetouredZwSetInformationFile)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_create_hard_link_w),
            reinterpret_cast<PVOID>(DetouredCreateHardLinkW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_create_hard_link_a),
            reinterpret_cast<PVOID>(DetouredCreateHardLinkA)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_create_symbolic_link_w),
            reinterpret_cast<PVOID>(DetouredCreateSymbolicLinkW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_create_symbolic_link_a),
            reinterpret_cast<PVOID>(DetouredCreateSymbolicLinkA)) != NO_ERROR ||
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
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_sh_file_operation_w),
            reinterpret_cast<PVOID>(DetouredSHFileOperationW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_sh_file_operation_a),
            reinterpret_cast<PVOID>(DetouredSHFileOperationA)) != NO_ERROR ||
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
