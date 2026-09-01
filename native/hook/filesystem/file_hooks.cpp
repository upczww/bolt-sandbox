#include "hook/filesystem/file_hooks.h"

#include "hook/filesystem/access_classifier.h"
#include "hook/filesystem/final_path_resolver.h"
#include "hook/filesystem/filesystem_policy.h"
#include "hook/filesystem/handle_access_cache.h"
#include "hook/filesystem/path_cache.h"
#include "hook/filesystem/safe_device.h"
#include "hook/event_sink.h"
#include "hook/process/process_hooks.h"
#include "hook/recovery/recovery_client.h"

#include "DetouredFunctionTypes.h"
#include "DetouredScope.h"

#include <algorithm>
#include <cstring>
#include <cwchar>
#include <array>
#include <atomic>
#include <filesystem>
#include <memory>
#include <new>
#include <string>
#include <utility>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <winioctl.h>
#include <shellapi.h>
#include <shobjidl.h>

#include <detours.h>

namespace bolt::filesystem {
namespace {

std::unique_ptr<FilesystemPolicy> g_policy;
HandleAccessCache g_handle_access_cache;
constexpr LONG kRequiredFilesystemHookCount = 86;
volatile LONG g_installed_file_hook_count = 0;

CreateFileW_t g_create_file_w = CreateFileW;
CreateFileA_t g_create_file_a = CreateFileA;
decltype(&CreateNamedPipeW) g_create_named_pipe_w = CreateNamedPipeW;
decltype(&CreateNamedPipeA) g_create_named_pipe_a = CreateNamedPipeA;
decltype(&CreatePipe) g_create_pipe = CreatePipe;
decltype(&GetDiskFreeSpaceW) g_get_disk_free_space_w = GetDiskFreeSpaceW;
decltype(&GetDiskFreeSpaceA) g_get_disk_free_space_a = GetDiskFreeSpaceA;
decltype(&GetDiskFreeSpaceExW) g_get_disk_free_space_ex_w = GetDiskFreeSpaceExW;
decltype(&GetDiskFreeSpaceExA) g_get_disk_free_space_ex_a = GetDiskFreeSpaceExA;
decltype(&CreateMailslotW) g_create_mailslot_w = CreateMailslotW;
decltype(&CreateMailslotA) g_create_mailslot_a = CreateMailslotA;
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
using NtMapViewOfSectionFunction = NTSTATUS(NTAPI*)(
    HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
NtMapViewOfSectionFunction g_nt_map_view_of_section = nullptr;
using NtUnmapViewOfSectionFunction = NTSTATUS(NTAPI*)(HANDLE, PVOID);
NtUnmapViewOfSectionFunction g_nt_unmap_view_of_section = nullptr;
using NtQuerySectionFunction = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
NtQuerySectionFunction g_nt_query_section = nullptr;
using NtCloseFunction = NTSTATUS(NTAPI*)(HANDLE);
NtCloseFunction g_nt_close = nullptr;
using NtDuplicateObjectFunction = NTSTATUS(NTAPI*)(
    HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
NtDuplicateObjectFunction g_nt_duplicate_object = nullptr;
using NtCompareObjectsFunction = NTSTATUS(NTAPI*)(HANDLE, HANDLE);
NtCompareObjectsFunction g_nt_compare_objects = nullptr;
std::array<HANDLE, 5> g_trusted_standard_streams{};
using GetMappedFileNameWFunction = DWORD(WINAPI*)(HANDLE, LPVOID, LPWSTR, DWORD);
GetMappedFileNameWFunction g_get_mapped_file_name_w = nullptr;

enum class SectionCapability : std::uint8_t {
    kNone,
    kAnonymous,
    kAuthorizedFile,
};

struct SectionCapabilityEntry {
    SectionCapability capability = SectionCapability::kNone;
    HANDLE handle = nullptr;
};

constexpr std::size_t kSectionCapabilityCapacity = 2'048;
SRWLOCK g_section_capability_lock = SRWLOCK_INIT;
std::array<SectionCapabilityEntry, kSectionCapabilityCapacity>
    g_section_capabilities{};
std::size_t g_section_capability_count = 0;

bool TrackSectionCapability(
    const HANDLE handle,
    const SectionCapability capability) noexcept {
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE) {
        return false;
    }
    AcquireSRWLockExclusive(&g_section_capability_lock);
    for (std::size_t index = 0; index < g_section_capability_count; ++index) {
        auto& entry = g_section_capabilities[index];
        if (entry.handle == handle) {
            entry.capability = capability;
            ReleaseSRWLockExclusive(&g_section_capability_lock);
            return true;
        }
    }
    if (g_section_capability_count == g_section_capabilities.size()) {
        ReleaseSRWLockExclusive(&g_section_capability_lock);
        return false;
    }
    auto& available =
        g_section_capabilities[g_section_capability_count++];
    available.capability = capability;
    available.handle = handle;
    ReleaseSRWLockExclusive(&g_section_capability_lock);
    return true;
}

void UntrackSectionCapability(const HANDLE handle) noexcept {
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE) {
        return;
    }
    AcquireSRWLockExclusive(&g_section_capability_lock);
    for (std::size_t index = 0; index < g_section_capability_count; ++index) {
        if (g_section_capabilities[index].handle == handle) {
            --g_section_capability_count;
            g_section_capabilities[index] =
                g_section_capabilities[g_section_capability_count];
            g_section_capabilities[g_section_capability_count] = {};
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_section_capability_lock);
}

bool HasSectionCapability(
    const HANDLE handle,
    const SectionCapability capability) noexcept {
    AcquireSRWLockShared(&g_section_capability_lock);
    bool found = false;
    for (std::size_t index = 0; index < g_section_capability_count; ++index) {
        const auto& entry = g_section_capabilities[index];
        if (entry.capability == capability && entry.handle == handle) {
            found = true;
            break;
        }
    }
    ReleaseSRWLockShared(&g_section_capability_lock);
    return found;
}
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
decltype(&CoCreateInstance) g_co_create_instance = CoCreateInstance;
decltype(&CoCreateInstanceEx) g_co_create_instance_ex = CoCreateInstanceEx;
decltype(&CoGetClassObject) g_co_get_class_object = CoGetClassObject;
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
using NtCreateNamedPipeFileFunction = NTSTATUS(NTAPI*)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG,
    ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, PLARGE_INTEGER);
NtCreateNamedPipeFileFunction g_nt_create_named_pipe_file = nullptr;
using NtCreateMailslotFileFunction = NTSTATUS(NTAPI*)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG,
    ULONG, PLARGE_INTEGER);
NtCreateMailslotFileFunction g_nt_create_mailslot_file = nullptr;

enum class PrivatePipeCapability : std::uint8_t {
    kNone,
    kFilesystemRoot,
    kServer,
    kClient,
};

struct PrivatePipeCapabilityEntry {
    HANDLE handle = nullptr;
    PrivatePipeCapability capability = PrivatePipeCapability::kNone;
    ACCESS_MASK access = 0;
};

constexpr std::size_t kPrivatePipeCapabilityCapacity = 512;
SRWLOCK g_private_pipe_capability_lock = SRWLOCK_INIT;
std::array<PrivatePipeCapabilityEntry, kPrivatePipeCapabilityCapacity>
    g_private_pipe_capabilities{};
std::size_t g_private_pipe_capability_count = 0;

bool TrackPrivatePipeCapability(
    const HANDLE handle,
    const PrivatePipeCapability capability,
    const ACCESS_MASK access = 0) noexcept {
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE ||
        capability == PrivatePipeCapability::kNone) {
        return false;
    }
    AcquireSRWLockExclusive(&g_private_pipe_capability_lock);
    for (std::size_t index = 0;
         index < g_private_pipe_capability_count; ++index) {
        auto& entry = g_private_pipe_capabilities[index];
        if (entry.handle == handle) {
            entry.capability = capability;
            entry.access = access;
            ReleaseSRWLockExclusive(&g_private_pipe_capability_lock);
            return true;
        }
    }
    if (g_private_pipe_capability_count ==
        g_private_pipe_capabilities.size()) {
        ReleaseSRWLockExclusive(&g_private_pipe_capability_lock);
        return false;
    }
    g_private_pipe_capabilities[g_private_pipe_capability_count++] = {
        handle, capability, access};
    ReleaseSRWLockExclusive(&g_private_pipe_capability_lock);
    return true;
}

bool HasPrivatePipeCapability(
    const HANDLE handle,
    const PrivatePipeCapability capability) noexcept {
    AcquireSRWLockShared(&g_private_pipe_capability_lock);
    bool found = false;
    for (std::size_t index = 0;
         index < g_private_pipe_capability_count; ++index) {
        const auto& entry = g_private_pipe_capabilities[index];
        if (entry.handle == handle && entry.capability == capability) {
            found = true;
            break;
        }
    }
    ReleaseSRWLockShared(&g_private_pipe_capability_lock);
    return found;
}

bool ReadPrivatePipeCapability(
    const HANDLE handle,
    PrivatePipeCapability& capability,
    ACCESS_MASK& access) noexcept {
    capability = PrivatePipeCapability::kNone;
    access = 0;
    AcquireSRWLockShared(&g_private_pipe_capability_lock);
    for (std::size_t index = 0;
         index < g_private_pipe_capability_count; ++index) {
        const auto& entry = g_private_pipe_capabilities[index];
        if (entry.handle == handle) {
            capability = entry.capability;
            access = entry.access;
            break;
        }
    }
    ReleaseSRWLockShared(&g_private_pipe_capability_lock);
    return capability != PrivatePipeCapability::kNone;
}

void UntrackPrivatePipeCapability(const HANDLE handle) noexcept {
    AcquireSRWLockExclusive(&g_private_pipe_capability_lock);
    for (std::size_t index = 0;
         index < g_private_pipe_capability_count; ++index) {
        if (g_private_pipe_capabilities[index].handle == handle) {
            --g_private_pipe_capability_count;
            g_private_pipe_capabilities[index] =
                g_private_pipe_capabilities[g_private_pipe_capability_count];
            g_private_pipe_capabilities[g_private_pipe_capability_count] = {};
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_private_pipe_capability_lock);
}

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

class Win32LastErrorGuard final {
  public:
    Win32LastErrorGuard() noexcept : error_(GetLastError()) {}

    ~Win32LastErrorGuard() noexcept {
        SetLastError(error_);
    }

    Win32LastErrorGuard(const Win32LastErrorGuard&) = delete;
    Win32LastErrorGuard& operator=(const Win32LastErrorGuard&) = delete;

  private:
    DWORD error_;
};

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
    const DWORD source_attributes = g_get_file_attributes_w(source_path);
    const bool moves_directory_tree =
        source_attributes != INVALID_FILE_ATTRIBUTES &&
        (source_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    if (moves_directory_tree &&
        (policy->HasDeniedDescendant(source_path) ||
         policy->HasDeniedDescendant(destination_path))) {
        ReportDenied(protocol::FilesystemOperation::kRename, source_path);
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }
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
    if (moves_directory_tree &&
        (policy->HasDeniedDescendant(resolved_source.c_str()) ||
         policy->HasDeniedDescendant(resolved_destination.c_str()))) {
        ReportDenied(
            protocol::FilesystemOperation::kRename, resolved_source.c_str());
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
    } else if (backup_path != nullptr &&
               backup_text.decision == Decision::kDeny) {
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
    } else if (backup_path != nullptr &&
               backup_final.decision == Decision::kDeny) {
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

bool NativeCreateFilePath(
    const wchar_t* path,
    std::wstring& extended,
    const wchar_t*& native_path) noexcept {
    native_path = path;
    if (path == nullptr) {
        return true;
    }
    const std::size_t length = std::wcslen(path);
    if (length < MAX_PATH || std::wcsncmp(path, L"\\\\?\\", 4) == 0 ||
        std::wcsncmp(path, L"\\\\.\\", 4) == 0) {
        return true;
    }
    const auto is_separator = [](const wchar_t value) {
        return value == L'\\' || value == L'/';
    };
    try {
        if (length >= 3 && path[1] == L':' && is_separator(path[2])) {
            extended.assign(L"\\\\?\\");
            extended.append(path);
        } else if (length >= 2 && is_separator(path[0]) &&
                   is_separator(path[1])) {
            extended.assign(L"\\\\?\\UNC\\");
            extended.append(path + 2);
        } else {
            return true;
        }
    } catch (...) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return false;
    }
    native_path = extended.c_str();
    return true;
}

bool TryConvertDevicePathToDosPath(
    const std::wstring& device_path,
    std::wstring& dos_path) noexcept;

bool TryGetNtObjectPath(const HANDLE handle, std::wstring& path) noexcept {
    using NtQueryObjectFunction = NTSTATUS(NTAPI*)(
        HANDLE, ULONG, PVOID, ULONG, PULONG);
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto query_object =
        ntdll == nullptr
            ? nullptr
            : reinterpret_cast<NtQueryObjectFunction>(
                  GetProcAddress(ntdll, "NtQueryObject"));
    if (query_object == nullptr) {
        return false;
    }
    constexpr ULONG object_name_information = 1;
    constexpr ULONG maximum_name_information = 128 * 1'024;
    ULONG required = 0;
    query_object(
        handle, object_name_information, nullptr, 0, &required);
    if (required < sizeof(UNICODE_STRING) ||
        required > maximum_name_information) {
        return false;
    }
    std::vector<std::uint8_t> storage;
    try {
        storage.resize(required);
    } catch (...) {
        return false;
    }
    if (query_object(
            handle, object_name_information, storage.data(), required,
            &required) < 0) {
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
    std::wstring device_path;
    try {
        device_path.assign(
            information->Buffer,
            information->Length / sizeof(wchar_t));
    } catch (...) {
        return false;
    }
    return TryConvertDevicePathToDosPath(device_path, path);
}

bool TryGetHandlePath(const HANDLE handle, std::wstring& path) noexcept {
    if (IsNullDeviceHandle(handle)) {
        path = L"NUL";
        return true;
    }
    constexpr DWORD flags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
    std::array<wchar_t, 1'024> common_path{};
    const DWORD common_written = GetFinalPathNameByHandleW(
        handle, common_path.data(), static_cast<DWORD>(common_path.size()),
        flags);
    if (common_written == 0) {
        return TryGetNtObjectPath(handle, path);
    }
    if (common_written < common_path.size()) {
        try {
            path.assign(common_path.data(), common_written);
            return true;
        } catch (...) {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return false;
        }
    }
    try {
        path.assign(static_cast<std::size_t>(common_written) + 1, L'\0');
    } catch (...) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return false;
    }
    const DWORD written =
        GetFinalPathNameByHandleW(handle, path.data(), static_cast<DWORD>(path.size()), flags);
    if (written == 0 || written >= path.size()) {
        path.clear();
        return TryGetNtObjectPath(handle, path);
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

bool HasCaseInsensitivePrefix(
    const std::wstring& value,
    const wchar_t* prefix,
    const std::size_t prefix_length) noexcept {
    return value.size() >= prefix_length &&
           CompareStringOrdinal(
               value.data(), static_cast<int>(prefix_length), prefix,
               static_cast<int>(prefix_length), TRUE) == CSTR_EQUAL;
}

bool TryConvertDevicePathToDosPath(
    const std::wstring& device_path,
    std::wstring& dos_path) noexcept {
    constexpr wchar_t nt_dos_prefix[] = L"\\??\\";
    if (HasCaseInsensitivePrefix(device_path, nt_dos_prefix, 4)) {
        try {
            dos_path.assign(device_path, 4, std::wstring::npos);
        } catch (...) {
            return false;
        }
        return true;
    }

    constexpr wchar_t mup_prefix[] = L"\\Device\\Mup\\";
    if (HasCaseInsensitivePrefix(device_path, mup_prefix, 12)) {
        try {
            dos_path.assign(L"\\\\");
            dos_path.append(device_path, 12, std::wstring::npos);
        } catch (...) {
            return false;
        }
        return true;
    }

    const DWORD drive_chars = GetLogicalDriveStringsW(0, nullptr);
    if (drive_chars == 0) {
        return false;
    }
    std::wstring drives;
    std::wstring target;
    try {
        drives.assign(static_cast<std::size_t>(drive_chars) + 1, L'\0');
        target.assign(32768, L'\0');
    } catch (...) {
        return false;
    }
    if (GetLogicalDriveStringsW(drive_chars, drives.data()) == 0) {
        return false;
    }

    for (const wchar_t* drive = drives.c_str(); *drive != L'\0';
         drive += std::wcslen(drive) + 1) {
        if (std::wcslen(drive) < 2) {
            continue;
        }
        const wchar_t drive_name[] = {drive[0], L':', L'\0'};
        const DWORD target_length =
            QueryDosDeviceW(drive_name, target.data(), static_cast<DWORD>(target.size()));
        if (target_length == 0) {
            continue;
        }
        const std::size_t prefix_length = std::wcslen(target.c_str());
        if (!HasCaseInsensitivePrefix(device_path, target.c_str(), prefix_length) ||
            (device_path.size() > prefix_length && device_path[prefix_length] != L'\\')) {
            continue;
        }
        try {
            dos_path.assign(drive_name);
            dos_path.append(device_path, prefix_length, std::wstring::npos);
        } catch (...) {
            return false;
        }
        return true;
    }
    return false;
}

bool TryGetSectionPath(const HANDLE section, std::wstring& path) noexcept {
    struct SectionBasicInformation {
        PVOID base_address;
        ULONG allocation_attributes;
        LARGE_INTEGER maximum_size;
    };
    constexpr ULONG section_basic_information = 0;
    constexpr ULONG file_backed_attributes = SEC_FILE | SEC_IMAGE;
    constexpr NTSTATUS status_success = 0;
    SectionBasicInformation information{};
    NTSTATUS query_status = g_nt_query_section(
        section, section_basic_information, &information, sizeof(information),
        nullptr);
    if (query_status != status_success) {
        constexpr DWORD section_query = 0x0001;
        HANDLE query_handle = nullptr;
        if (!DuplicateHandle(
                GetCurrentProcess(), section, GetCurrentProcess(),
                &query_handle, section_query, FALSE, 0)) {
            return false;
        }
        query_status = g_nt_query_section(
            query_handle, section_basic_information, &information,
            sizeof(information), nullptr);
        CloseHandle(query_handle);
        if (query_status != status_success) {
            return false;
        }
    }
    if ((information.allocation_attributes & file_backed_attributes) == 0) {
        path.clear();
        return true;
    }

    PVOID probe_base = nullptr;
    LARGE_INTEGER probe_offset{};
    SIZE_T probe_size = 1;
    constexpr ULONG view_unmap = 2;
    if (g_nt_map_view_of_section(
            section, GetCurrentProcess(), &probe_base, 0, 0, &probe_offset, &probe_size,
            view_unmap, 0, PAGE_READONLY) != status_success) {
        return false;
    }

    std::wstring device_path;
    bool resolved = false;
    try {
        device_path.assign(32768, L'\0');
        const DWORD length = g_get_mapped_file_name_w(
            GetCurrentProcess(), probe_base, device_path.data(),
            static_cast<DWORD>(device_path.size()));
        if (length != 0 && length < device_path.size()) {
            device_path.resize(length);
            resolved = TryConvertDevicePathToDosPath(device_path, path);
        }
    } catch (...) {
        resolved = false;
    }
    if (g_nt_unmap_view_of_section(GetCurrentProcess(), probe_base) != status_success) {
        return false;
    }
    return resolved;
}

bool AuthorizeSectionMapping(const HANDLE section, const ULONG protection) noexcept {
    if (HasSectionCapability(section, SectionCapability::kAnonymous) ||
        HasSectionCapability(section, SectionCapability::kAuthorizedFile)) {
        return true;
    }
    std::wstring source_path;
    if (!TryGetSectionPath(section, source_path)) {
        return false;
    }
    if (source_path.empty()) {
        return true;
    }
    const ULONG base_protection = protection & 0xffU;
    const bool writes_file = base_protection == PAGE_READWRITE ||
                             base_protection == PAGE_EXECUTE_READWRITE;
    const Access access = writes_file ? Access::kWrite : Access::kRead;
    const auto* policy = g_policy.get();
    const auto evaluation = policy == nullptr
                                ? PolicyEvaluation{}
                                : policy->Evaluate(source_path.c_str(), access);
    if (evaluation.decision != Decision::kDeny) {
        return true;
    }
    ReportDenied(
        writes_file ? protocol::FilesystemOperation::kWrite
                    : protocol::FilesystemOperation::kRead,
        EvaluatedPath(evaluation, source_path.c_str()));
    return false;
}

bool ReadCreatedHandle(
    const PHANDLE handle_pointer,
    HANDLE& handle) noexcept {
    handle = nullptr;
    if (handle_pointer == nullptr) {
        return false;
    }
    __try {
        handle = *handle_pointer;
        return handle != nullptr && handle != INVALID_HANDLE_VALUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        handle = nullptr;
        return false;
    }
}

void ClearCreatedHandle(const PHANDLE handle_pointer) noexcept {
    if (handle_pointer == nullptr) {
        return;
    }
    __try {
        *handle_pointer = nullptr;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
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
    if (IsNullDevicePath(path)) {
        resolved_path = L"NUL";
        return true;
    }
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

bool IsTrustedStandardStream(const HANDLE file) noexcept {
    return g_nt_compare_objects != nullptr &&
        std::any_of(
            g_trusted_standard_streams.begin(),
            g_trusted_standard_streams.end(),
            [file](const HANDLE trusted) {
                return trusted != nullptr &&
                    g_nt_compare_objects(file, trusted) >= 0;
            });
}

bool AuthorizeHandleMetadata(const HANDLE file) noexcept {
    if (g_handle_access_cache.Allows(file, HandleAccess::kMetadata)) {
        return true;
    }
    if (IsTrustedStandardStream(file)) {
        return g_handle_access_cache.Store(
            file, HandleAccess::kMetadata);
    }
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
    static_cast<void>(
        g_handle_access_cache.Store(file, HandleAccess::kMetadata));
    return true;
}

bool AuthorizeHandleEnumeration(const HANDLE directory) noexcept {
    if (g_handle_access_cache.Allows(
            directory, HandleAccess::kEnumerate)) {
        return true;
    }
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
    static_cast<void>(
        g_handle_access_cache.Store(directory, HandleAccess::kEnumerate));
    return true;
}

bool AuthorizeHandleIo(
    const HANDLE file,
    const Access access,
    const protocol::FilesystemOperation operation) noexcept {
    if (hook::IsRuntimeIoHandle(file, access == Access::kWrite)) {
        return true;
    }
    const HandleAccess cached_access =
        access == Access::kRead ? HandleAccess::kRead
        : access == Access::kWrite ? HandleAccess::kWrite
                                   : HandleAccess::kMetadata;
    if (g_handle_access_cache.Allows(file, cached_access)) {
        return true;
    }
    if (IsTrustedStandardStream(file)) {
        const bool cached =
            g_handle_access_cache.Store(file, cached_access);
        if (cached_access != HandleAccess::kMetadata) {
            return g_handle_access_cache.Store(
                       file, HandleAccess::kMetadata) &&
                cached;
        }
        return cached;
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
    static_cast<void>(g_handle_access_cache.Store(file, cached_access));
    if (cached_access != HandleAccess::kMetadata) {
        static_cast<void>(
            g_handle_access_cache.Store(file, HandleAccess::kMetadata));
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

struct NtFileTargetInformation {
    BOOLEAN replace_if_exists;
    HANDLE root_directory;
    ULONG file_name_length;
    WCHAR file_name[1];
};

struct NtFileTargetInformationEx {
    ULONG flags;
    HANDLE root_directory;
    ULONG file_name_length;
    WCHAR file_name[1];
};

bool TryGetFileInformationDestination(
    const PVOID information,
    const ULONG information_size,
    const bool extended,
    std::wstring& destination) noexcept {
    const std::size_t header_size = extended
                                        ? offsetof(NtFileTargetInformationEx, file_name)
                                        : offsetof(NtFileTargetInformation, file_name);
    if (information == nullptr || information_size < header_size) {
        return false;
    }

    const auto* standard = static_cast<const NtFileTargetInformation*>(information);
    const auto* extended_information =
        static_cast<const NtFileTargetInformationEx*>(information);
    const ULONG name_length = extended ? extended_information->file_name_length
                                       : standard->file_name_length;
    const HANDLE root_directory = extended ? extended_information->root_directory
                                           : standard->root_directory;
    const WCHAR* const name = extended ? extended_information->file_name
                                       : standard->file_name;
    if (name_length == 0 || name_length % sizeof(wchar_t) != 0 ||
        name_length > information_size - header_size || name_length > 0xffffU) {
        return false;
    }

    UNICODE_STRING object_name{};
    object_name.Length = static_cast<USHORT>(name_length);
    object_name.MaximumLength = object_name.Length;
    object_name.Buffer = const_cast<PWCH>(name);
    OBJECT_ATTRIBUTES object_attributes{};
    object_attributes.Length = sizeof(object_attributes);
    object_attributes.RootDirectory = root_directory;
    object_attributes.ObjectName = &object_name;
    object_attributes.Attributes = OBJ_CASE_INSENSITIVE;
    return TryGetObjectAttributesPath(&object_attributes, destination);
}

bool AuthorizeHandleHardLink(
    const HANDLE source,
    const PVOID information,
    const ULONG information_size,
    const bool extended) noexcept {
    std::wstring source_path;
    std::wstring destination_path;
    if (!TryGetHandlePath(source, source_path) ||
        !TryGetFileInformationDestination(
            information, information_size, extended, destination_path)) {
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }
    return AuthorizeCopy(source_path.c_str(), destination_path.c_str());
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

bool IsAuthorizedExactDevicePath(
    const wchar_t* path,
    const ClassifiedAccess& request) noexcept {
    if (request.access == Access::kWrite || path == nullptr) {
        return false;
    }
    constexpr wchar_t nt_prefix[] = L"\\Device\\";
    constexpr wchar_t win32_prefix[] = L"\\\\.\\";
    const std::size_t path_length = std::wcslen(path);
    const bool has_device_prefix =
        (path_length > std::size(nt_prefix) - 1 &&
         CompareStringOrdinal(
             path, static_cast<int>(std::size(nt_prefix) - 1),
             nt_prefix, static_cast<int>(std::size(nt_prefix) - 1), TRUE) ==
             CSTR_EQUAL) ||
        (path_length > std::size(win32_prefix) - 1 &&
         CompareStringOrdinal(
             path, static_cast<int>(std::size(win32_prefix) - 1),
             win32_prefix,
             static_cast<int>(std::size(win32_prefix) - 1), TRUE) ==
             CSTR_EQUAL);
    if (!has_device_prefix) {
        return false;
    }
    const auto* policy = g_policy.get();
    return policy != nullptr &&
           policy->Decide(path, request.access) == Decision::kAllow;
}

bool IsAuthorizedExactDeviceOpen(
    const POBJECT_ATTRIBUTES object_attributes,
    const ClassifiedAccess& request) noexcept {
    std::wstring path;
    return TryGetObjectAttributesPath(object_attributes, path) &&
           IsAuthorizedExactDevicePath(path.c_str(), request);
}

bool CacheExactDeviceHandle(
    const HANDLE handle,
    const ClassifiedAccess& request) noexcept {
    return g_handle_access_cache.Store(
               handle,
               request.access == Access::kRead ? HandleAccess::kRead
                                               : HandleAccess::kMetadata) &&
           g_handle_access_cache.Store(handle, HandleAccess::kMetadata);
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

bool HasEmptyObjectName(
    const POBJECT_ATTRIBUTES object_attributes) noexcept {
    if (object_attributes == nullptr) {
        return false;
    }
    __try {
        return object_attributes->ObjectName != nullptr &&
            object_attributes->ObjectName->Length == 0 &&
            object_attributes->ObjectName->MaximumLength == 0 &&
            object_attributes->ObjectName->Buffer == nullptr;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool ReadObjectRootDirectory(
    const POBJECT_ATTRIBUTES object_attributes,
    HANDLE& root_directory) noexcept {
    root_directory = nullptr;
    if (object_attributes == nullptr) {
        return false;
    }
    __try {
        if (object_attributes->Length < sizeof(OBJECT_ATTRIBUTES)) {
            return false;
        }
        root_directory = object_attributes->RootDirectory;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        root_directory = nullptr;
        return false;
    }
}

bool IsPrivatePipeFilesystemRootOpen(
    const ACCESS_MASK desired_access,
    const POBJECT_ATTRIBUTES object_attributes,
    const ULONG share_access,
    const ULONG open_options) noexcept {
    if (desired_access != (SYNCHRONIZE | GENERIC_READ) ||
        share_access != (FILE_SHARE_READ | FILE_SHARE_WRITE) ||
        open_options != FILE_SYNCHRONOUS_IO_NONALERT) {
        return false;
    }
    std::wstring path;
    return TryGetObjectAttributesPath(object_attributes, path) &&
        CompareStringOrdinal(
            path.c_str(), -1, L"\\Device\\NamedPipe\\", -1, TRUE) ==
        CSTR_EQUAL;
}

bool IsPrivatePipeClientOpen(
    const ACCESS_MASK desired_access,
    const POBJECT_ATTRIBUTES object_attributes,
    const ULONG share_access,
    const ULONG open_options) noexcept {
    if (!HasEmptyObjectName(object_attributes) || share_access != 0 ||
        open_options !=
            (FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT)) {
        return false;
    }
    const ACCESS_MASK write_access =
        SYNCHRONIZE | GENERIC_WRITE | FILE_READ_ATTRIBUTES;
    const ACCESS_MASK read_access = SYNCHRONIZE | GENERIC_READ;
    HANDLE root_directory = nullptr;
    return (desired_access == write_access || desired_access == read_access) &&
        ReadObjectRootDirectory(object_attributes, root_directory) &&
        HasPrivatePipeCapability(
            root_directory, PrivatePipeCapability::kServer);
}

bool IsPrivateAnonymousPipeCreation(
    const ACCESS_MASK desired_access,
    const POBJECT_ATTRIBUTES object_attributes,
    const ULONG share_access,
    const ULONG create_disposition,
    const ULONG create_options,
    const ULONG pipe_type,
    const ULONG read_mode,
    const ULONG completion_mode,
    const ULONG maximum_instances,
    const ULONG inbound_quota,
    const ULONG outbound_quota) noexcept {
    constexpr ULONG maximum_pipe_quota = 1U << 20U;
    const ACCESS_MASK read_access = SYNCHRONIZE | GENERIC_READ;
    const ACCESS_MASK write_access = SYNCHRONIZE | GENERIC_WRITE;
    const bool access_valid =
        (desired_access == read_access && share_access == FILE_SHARE_WRITE) ||
        (desired_access == write_access && share_access == FILE_SHARE_READ);
    HANDLE root_directory = nullptr;
    return access_valid && HasEmptyObjectName(object_attributes) &&
        ReadObjectRootDirectory(object_attributes, root_directory) &&
        HasPrivatePipeCapability(
            root_directory,
            PrivatePipeCapability::kFilesystemRoot) &&
        create_disposition == FILE_CREATE && create_options == 0 &&
        pipe_type == 0 && read_mode == 0 && completion_mode == 0 &&
        maximum_instances == 1 && inbound_quota != 0 && outbound_quota != 0 &&
        inbound_quota <= maximum_pipe_quota &&
        outbound_quota <= maximum_pipe_quota;
}

bool CachePrivatePipeAccess(
    const HANDLE handle,
    const ACCESS_MASK desired_access) noexcept {
    bool cached = g_handle_access_cache.Store(
        handle, HandleAccess::kMetadata);
    if ((desired_access & (GENERIC_READ | FILE_READ_DATA)) != 0) {
        cached = g_handle_access_cache.Store(
                     handle, HandleAccess::kRead) &&
            cached;
    }
    if ((desired_access & (GENERIC_WRITE | FILE_WRITE_DATA)) != 0) {
        cached = g_handle_access_cache.Store(
                     handle, HandleAccess::kWrite) &&
            cached;
    }
    return cached;
}

NTSTATUS FailPrivatePipeCapability(
    const HANDLE handle,
    const PHANDLE output,
    const PIO_STATUS_BLOCK io_status) noexcept {
    if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
        g_nt_close(handle);
    }
    return DenyNativeFileOpen(output, io_status);
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

bool AuthorizeOpenedFileHandle(
    const HANDLE file,
    const ClassifiedAccess& request) noexcept {
    if (file == nullptr || file == INVALID_HANDLE_VALUE) {
        return false;
    }
    SetLastError(ERROR_SUCCESS);
    const DWORD file_type = GetFileType(file);
    if (file_type == FILE_TYPE_PIPE || file_type == FILE_TYPE_CHAR) {
        return true;
    }
    if (file_type != FILE_TYPE_DISK) {
        return false;
    }
    std::wstring final_path;
    if (!TryGetHandlePath(file, final_path)) {
        return false;
    }
    const auto* policy = g_policy.get();
    const auto evaluation = policy == nullptr
                                ? PolicyEvaluation{}
                                : policy->Evaluate(final_path.c_str(), request.access);
    if (evaluation.decision == Decision::kDeny) {
        ReportDenied(
            request.operation, EvaluatedPath(evaluation, final_path.c_str()));
        return false;
    }
    const HandleAccess cached_access =
        request.access == Access::kRead ? HandleAccess::kRead
        : request.access == Access::kWrite ? HandleAccess::kWrite
                                          : HandleAccess::kMetadata;
    static_cast<void>(g_handle_access_cache.Store(file, cached_access));
    if (cached_access != HandleAccess::kMetadata) {
        static_cast<void>(
            g_handle_access_cache.Store(file, HandleAccess::kMetadata));
    }
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
    if (IsNetworkDevicePath(path) || IsKernelSecurityDevicePath(path)) {
        return true;
    }
    const auto* policy = g_policy.get();
    const auto text_evaluation =
        policy == nullptr ? PolicyEvaluation{} : policy->Evaluate(path, request.access);
    if (text_evaluation.decision == Decision::kDeny) {
        ReportDenied(request.operation, EvaluatedPath(text_evaluation, path));
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }
    if (!RequiresPreOpenFinalResolution(request, flags_and_attributes)) {
        return true;
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
    const Win32LastErrorGuard last_error_guard;
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_nt_create_file(
            file, desired_access, object_attributes, io_status, allocation_size,
            file_attributes, share_access, create_disposition, create_options,
            ea_buffer, ea_length);
    }
    auto request = ClassifyCreateFileRequest(
        desired_access, MapNtCreateDisposition(create_disposition));
    if ((create_options & FILE_DELETE_ON_CLOSE) != 0) {
        request = {Access::kWrite, protocol::FilesystemOperation::kDelete};
    }
    const bool exact_device_open =
        IsAuthorizedExactDeviceOpen(object_attributes, request);
    if (!AuthorizeNativeFileOpen(
            desired_access, object_attributes, create_disposition,
            create_options)) {
        return DenyNativeFileOpen(file, io_status);
    }
    const NTSTATUS result = g_nt_create_file(
        file, desired_access, object_attributes, io_status, allocation_size,
        file_attributes, share_access, create_disposition, create_options,
        ea_buffer, ea_length);
    if (result >= 0 && file != nullptr && *file != nullptr) {
        const bool authorized = exact_device_open
            ? CacheExactDeviceHandle(*file, request)
            : AuthorizeOpenedFileHandle(*file, request);
        if (!authorized) {
            CloseHandle(*file);
            return DenyNativeFileOpen(file, io_status);
        }
    }
    return result;
}

NTSTATUS NTAPI DetouredNtOpenFile(
    const PHANDLE file,
    const ACCESS_MASK desired_access,
    const POBJECT_ATTRIBUTES object_attributes,
    const PIO_STATUS_BLOCK io_status,
    const ULONG share_access,
    const ULONG open_options) noexcept {
    const Win32LastErrorGuard last_error_guard;
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_nt_open_file(
            file, desired_access, object_attributes, io_status, share_access,
            open_options);
    }
    const bool pipe_filesystem_root = IsPrivatePipeFilesystemRootOpen(
        desired_access, object_attributes, share_access, open_options);
    const bool private_pipe_client = IsPrivatePipeClientOpen(
        desired_access, object_attributes, share_access, open_options);
    if (pipe_filesystem_root || private_pipe_client) {
        const NTSTATUS result = g_nt_open_file(
            file, desired_access, object_attributes, io_status, share_access,
            open_options);
        if (result < 0) {
            return result;
        }
        HANDLE opened = nullptr;
        if (!ReadCreatedHandle(file, opened)) {
            return FailPrivatePipeCapability(
                nullptr, file, io_status);
        }
        const auto capability =
            pipe_filesystem_root
                ? PrivatePipeCapability::kFilesystemRoot
                : PrivatePipeCapability::kClient;
        if (!TrackPrivatePipeCapability(
                opened, capability,
                pipe_filesystem_root ? 0 : desired_access) ||
            (!pipe_filesystem_root &&
             !CachePrivatePipeAccess(opened, desired_access))) {
            UntrackPrivatePipeCapability(opened);
            return FailPrivatePipeCapability(
                opened, file, io_status);
        }
        return result;
    }
    HANDLE pipe_root_directory = nullptr;
    if (ReadObjectRootDirectory(
            object_attributes, pipe_root_directory) &&
        pipe_root_directory != nullptr &&
        (HasPrivatePipeCapability(
             pipe_root_directory,
             PrivatePipeCapability::kFilesystemRoot) ||
         HasPrivatePipeCapability(
             pipe_root_directory,
             PrivatePipeCapability::kServer))) {
        ReportDenied(
            protocol::FilesystemOperation::kRead,
            L"<private-anonymous-pipe>");
        return DenyNativeFileOpen(file, io_status);
    }
    if (!AuthorizeNativeFileOpen(
            desired_access, object_attributes, FILE_OPEN, open_options)) {
        return DenyNativeFileOpen(file, io_status);
    }
    const NTSTATUS result = g_nt_open_file(
        file, desired_access, object_attributes, io_status, share_access,
        open_options);
    if (result >= 0 && file != nullptr && *file != nullptr) {
        auto request = ClassifyCreateFileRequest(desired_access, OPEN_EXISTING);
        if ((open_options & FILE_DELETE_ON_CLOSE) != 0) {
            request = {Access::kWrite, protocol::FilesystemOperation::kDelete};
        }
        if (!AuthorizeOpenedFileHandle(*file, request)) {
            CloseHandle(*file);
            return DenyNativeFileOpen(file, io_status);
        }
    }
    return result;
}

NTSTATUS NTAPI DetouredNtCreateNamedPipeFile(
    const PHANDLE file,
    const ACCESS_MASK desired_access,
    const POBJECT_ATTRIBUTES object_attributes,
    const PIO_STATUS_BLOCK io_status,
    const ULONG share_access,
    const ULONG create_disposition,
    const ULONG create_options,
    const ULONG pipe_type,
    const ULONG read_mode,
    const ULONG completion_mode,
    const ULONG maximum_instances,
    const ULONG inbound_quota,
    const ULONG outbound_quota,
    const PLARGE_INTEGER default_timeout) noexcept {
    const Win32LastErrorGuard last_error_guard;
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_nt_create_named_pipe_file(
            file, desired_access, object_attributes, io_status, share_access,
            create_disposition, create_options, pipe_type, read_mode,
            completion_mode, maximum_instances, inbound_quota, outbound_quota,
            default_timeout);
    }
    if (!IsPrivateAnonymousPipeCreation(
            desired_access, object_attributes, share_access,
            create_disposition, create_options, pipe_type, read_mode,
            completion_mode, maximum_instances, inbound_quota,
            outbound_quota)) {
        ReportDenied(
            protocol::FilesystemOperation::kCreate,
            L"<private-anonymous-pipe>");
        return DenyNativeFileOpen(file, io_status);
    }
    const NTSTATUS result = g_nt_create_named_pipe_file(
        file, desired_access, object_attributes, io_status, share_access,
        create_disposition, create_options, pipe_type, read_mode,
        completion_mode, maximum_instances, inbound_quota, outbound_quota,
        default_timeout);
    if (result < 0) {
        return result;
    }
    HANDLE opened = nullptr;
    if (!ReadCreatedHandle(file, opened)) {
        return FailPrivatePipeCapability(nullptr, file, io_status);
    }
    if (!TrackPrivatePipeCapability(
            opened, PrivatePipeCapability::kServer, desired_access) ||
        !CachePrivatePipeAccess(opened, desired_access)) {
        UntrackPrivatePipeCapability(opened);
        return FailPrivatePipeCapability(opened, file, io_status);
    }
    return result;
}

NTSTATUS NTAPI DetouredNtCreateMailslotFile(
    const PHANDLE file,
    const ACCESS_MASK desired_access,
    const POBJECT_ATTRIBUTES object_attributes,
    const PIO_STATUS_BLOCK io_status,
    const ULONG create_options,
    const ULONG mailslot_quota,
    const ULONG maximum_message_size,
    const PLARGE_INTEGER read_timeout) noexcept {
    const Win32LastErrorGuard last_error_guard;
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_nt_create_mailslot_file(
            file, desired_access, object_attributes, io_status,
            create_options, mailslot_quota, maximum_message_size,
            read_timeout);
    }
    ReportDenied(
        protocol::FilesystemOperation::kCreate, L"<mailslot>");
    return DenyNativeFileOpen(file, io_status);
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

bool RequestsReplacement(
    const PVOID information,
    const ULONG information_size,
    const bool extended) noexcept {
    const std::size_t header_size = extended
                                        ? offsetof(NtFileTargetInformationEx, file_name)
                                        : offsetof(NtFileTargetInformation, file_name);
    if (information == nullptr || information_size < header_size) {
        return false;
    }
    if (extended) {
        return (static_cast<const NtFileTargetInformationEx*>(information)
                    ->flags &
                FILE_RENAME_FLAG_REPLACE_IF_EXISTS) != 0;
    }
    return static_cast<const NtFileTargetInformation*>(information)
               ->replace_if_exists != FALSE;
}

bool ShellItemPath(IShellItem* const item, std::wstring& path) noexcept {
    path.clear();
    if (item == nullptr) {
        return false;
    }
    PWSTR raw_path = nullptr;
    const HRESULT status = item->GetDisplayName(SIGDN_FILESYSPATH, &raw_path);
    if (FAILED(status) || raw_path == nullptr) {
        CoTaskMemFree(raw_path);
        return false;
    }
    try {
        path.assign(raw_path);
    } catch (...) {
        CoTaskMemFree(raw_path);
        return false;
    }
    CoTaskMemFree(raw_path);
    return !path.empty();
}

bool ShellDestinationPath(
    IShellItem* const source,
    IShellItem* const destination_folder,
    const wchar_t* const requested_name,
    std::wstring& source_path,
    std::wstring& destination_path) noexcept {
    std::wstring folder_path;
    if (!ShellItemPath(source, source_path) ||
        !ShellItemPath(destination_folder, folder_path)) {
        return false;
    }
    try {
        std::filesystem::path destination(folder_path);
        destination /= requested_name != nullptr && *requested_name != L'\0'
                           ? requested_name
                           : std::filesystem::path(source_path).filename();
        destination_path = destination.wstring();
    } catch (...) {
        return false;
    }
    return !destination_path.empty();
}

bool AuthorizeIFileOperationCopy(
    IShellItem* const source,
    IShellItem* const destination_folder,
    const wchar_t* const requested_name) noexcept {
    DetouredScope scope;
    std::wstring source_path;
    std::wstring destination_path;
    return ShellDestinationPath(
               source, destination_folder, requested_name, source_path,
               destination_path) &&
           AuthorizeCopy(source_path.c_str(), destination_path.c_str());
}

bool AuthorizeIFileOperationMove(
    IShellItem* const source,
    IShellItem* const destination_folder,
    const wchar_t* const requested_name) noexcept {
    DetouredScope scope;
    std::wstring source_path;
    std::wstring destination_path;
    return ShellDestinationPath(
               source, destination_folder, requested_name, source_path,
               destination_path) &&
           AuthorizeMove(source_path.c_str(), destination_path.c_str());
}

bool AuthorizeIFileOperationRename(
    IShellItem* const item,
    const wchar_t* const requested_name) noexcept {
    DetouredScope scope;
    std::wstring source_path;
    if (requested_name == nullptr || *requested_name == L'\0' ||
        !ShellItemPath(item, source_path)) {
        return false;
    }
    try {
        const std::wstring destination_path =
            (std::filesystem::path(source_path).parent_path() / requested_name)
                .wstring();
        return AuthorizeMove(source_path.c_str(), destination_path.c_str());
    } catch (...) {
        return false;
    }
}

bool AuthorizeIFileOperationDelete(IShellItem* const item) noexcept {
    DetouredScope scope;
    std::wstring path;
    return ShellItemPath(item, path) && AuthorizeDeletion(path.c_str());
}

bool AuthorizeIFileOperationNew(
    IShellItem* const destination_folder,
    const wchar_t* const requested_name) noexcept {
    DetouredScope scope;
    std::wstring folder_path;
    if (requested_name == nullptr || *requested_name == L'\0' ||
        !ShellItemPath(destination_folder, folder_path) || g_policy == nullptr) {
        return false;
    }
    try {
        const std::wstring path =
            (std::filesystem::path(folder_path) / requested_name).wstring();
        const auto evaluation = g_policy->Evaluate(path.c_str(), Access::kWrite);
        if (evaluation.decision == Decision::kDeny) {
            ReportDenied(
                protocol::FilesystemOperation::kCreate,
                EvaluatedPath(evaluation, path.c_str()));
            SetLastError(ERROR_ACCESS_DENIED);
            return false;
        }
        return true;
    } catch (...) {
        return false;
    }
}

HRESULT DeniedFileOperation() noexcept {
    SetLastError(ERROR_ACCESS_DENIED);
    return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
}

class SandboxedFileOperation final : public IFileOperation {
  public:
    explicit SandboxedFileOperation(IFileOperation* const inner) noexcept
        : inner_(inner) {}

    SandboxedFileOperation(const SandboxedFileOperation&) = delete;
    SandboxedFileOperation& operator=(const SandboxedFileOperation&) = delete;
    SandboxedFileOperation(SandboxedFileOperation&&) = delete;
    SandboxedFileOperation& operator=(SandboxedFileOperation&&) = delete;

    HRESULT STDMETHODCALLTYPE QueryInterface(
        const IID& interface_id,
        void** const output) override {
        if (output == nullptr) {
            return E_POINTER;
        }
        *output = nullptr;
        if (IsEqualIID(interface_id, IID_IUnknown) ||
            IsEqualIID(interface_id, IID_IFileOperation)) {
            *output = static_cast<IFileOperation*>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override {
        return references_.fetch_add(1, std::memory_order_relaxed) + 1;
    }

    ULONG STDMETHODCALLTYPE Release() override {
        const ULONG remaining =
            references_.fetch_sub(1, std::memory_order_acq_rel) - 1;
        if (remaining == 0) {
            delete this;
        }
        return remaining;
    }

    HRESULT STDMETHODCALLTYPE Advise(
        IFileOperationProgressSink* const sink,
        DWORD* const cookie) override {
        return inner_->Advise(sink, cookie);
    }
    HRESULT STDMETHODCALLTYPE Unadvise(const DWORD cookie) override {
        return inner_->Unadvise(cookie);
    }
    HRESULT STDMETHODCALLTYPE SetOperationFlags(const DWORD flags) override {
        return inner_->SetOperationFlags(flags);
    }
    HRESULT STDMETHODCALLTYPE SetProgressMessage(const LPCWSTR message) override {
        return inner_->SetProgressMessage(message);
    }
    HRESULT STDMETHODCALLTYPE SetProgressDialog(
        IOperationsProgressDialog* const dialog) override {
        return inner_->SetProgressDialog(dialog);
    }
    HRESULT STDMETHODCALLTYPE SetProperties(
        IPropertyChangeArray* const properties) override {
        return inner_->SetProperties(properties);
    }
    HRESULT STDMETHODCALLTYPE SetOwnerWindow(const HWND owner) override {
        return inner_->SetOwnerWindow(owner);
    }
    HRESULT STDMETHODCALLTYPE ApplyPropertiesToItem(IShellItem* const item) override {
        return inner_->ApplyPropertiesToItem(item);
    }
    HRESULT STDMETHODCALLTYPE ApplyPropertiesToItems(IUnknown* const items) override {
        return inner_->ApplyPropertiesToItems(items);
    }

    HRESULT STDMETHODCALLTYPE RenameItem(
        IShellItem* const item,
        const LPCWSTR new_name,
        IFileOperationProgressSink* const sink) override {
        return AuthorizeIFileOperationRename(item, new_name)
                   ? inner_->RenameItem(item, new_name, sink)
                   : DeniedFileOperation();
    }
    HRESULT STDMETHODCALLTYPE RenameItems(
        IUnknown* const items,
        const LPCWSTR new_name) override {
        static_cast<void>(items);
        static_cast<void>(new_name);
        return DeniedFileOperation();
    }
    HRESULT STDMETHODCALLTYPE MoveItem(
        IShellItem* const item,
        IShellItem* const destination_folder,
        const LPCWSTR new_name,
        IFileOperationProgressSink* const sink) override {
        return AuthorizeIFileOperationMove(item, destination_folder, new_name)
                   ? inner_->MoveItem(item, destination_folder, new_name, sink)
                   : DeniedFileOperation();
    }
    HRESULT STDMETHODCALLTYPE MoveItems(
        IUnknown* const items,
        IShellItem* const destination_folder) override {
        static_cast<void>(items);
        static_cast<void>(destination_folder);
        return DeniedFileOperation();
    }
    HRESULT STDMETHODCALLTYPE CopyItem(
        IShellItem* const item,
        IShellItem* const destination_folder,
        const LPCWSTR copy_name,
        IFileOperationProgressSink* const sink) override {
        return AuthorizeIFileOperationCopy(item, destination_folder, copy_name)
                   ? inner_->CopyItem(item, destination_folder, copy_name, sink)
                   : DeniedFileOperation();
    }
    HRESULT STDMETHODCALLTYPE CopyItems(
        IUnknown* const items,
        IShellItem* const destination_folder) override {
        static_cast<void>(items);
        static_cast<void>(destination_folder);
        return DeniedFileOperation();
    }
    HRESULT STDMETHODCALLTYPE DeleteItem(
        IShellItem* const item,
        IFileOperationProgressSink* const sink) override {
        return AuthorizeIFileOperationDelete(item)
                   ? inner_->DeleteItem(item, sink)
                   : DeniedFileOperation();
    }
    HRESULT STDMETHODCALLTYPE DeleteItems(IUnknown* const items) override {
        static_cast<void>(items);
        return DeniedFileOperation();
    }
    HRESULT STDMETHODCALLTYPE NewItem(
        IShellItem* const destination_folder,
        const DWORD file_attributes,
        const LPCWSTR name,
        const LPCWSTR template_name,
        IFileOperationProgressSink* const sink) override {
        return AuthorizeIFileOperationNew(destination_folder, name)
                   ? inner_->NewItem(
                         destination_folder, file_attributes, name, template_name,
                         sink)
                   : DeniedFileOperation();
    }
    HRESULT STDMETHODCALLTYPE PerformOperations() override {
        return inner_->PerformOperations();
    }
    HRESULT STDMETHODCALLTYPE GetAnyOperationsAborted(BOOL* const aborted) override {
        return inner_->GetAnyOperationsAborted(aborted);
    }

  private:
    ~SandboxedFileOperation() noexcept {
        inner_->Release();
    }

    std::atomic<ULONG> references_{1};
    IFileOperation* const inner_;
};

HRESULT WINAPI DetouredCoCreateInstance(
    REFCLSID class_id,
    IUnknown* const outer,
    const DWORD context,
    REFIID interface_id,
    void** const output) noexcept {
    if ((context & (CLSCTX_LOCAL_SERVER | CLSCTX_REMOTE_SERVER)) != 0) {
        hook::TryReportProcessViolation(
            protocol::ProcessOperation::kExternalDelegation);
        if (output != nullptr) {
            *output = nullptr;
        }
        return E_ACCESSDENIED;
    }
    const HRESULT status =
        g_co_create_instance(class_id, outer, context, interface_id, output);
    if (FAILED(status) || output == nullptr || *output == nullptr ||
        !IsEqualCLSID(class_id, CLSID_FileOperation)) {
        return status;
    }
    if (outer != nullptr ||
        (!IsEqualIID(interface_id, IID_IFileOperation) &&
         !IsEqualIID(interface_id, IID_IUnknown))) {
        static_cast<IUnknown*>(*output)->Release();
        *output = nullptr;
        return E_NOINTERFACE;
    }

    IFileOperation* inner = nullptr;
    if (IsEqualIID(interface_id, IID_IFileOperation)) {
        inner = static_cast<IFileOperation*>(*output);
    } else {
        auto* const unknown = static_cast<IUnknown*>(*output);
        const HRESULT query_status = unknown->QueryInterface(
            IID_IFileOperation, reinterpret_cast<void**>(&inner));
        unknown->Release();
        if (FAILED(query_status) || inner == nullptr) {
            *output = nullptr;
            return FAILED(query_status) ? query_status : E_NOINTERFACE;
        }
    }
    auto* const wrapped = new (std::nothrow) SandboxedFileOperation(inner);
    if (wrapped == nullptr) {
        inner->Release();
        *output = nullptr;
        return E_OUTOFMEMORY;
    }
    *output = static_cast<IFileOperation*>(wrapped);
    return S_OK;
}

HRESULT WINAPI DetouredCoCreateInstanceEx(
    REFCLSID class_id,
    IUnknown* const outer,
    const DWORD context,
    COSERVERINFO* const server,
    const DWORD query_count,
    MULTI_QI* const queries) noexcept {
    if ((context & (CLSCTX_LOCAL_SERVER | CLSCTX_REMOTE_SERVER)) != 0) {
        hook::TryReportProcessViolation(
            protocol::ProcessOperation::kExternalDelegation);
        if (queries != nullptr) {
            for (DWORD index = 0; index < query_count; ++index) {
                queries[index].pItf = nullptr;
                queries[index].hr = E_ACCESSDENIED;
            }
        }
        return E_ACCESSDENIED;
    }
    return g_co_create_instance_ex(
        class_id, outer, context, server, query_count, queries);
}

HRESULT WINAPI DetouredCoGetClassObject(
    REFCLSID class_id,
    const DWORD context,
    LPVOID reserved,
    REFIID interface_id,
    LPVOID* const output) noexcept {
    if ((context & (CLSCTX_LOCAL_SERVER | CLSCTX_REMOTE_SERVER)) != 0) {
        hook::TryReportProcessViolation(
            protocol::ProcessOperation::kExternalDelegation);
        if (output != nullptr) {
            *output = nullptr;
        }
        return E_ACCESSDENIED;
    }
    return g_co_get_class_object(
        class_id, context, reserved, interface_id, output);
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
    const Win32LastErrorGuard last_error_guard;
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
    const Win32LastErrorGuard last_error_guard;
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
    const Win32LastErrorGuard last_error_guard;
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
    const Win32LastErrorGuard last_error_guard;
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
    const Win32LastErrorGuard last_error_guard;
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
    const Win32LastErrorGuard last_error_guard;
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
    const Win32LastErrorGuard last_error_guard;
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
    const Win32LastErrorGuard last_error_guard;
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
    const Win32LastErrorGuard last_error_guard;
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

bool IsWorkspaceVolumeQuery(
    const wchar_t* const directory_name,
    std::wstring& authorized_path) noexcept {
    authorized_path.clear();
    try {
        std::array<wchar_t, 32'768> current{};
        std::array<wchar_t, 32'768> requested{};
        std::array<wchar_t, 32'768> current_volume{};
        std::array<wchar_t, 32'768> requested_volume{};
        const DWORD current_length = GetCurrentDirectoryW(
            static_cast<DWORD>(current.size()), current.data());
        if (current_length == 0 || current_length >= current.size()) {
            return false;
        }
        bool separators_only = directory_name != nullptr && directory_name[0] != L'\0';
        if (directory_name != nullptr) {
            for (const wchar_t* value = directory_name; *value != L'\0'; ++value) {
                if (*value != L'\\' && *value != L'/') {
                    separators_only = false;
                    break;
                }
            }
        }
        const wchar_t* const query =
            directory_name == nullptr || directory_name[0] == L'\0' || separators_only
                ? current.data()
                : directory_name;
        const DWORD requested_length = GetFullPathNameW(
            query, static_cast<DWORD>(requested.size()), requested.data(),
            nullptr);
        if (requested_length == 0 || requested_length >= requested.size() ||
            !GetVolumePathNameW(
                current.data(), current_volume.data(),
                static_cast<DWORD>(current_volume.size())) ||
            !GetVolumePathNameW(
                requested.data(), requested_volume.data(),
                static_cast<DWORD>(requested_volume.size()))) {
            return false;
        }
        if (CompareStringOrdinal(
                current_volume.data(), -1, requested_volume.data(), -1,
                TRUE) != CSTR_EQUAL) {
            return false;
        }
        authorized_path.assign(requested.data(), requested_length);
        return true;
    } catch (...) {
        authorized_path.clear();
        return false;
    }
}

BOOL WINAPI DetouredGetDiskFreeSpaceW(
    const LPCWSTR root_path_name,
    const LPDWORD sectors_per_cluster,
    const LPDWORD bytes_per_sector,
    const LPDWORD number_of_free_clusters,
    const LPDWORD total_number_of_clusters) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_get_disk_free_space_w(
            root_path_name, sectors_per_cluster, bytes_per_sector,
            number_of_free_clusters, total_number_of_clusters);
    }
    std::wstring authorized_path;
    if (!IsWorkspaceVolumeQuery(root_path_name, authorized_path)) {
        ReportDenied(
            protocol::FilesystemOperation::kMetadata,
            root_path_name == nullptr ? L"<current-volume>" : root_path_name);
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return g_get_disk_free_space_w(
        authorized_path.c_str(), sectors_per_cluster, bytes_per_sector,
        number_of_free_clusters, total_number_of_clusters);
}

BOOL WINAPI DetouredGetDiskFreeSpaceA(
    const LPCSTR root_path_name,
    const LPDWORD sectors_per_cluster,
    const LPDWORD bytes_per_sector,
    const LPDWORD number_of_free_clusters,
    const LPDWORD total_number_of_clusters) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_get_disk_free_space_a(
            root_path_name, sectors_per_cluster, bytes_per_sector,
            number_of_free_clusters, total_number_of_clusters);
    }
    std::wstring wide_path;
    const wchar_t* query = nullptr;
    if (root_path_name != nullptr) {
        if (!ConvertAnsiPath(root_path_name, wide_path)) {
            SetLastError(ERROR_INVALID_NAME);
            return FALSE;
        }
        query = wide_path.c_str();
    }
    std::wstring authorized_path;
    if (!IsWorkspaceVolumeQuery(query, authorized_path)) {
        ReportDenied(
            protocol::FilesystemOperation::kMetadata,
            query == nullptr ? L"<current-volume>" : query);
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return g_get_disk_free_space_w(
        authorized_path.c_str(), sectors_per_cluster, bytes_per_sector,
        number_of_free_clusters, total_number_of_clusters);
}

BOOL WINAPI DetouredGetDiskFreeSpaceExW(
    const LPCWSTR directory_name,
    const PULARGE_INTEGER free_bytes_available,
    const PULARGE_INTEGER total_number_of_bytes,
    const PULARGE_INTEGER total_number_of_free_bytes) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_get_disk_free_space_ex_w(
            directory_name, free_bytes_available, total_number_of_bytes,
            total_number_of_free_bytes);
    }
    std::wstring authorized_path;
    if (!IsWorkspaceVolumeQuery(directory_name, authorized_path)) {
        ReportDenied(
            protocol::FilesystemOperation::kMetadata,
            directory_name == nullptr ? L"<current-volume>" : directory_name);
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return g_get_disk_free_space_ex_w(
        authorized_path.c_str(), free_bytes_available, total_number_of_bytes,
        total_number_of_free_bytes);
}

BOOL WINAPI DetouredGetDiskFreeSpaceExA(
    const LPCSTR directory_name,
    const PULARGE_INTEGER free_bytes_available,
    const PULARGE_INTEGER total_number_of_bytes,
    const PULARGE_INTEGER total_number_of_free_bytes) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_get_disk_free_space_ex_a(
            directory_name, free_bytes_available, total_number_of_bytes,
            total_number_of_free_bytes);
    }
    std::wstring wide_path;
    const wchar_t* query = nullptr;
    if (directory_name != nullptr) {
        if (!ConvertAnsiPath(directory_name, wide_path)) {
            SetLastError(ERROR_INVALID_NAME);
            return FALSE;
        }
        query = wide_path.c_str();
    }
    std::wstring authorized_path;
    if (!IsWorkspaceVolumeQuery(query, authorized_path)) {
        ReportDenied(
            protocol::FilesystemOperation::kMetadata,
            query == nullptr ? L"<current-volume>" : query);
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return g_get_disk_free_space_ex_w(
        authorized_path.c_str(), free_bytes_available, total_number_of_bytes,
        total_number_of_free_bytes);
}

BOOL WINAPI DetouredCreatePipe(
    const PHANDLE read_pipe,
    const PHANDLE write_pipe,
    const LPSECURITY_ATTRIBUTES pipe_attributes,
    const DWORD size) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_create_pipe(read_pipe, write_pipe, pipe_attributes, size);
    }
    if (read_pipe == nullptr || write_pipe == nullptr) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    *read_pipe = nullptr;
    *write_pipe = nullptr;
    if (!g_create_pipe(read_pipe, write_pipe, pipe_attributes, size)) {
        return FALSE;
    }
    if (!CachePrivatePipeAccess(*read_pipe, GENERIC_READ) ||
        !CachePrivatePipeAccess(*write_pipe, GENERIC_WRITE)) {
        CloseHandle(*read_pipe);
        CloseHandle(*write_pipe);
        *read_pipe = nullptr;
        *write_pipe = nullptr;
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    return TRUE;
}

HANDLE WINAPI DetouredCreateNamedPipeW(
    const LPCWSTR name,
    const DWORD open_mode,
    const DWORD pipe_mode,
    const DWORD maximum_instances,
    const DWORD output_buffer_size,
    const DWORD input_buffer_size,
    const DWORD default_timeout,
    const LPSECURITY_ATTRIBUTES security_attributes) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_create_named_pipe_w(
            name, open_mode, pipe_mode, maximum_instances, output_buffer_size,
            input_buffer_size, default_timeout, security_attributes);
    }
    std::wstring isolated_pipe;
    if (!process::RewriteIsolatedNamedPipePath(name, isolated_pipe)) {
        ReportDenied(protocol::FilesystemOperation::kCreate, name);
        SetLastError(ERROR_ACCESS_DENIED);
        return INVALID_HANDLE_VALUE;
    }
    const HANDLE opened = g_create_named_pipe_w(
        isolated_pipe.c_str(), open_mode, pipe_mode, maximum_instances,
        output_buffer_size, input_buffer_size, default_timeout,
        security_attributes);
    ACCESS_MASK access = 0;
    switch (open_mode & 0x3U) {
        case PIPE_ACCESS_INBOUND:
            access = GENERIC_READ;
            break;
        case PIPE_ACCESS_OUTBOUND:
            access = GENERIC_WRITE;
            break;
        case PIPE_ACCESS_DUPLEX:
            access = GENERIC_READ | GENERIC_WRITE;
            break;
        default:
            break;
    }
    if (opened != INVALID_HANDLE_VALUE &&
        (access == 0 || !CachePrivatePipeAccess(opened, access))) {
        CloseHandle(opened);
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return INVALID_HANDLE_VALUE;
    }
    return opened;
}

HANDLE WINAPI DetouredCreateNamedPipeA(
    const LPCSTR name,
    const DWORD open_mode,
    const DWORD pipe_mode,
    const DWORD maximum_instances,
    const DWORD output_buffer_size,
    const DWORD input_buffer_size,
    const DWORD default_timeout,
    const LPSECURITY_ATTRIBUTES security_attributes) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_create_named_pipe_a(
            name, open_mode, pipe_mode, maximum_instances, output_buffer_size,
            input_buffer_size, default_timeout, security_attributes);
    }
    std::wstring wide_name;
    std::wstring isolated_pipe;
    if (!ConvertAnsiPath(name, wide_name) ||
        !process::RewriteIsolatedNamedPipePath(
            wide_name.c_str(), isolated_pipe)) {
        ReportDenied(
            protocol::FilesystemOperation::kCreate,
            wide_name.empty() ? L"<invalid-named-pipe>" : wide_name.c_str());
        SetLastError(ERROR_ACCESS_DENIED);
        return INVALID_HANDLE_VALUE;
    }
    const HANDLE opened = g_create_named_pipe_w(
        isolated_pipe.c_str(), open_mode, pipe_mode, maximum_instances,
        output_buffer_size, input_buffer_size, default_timeout,
        security_attributes);
    ACCESS_MASK access = 0;
    switch (open_mode & 0x3U) {
        case PIPE_ACCESS_INBOUND:
            access = GENERIC_READ;
            break;
        case PIPE_ACCESS_OUTBOUND:
            access = GENERIC_WRITE;
            break;
        case PIPE_ACCESS_DUPLEX:
            access = GENERIC_READ | GENERIC_WRITE;
            break;
        default:
            break;
    }
    if (opened != INVALID_HANDLE_VALUE &&
        (access == 0 || !CachePrivatePipeAccess(opened, access))) {
        CloseHandle(opened);
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return INVALID_HANDLE_VALUE;
    }
    return opened;
}

HANDLE WINAPI DetouredCreateMailslotW(
    const LPCWSTR name,
    const DWORD maximum_message_size,
    const DWORD read_timeout,
    const LPSECURITY_ATTRIBUTES security_attributes) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_create_mailslot_w(
            name, maximum_message_size, read_timeout, security_attributes);
    }
    ReportDenied(protocol::FilesystemOperation::kCreate, name);
    SetLastError(ERROR_ACCESS_DENIED);
    return INVALID_HANDLE_VALUE;
}

HANDLE WINAPI DetouredCreateMailslotA(
    const LPCSTR name,
    const DWORD maximum_message_size,
    const DWORD read_timeout,
    const LPSECURITY_ATTRIBUTES security_attributes) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_create_mailslot_a(
            name, maximum_message_size, read_timeout, security_attributes);
    }
    std::wstring wide_name;
    if (!ConvertAnsiPath(name, wide_name)) {
        wide_name = L"<invalid-mailslot>";
    }
    ReportDenied(protocol::FilesystemOperation::kCreate, wide_name.c_str());
    SetLastError(ERROR_ACCESS_DENIED);
    return INVALID_HANDLE_VALUE;
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
    std::wstring isolated_pipe;
    if (process::RewriteIsolatedNamedPipePath(filename, isolated_pipe)) {
        const HANDLE opened = g_create_file_w(
            isolated_pipe.c_str(), desired_access, share_mode,
            security_attributes, creation_disposition, flags_and_attributes,
            template_file);
        if (opened != INVALID_HANDLE_VALUE &&
            !CachePrivatePipeAccess(opened, desired_access)) {
            CloseHandle(opened);
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return INVALID_HANDLE_VALUE;
        }
        return opened;
    }
    if (IsConsoleDevicePath(filename)) {
        if (process::AllowsIsolatedConsole()) {
            return g_create_file_w(
                filename, desired_access, share_mode, security_attributes,
                creation_disposition, flags_and_attributes, template_file);
        }
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
    const auto request = ClassifyCreateFileRequestWithFlags(
        desired_access, creation_disposition, flags_and_attributes);
    const bool exact_device_open =
        IsAuthorizedExactDevicePath(filename, request);
    if (!AuthorizeCreateFile(filename, request, flags_and_attributes)) {
        return INVALID_HANDLE_VALUE;
    }
    std::wstring extended_filename;
    const wchar_t* native_filename = nullptr;
    if (!NativeCreateFilePath(filename, extended_filename, native_filename)) {
        return INVALID_HANDLE_VALUE;
    }
    const HANDLE opened = g_create_file_w(
        native_filename, desired_access, share_mode, security_attributes, creation_disposition,
        flags_and_attributes, template_file);
    if (opened == INVALID_HANDLE_VALUE) {
        return opened;
    }
    const DWORD native_error = GetLastError();
    if (!(exact_device_open ? CacheExactDeviceHandle(opened, request)
                            : AuthorizeOpenedFileHandle(opened, request))) {
        CloseHandle(opened);
        SetLastError(ERROR_ACCESS_DENIED);
        return INVALID_HANDLE_VALUE;
    }
    SetLastError(native_error);
    return opened;
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
    const auto request = ClassifyCreateFileRequestWithFlags(
        desired_access, creation_disposition, flags_and_attributes);
    if (!ConvertAnsiPath(filename, filename_wide)) {
        return INVALID_HANDLE_VALUE;
    }
    const bool exact_device_open =
        IsAuthorizedExactDevicePath(filename_wide.c_str(), request);
    std::wstring isolated_pipe;
    if (process::RewriteIsolatedNamedPipePath(
            filename_wide.c_str(), isolated_pipe)) {
        const HANDLE opened = g_create_file_w(
            isolated_pipe.c_str(), desired_access, share_mode,
            security_attributes, creation_disposition, flags_and_attributes,
            template_file);
        if (opened != INVALID_HANDLE_VALUE &&
            !CachePrivatePipeAccess(opened, desired_access)) {
            CloseHandle(opened);
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return INVALID_HANDLE_VALUE;
        }
        return opened;
    }
    if (IsConsoleDevicePath(filename_wide.c_str())) {
        if (process::AllowsIsolatedConsole()) {
            return g_create_file_a(
                filename, desired_access, share_mode, security_attributes,
                creation_disposition, flags_and_attributes, template_file);
        }
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
    if (
        !AuthorizeCreateFile(
            filename_wide.c_str(), request, flags_and_attributes)) {
        return INVALID_HANDLE_VALUE;
    }
    std::wstring extended_filename;
    const wchar_t* native_filename = nullptr;
    if (!NativeCreateFilePath(
            filename_wide.c_str(), extended_filename, native_filename)) {
        return INVALID_HANDLE_VALUE;
    }
    const HANDLE opened = g_create_file_w(
        native_filename, desired_access, share_mode, security_attributes,
        creation_disposition, flags_and_attributes, template_file);
    if (opened == INVALID_HANDLE_VALUE) {
        return opened;
    }
    const DWORD native_error = GetLastError();
    if (!(exact_device_open ? CacheExactDeviceHandle(opened, request)
                            : AuthorizeOpenedFileHandle(opened, request))) {
        CloseHandle(opened);
        SetLastError(ERROR_ACCESS_DENIED);
        return INVALID_HANDLE_VALUE;
    }
    SetLastError(native_error);
    return opened;
}

// BuildXL classifies DeleteFileW as a write and preserves the last reparse
// point because the API deletes a link itself rather than its target.
BOOL WINAPI DetouredDeleteFileW(const LPCWSTR filename) noexcept {
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_delete_file_w(filename);
    }
    if (!AuthorizeDeletion(filename)) {
        return FALSE;
    }
    recovery::BackupPath(filename, protocol::RecoveryOperation::kDelete);
    return g_delete_file_w(filename);
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
    recovery::BackupPath(
        filename_wide.c_str(), protocol::RecoveryOperation::kDelete);
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
    if (!AuthorizeMove(existing_path, new_path)) {
        return FALSE;
    }
    if ((flags & MOVEFILE_REPLACE_EXISTING) != 0) {
        recovery::BackupPath(
            new_path, protocol::RecoveryOperation::kRename);
    }
    return g_move_file_ex_w(existing_path, new_path, flags);
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
    if ((flags & MOVEFILE_REPLACE_EXISTING) != 0) {
        recovery::BackupPath(
            new_wide.c_str(), protocol::RecoveryOperation::kRename);
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
    if (!AuthorizeMove(existing_path, new_path)) {
        return FALSE;
    }
    if ((flags & MOVEFILE_REPLACE_EXISTING) != 0) {
        recovery::BackupPath(
            new_path, protocol::RecoveryOperation::kRename);
    }
    return g_move_file_with_progress_w(
        existing_path, new_path, progress_routine, data, flags);
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
    if ((flags & MOVEFILE_REPLACE_EXISTING) != 0) {
        recovery::BackupPath(
            new_wide.c_str(), protocol::RecoveryOperation::kRename);
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
    if (!AuthorizeReplace(replaced_path, replacement_path, backup_path)) {
        return FALSE;
    }
    recovery::BackupPath(
        replaced_path, protocol::RecoveryOperation::kReplace);
    return g_replace_file_w(
        replaced_path, replacement_path, backup_path, flags, exclude,
        reserved);
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
    recovery::BackupPath(
        replaced_wide.c_str(), protocol::RecoveryOperation::kReplace);
    return g_replace_file_w(
        replaced_wide.c_str(), replacement_wide.c_str(),
        backup_path == nullptr ? nullptr : backup_wide.c_str(), flags, exclude, reserved);
}

BOOL WINAPI DetouredSetFileInformationByHandle(
    const HANDLE file,
    const FILE_INFO_BY_HANDLE_CLASS information_class,
    const LPVOID information,
    const DWORD information_size) noexcept {
    const bool is_rename = information_class == FileRenameInfo ||
                           information_class == FileRenameInfoEx;
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
        recovery::BackupPath(
            source_path.c_str(), protocol::RecoveryOperation::kDelete);
        return g_set_file_information_by_handle(
            file, information_class, information, information_size);
    }

    std::wstring source_path;
    std::wstring destination_path;
    const bool extended = information_class == FileRenameInfoEx;
    if (!TryGetHandlePath(file, source_path) ||
        !TryGetFileInformationDestination(
            information, information_size, extended, destination_path)) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    if (!AuthorizeMove(source_path.c_str(), destination_path.c_str())) {
        return FALSE;
    }
    if (RequestsReplacement(
            information, information_size, extended)) {
        recovery::BackupPath(
            destination_path.c_str(),
            protocol::RecoveryOperation::kRename);
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
    recovery::BackupPath(
        source_path.c_str(), protocol::RecoveryOperation::kTruncate);
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
    const HANDLE mapping = g_create_file_mapping_w(
        file, security_attributes, protection, maximum_size_high,
        maximum_size_low, name);
    if (mapping != nullptr) {
        if (file == nullptr || file == INVALID_HANDLE_VALUE) {
            if (!TrackSectionCapability(
                    mapping, SectionCapability::kAnonymous)) {
                CloseHandle(mapping);
                SetLastError(ERROR_NOT_ENOUGH_MEMORY);
                return nullptr;
            }
        } else {
            if (!TrackSectionCapability(
                    mapping, SectionCapability::kAuthorizedFile)) {
                CloseHandle(mapping);
                SetLastError(ERROR_NOT_ENOUGH_MEMORY);
                return nullptr;
            }
        }
    }
    return mapping;
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
    const HANDLE mapping = g_create_file_mapping_a(
        file, security_attributes, protection, maximum_size_high,
        maximum_size_low, name);
    if (mapping != nullptr) {
        if (file == nullptr || file == INVALID_HANDLE_VALUE) {
            if (!TrackSectionCapability(
                    mapping, SectionCapability::kAnonymous)) {
                CloseHandle(mapping);
                SetLastError(ERROR_NOT_ENOUGH_MEMORY);
                return nullptr;
            }
        } else {
            if (!TrackSectionCapability(
                    mapping, SectionCapability::kAuthorizedFile)) {
                CloseHandle(mapping);
                SetLastError(ERROR_NOT_ENOUGH_MEMORY);
                return nullptr;
            }
        }
    }
    return mapping;
}

NTSTATUS NTAPI DetouredNtCreateSection(
    const PHANDLE section,
    const ACCESS_MASK desired_access,
    const POBJECT_ATTRIBUTES object_attributes,
    const PLARGE_INTEGER maximum_size,
    const ULONG protection,
    const ULONG allocation_attributes,
    const HANDLE file) noexcept {
    const Win32LastErrorGuard last_error_guard;
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_nt_create_section(
            section, desired_access, object_attributes, maximum_size, protection,
            allocation_attributes, file);
    }
    const bool anonymous = file == nullptr || file == INVALID_HANDLE_VALUE;
    if (!anonymous && !AuthorizeFileMapping(file, protection)) {
        if (section != nullptr) {
            *section = nullptr;
        }
        constexpr NTSTATUS status_access_denied = static_cast<NTSTATUS>(0xC0000022UL);
        return status_access_denied;
    }
    const NTSTATUS status = g_nt_create_section(
        section, desired_access, object_attributes, maximum_size, protection,
        allocation_attributes, file);
    if (status >= 0) {
        HANDLE created = nullptr;
        if (!ReadCreatedHandle(section, created)) {
            constexpr NTSTATUS status_invalid_handle =
                static_cast<NTSTATUS>(0xC0000008UL);
            return status_invalid_handle;
        }
        if (anonymous) {
            if (!TrackSectionCapability(
                    created, SectionCapability::kAnonymous)) {
                g_nt_close(created);
                ClearCreatedHandle(section);
                constexpr NTSTATUS status_insufficient_resources =
                    static_cast<NTSTATUS>(0xC000009AUL);
                return status_insufficient_resources;
            }
        } else {
            if (!TrackSectionCapability(
                    created, SectionCapability::kAuthorizedFile)) {
                g_nt_close(created);
                ClearCreatedHandle(section);
                constexpr NTSTATUS status_insufficient_resources =
                    static_cast<NTSTATUS>(0xC000009AUL);
                return status_insufficient_resources;
            }
        }
    }
    return status;
}

NTSTATUS NTAPI DetouredNtClose(const HANDLE handle) noexcept {
    UntrackSectionCapability(handle);
    UntrackPrivatePipeCapability(handle);
    g_handle_access_cache.Remove(handle);
    return g_nt_close(handle);
}

bool IsCurrentProcessHandle(const HANDLE process) noexcept {
    return process == GetCurrentProcess() ||
        (process != nullptr && process != INVALID_HANDLE_VALUE &&
         GetProcessId(process) == GetCurrentProcessId());
}

NTSTATUS NTAPI DetouredNtDuplicateObject(
    const HANDLE source_process,
    const HANDLE source_handle,
    const HANDLE target_process,
    const PHANDLE target_handle,
    const ACCESS_MASK desired_access,
    const ULONG handle_attributes,
    const ULONG options) noexcept {
    const Win32LastErrorGuard last_error_guard;
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_nt_duplicate_object(
            source_process, source_handle, target_process, target_handle,
            desired_access, handle_attributes, options);
    }
    PrivatePipeCapability capability = PrivatePipeCapability::kNone;
    ACCESS_MASK pipe_access = 0;
    const bool private_pipe_source =
        ReadPrivatePipeCapability(
            source_handle, capability, pipe_access) &&
        IsCurrentProcessHandle(source_process);
    if (private_pipe_source && !IsCurrentProcessHandle(target_process)) {
        ClearCreatedHandle(target_handle);
        constexpr NTSTATUS status_access_denied =
            static_cast<NTSTATUS>(0xC0000022UL);
        return status_access_denied;
    }
    const NTSTATUS status = g_nt_duplicate_object(
        source_process, source_handle, target_process, target_handle,
        desired_access, handle_attributes, options);
    if (status < 0 || !private_pipe_source) {
        return status;
    }
    if ((options & DUPLICATE_CLOSE_SOURCE) != 0) {
        UntrackPrivatePipeCapability(source_handle);
        g_handle_access_cache.Remove(source_handle);
    }
    HANDLE duplicated = nullptr;
    if (!ReadCreatedHandle(target_handle, duplicated)) {
        return status;
    }
    if (!TrackPrivatePipeCapability(
            duplicated, capability, pipe_access) ||
        (capability != PrivatePipeCapability::kFilesystemRoot &&
         !CachePrivatePipeAccess(duplicated, pipe_access))) {
        UntrackPrivatePipeCapability(duplicated);
        g_handle_access_cache.Remove(duplicated);
        g_nt_close(duplicated);
        ClearCreatedHandle(target_handle);
        constexpr NTSTATUS status_insufficient_resources =
            static_cast<NTSTATUS>(0xC000009AUL);
        return status_insufficient_resources;
    }
    return status;
}

NTSTATUS NTAPI DetouredNtMapViewOfSection(
    const HANDLE section,
    const HANDLE process,
    PVOID* const base_address,
    const ULONG_PTR zero_bits,
    const SIZE_T commit_size,
    const PLARGE_INTEGER section_offset,
    const PSIZE_T view_size,
    const ULONG inherit_disposition,
    const ULONG allocation_type,
    const ULONG protection) noexcept {
    const Win32LastErrorGuard last_error_guard;
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()) {
        return g_nt_map_view_of_section(
            section, process, base_address, zero_bits, commit_size, section_offset, view_size,
            inherit_disposition, allocation_type, protection);
    }
    if (!AuthorizeSectionMapping(section, protection)) {
        if (base_address != nullptr) {
            *base_address = nullptr;
        }
        if (view_size != nullptr) {
            *view_size = 0;
        }
        constexpr NTSTATUS status_access_denied = static_cast<NTSTATUS>(0xC0000022UL);
        return status_access_denied;
    }
    return g_nt_map_view_of_section(
        section, process, base_address, zero_bits, commit_size, section_offset, view_size,
        inherit_disposition, allocation_type, protection);
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
    const Win32LastErrorGuard last_error_guard;
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
    constexpr FILE_INFORMATION_CLASS file_short_name_information =
        static_cast<FILE_INFORMATION_CLASS>(40);
    constexpr FILE_INFORMATION_CLASS file_link_information =
        static_cast<FILE_INFORMATION_CLASS>(11);
    constexpr FILE_INFORMATION_CLASS file_link_information_ex =
        static_cast<FILE_INFORMATION_CLASS>(72);
    const bool is_truncation = information_class == file_allocation_information ||
                               information_class == file_end_of_file_information;
    const bool is_disposition = information_class == file_disposition_information ||
                                information_class == file_disposition_information_ex;
    const bool is_rename = information_class == file_rename_information ||
                           information_class == file_rename_information_ex;
    const bool is_basic = information_class == file_basic_information;
    const bool is_short_name = information_class == file_short_name_information;
    const bool is_link = information_class == file_link_information ||
                         information_class == file_link_information_ex;
    if (!is_truncation && !is_disposition && !is_rename && !is_basic &&
        !is_short_name && !is_link) {
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
    if (is_link) {
        const bool extended = information_class == file_link_information_ex;
        if (!AuthorizeHandleHardLink(
                file, information, information_size, extended)) {
            if (io_status != nullptr) {
                io_status->Status = status_access_denied;
                io_status->Information = 0;
            }
            return status_access_denied;
        }
        return g_zw_set_information_file(
            file, io_status, information, information_size, information_class);
    }
    if (is_rename) {
        std::wstring source_path;
        std::wstring destination_path;
        const bool extended = information_class == file_rename_information_ex;
        if (!TryGetHandlePath(file, source_path) ||
            !TryGetFileInformationDestination(
                information, information_size, extended, destination_path)) {
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
        if (RequestsReplacement(
                information, information_size, extended)) {
            recovery::BackupPath(
                destination_path.c_str(),
                protocol::RecoveryOperation::kRename);
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
    if (is_disposition) {
        recovery::BackupPath(
            source_path.c_str(), protocol::RecoveryOperation::kDelete);
    } else if (is_truncation) {
        recovery::BackupPath(
            source_path.c_str(), protocol::RecoveryOperation::kTruncate);
    }
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
    const std::size_t policy_length,
    const HANDLE trusted_stdout,
    const HANDLE trusted_stderr) noexcept {
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
    g_nt_map_view_of_section = reinterpret_cast<NtMapViewOfSectionFunction>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtMapViewOfSection"));
    g_nt_unmap_view_of_section = reinterpret_cast<NtUnmapViewOfSectionFunction>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtUnmapViewOfSection"));
    g_nt_query_section = reinterpret_cast<NtQuerySectionFunction>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySection"));
    g_nt_close = reinterpret_cast<NtCloseFunction>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtClose"));
    g_nt_duplicate_object = reinterpret_cast<NtDuplicateObjectFunction>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtDuplicateObject"));
    g_nt_compare_objects = reinterpret_cast<NtCompareObjectsFunction>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCompareObjects"));
    g_get_mapped_file_name_w = reinterpret_cast<GetMappedFileNameWFunction>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "K32GetMappedFileNameW"));
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
    g_nt_create_named_pipe_file =
        reinterpret_cast<NtCreateNamedPipeFileFunction>(GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), "NtCreateNamedPipeFile"));
    g_nt_create_mailslot_file =
        reinterpret_cast<NtCreateMailslotFileFunction>(GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), "NtCreateMailslotFile"));
    g_nt_notify_change_directory_file =
        reinterpret_cast<NtNotifyChangeDirectoryFileFunction>(GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), "NtNotifyChangeDirectoryFile"));
    g_nt_notify_change_directory_file_ex =
        reinterpret_cast<NtNotifyChangeDirectoryFileExFunction>(GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), "NtNotifyChangeDirectoryFileEx"));
    if (g_zw_set_information_file == nullptr || g_nt_create_section == nullptr ||
        g_nt_map_view_of_section == nullptr || g_nt_unmap_view_of_section == nullptr ||
        g_nt_query_section == nullptr || g_nt_close == nullptr ||
        g_nt_duplicate_object == nullptr ||
        g_nt_compare_objects == nullptr ||
        g_get_mapped_file_name_w == nullptr ||
        g_nt_query_information_file == nullptr || g_nt_query_attributes_file == nullptr ||
        g_nt_query_full_attributes_file == nullptr || g_nt_query_directory_file == nullptr ||
        g_nt_query_directory_file_ex == nullptr || g_nt_read_file == nullptr ||
        g_nt_write_file == nullptr || g_nt_create_file == nullptr ||
        g_nt_open_file == nullptr || g_nt_create_named_pipe_file == nullptr ||
        g_nt_create_mailslot_file == nullptr ||
        g_nt_notify_change_directory_file == nullptr ||
        g_nt_notify_change_directory_file_ex == nullptr) {
        return HookInstallStatus::kTransactionFailed;
    }
    const std::array<HANDLE, 5> standard_streams = {
        GetStdHandle(STD_INPUT_HANDLE), GetStdHandle(STD_OUTPUT_HANDLE),
        GetStdHandle(STD_ERROR_HANDLE), trusted_stdout, trusted_stderr};
    for (std::size_t index = 0; index < standard_streams.size(); ++index) {
        const HANDLE stream = standard_streams[index];
        if (stream == nullptr || stream == INVALID_HANDLE_VALUE ||
            GetFileType(stream) != FILE_TYPE_PIPE) {
            continue;
        }
        if (!DuplicateHandle(
                GetCurrentProcess(), stream, GetCurrentProcess(),
                &g_trusted_standard_streams[index], 0, FALSE,
                DUPLICATE_SAME_ACCESS)) {
            return HookInstallStatus::kTransactionFailed;
        }
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
            reinterpret_cast<PVOID*>(&g_nt_create_named_pipe_file),
            reinterpret_cast<PVOID>(DetouredNtCreateNamedPipeFile)) !=
            NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_nt_create_mailslot_file),
            reinterpret_cast<PVOID>(DetouredNtCreateMailslotFile)) !=
            NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_create_named_pipe_w),
            reinterpret_cast<PVOID>(DetouredCreateNamedPipeW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_create_named_pipe_a),
            reinterpret_cast<PVOID>(DetouredCreateNamedPipeA)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_create_pipe),
            reinterpret_cast<PVOID>(DetouredCreatePipe)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_get_disk_free_space_w),
            reinterpret_cast<PVOID>(DetouredGetDiskFreeSpaceW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_get_disk_free_space_a),
            reinterpret_cast<PVOID>(DetouredGetDiskFreeSpaceA)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_get_disk_free_space_ex_w),
            reinterpret_cast<PVOID>(DetouredGetDiskFreeSpaceExW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_get_disk_free_space_ex_a),
            reinterpret_cast<PVOID>(DetouredGetDiskFreeSpaceExA)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_create_mailslot_w),
            reinterpret_cast<PVOID>(DetouredCreateMailslotW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_create_mailslot_a),
            reinterpret_cast<PVOID>(DetouredCreateMailslotA)) != NO_ERROR ||
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
            reinterpret_cast<PVOID*>(&g_nt_map_view_of_section),
            reinterpret_cast<PVOID>(DetouredNtMapViewOfSection)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_nt_close),
            reinterpret_cast<PVOID>(DetouredNtClose)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_nt_duplicate_object),
            reinterpret_cast<PVOID>(DetouredNtDuplicateObject)) != NO_ERROR ||
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
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_co_create_instance),
            reinterpret_cast<PVOID>(DetouredCoCreateInstance)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_co_create_instance_ex),
            reinterpret_cast<PVOID>(DetouredCoCreateInstanceEx)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_co_get_class_object),
            reinterpret_cast<PVOID>(DetouredCoGetClassObject)) != NO_ERROR ||
        (g_copy_file_2 != nullptr &&
         DetourAttach(
             reinterpret_cast<PVOID*>(&g_copy_file_2),
             reinterpret_cast<PVOID>(DetouredCopyFile2)) != NO_ERROR) ||
        DetourTransactionCommit() != NO_ERROR) {
        DetourTransactionAbort();
        return HookInstallStatus::kTransactionFailed;
    }
    g_policy = std::move(policy);
    InterlockedExchange(
        &g_installed_file_hook_count,
        kRequiredFilesystemHookCount + (g_copy_file_2 != nullptr ? 1 : 0));
    return HookInstallStatus::kSuccess;
}

std::uint32_t InstalledFileHookCount() noexcept {
    return static_cast<std::uint32_t>(InterlockedCompareExchange(
        &g_installed_file_hook_count, 0, 0));
}

}  // namespace bolt::filesystem
