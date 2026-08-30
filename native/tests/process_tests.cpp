#include "common/execution_job.h"
#include "common/immutable_policy_mapping.h"
#include "common/private_pipe.h"
#include "common/suspended_process.h"
#include "protocol/event_frame.h"
#include "tests/policy_fixture.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#include <winternl.h>
#include <shellapi.h>

namespace {

std::wstring CurrentExecutable() {
    std::wstring path(32'768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (length == 0 || length == path.size()) {
        return {};
    }
    path.resize(length);
    return path;
}

std::wstring HandleText(const HANDLE handle) {
    return std::to_wstring(reinterpret_cast<std::uintptr_t>(handle));
}

std::wstring PipeName(const DWORD process_id) {
    std::wostringstream suffix;
    suffix << std::hex << std::nouppercase << std::setfill(L'0') << std::setw(32)
           << static_cast<std::uint64_t>(process_id);
    return L"\\\\.\\pipe\\bolt-sandbox-" + suffix.str();
}

std::string AnsiPath(const wchar_t* path) {
    const int length = WideCharToMultiByte(CP_ACP, 0, path, -1, nullptr, 0, nullptr, nullptr);
    if (length <= 1) {
        return {};
    }
    std::string converted(static_cast<std::size_t>(length), '\0');
    if (WideCharToMultiByte(
            CP_ACP, 0, path, -1, converted.data(), length, nullptr, nullptr) != length) {
        return {};
    }
    converted.pop_back();
    return converted;
}

bool WriteFixture(const std::filesystem::path& path, const std::string_view content) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream.write(content.data(), static_cast<std::streamsize>(content.size()));
    return stream.good();
}

std::string ReadFixture(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    return {std::istreambuf_iterator<char>{stream}, std::istreambuf_iterator<char>{}};
}

bool ReadSecurityDescriptor(
    const std::filesystem::path& path,
    std::vector<std::uint8_t>& descriptor) {
    DWORD required = 0;
    if (GetFileSecurityW(
            path.c_str(), DACL_SECURITY_INFORMATION, nullptr, 0, &required) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER || required == 0) {
        return false;
    }
    descriptor.resize(required);
    return GetFileSecurityW(
               path.c_str(), DACL_SECURITY_INFORMATION,
               reinterpret_cast<PSECURITY_DESCRIPTOR>(descriptor.data()), required,
               &required) != FALSE;
}

bool ReadCompressionState(const HANDLE file, USHORT& state) {
    DWORD bytes_returned = 0;
    return DeviceIoControl(
               file, FSCTL_GET_COMPRESSION, nullptr, 0, &state, sizeof(state),
               &bytes_returned, nullptr) != FALSE &&
           bytes_returned == sizeof(state);
}

bool CreateJunction(
    const std::filesystem::path& junction,
    const std::filesystem::path& target) {
    struct MountPointReparseDataBuffer {
        ULONG tag;
        USHORT data_length;
        USHORT reserved;
        USHORT substitute_offset;
        USHORT substitute_length;
        USHORT print_offset;
        USHORT print_length;
        WCHAR path_buffer[1];
    };
    constexpr DWORD reparse_header_size = 8;
    if (!CreateDirectoryW(junction.c_str(), nullptr)) {
        return false;
    }
    const HANDLE handle = CreateFileW(
        junction.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        RemoveDirectoryW(junction.c_str());
        return false;
    }

    const std::wstring substitute = L"\\??\\" + target.wstring();
    const std::wstring print_name = target.wstring();
    std::array<std::uint8_t, MAXIMUM_REPARSE_DATA_BUFFER_SIZE> storage{};
    auto* const reparse =
        reinterpret_cast<MountPointReparseDataBuffer*>(storage.data());
    reparse->tag = IO_REPARSE_TAG_MOUNT_POINT;
    reparse->substitute_offset = 0;
    reparse->substitute_length =
        static_cast<USHORT>(substitute.size() * sizeof(wchar_t));
    reparse->print_offset = reparse->substitute_length + sizeof(wchar_t);
    reparse->print_length =
        static_cast<USHORT>(print_name.size() * sizeof(wchar_t));
    std::memcpy(
        reparse->path_buffer, substitute.data(), reparse->substitute_length);
    std::memcpy(
        reinterpret_cast<std::uint8_t*>(reparse->path_buffer) + reparse->print_offset,
        print_name.data(), reparse->print_length);
    const DWORD path_bytes = reparse->print_offset + reparse->print_length +
                             sizeof(wchar_t);
    reparse->data_length = static_cast<USHORT>(8 + path_bytes);
    DWORD returned = 0;
    const BOOL created = DeviceIoControl(
        handle, FSCTL_SET_REPARSE_POINT, reparse,
        reparse_header_size + reparse->data_length, nullptr, 0, &returned,
        nullptr);
    CloseHandle(handle);
    if (!created) {
        const DWORD error = GetLastError();
        RemoveDirectoryW(junction.c_str());
        SetLastError(error);
    }
    return created != FALSE;
}

bool ReadExact(const HANDLE handle, std::uint8_t* bytes, const std::size_t length) {
    std::size_t offset = 0;
    while (offset < length) {
        DWORD bytes_read = 0;
        if (!ReadFile(
                handle, bytes + offset, static_cast<DWORD>(length - offset), &bytes_read,
                nullptr) ||
            bytes_read == 0) {
            return false;
        }
        offset += bytes_read;
    }
    return true;
}

std::uint32_t ReadU32(const std::uint8_t* bytes) {
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < 4; ++index) {
        value |= static_cast<std::uint32_t>(bytes[index]) << (index * 8);
    }
    return value;
}

bool ReadFilesystemViolation(
    const HANDLE event_pipe,
    const std::uint32_t process_id,
    const bolt::protocol::FilesystemOperation operation,
    const std::wstring& path,
    const std::uint64_t sequence) {
    std::array<std::uint8_t, bolt::protocol::kEventHeaderLength> header{};
    if (!ReadExact(event_pipe, header.data(), header.size())) {
        return false;
    }
    const std::size_t payload_length = ReadU32(header.data() + 8);
    const std::size_t frame_length = header.size() + payload_length;
    if (frame_length != bolt::protocol::FilesystemViolationFrameLength(path.c_str())) {
        return false;
    }
    std::vector<std::uint8_t> actual(frame_length);
    std::copy(header.begin(), header.end(), actual.begin());
    if (!ReadExact(
            event_pipe, actual.data() + header.size(), frame_length - header.size())) {
        return false;
    }
    std::vector<std::uint8_t> expected(frame_length);
    std::size_t written = 0;
    return bolt::protocol::EncodeFilesystemViolationFrame(
               process_id, operation, path.c_str(), sequence, expected.data(), expected.size(),
               written) == bolt::protocol::FrameEncodeStatus::kSuccess &&
           written == expected.size() && actual == expected;
}

volatile LONG g_io_completion_calls = 0;

void CALLBACK IoCompletionProbe(
    const DWORD error,
    const DWORD bytes,
    const LPOVERLAPPED overlapped) {
    static_cast<void>(error);
    static_cast<void>(bytes);
    static_cast<void>(overlapped);
    InterlockedIncrement(&g_io_completion_calls);
}

}  // namespace

int RunProcessChild(const int argument_count, wchar_t** arguments) {
    if (argument_count != 38) {
        return 80;
    }
    const auto allowed = reinterpret_cast<HANDLE>(_wcstoui64(arguments[2], nullptr, 10));
    const auto denied = reinterpret_cast<HANDLE>(_wcstoui64(arguments[3], nullptr, 10));
    if (!SetEvent(allowed)) {
        return 81;
    }
    using NtQueryObjectFunction = NTSTATUS(NTAPI*)(
        HANDLE, ULONG, PVOID, ULONG, PULONG);
    const auto nt_query_object = reinterpret_cast<NtQueryObjectFunction>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject"));
    if (nt_query_object == nullptr) {
        return 156;
    }
    struct ObjectNameInformation {
        UNICODE_STRING name;
    };
    std::array<std::uint8_t, 4'096> object_name_storage{};
    ULONG object_name_size = 0;
    const NTSTATUS object_name_status = nt_query_object(
        denied, 1, object_name_storage.data(),
        static_cast<ULONG>(object_name_storage.size()), &object_name_size);
    const auto* object_name = reinterpret_cast<const ObjectNameInformation*>(
        object_name_storage.data());
    const std::wstring_view expected_name(arguments[35]);
    const std::size_t separator = expected_name.find_last_of(L'\\');
    const std::wstring_view expected_leaf =
        separator == std::wstring_view::npos
            ? expected_name
            : expected_name.substr(separator + 1);
    const std::wstring_view actual_name =
        object_name_status >= 0 && object_name->name.Buffer != nullptr
            ? std::wstring_view(
                  object_name->name.Buffer,
                  object_name->name.Length / sizeof(wchar_t))
            : std::wstring_view{};
    if (actual_name.size() >= expected_leaf.size() &&
        actual_name.substr(actual_name.size() - expected_leaf.size()) ==
            expected_leaf) {
        return 82;
    }
    if (GetModuleHandleW(arguments[4]) == nullptr) {
        return 83;
    }
    const HMODULE hook = GetModuleHandleW(arguments[4]);
    const auto initialized = reinterpret_cast<BOOL(*)()>(
        GetProcAddress(hook, "BoltSandboxRuntimeInitialized"));
    if (initialized == nullptr || !initialized()) {
        return 84;
    }
    const HANDLE denied_file = CreateFileW(
        arguments[5], GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (denied_file != INVALID_HANDLE_VALUE || GetLastError() != ERROR_ACCESS_DENIED) {
        if (denied_file != INVALID_HANDLE_VALUE) {
            CloseHandle(denied_file);
        }
        return 85;
    }
    if (DeleteFileW(arguments[6]) || GetLastError() != ERROR_ACCESS_DENIED) {
        return 86;
    }
    if (CreateDirectoryW(arguments[7], nullptr) || GetLastError() != ERROR_ACCESS_DENIED) {
        return 87;
    }
    if (RemoveDirectoryW(arguments[8]) || GetLastError() != ERROR_ACCESS_DENIED) {
        return 88;
    }
    if (MoveFileExW(arguments[9], arguments[10], MOVEFILE_REPLACE_EXISTING) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 89;
    }
    if (MoveFileW(arguments[9], arguments[10]) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 105;
    }
    const std::string ansi_move_source = AnsiPath(arguments[9]);
    const std::string ansi_move_destination = AnsiPath(arguments[10]);
    if (ansi_move_source.empty() || ansi_move_destination.empty()) {
        return 106;
    }
    if (MoveFileA(ansi_move_source.c_str(), ansi_move_destination.c_str()) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 107;
    }
    if (MoveFileExA(
            ansi_move_source.c_str(), ansi_move_destination.c_str(),
            MOVEFILE_REPLACE_EXISTING) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 108;
    }
    if (MoveFileWithProgressW(
            arguments[9], arguments[10], nullptr, nullptr, MOVEFILE_REPLACE_EXISTING) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 109;
    }
    if (MoveFileWithProgressA(
            ansi_move_source.c_str(), ansi_move_destination.c_str(), nullptr, nullptr,
            MOVEFILE_REPLACE_EXISTING) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 110;
    }
    if (MoveFileTransactedW(
            arguments[9], arguments[10], nullptr, nullptr, MOVEFILE_REPLACE_EXISTING,
            INVALID_HANDLE_VALUE) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 111;
    }
    if (MoveFileTransactedA(
            ansi_move_source.c_str(), ansi_move_destination.c_str(), nullptr, nullptr,
            MOVEFILE_REPLACE_EXISTING, INVALID_HANDLE_VALUE) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 112;
    }
    if (CreateHardLinkW(arguments[11], arguments[9], nullptr) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 90;
    }
    if (CopyFileW(arguments[12], arguments[13], FALSE) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 91;
    }
    if (CopyFileExW(arguments[12], arguments[13], nullptr, nullptr, nullptr, 0) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 92;
    }
    const std::string ansi_copy_source = AnsiPath(arguments[12]);
    const std::string ansi_copy_destination = AnsiPath(arguments[13]);
    if (ansi_copy_source.empty() || ansi_copy_destination.empty()) {
        return 93;
    }
    if (CopyFileA(ansi_copy_source.c_str(), ansi_copy_destination.c_str(), FALSE) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 94;
    }
    if (CopyFileExA(
            ansi_copy_source.c_str(), ansi_copy_destination.c_str(), nullptr, nullptr, nullptr,
            0) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 95;
    }
    using CopyFile2Function = HRESULT(WINAPI*)(
        PCWSTR, PCWSTR, const COPYFILE2_EXTENDED_PARAMETERS*);
    const auto copy_file_2 = reinterpret_cast<CopyFile2Function>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CopyFile2"));
    if (copy_file_2 == nullptr ||
        copy_file_2(arguments[12], arguments[13], nullptr) !=
            HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED)) {
        return 96;
    }
    if (CopyFileTransactedW(
            arguments[12], arguments[13], nullptr, nullptr, nullptr, 0,
            INVALID_HANDLE_VALUE) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 97;
    }
    if (CopyFileTransactedA(
            ansi_copy_source.c_str(), ansi_copy_destination.c_str(), nullptr, nullptr, nullptr, 0,
            INVALID_HANDLE_VALUE) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 98;
    }
    if (!CopyFileW(arguments[14], arguments[15], TRUE)) {
        return 99;
    }
    if (CopyFileExW(arguments[14], arguments[13], nullptr, nullptr, nullptr, 0) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 100;
    }
    if (CopyFileW(arguments[16], arguments[17], TRUE) ||
        GetLastError() != ERROR_FILE_NOT_FOUND) {
        return 101;
    }
    if (CopyFileW(arguments[14], arguments[18], FALSE) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 102;
    }
    if (MoveFileExW(arguments[19], arguments[20], MOVEFILE_REPLACE_EXISTING) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 103;
    }
    if (ReplaceFileW(arguments[21], arguments[12], nullptr, 0, nullptr, nullptr) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 113;
    }
    const std::string ansi_replace_target = AnsiPath(arguments[21]);
    if (ansi_replace_target.empty() ||
        ReplaceFileA(
            ansi_replace_target.c_str(), ansi_copy_source.c_str(), nullptr, 0, nullptr,
            nullptr) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 114;
    }
    const HANDLE rename_handle = CreateFileW(
        arguments[22], DELETE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (rename_handle == INVALID_HANDLE_VALUE) {
        return 115;
    }
    const std::size_t rename_name_bytes = std::wcslen(arguments[23]) * sizeof(wchar_t);
    std::vector<std::uint8_t> rename_buffer(
        offsetof(FILE_RENAME_INFO, FileName) + rename_name_bytes);
    auto* rename_info = reinterpret_cast<FILE_RENAME_INFO*>(rename_buffer.data());
    rename_info->ReplaceIfExists = FALSE;
    rename_info->RootDirectory = nullptr;
    rename_info->FileNameLength = static_cast<DWORD>(rename_name_bytes);
    std::memcpy(rename_info->FileName, arguments[23], rename_name_bytes);
    if (SetFileInformationByHandle(
            rename_handle, FileRenameInfo, rename_info,
            static_cast<DWORD>(rename_buffer.size())) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        CloseHandle(rename_handle);
        return 116;
    }
    CloseHandle(rename_handle);
    const HANDLE allowed_disposition_handle = CreateFileW(
        arguments[24], DELETE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    FILE_DISPOSITION_INFO disposition{TRUE};
    if (allowed_disposition_handle == INVALID_HANDLE_VALUE ||
        !SetFileInformationByHandle(
            allowed_disposition_handle, FileDispositionInfo, &disposition,
            sizeof(disposition))) {
        if (allowed_disposition_handle != INVALID_HANDLE_VALUE) {
            CloseHandle(allowed_disposition_handle);
        }
        return 117;
    }
    CloseHandle(allowed_disposition_handle);

    const auto denied_disposition_handle =
        reinterpret_cast<HANDLE>(_wcstoui64(arguments[25], nullptr, 10));
    if (SetFileInformationByHandle(
            denied_disposition_handle, FileDispositionInfo, &disposition,
            sizeof(disposition)) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 118;
    }
    FILE_DISPOSITION_INFO_EX disposition_ex{FILE_DISPOSITION_FLAG_DELETE};
    if (SetFileInformationByHandle(
            denied_disposition_handle, FileDispositionInfoEx, &disposition_ex,
            sizeof(disposition_ex)) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 119;
    }
    const HANDLE allowed_truncate_handle = CreateFileW(
        arguments[26], GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    LARGE_INTEGER truncate_offset{};
    truncate_offset.QuadPart = 4;
    if (allowed_truncate_handle == INVALID_HANDLE_VALUE ||
        !SetFilePointerEx(allowed_truncate_handle, truncate_offset, nullptr, FILE_BEGIN) ||
        !SetEndOfFile(allowed_truncate_handle)) {
        if (allowed_truncate_handle != INVALID_HANDLE_VALUE) {
            CloseHandle(allowed_truncate_handle);
        }
        return 120;
    }
    CloseHandle(allowed_truncate_handle);

    const auto denied_truncate_handle =
        reinterpret_cast<HANDLE>(_wcstoui64(arguments[27], nullptr, 10));
    if (!SetFilePointerEx(denied_truncate_handle, truncate_offset, nullptr, FILE_BEGIN) ||
        SetEndOfFile(denied_truncate_handle) || GetLastError() != ERROR_ACCESS_DENIED) {
        return 121;
    }
    using ZwSetInformationFileFunction = NTSTATUS(NTAPI*)(
        HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
    const auto zw_set_information_file = reinterpret_cast<ZwSetInformationFileFunction>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "ZwSetInformationFile"));
    IO_STATUS_BLOCK io_status{};
    LARGE_INTEGER direct_end_of_file{};
    direct_end_of_file.QuadPart = 2;
    constexpr NTSTATUS status_access_denied = static_cast<NTSTATUS>(0xC0000022UL);
    constexpr FILE_INFORMATION_CLASS file_end_of_file_information =
        static_cast<FILE_INFORMATION_CLASS>(20);
    if (zw_set_information_file == nullptr ||
        zw_set_information_file(
            denied_truncate_handle, &io_status, &direct_end_of_file,
            sizeof(direct_end_of_file), file_end_of_file_information) !=
            status_access_denied) {
        return 122;
    }
    constexpr FILE_INFORMATION_CLASS file_disposition_information =
        static_cast<FILE_INFORMATION_CLASS>(13);
    FILE_DISPOSITION_INFO direct_disposition{TRUE};
    if (zw_set_information_file(
            denied_disposition_handle, &io_status, &direct_disposition,
            sizeof(direct_disposition), file_disposition_information) !=
        status_access_denied) {
        return 123;
    }
    struct NtFileRenameInformation {
        BOOLEAN replace_if_exists;
        HANDLE root_directory;
        ULONG file_name_length;
        WCHAR file_name[1];
    };
    const HANDLE direct_rename_handle = CreateFileW(
        arguments[22], DELETE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    const std::size_t direct_rename_name_bytes =
        std::wcslen(arguments[23]) * sizeof(wchar_t);
    std::vector<std::uint8_t> direct_rename_buffer(
        offsetof(NtFileRenameInformation, file_name) + direct_rename_name_bytes);
    auto* direct_rename =
        reinterpret_cast<NtFileRenameInformation*>(direct_rename_buffer.data());
    direct_rename->replace_if_exists = FALSE;
    direct_rename->root_directory = nullptr;
    direct_rename->file_name_length = static_cast<ULONG>(direct_rename_name_bytes);
    std::memcpy(direct_rename->file_name, arguments[23], direct_rename_name_bytes);
    constexpr FILE_INFORMATION_CLASS file_rename_information =
        static_cast<FILE_INFORMATION_CLASS>(10);
    if (direct_rename_handle == INVALID_HANDLE_VALUE ||
        zw_set_information_file(
            direct_rename_handle, &io_status, direct_rename,
            static_cast<ULONG>(direct_rename_buffer.size()), file_rename_information) !=
            status_access_denied) {
        if (direct_rename_handle != INVALID_HANDLE_VALUE) {
            CloseHandle(direct_rename_handle);
        }
        return 124;
    }
    CloseHandle(direct_rename_handle);
    const HANDLE allowed_mapping_file = CreateFileW(
        arguments[28], GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    const HANDLE allowed_mapping = allowed_mapping_file == INVALID_HANDLE_VALUE
                                       ? nullptr
                                       : CreateFileMappingW(
                                             allowed_mapping_file, nullptr, PAGE_READWRITE, 0, 0,
                                             nullptr);
    void* allowed_view = allowed_mapping == nullptr
                             ? nullptr
                             : MapViewOfFile(allowed_mapping, FILE_MAP_WRITE, 0, 0, 0);
    if (allowed_view == nullptr) {
        if (allowed_mapping != nullptr) {
            CloseHandle(allowed_mapping);
        }
        if (allowed_mapping_file != INVALID_HANDLE_VALUE) {
            CloseHandle(allowed_mapping_file);
        }
        return 125;
    }
    static_cast<char*>(allowed_view)[0] = 'X';
    if (!FlushViewOfFile(allowed_view, 1)) {
        UnmapViewOfFile(allowed_view);
        CloseHandle(allowed_mapping);
        CloseHandle(allowed_mapping_file);
        return 126;
    }
    UnmapViewOfFile(allowed_view);
    CloseHandle(allowed_mapping);
    CloseHandle(allowed_mapping_file);

    const auto denied_mapping_file =
        reinterpret_cast<HANDLE>(_wcstoui64(arguments[29], nullptr, 10));
    const HANDLE denied_mapping_w =
        CreateFileMappingW(denied_mapping_file, nullptr, PAGE_READWRITE, 0, 0, nullptr);
    if (denied_mapping_w != nullptr || GetLastError() != ERROR_ACCESS_DENIED) {
        if (denied_mapping_w != nullptr) {
            CloseHandle(denied_mapping_w);
        }
        return 127;
    }
    const HANDLE denied_mapping_a =
        CreateFileMappingA(denied_mapping_file, nullptr, PAGE_READWRITE, 0, 0, nullptr);
    if (denied_mapping_a != nullptr || GetLastError() != ERROR_ACCESS_DENIED) {
        if (denied_mapping_a != nullptr) {
            CloseHandle(denied_mapping_a);
        }
        return 128;
    }
    const auto read_only_mapping_file =
        reinterpret_cast<HANDLE>(_wcstoui64(arguments[30], nullptr, 10));
    const HANDLE read_only_mapping =
        CreateFileMappingW(read_only_mapping_file, nullptr, PAGE_READONLY, 0, 0, nullptr);
    const void* read_only_view = read_only_mapping == nullptr
                                     ? nullptr
                                     : MapViewOfFile(read_only_mapping, FILE_MAP_READ, 0, 0, 0);
    if (read_only_view == nullptr ||
        std::memcmp(read_only_view, "read-only-content", 17) != 0) {
        if (read_only_view != nullptr) {
            UnmapViewOfFile(read_only_view);
        }
        if (read_only_mapping != nullptr) {
            CloseHandle(read_only_mapping);
        }
        return 129;
    }
    UnmapViewOfFile(read_only_view);
    CloseHandle(read_only_mapping);
    const HANDLE forbidden_read_only_write =
        CreateFileMappingW(read_only_mapping_file, nullptr, PAGE_READWRITE, 0, 0, nullptr);
    if (forbidden_read_only_write != nullptr || GetLastError() != ERROR_ACCESS_DENIED) {
        if (forbidden_read_only_write != nullptr) {
            CloseHandle(forbidden_read_only_write);
        }
        return 130;
    }
    using NtCreateSectionFunction = NTSTATUS(NTAPI*)(
        PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
    const auto nt_create_section = reinterpret_cast<NtCreateSectionFunction>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateSection"));
    HANDLE denied_section = nullptr;
    if (nt_create_section == nullptr ||
        nt_create_section(
            &denied_section, SECTION_MAP_READ | SECTION_MAP_WRITE, nullptr, nullptr,
            PAGE_READWRITE, SEC_COMMIT, denied_mapping_file) != status_access_denied ||
        denied_section != nullptr) {
        if (denied_section != nullptr) {
            CloseHandle(denied_section);
        }
        return 131;
    }
    if (CreateHardLinkW(arguments[31], arguments[14], nullptr) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 132;
    }
    const std::string ansi_alias_hardlink = AnsiPath(arguments[31]);
    const std::string ansi_allowed_hardlink_source = AnsiPath(arguments[14]);
    if (ansi_alias_hardlink.empty() || ansi_allowed_hardlink_source.empty() ||
        CreateHardLinkA(
            ansi_alias_hardlink.c_str(), ansi_allowed_hardlink_source.c_str(), nullptr) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 133;
    }
    if (CreateJunction(arguments[32], arguments[33]) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 134;
    }
    WIN32_FIND_DATAW find_data_w{};
    HANDLE find = FindFirstFileW(arguments[34], &find_data_w);
    if (find != INVALID_HANDLE_VALUE || GetLastError() != ERROR_ACCESS_DENIED) {
        if (find != INVALID_HANDLE_VALUE) {
            FindClose(find);
        }
        return 135;
    }
    const std::string ansi_denied_wildcard = AnsiPath(arguments[34]);
    WIN32_FIND_DATAA find_data_a{};
    find = ansi_denied_wildcard.empty()
               ? INVALID_HANDLE_VALUE
               : FindFirstFileA(ansi_denied_wildcard.c_str(), &find_data_a);
    if (find != INVALID_HANDLE_VALUE || GetLastError() != ERROR_ACCESS_DENIED) {
        if (find != INVALID_HANDLE_VALUE) {
            FindClose(find);
        }
        return 136;
    }
    find = FindFirstFileExW(
        arguments[34], FindExInfoBasic, &find_data_w, FindExSearchNameMatch, nullptr, 0);
    if (find != INVALID_HANDLE_VALUE || GetLastError() != ERROR_ACCESS_DENIED) {
        if (find != INVALID_HANDLE_VALUE) {
            FindClose(find);
        }
        return 137;
    }
    find = FindFirstFileExA(
        ansi_denied_wildcard.c_str(), FindExInfoBasic, &find_data_a,
        FindExSearchNameMatch, nullptr, 0);
    if (find != INVALID_HANDLE_VALUE || GetLastError() != ERROR_ACCESS_DENIED) {
        if (find != INVALID_HANDLE_VALUE) {
            FindClose(find);
        }
        return 138;
    }
    if (GetFileAttributesW(arguments[6]) != INVALID_FILE_ATTRIBUTES ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 139;
    }
    const std::string ansi_denied_metadata = AnsiPath(arguments[6]);
    if (ansi_denied_metadata.empty() ||
        GetFileAttributesA(ansi_denied_metadata.c_str()) != INVALID_FILE_ATTRIBUTES ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 140;
    }
    WIN32_FILE_ATTRIBUTE_DATA attribute_data{};
    if (GetFileAttributesExW(arguments[6], GetFileExInfoStandard, &attribute_data) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 141;
    }
    if (GetFileAttributesExA(
            ansi_denied_metadata.c_str(), GetFileExInfoStandard, &attribute_data) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 142;
    }
    if (SetFileAttributesW(arguments[6], FILE_ATTRIBUTE_HIDDEN) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 143;
    }
    if (SetFileAttributesA(ansi_denied_metadata.c_str(), FILE_ATTRIBUTE_HIDDEN) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 144;
    }
    FILETIME forbidden_write_time{};
    forbidden_write_time.dwHighDateTime = 1;
    forbidden_write_time.dwLowDateTime = 2;
    if (SetFileTime(
            denied_mapping_file, nullptr, nullptr, &forbidden_write_time) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 145;
    }
    struct NtFileBasicInformation {
        LARGE_INTEGER creation_time;
        LARGE_INTEGER last_access_time;
        LARGE_INTEGER last_write_time;
        LARGE_INTEGER change_time;
        ULONG file_attributes;
    };
    NtFileBasicInformation basic_information{};
    basic_information.last_write_time.QuadPart = 0x0000000200000000LL;
    basic_information.file_attributes = FILE_ATTRIBUTE_HIDDEN;
    constexpr FILE_INFORMATION_CLASS file_basic_information =
        static_cast<FILE_INFORMATION_CLASS>(4);
    if (zw_set_information_file(
            denied_mapping_file, &io_status, &basic_information,
            sizeof(basic_information), file_basic_information) != status_access_denied) {
        return 146;
    }
    SECURITY_DESCRIPTOR security_descriptor{};
    if (!InitializeSecurityDescriptor(
            &security_descriptor, SECURITY_DESCRIPTOR_REVISION) ||
        !SetSecurityDescriptorDacl(
            &security_descriptor, TRUE, nullptr, FALSE)) {
        return 147;
    }
    if (SetFileSecurityW(
            arguments[6], DACL_SECURITY_INFORMATION, &security_descriptor) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 148;
    }
    if (SetFileSecurityA(
            ansi_denied_metadata.c_str(), DACL_SECURITY_INFORMATION,
            &security_descriptor) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 149;
    }
    USHORT compression_before = 0;
    if (!ReadCompressionState(denied_mapping_file, compression_before)) {
        return 150;
    }
    USHORT forbidden_compression =
        compression_before == COMPRESSION_FORMAT_NONE
            ? COMPRESSION_FORMAT_DEFAULT
            : COMPRESSION_FORMAT_NONE;
    DWORD compression_bytes = 0;
    if (DeviceIoControl(
            denied_mapping_file, FSCTL_SET_COMPRESSION,
            &forbidden_compression, sizeof(forbidden_compression), nullptr, 0,
            &compression_bytes, nullptr) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 151;
    }
    if (EncryptFileW(arguments[6]) || GetLastError() != ERROR_ACCESS_DENIED) {
        return 152;
    }
    if (EncryptFileA(ansi_denied_metadata.c_str()) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 153;
    }
    if (DecryptFileW(arguments[6], 0) || GetLastError() != ERROR_ACCESS_DENIED) {
        return 154;
    }
    if (DecryptFileA(ansi_denied_metadata.c_str(), 0) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 155;
    }
    BY_HANDLE_FILE_INFORMATION handle_information{};
    if (GetFileInformationByHandle(
            denied_mapping_file, &handle_information) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 157;
    }
    FILE_BASIC_INFO handle_basic_information{};
    if (GetFileInformationByHandleEx(
            denied_mapping_file, FileBasicInfo, &handle_basic_information,
            sizeof(handle_basic_information)) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 158;
    }
    using NtQueryInformationFileFunction = NTSTATUS(NTAPI*)(
        HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
    const auto nt_query_information_file =
        reinterpret_cast<NtQueryInformationFileFunction>(GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationFile"));
    NtFileBasicInformation queried_basic_information{};
    if (nt_query_information_file == nullptr ||
        nt_query_information_file(
            denied_mapping_file, &io_status, &queried_basic_information,
            sizeof(queried_basic_information), file_basic_information) !=
            status_access_denied) {
        return 159;
    }
    using NtQueryAttributesFileFunction = NTSTATUS(NTAPI*)(
        POBJECT_ATTRIBUTES, PVOID);
    const auto nt_query_attributes_file =
        reinterpret_cast<NtQueryAttributesFileFunction>(GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), "NtQueryAttributesFile"));
    const auto nt_query_full_attributes_file =
        reinterpret_cast<NtQueryAttributesFileFunction>(GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), "NtQueryFullAttributesFile"));
    std::wstring nt_metadata_path = L"\\??\\" + std::wstring(arguments[6]);
    UNICODE_STRING nt_metadata_name{};
    nt_metadata_name.Length =
        static_cast<USHORT>(nt_metadata_path.size() * sizeof(wchar_t));
    nt_metadata_name.MaximumLength = nt_metadata_name.Length;
    nt_metadata_name.Buffer = nt_metadata_path.data();
    OBJECT_ATTRIBUTES nt_metadata_attributes{};
    nt_metadata_attributes.Length = sizeof(nt_metadata_attributes);
    nt_metadata_attributes.ObjectName = &nt_metadata_name;
    nt_metadata_attributes.Attributes = OBJ_CASE_INSENSITIVE;
    NtFileBasicInformation nt_path_basic_information{};
    if (nt_query_attributes_file == nullptr ||
        nt_query_attributes_file(
            &nt_metadata_attributes, &nt_path_basic_information) !=
            status_access_denied) {
        return 160;
    }
    struct NtFileNetworkOpenInformation {
        LARGE_INTEGER creation_time;
        LARGE_INTEGER last_access_time;
        LARGE_INTEGER last_write_time;
        LARGE_INTEGER change_time;
        LARGE_INTEGER allocation_size;
        LARGE_INTEGER end_of_file;
        ULONG file_attributes;
    };
    NtFileNetworkOpenInformation nt_path_full_information{};
    if (nt_query_full_attributes_file == nullptr ||
        nt_query_full_attributes_file(
            &nt_metadata_attributes, &nt_path_full_information) !=
            status_access_denied) {
        return 161;
    }
    using NtQueryDirectoryFileFunction = NTSTATUS(NTAPI*)(
        HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG,
        FILE_INFORMATION_CLASS, BOOLEAN, PUNICODE_STRING, BOOLEAN);
    using NtQueryDirectoryFileExFunction = NTSTATUS(NTAPI*)(
        HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG,
        FILE_INFORMATION_CLASS, ULONG, PUNICODE_STRING);
    const auto nt_query_directory_file =
        reinterpret_cast<NtQueryDirectoryFileFunction>(GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), "NtQueryDirectoryFile"));
    const auto nt_query_directory_file_ex =
        reinterpret_cast<NtQueryDirectoryFileExFunction>(GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), "NtQueryDirectoryFileEx"));
    const auto denied_directory_handle =
        reinterpret_cast<HANDLE>(_wcstoui64(arguments[36], nullptr, 10));
    std::array<std::uint8_t, 1'024> directory_information{};
    constexpr FILE_INFORMATION_CLASS file_directory_information =
        static_cast<FILE_INFORMATION_CLASS>(1);
    if (nt_query_directory_file == nullptr ||
        nt_query_directory_file(
            denied_directory_handle, nullptr, nullptr, nullptr, &io_status,
            directory_information.data(),
            static_cast<ULONG>(directory_information.size()),
            file_directory_information, FALSE, nullptr, TRUE) !=
            status_access_denied) {
        return 162;
    }
    constexpr ULONG restart_scan = 0x01;
    if (nt_query_directory_file_ex == nullptr ||
        nt_query_directory_file_ex(
            denied_directory_handle, nullptr, nullptr, nullptr, &io_status,
            directory_information.data(),
            static_cast<ULONG>(directory_information.size()),
            file_directory_information, restart_scan, nullptr) !=
            status_access_denied) {
        return 163;
    }
    constexpr DWORD allow_unprivileged_create = 0x2;
    constexpr DWORD symbolic_link_flags =
        SYMBOLIC_LINK_FLAG_DIRECTORY | allow_unprivileged_create;
    if (CreateSymbolicLinkW(arguments[32], arguments[33], symbolic_link_flags) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 164;
    }
    const std::string ansi_forbidden_symlink = AnsiPath(arguments[32]);
    const std::string ansi_forbidden_target = AnsiPath(arguments[33]);
    if (ansi_forbidden_symlink.empty() || ansi_forbidden_target.empty() ||
        CreateSymbolicLinkA(
            ansi_forbidden_symlink.c_str(), ansi_forbidden_target.c_str(),
            symbolic_link_flags) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 165;
    }
    std::wstring shell_delete_w(arguments[6]);
    shell_delete_w.push_back(L'\0');
    shell_delete_w.push_back(L'\0');
    SHFILEOPSTRUCTW shell_operation_w{};
    shell_operation_w.wFunc = FO_DELETE;
    shell_operation_w.pFrom = shell_delete_w.c_str();
    shell_operation_w.fFlags =
        FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
    if (SHFileOperationW(&shell_operation_w) != ERROR_ACCESS_DENIED) {
        return 166;
    }
    std::string shell_delete_a = ansi_denied_metadata;
    shell_delete_a.push_back('\0');
    shell_delete_a.push_back('\0');
    SHFILEOPSTRUCTA shell_operation_a{};
    shell_operation_a.wFunc = FO_DELETE;
    shell_operation_a.pFrom = shell_delete_a.c_str();
    shell_operation_a.fFlags =
        FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
    if (SHFileOperationA(&shell_operation_a) != ERROR_ACCESS_DENIED) {
        return 167;
    }
    std::wstring shell_copy_source_w(arguments[12]);
    shell_copy_source_w.append(2, L'\0');
    std::wstring shell_copy_destination_w(arguments[13]);
    shell_copy_destination_w.append(2, L'\0');
    shell_operation_w = {};
    shell_operation_w.wFunc = FO_COPY;
    shell_operation_w.pFrom = shell_copy_source_w.c_str();
    shell_operation_w.pTo = shell_copy_destination_w.c_str();
    shell_operation_w.fFlags =
        FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
    if (SHFileOperationW(&shell_operation_w) != ERROR_ACCESS_DENIED) {
        return 168;
    }
    std::string shell_copy_source_a = ansi_copy_source;
    shell_copy_source_a.append(2, '\0');
    std::string shell_copy_destination_a = ansi_copy_destination;
    shell_copy_destination_a.append(2, '\0');
    shell_operation_a = {};
    shell_operation_a.wFunc = FO_COPY;
    shell_operation_a.pFrom = shell_copy_source_a.c_str();
    shell_operation_a.pTo = shell_copy_destination_a.c_str();
    shell_operation_a.fFlags =
        FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
    if (SHFileOperationA(&shell_operation_a) != ERROR_ACCESS_DENIED) {
        return 169;
    }
    std::wstring shell_move_source_w(arguments[9]);
    shell_move_source_w.append(2, L'\0');
    std::wstring shell_move_destination_w(arguments[10]);
    shell_move_destination_w.append(2, L'\0');
    shell_operation_w = {};
    shell_operation_w.wFunc = FO_MOVE;
    shell_operation_w.pFrom = shell_move_source_w.c_str();
    shell_operation_w.pTo = shell_move_destination_w.c_str();
    shell_operation_w.fFlags =
        FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
    if (SHFileOperationW(&shell_operation_w) != ERROR_ACCESS_DENIED) {
        return 170;
    }
    std::string shell_move_source_a = ansi_move_source;
    shell_move_source_a.append(2, '\0');
    std::string shell_move_destination_a = ansi_move_destination;
    shell_move_destination_a.append(2, '\0');
    shell_operation_a = {};
    shell_operation_a.wFunc = FO_MOVE;
    shell_operation_a.pFrom = shell_move_source_a.c_str();
    shell_operation_a.pTo = shell_move_destination_a.c_str();
    shell_operation_a.fFlags =
        FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
    if (SHFileOperationA(&shell_operation_a) != ERROR_ACCESS_DENIED) {
        return 171;
    }
    if (DeleteFileW(arguments[18]) || GetLastError() != ERROR_ACCESS_DENIED) {
        return 172;
    }
    const std::string ansi_alias_delete = AnsiPath(arguments[18]);
    if (ansi_alias_delete.empty() || DeleteFileA(ansi_alias_delete.c_str()) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 173;
    }
    const HANDLE alias_write_w = CreateFileW(
        arguments[18], GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (alias_write_w != INVALID_HANDLE_VALUE ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        if (alias_write_w != INVALID_HANDLE_VALUE) {
            CloseHandle(alias_write_w);
        }
        return 174;
    }
    const HANDLE alias_write_a = CreateFileA(
        ansi_alias_delete.c_str(), GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (alias_write_a != INVALID_HANDLE_VALUE ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        if (alias_write_a != INVALID_HANDLE_VALUE) {
            CloseHandle(alias_write_a);
        }
        return 175;
    }
    LARGE_INTEGER file_start{};
    if (!SetFilePointerEx(
            denied_mapping_file, file_start, nullptr, FILE_BEGIN)) {
        return 176;
    }
    std::array<char, 4> denied_read_buffer = {'x', 'x', 'x', 'x'};
    DWORD denied_read_bytes = 123;
    if (ReadFile(
            denied_mapping_file, denied_read_buffer.data(),
            static_cast<DWORD>(denied_read_buffer.size()), &denied_read_bytes,
            nullptr) ||
        GetLastError() != ERROR_ACCESS_DENIED || denied_read_bytes != 0 ||
        denied_read_buffer != std::array<char, 4>{'x', 'x', 'x', 'x'}) {
        return 177;
    }
    if (!SetFilePointerEx(
            denied_mapping_file, file_start, nullptr, FILE_BEGIN)) {
        return 178;
    }
    constexpr std::array<char, 4> forbidden_write = {'N', 'O', 'P', 'E'};
    DWORD denied_write_bytes = 123;
    if (WriteFile(
            denied_mapping_file, forbidden_write.data(),
            static_cast<DWORD>(forbidden_write.size()), &denied_write_bytes,
            nullptr) ||
        GetLastError() != ERROR_ACCESS_DENIED || denied_write_bytes != 0) {
        return 179;
    }
    using NtReadWriteFileFunction = NTSTATUS(NTAPI*)(
        HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG,
        PLARGE_INTEGER, PULONG);
    const auto nt_read_file = reinterpret_cast<NtReadWriteFileFunction>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtReadFile"));
    const auto nt_write_file = reinterpret_cast<NtReadWriteFileFunction>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtWriteFile"));
    if (!SetFilePointerEx(
            denied_mapping_file, file_start, nullptr, FILE_BEGIN)) {
        return 180;
    }
    std::array<char, 4> denied_nt_read_buffer = {'y', 'y', 'y', 'y'};
    io_status.Status = 0;
    io_status.Information = 123;
    if (nt_read_file == nullptr ||
        nt_read_file(
            denied_mapping_file, nullptr, nullptr, nullptr, &io_status,
            denied_nt_read_buffer.data(),
            static_cast<ULONG>(denied_nt_read_buffer.size()), nullptr, nullptr) !=
            status_access_denied ||
        io_status.Status != status_access_denied || io_status.Information != 0 ||
        denied_nt_read_buffer != std::array<char, 4>{'y', 'y', 'y', 'y'}) {
        return 181;
    }
    io_status.Status = 0;
    io_status.Information = 123;
    std::array<char, 4> denied_nt_write_buffer = forbidden_write;
    if (nt_write_file == nullptr ||
        nt_write_file(
            denied_mapping_file, nullptr, nullptr, nullptr, &io_status,
            denied_nt_write_buffer.data(),
            static_cast<ULONG>(denied_nt_write_buffer.size()), nullptr, nullptr) !=
            status_access_denied ||
        io_status.Status != status_access_denied || io_status.Information != 0) {
        return 182;
    }
    const auto denied_overlapped_file =
        reinterpret_cast<HANDLE>(_wcstoui64(arguments[37], nullptr, 10));
    OVERLAPPED denied_read_overlapped{};
    std::array<char, 4> denied_ex_read_buffer = {'z', 'z', 'z', 'z'};
    InterlockedExchange(&g_io_completion_calls, 0);
    if (ReadFileEx(
            denied_overlapped_file, denied_ex_read_buffer.data(),
            static_cast<DWORD>(denied_ex_read_buffer.size()),
            &denied_read_overlapped, IoCompletionProbe) ||
        GetLastError() != ERROR_ACCESS_DENIED ||
        InterlockedCompareExchange(&g_io_completion_calls, 0, 0) != 0 ||
        denied_ex_read_buffer != std::array<char, 4>{'z', 'z', 'z', 'z'}) {
        return 183;
    }
    OVERLAPPED denied_write_overlapped{};
    std::array<char, 4> denied_ex_write_buffer = forbidden_write;
    if (WriteFileEx(
            denied_overlapped_file, denied_ex_write_buffer.data(),
            static_cast<DWORD>(denied_ex_write_buffer.size()),
            &denied_write_overlapped, IoCompletionProbe) ||
        GetLastError() != ERROR_ACCESS_DENIED ||
        InterlockedCompareExchange(&g_io_completion_calls, 0, 0) != 0) {
        return 184;
    }
    SleepEx(0, TRUE);
    if (InterlockedCompareExchange(&g_io_completion_calls, 0, 0) != 0) {
        return 185;
    }
    if (GetFileAttributesW(arguments[18]) != INVALID_FILE_ATTRIBUTES ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 186;
    }
    if (GetFileAttributesA(ansi_alias_delete.c_str()) !=
            INVALID_FILE_ATTRIBUTES ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 187;
    }
    if (SetFileAttributesW(arguments[18], FILE_ATTRIBUTE_HIDDEN) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 188;
    }
    if (SetFileAttributesA(ansi_alias_delete.c_str(), FILE_ATTRIBUTE_HIDDEN) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 189;
    }
    const std::filesystem::path alias_create_directory =
        std::filesystem::path(arguments[18]).parent_path() / L"created-directory";
    if (CreateDirectoryW(alias_create_directory.c_str(), nullptr) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 190;
    }
    const auto flush_events = reinterpret_cast<BOOL (*)(DWORD)>(
        GetProcAddress(hook, "BoltSandboxFlushEvents"));
    if (flush_events == nullptr || !flush_events(5'000)) {
        return 104;
    }
    return 0;
}

bool RunProcessTests() {
    const std::wstring unique_suffix = std::to_wstring(GetCurrentProcessId());
    const std::filesystem::path test_root =
        std::filesystem::temp_directory_path() /
        (L"bolt-sandbox-process-" + unique_suffix);
    const std::filesystem::path denied_root = test_root / L"denied";
    const std::filesystem::path allowed_root = test_root / L"allowed";
    const std::filesystem::path read_only_root = test_root / L"read-only";
    std::error_code filesystem_error;
    std::filesystem::remove_all(test_root, filesystem_error);
    filesystem_error.clear();
    if (!std::filesystem::create_directories(denied_root, filesystem_error) || filesystem_error ||
        !std::filesystem::create_directories(allowed_root, filesystem_error) || filesystem_error ||
        !std::filesystem::create_directories(read_only_root, filesystem_error) ||
        filesystem_error) {
        return false;
    }

    const std::filesystem::path denied_path = denied_root / L"create.txt";
    const std::filesystem::path denied_delete_path = denied_root / L"delete.txt";
    const std::filesystem::path denied_create_directory = denied_root / L"mkdir";
    const std::filesystem::path denied_remove_directory = denied_root / L"rmdir";
    const std::filesystem::path denied_move_source = denied_root / L"move-source.txt";
    const std::filesystem::path denied_move_destination = denied_root / L"move-destination.txt";
    const std::filesystem::path denied_hardlink_destination = denied_root / L"hardlink.txt";
    const std::filesystem::path denied_copy_source = denied_root / L"copy-source.txt";
    const std::filesystem::path denied_copy_destination = denied_root / L"copy-destination.txt";
    const std::filesystem::path allowed_copy_source = allowed_root / L"copy-source.txt";
    const std::filesystem::path allowed_copy_destination = allowed_root / L"copy-destination.txt";
    const std::filesystem::path missing_copy_source = allowed_root / L"missing-source.txt";
    const std::filesystem::path missing_copy_destination = allowed_root / L"missing-destination.txt";
    const std::filesystem::path denied_junction_target = denied_root / L"junction-target";
    const std::filesystem::path denied_alias_target = denied_junction_target / L"protected.txt";
    const std::filesystem::path allowed_junction = allowed_root / L"junction";
    const std::filesystem::path alias_copy_destination = allowed_junction / L"protected.txt";
    const std::filesystem::path denied_alias_created_directory =
        denied_junction_target / L"created-directory";
    const std::filesystem::path allowed_alias_move_source = allowed_root / L"move-source.txt";
    const std::filesystem::path alias_move_destination = allowed_junction / L"move-target.txt";
    const std::filesystem::path denied_alias_move_target =
        denied_junction_target / L"move-target.txt";
    const std::filesystem::path allowed_replace_target =
        allowed_root / L"replace-target.txt";
    const std::filesystem::path allowed_handle_rename_source =
        allowed_root / L"handle-rename-source.txt";
    const std::filesystem::path denied_handle_rename_destination =
        denied_root / L"handle-rename-destination.txt";
    const std::filesystem::path allowed_disposition_path =
        allowed_root / L"handle-delete.txt";
    const std::filesystem::path denied_disposition_path =
        denied_root / L"handle-delete.txt";
    const std::filesystem::path allowed_truncate_path =
        allowed_root / L"handle-truncate.txt";
    const std::filesystem::path denied_truncate_path =
        denied_root / L"handle-truncate.txt";
    const std::filesystem::path allowed_mapping_path =
        allowed_root / L"mapping.txt";
    const std::filesystem::path denied_mapping_path =
        denied_root / L"mapping.txt";
    const std::filesystem::path read_only_mapping_path =
        read_only_root / L"mapping.txt";
    const std::filesystem::path alias_hardlink_destination =
        allowed_junction / L"hardlink-escape.txt";
    const std::filesystem::path denied_hardlink_escape_target =
        denied_junction_target / L"hardlink-escape.txt";
    const std::filesystem::path forbidden_junction =
        allowed_root / L"forbidden-junction";
    const std::filesystem::path denied_wildcard = denied_root / L"*";
    if (!std::filesystem::create_directories(denied_junction_target, filesystem_error) ||
        filesystem_error) {
        return false;
    }
    const auto policy_payload = bolt::tests::SealPolicy({
        {bolt::tests::FilesystemRuleKind::kReadWrite, test_root},
        {bolt::tests::FilesystemRuleKind::kReadOnly, read_only_root},
        {bolt::tests::FilesystemRuleKind::kDeny, denied_root},
    });
    constexpr std::array<std::uint8_t, 16> nonce = {
        0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
        0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
    };
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    const HANDLE allowed = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    const std::wstring denied_event_name =
        L"Local\\bolt-sandbox-denied-" + unique_suffix;
    const HANDLE denied =
        CreateEventW(&inheritable, TRUE, FALSE, denied_event_name.c_str());
    const HANDLE release = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    bolt::common::ImmutablePolicyMapping policy;
    bolt::common::PrivatePipe event_pipe;
    const std::wstring pipe_name = PipeName(GetCurrentProcessId());
    const auto policy_status = bolt::common::ImmutablePolicyMapping::Create(
        policy_payload.data(), policy_payload.size(), policy);
    if (policy_payload.empty() || allowed == nullptr || denied == nullptr || release == nullptr ||
        policy_status != bolt::common::PolicyMappingStatus::kSuccess ||
        bolt::common::PrivatePipe::Create(pipe_name, event_pipe) !=
            bolt::common::PipeStatus::kSuccess) {
        return false;
    }
    HANDLE event_client = CreateFileW(
        pipe_name.c_str(), FILE_WRITE_DATA, 0, &inheritable, OPEN_EXISTING, 0, nullptr);
    if (event_client == INVALID_HANDLE_VALUE ||
        event_pipe.Accept() != bolt::common::PipeStatus::kSuccess) {
        return false;
    }

    const std::wstring executable = CurrentExecutable();
#if defined(_WIN64)
    constexpr auto hook_name = L"bolt-sandbox-x64.dll";
#else
    constexpr auto hook_name = L"bolt-sandbox-x86.dll";
#endif
    const std::filesystem::path hook_path =
        std::filesystem::path(executable).parent_path() / hook_name;
    DeleteFileW(denied_path.c_str());
    DeleteFileW(denied_delete_path.c_str());
    RemoveDirectoryW(denied_create_directory.c_str());
    RemoveDirectoryW(denied_remove_directory.c_str());
    DeleteFileW(denied_move_source.c_str());
    DeleteFileW(denied_move_destination.c_str());
    DeleteFileW(denied_hardlink_destination.c_str());
    DeleteFileW(denied_copy_source.c_str());
    DeleteFileW(denied_copy_destination.c_str());
    DeleteFileW(allowed_copy_source.c_str());
    DeleteFileW(allowed_copy_destination.c_str());
    DeleteFileW(missing_copy_source.c_str());
    DeleteFileW(missing_copy_destination.c_str());
    DeleteFileW(allowed_replace_target.c_str());
    DeleteFileW(allowed_handle_rename_source.c_str());
    DeleteFileW(denied_handle_rename_destination.c_str());
    DeleteFileW(allowed_disposition_path.c_str());
    DeleteFileW(denied_disposition_path.c_str());
    DeleteFileW(allowed_truncate_path.c_str());
    DeleteFileW(denied_truncate_path.c_str());
    DeleteFileW(allowed_mapping_path.c_str());
    DeleteFileW(denied_mapping_path.c_str());
    DeleteFileW(read_only_mapping_path.c_str());
    DeleteFileW(denied_hardlink_escape_target.c_str());
    RemoveDirectoryW(forbidden_junction.c_str());
    RemoveDirectoryW(denied_alias_created_directory.c_str());
    const HANDLE delete_fixture = CreateFileW(
        denied_delete_path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (delete_fixture == INVALID_HANDLE_VALUE) {
        return false;
    }
    CloseHandle(delete_fixture);
    const DWORD denied_delete_attributes = GetFileAttributesW(denied_delete_path.c_str());
    if (denied_delete_attributes == INVALID_FILE_ATTRIBUTES) {
        return false;
    }
    std::vector<std::uint8_t> denied_delete_security_before;
    if (!ReadSecurityDescriptor(
            denied_delete_path, denied_delete_security_before)) {
        return false;
    }
    const HANDLE move_fixture = CreateFileW(
        denied_move_source.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (move_fixture == INVALID_HANDLE_VALUE) {
        DeleteFileW(denied_delete_path.c_str());
        return false;
    }
    CloseHandle(move_fixture);
    const HANDLE copy_fixture = CreateFileW(
        denied_copy_source.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (copy_fixture == INVALID_HANDLE_VALUE) {
        DeleteFileW(denied_delete_path.c_str());
        DeleteFileW(denied_move_source.c_str());
        return false;
    }
    CloseHandle(copy_fixture);
    constexpr std::string_view replacement_nonce = "denied-replacement";
    constexpr std::string_view replace_target_nonce = "replace-target";
    if (!WriteFixture(denied_copy_source, replacement_nonce) ||
        !WriteFixture(allowed_replace_target, replace_target_nonce)) {
        return false;
    }
    constexpr std::string_view handle_rename_nonce = "handle-rename-source";
    if (!WriteFixture(allowed_handle_rename_source, handle_rename_nonce)) {
        return false;
    }
    constexpr std::string_view disposition_nonce = "handle-delete";
    if (!WriteFixture(allowed_disposition_path, disposition_nonce) ||
        !WriteFixture(denied_disposition_path, disposition_nonce)) {
        return false;
    }
    const HANDLE denied_disposition_handle = CreateFileW(
        denied_disposition_path.c_str(), DELETE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, &inheritable, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (denied_disposition_handle == INVALID_HANDLE_VALUE) {
        return false;
    }
    constexpr std::string_view truncate_nonce = "truncate-content";
    if (!WriteFixture(allowed_truncate_path, truncate_nonce) ||
        !WriteFixture(denied_truncate_path, truncate_nonce)) {
        CloseHandle(denied_disposition_handle);
        return false;
    }
    const HANDLE denied_truncate_handle = CreateFileW(
        denied_truncate_path.c_str(), GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, &inheritable, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (denied_truncate_handle == INVALID_HANDLE_VALUE) {
        CloseHandle(denied_disposition_handle);
        return false;
    }
    constexpr std::string_view mapping_nonce = "mapping-content";
    if (!WriteFixture(allowed_mapping_path, mapping_nonce) ||
        !WriteFixture(denied_mapping_path, mapping_nonce)) {
        CloseHandle(denied_disposition_handle);
        CloseHandle(denied_truncate_handle);
        return false;
    }
    const HANDLE denied_mapping_handle = CreateFileW(
        denied_mapping_path.c_str(), GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, &inheritable, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (denied_mapping_handle == INVALID_HANDLE_VALUE) {
        CloseHandle(denied_disposition_handle);
        CloseHandle(denied_truncate_handle);
        return false;
    }
    FILETIME denied_mapping_write_time_before{};
    if (!GetFileTime(
            denied_mapping_handle, nullptr, nullptr,
            &denied_mapping_write_time_before)) {
        CloseHandle(denied_disposition_handle);
        CloseHandle(denied_truncate_handle);
        CloseHandle(denied_mapping_handle);
        return false;
    }
    USHORT denied_mapping_compression_before = 0;
    if (!ReadCompressionState(
            denied_mapping_handle, denied_mapping_compression_before)) {
        CloseHandle(denied_disposition_handle);
        CloseHandle(denied_truncate_handle);
        CloseHandle(denied_mapping_handle);
        return false;
    }
    constexpr std::string_view read_only_mapping_nonce = "read-only-content";
    if (!WriteFixture(read_only_mapping_path, read_only_mapping_nonce)) {
        CloseHandle(denied_disposition_handle);
        CloseHandle(denied_truncate_handle);
        CloseHandle(denied_mapping_handle);
        return false;
    }
    const HANDLE read_only_mapping_handle = CreateFileW(
        read_only_mapping_path.c_str(), GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, &inheritable, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (read_only_mapping_handle == INVALID_HANDLE_VALUE) {
        CloseHandle(denied_disposition_handle);
        CloseHandle(denied_truncate_handle);
        CloseHandle(denied_mapping_handle);
        return false;
    }
    const HANDLE denied_directory_handle = CreateFileW(
        denied_root.c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, &inheritable,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (denied_directory_handle == INVALID_HANDLE_VALUE) {
        CloseHandle(denied_disposition_handle);
        CloseHandle(denied_truncate_handle);
        CloseHandle(denied_mapping_handle);
        CloseHandle(read_only_mapping_handle);
        return false;
    }
    const HANDLE denied_overlapped_handle = CreateFileW(
        denied_mapping_path.c_str(), GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, &inheritable,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, nullptr);
    if (denied_overlapped_handle == INVALID_HANDLE_VALUE) {
        CloseHandle(denied_disposition_handle);
        CloseHandle(denied_truncate_handle);
        CloseHandle(denied_mapping_handle);
        CloseHandle(read_only_mapping_handle);
        CloseHandle(denied_directory_handle);
        return false;
    }
    constexpr std::string_view copy_nonce = "bolt-copy-nonce";
    if (!WriteFixture(allowed_copy_source, copy_nonce)) {
        DeleteFileW(denied_delete_path.c_str());
        DeleteFileW(denied_move_source.c_str());
        DeleteFileW(denied_copy_source.c_str());
        return false;
    }
    constexpr std::string_view protected_nonce = "protected-target";
    if (!WriteFixture(denied_alias_target, protected_nonce) ||
        !CreateJunction(allowed_junction, denied_junction_target)) {
        return false;
    }
    const DWORD denied_alias_attributes_before =
        GetFileAttributesW(denied_alias_target.c_str());
    if (denied_alias_attributes_before == INVALID_FILE_ATTRIBUTES) {
        return false;
    }
    constexpr std::string_view move_nonce = "move-source";
    if (!WriteFixture(allowed_alias_move_source, move_nonce)) {
        return false;
    }
    if (!CreateDirectoryW(denied_remove_directory.c_str(), nullptr)) {
        DeleteFileW(denied_delete_path.c_str());
        return false;
    }
    const std::wstring command_line = L"\"" + executable + L"\" --process-child " +
                                      HandleText(allowed) + L" " + HandleText(denied) + L" " +
                                      hook_name + L" \"" + denied_path.wstring() + L"\" \"" +
                                      denied_delete_path.wstring() + L"\" \"" +
                                      denied_create_directory.wstring() + L"\" \"" +
                                      denied_remove_directory.wstring() + L"\" \"" +
                                      denied_move_source.wstring() + L"\" \"" +
                                      denied_move_destination.wstring() + L"\" \"" +
                                      denied_hardlink_destination.wstring() + L"\" \"" +
                                      denied_copy_source.wstring() + L"\" \"" +
                                      denied_copy_destination.wstring() + L"\" \"" +
                                      allowed_copy_source.wstring() + L"\" \"" +
                                      allowed_copy_destination.wstring() + L"\" \"" +
                                      missing_copy_source.wstring() + L"\" \"" +
                                      missing_copy_destination.wstring() + L"\" \"" +
                                      alias_copy_destination.wstring() + L"\" \"" +
                                      allowed_alias_move_source.wstring() + L"\" \"" +
                                      alias_move_destination.wstring() + L"\" \"" +
                                      allowed_replace_target.wstring() + L"\" \"" +
                                      allowed_handle_rename_source.wstring() + L"\" \"" +
                                      denied_handle_rename_destination.wstring() + L"\" \"" +
                                      allowed_disposition_path.wstring() + L"\" " +
                                      HandleText(denied_disposition_handle) + L" \"" +
                                      allowed_truncate_path.wstring() + L"\" " +
                                      HandleText(denied_truncate_handle) + L" \"" +
                                      allowed_mapping_path.wstring() + L"\" " +
                                      HandleText(denied_mapping_handle) + L" " +
                                      HandleText(read_only_mapping_handle) + L" \"" +
                                      alias_hardlink_destination.wstring() + L"\" \"" +
                                      forbidden_junction.wstring() + L"\" \"" +
                                      denied_junction_target.wstring() + L"\" \"" +
                                      denied_wildcard.wstring() + L"\" \"" +
                                      denied_event_name + L"\" " +
                                      HandleText(denied_directory_handle) + L" " +
                                      HandleText(denied_overlapped_handle);
    const HANDLE inherited[] = {
        allowed, policy.handle(), event_client, release, denied_disposition_handle,
        denied_truncate_handle, denied_mapping_handle, read_only_mapping_handle,
        denied_directory_handle, denied_overlapped_handle};
    bolt::common::ProcessLaunchOptions options{
        executable,
        command_line,
        L"",
        nullptr,
        inherited,
        std::size(inherited),
        0,
    };
    bolt::common::SuspendedProcess process;
    bolt::common::ExecutionJob job;
    const bool created = bolt::common::ExecutionJob::Create(job) ==
                             bolt::common::JobStatus::kSuccess &&
                         bolt::common::SuspendedProcess::Create(options, process) ==
                             bolt::common::ProcessStatus::kSuccess;
    const auto wait_suspended = process.Wait(100);
    const auto early_resume = process.Resume();
    const auto assigned = process.AssignTo(job);
    const auto assigned_resume = process.Resume();
    const auto wrong_mapping_status = process.InstallRuntimePayload(
        release, policy.length(), event_client, release, nonce);
    const auto payload_status = process.InstallRuntimePayload(
        policy.handle(), policy.length(), event_client, release, nonce);
    const auto inject_status = process.Inject(hook_path.string());
    const auto initialization_status = process.BeginHookInitialization();
    if (!created || wait_suspended != bolt::common::ProcessStatus::kWaitTimeout ||
        early_resume != bolt::common::ProcessStatus::kInvalidState ||
        assigned != bolt::common::ProcessStatus::kSuccess ||
        assigned_resume != bolt::common::ProcessStatus::kInvalidState ||
        wrong_mapping_status != bolt::common::ProcessStatus::kInvalidRuntimePayload ||
        payload_status != bolt::common::ProcessStatus::kSuccess ||
        inject_status != bolt::common::ProcessStatus::kSuccess ||
        initialization_status != bolt::common::ProcessStatus::kSuccess) {
        return false;
    }
    CloseHandle(event_client);
    event_client = INVALID_HANDLE_VALUE;
    std::array<std::uint8_t, bolt::protocol::kReadyFrameLength> ready{};
    DWORD bytes_read = 0;
    const BOOL read_ok = ReadFile(
        event_pipe.handle(), ready.data(), static_cast<DWORD>(ready.size()), &bytes_read, nullptr);
    const auto ready_status = bolt::protocol::ValidateReadyFrame(ready.data(), ready.size(), nonce);
    if (!read_ok || bytes_read != ready.size() ||
        ready_status != bolt::protocol::ReadyFrameStatus::kSuccess ||
        WaitForSingleObject(allowed, 0) != WAIT_TIMEOUT ||
        process.ReleaseAfterReady() != bolt::common::ProcessStatus::kSuccess ||
        process.Wait(5'000) != bolt::common::ProcessStatus::kSuccess) {
        CloseHandle(allowed);
        CloseHandle(denied);
        return false;
    }
    const std::uint32_t child_process_id = GetProcessId(process.process_handle());
    const bool violation_events =
        child_process_id != 0 &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kCreate, denied_path.wstring(), 1) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kDelete, denied_delete_path.wstring(), 2) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kCreate,
            denied_create_directory.wstring(), 3) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kDelete,
            denied_remove_directory.wstring(), 4) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRename, denied_move_source.wstring(), 5) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRename, denied_move_source.wstring(), 6) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRename, denied_move_source.wstring(), 7) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRename, denied_move_source.wstring(), 8) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRename, denied_move_source.wstring(), 9) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRename, denied_move_source.wstring(), 10) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRename, denied_move_source.wstring(), 11) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRename, denied_move_source.wstring(), 12) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRead, denied_move_source.wstring(), 13) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRead, denied_copy_source.wstring(), 14) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRead, denied_copy_source.wstring(), 15) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRead, denied_copy_source.wstring(), 16) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRead, denied_copy_source.wstring(), 17) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRead, denied_copy_source.wstring(), 18) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRead, denied_copy_source.wstring(), 19) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRead, denied_copy_source.wstring(), 20) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kCreate,
            denied_copy_destination.wstring(), 21) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kCreate, denied_alias_target.wstring(), 22) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRename,
            denied_alias_move_target.wstring(), 23) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRename, denied_copy_source.wstring(), 24) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRename, denied_copy_source.wstring(), 25) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRename,
            denied_handle_rename_destination.wstring(), 26) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kDelete,
            denied_disposition_path.wstring(), 27) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kDelete,
            denied_disposition_path.wstring(), 28) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kWrite,
            denied_truncate_path.wstring(), 29) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kWrite,
            denied_truncate_path.wstring(), 30) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kDelete,
            denied_disposition_path.wstring(), 31) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRename,
            denied_handle_rename_destination.wstring(), 32) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kWrite,
            denied_mapping_path.wstring(), 33) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kWrite,
            denied_mapping_path.wstring(), 34) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kWrite,
            read_only_mapping_path.wstring(), 35) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kWrite,
            denied_mapping_path.wstring(), 36) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kCreate,
            denied_hardlink_escape_target.wstring(), 37) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kCreate,
            denied_hardlink_escape_target.wstring(), 38) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kCreate,
            denied_junction_target.wstring(), 39) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kEnumerate,
            denied_wildcard.wstring(), 40) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kEnumerate,
            denied_wildcard.wstring(), 41) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kEnumerate,
            denied_wildcard.wstring(), 42) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kEnumerate,
            denied_wildcard.wstring(), 43) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kMetadata,
            denied_delete_path.wstring(), 44) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kMetadata,
            denied_delete_path.wstring(), 45) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kMetadata,
            denied_delete_path.wstring(), 46) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kMetadata,
            denied_delete_path.wstring(), 47) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kWrite,
            denied_delete_path.wstring(), 48) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kWrite,
            denied_delete_path.wstring(), 49) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kWrite,
            denied_mapping_path.wstring(), 50) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kWrite,
            denied_mapping_path.wstring(), 51) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kWrite,
            denied_delete_path.wstring(), 52) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kWrite,
            denied_delete_path.wstring(), 53) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kWrite,
            denied_mapping_path.wstring(), 54) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kWrite,
            denied_delete_path.wstring(), 55) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kWrite,
            denied_delete_path.wstring(), 56) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kWrite,
            denied_delete_path.wstring(), 57) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kWrite,
            denied_delete_path.wstring(), 58) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kMetadata,
            denied_mapping_path.wstring(), 59) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kMetadata,
            denied_mapping_path.wstring(), 60) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kMetadata,
            denied_mapping_path.wstring(), 61) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kMetadata,
            denied_delete_path.wstring(), 62) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kMetadata,
            denied_delete_path.wstring(), 63) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kEnumerate,
            denied_root.wstring(), 64) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kEnumerate,
            denied_root.wstring(), 65) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kCreate,
            denied_junction_target.wstring(), 66) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kCreate,
            denied_junction_target.wstring(), 67) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kDelete,
            denied_delete_path.wstring(), 68) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kDelete,
            denied_delete_path.wstring(), 69) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRead,
            denied_copy_source.wstring(), 70) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRead,
            denied_copy_source.wstring(), 71) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRename,
            denied_move_source.wstring(), 72) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRename,
            denied_move_source.wstring(), 73) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kDelete,
            denied_alias_target.wstring(), 74) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kDelete,
            denied_alias_target.wstring(), 75) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kWrite,
            denied_alias_target.wstring(), 76) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kWrite,
            denied_alias_target.wstring(), 77) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRead,
            denied_mapping_path.wstring(), 78) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kWrite,
            denied_mapping_path.wstring(), 79) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRead,
            denied_mapping_path.wstring(), 80) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kWrite,
            denied_mapping_path.wstring(), 81) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRead,
            denied_mapping_path.wstring(), 82) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kWrite,
            denied_mapping_path.wstring(), 83) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kMetadata,
            denied_alias_target.wstring(), 84) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kMetadata,
            denied_alias_target.wstring(), 85) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kWrite,
            denied_alias_target.wstring(), 86) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kWrite,
            denied_alias_target.wstring(), 87) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kCreate,
            denied_alias_created_directory.wstring(), 88);
    DWORD exit_code = 0;
    FILETIME denied_mapping_write_time_after{};
    const bool denied_mapping_time_unchanged =
        GetFileTime(
            denied_mapping_handle, nullptr, nullptr,
            &denied_mapping_write_time_after) &&
        CompareFileTime(
            &denied_mapping_write_time_before,
            &denied_mapping_write_time_after) == 0;
    USHORT denied_mapping_compression_after = 0;
    const bool denied_mapping_compression_unchanged =
        ReadCompressionState(
            denied_mapping_handle, denied_mapping_compression_after) &&
        denied_mapping_compression_after == denied_mapping_compression_before;
    std::vector<std::uint8_t> denied_delete_security_after;
    const bool denied_delete_security_unchanged =
        ReadSecurityDescriptor(
            denied_delete_path, denied_delete_security_after) &&
        denied_delete_security_after == denied_delete_security_before;
    CloseHandle(denied_disposition_handle);
    CloseHandle(denied_truncate_handle);
    CloseHandle(denied_mapping_handle);
    CloseHandle(read_only_mapping_handle);
    CloseHandle(denied_directory_handle);
    CloseHandle(denied_overlapped_handle);
    const bool exact_exit = process.ExitCode(exit_code) == bolt::common::ProcessStatus::kSuccess &&
                            violation_events &&
                            exit_code == 0 &&
                            WaitForSingleObject(allowed, 0) == WAIT_OBJECT_0 &&
                            WaitForSingleObject(denied, 0) == WAIT_TIMEOUT &&
                            !std::filesystem::exists(denied_path) &&
                            std::filesystem::exists(denied_delete_path) &&
                            GetFileAttributesW(denied_delete_path.c_str()) ==
                                denied_delete_attributes &&
                            denied_delete_security_unchanged &&
                            !std::filesystem::exists(denied_create_directory) &&
                            std::filesystem::is_directory(denied_remove_directory) &&
                            std::filesystem::exists(denied_move_source) &&
                            !std::filesystem::exists(denied_move_destination) &&
                            !std::filesystem::exists(denied_hardlink_destination) &&
                            ReadFixture(denied_copy_source) == replacement_nonce &&
                            !std::filesystem::exists(denied_copy_destination) &&
                            ReadFixture(allowed_copy_source) == copy_nonce &&
                            ReadFixture(allowed_copy_destination) == copy_nonce &&
                            !std::filesystem::exists(missing_copy_source) &&
                            !std::filesystem::exists(missing_copy_destination) &&
                            ReadFixture(denied_alias_target) == protected_nonce &&
                            GetFileAttributesW(denied_alias_target.c_str()) ==
                                denied_alias_attributes_before &&
                            !std::filesystem::exists(denied_alias_created_directory) &&
                            ReadFixture(allowed_alias_move_source) == move_nonce &&
                            !std::filesystem::exists(denied_alias_move_target) &&
                            ReadFixture(allowed_replace_target) == replace_target_nonce &&
                            ReadFixture(allowed_handle_rename_source) == handle_rename_nonce &&
                            !std::filesystem::exists(denied_handle_rename_destination) &&
                            !std::filesystem::exists(allowed_disposition_path) &&
                            ReadFixture(denied_disposition_path) == disposition_nonce &&
                            ReadFixture(allowed_truncate_path) == truncate_nonce.substr(0, 4) &&
                            ReadFixture(denied_truncate_path) == truncate_nonce &&
                            ReadFixture(allowed_mapping_path) == "Xapping-content" &&
                            ReadFixture(denied_mapping_path) == mapping_nonce &&
                            denied_mapping_time_unchanged &&
                            denied_mapping_compression_unchanged &&
                            ReadFixture(read_only_mapping_path) == read_only_mapping_nonce &&
                            !std::filesystem::exists(denied_hardlink_escape_target) &&
                            !std::filesystem::exists(forbidden_junction);
    CloseHandle(allowed);
    CloseHandle(denied);
    if (event_client != INVALID_HANDLE_VALUE) {
        CloseHandle(event_client);
    }
    CloseHandle(release);
    DeleteFileW(denied_delete_path.c_str());
    RemoveDirectoryW(denied_remove_directory.c_str());
    DeleteFileW(denied_move_source.c_str());
    DeleteFileW(denied_copy_source.c_str());
    DeleteFileW(denied_copy_destination.c_str());
    DeleteFileW(allowed_copy_source.c_str());
    DeleteFileW(allowed_copy_destination.c_str());
    DeleteFileW(allowed_alias_move_source.c_str());
    DeleteFileW(allowed_replace_target.c_str());
    DeleteFileW(allowed_handle_rename_source.c_str());
    DeleteFileW(denied_disposition_path.c_str());
    DeleteFileW(allowed_truncate_path.c_str());
    DeleteFileW(denied_truncate_path.c_str());
    DeleteFileW(allowed_mapping_path.c_str());
    DeleteFileW(denied_mapping_path.c_str());
    DeleteFileW(read_only_mapping_path.c_str());
    std::filesystem::remove_all(test_root, filesystem_error);
    if (!exact_exit) {
        return false;
    }

    auto breakaway = options;
    breakaway.creation_flags = CREATE_BREAKAWAY_FROM_JOB;
    bolt::common::SuspendedProcess rejected;
    const auto breakaway_status = bolt::common::SuspendedProcess::Create(breakaway, rejected);
    return breakaway_status == bolt::common::ProcessStatus::kUnsupportedFlags;
}
