#include "common/execution_job.h"
#include "common/immutable_policy_mapping.h"
#include "common/private_pipe.h"
#include "common/required_mitigations.h"
#include "common/suspended_process.h"
#include "protocol/event_frame.h"
#include "protocol/runtime_payload.h"
#include "protocol/version.h"
#include "tests/policy_fixture.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
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

bool HasRequiredProcessMitigations() {
    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY extension_points{};
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY image_load{};
    return GetProcessMitigationPolicy(
               GetCurrentProcess(), ProcessExtensionPointDisablePolicy,
               &extension_points, sizeof(extension_points)) != FALSE &&
           GetProcessMitigationPolicy(
               GetCurrentProcess(), ProcessImageLoadPolicy, &image_load,
               sizeof(image_load)) != FALSE &&
           extension_points.DisableExtensionPoints != 0 &&
           image_load.NoRemoteImages != 0 &&
           image_load.NoLowMandatoryLabelImages != 0 &&
           image_load.PreferSystem32Images != 0;
}

// Narrow Native ABI fixture derived from winsiderss/phnt commit
// 53fbbdc5b5d2b08761db1c7b26bfa8c820924356 (MIT).
struct NativeSectionImageInformation {
    PVOID transfer_address;
    ULONG zero_bits;
    SIZE_T maximum_stack_size;
    SIZE_T committed_stack_size;
    ULONG subsystem_type;
    ULONG subsystem_version;
    ULONG operating_system_version;
    USHORT image_characteristics;
    USHORT dll_characteristics;
    USHORT machine;
    BOOLEAN image_contains_code;
    UCHAR image_flags;
    ULONG loader_flags;
    ULONG image_file_size;
    ULONG checksum;
};

struct NativeRtlUserProcessInformation {
    ULONG length;
    HANDLE process;
    HANDLE thread;
    CLIENT_ID client_id;
    NativeSectionImageInformation image_information;
};

#if defined(_WIN64)
static_assert(sizeof(NativeSectionImageInformation) == 64);
static_assert(sizeof(NativeRtlUserProcessInformation) == 104);
#else
static_assert(sizeof(NativeSectionImageInformation) == 48);
static_assert(sizeof(NativeRtlUserProcessInformation) == 68);
#endif

using RtlCreateProcessParametersExFunction = NTSTATUS(NTAPI*)(
    PRTL_USER_PROCESS_PARAMETERS*, PCUNICODE_STRING, PCUNICODE_STRING,
    PCUNICODE_STRING, PCUNICODE_STRING, PVOID, PCUNICODE_STRING,
    PCUNICODE_STRING, PCUNICODE_STRING, PCUNICODE_STRING, ULONG);
using RtlDestroyProcessParametersFunction = NTSTATUS(NTAPI*)(
    PRTL_USER_PROCESS_PARAMETERS);
using RtlCreateUserProcessFunction = NTSTATUS(NTAPI*)(
    PCUNICODE_STRING, ULONG, PRTL_USER_PROCESS_PARAMETERS,
    PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, HANDLE, BOOLEAN, HANDLE, HANDLE,
    NativeRtlUserProcessInformation*);

union NativePsCreateInfoData {
    struct {
        ULONG init_flags;
        ACCESS_MASK additional_file_access;
    } initial_state;
    ULONG_PTR alignment;
#if defined(_WIN64)
    std::array<std::uint8_t, 72> storage;
#else
    std::array<std::uint8_t, 64> storage;
#endif
};

struct NativePsCreateInfo {
    SIZE_T size;
    ULONG state;
    NativePsCreateInfoData data;
};

struct NativePsAttribute {
    ULONG_PTR attribute;
    SIZE_T size;
    union {
        ULONG_PTR value;
        PVOID value_ptr;
    };
    SIZE_T* return_length;
};

struct NativePsAttributeList {
    SIZE_T total_length;
    NativePsAttribute attributes[1];
};

#if defined(_WIN64)
static_assert(sizeof(NativePsCreateInfo) == 88);
static_assert(sizeof(NativePsAttribute) == 32);
static_assert(sizeof(NativePsAttributeList) == 40);
#else
static_assert(sizeof(NativePsCreateInfo) == 72);
static_assert(sizeof(NativePsAttribute) == 16);
static_assert(sizeof(NativePsAttributeList) == 20);
#endif

using NtCreateUserProcessFunction = NTSTATUS(NTAPI*)(
    PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK, POBJECT_ATTRIBUTES,
    POBJECT_ATTRIBUTES, ULONG, ULONG, PRTL_USER_PROCESS_PARAMETERS,
    NativePsCreateInfo*, NativePsAttributeList*);

bool InitializeUnicodeString(
    std::wstring& value,
    UNICODE_STRING& output) {
    constexpr std::size_t maximum_code_units =
        ((std::numeric_limits<USHORT>::max)() / sizeof(wchar_t)) - 1;
    if (value.size() > maximum_code_units) {
        return false;
    }
    output.Length = static_cast<USHORT>(value.size() * sizeof(wchar_t));
    output.MaximumLength =
        static_cast<USHORT>((value.size() + 1) * sizeof(wchar_t));
    output.Buffer = value.data();
    return true;
}

NTSTATUS CreateNativeRtlProcess(
    const std::wstring& executable,
    const std::wstring& arguments,
    const bool inherit_handles,
    NativeRtlUserProcessInformation& information) {
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto create_parameters =
        reinterpret_cast<RtlCreateProcessParametersExFunction>(GetProcAddress(
            ntdll, "RtlCreateProcessParametersEx"));
    const auto destroy_parameters =
        reinterpret_cast<RtlDestroyProcessParametersFunction>(GetProcAddress(
            ntdll, "RtlDestroyProcessParameters"));
    const auto create_process = reinterpret_cast<RtlCreateUserProcessFunction>(
        GetProcAddress(ntdll, "RtlCreateUserProcess"));
    if (create_parameters == nullptr || destroy_parameters == nullptr ||
        create_process == nullptr) {
        return static_cast<NTSTATUS>(0xC0000002UL);
    }

    std::wstring nt_image_path = L"\\??\\" + executable;
    std::wstring command_line = L"\"" + executable + L"\"";
    if (!arguments.empty()) {
        command_line += L" ";
        command_line += arguments;
    }
    UNICODE_STRING image{};
    UNICODE_STRING command{};
    if (!InitializeUnicodeString(nt_image_path, image) ||
        !InitializeUnicodeString(command_line, command)) {
        return static_cast<NTSTATUS>(0xC0000106UL);
    }
    PRTL_USER_PROCESS_PARAMETERS parameters = nullptr;
    const NTSTATUS parameter_status = create_parameters(
        &parameters, &image, nullptr, nullptr, &command, nullptr, nullptr,
        nullptr, nullptr, nullptr, 1);
    if (parameter_status < 0) {
        return parameter_status;
    }
    information = {};
    information.length = sizeof(information);
    const NTSTATUS create_status = create_process(
        &image, 0, parameters, nullptr, nullptr, nullptr,
        inherit_handles ? TRUE : FALSE, nullptr, nullptr, &information);
    destroy_parameters(parameters);
    return create_status;
}

void CloseNativeProcessInformation(
    NativeRtlUserProcessInformation& information) {
    if (information.thread != nullptr) {
        CloseHandle(information.thread);
    }
    if (information.process != nullptr) {
        CloseHandle(information.process);
    }
    information = {};
}

NTSTATUS CreateNativeNtProcess(
    const std::wstring& executable,
    const std::wstring& arguments,
    const bool inherit_handles,
    HANDLE& process,
    HANDLE& thread,
    const ULONG additional_process_flags = 0) {
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto create_parameters =
        reinterpret_cast<RtlCreateProcessParametersExFunction>(GetProcAddress(
            ntdll, "RtlCreateProcessParametersEx"));
    const auto destroy_parameters =
        reinterpret_cast<RtlDestroyProcessParametersFunction>(GetProcAddress(
            ntdll, "RtlDestroyProcessParameters"));
    const auto create_process = reinterpret_cast<NtCreateUserProcessFunction>(
        GetProcAddress(ntdll, "NtCreateUserProcess"));
    if (create_parameters == nullptr || destroy_parameters == nullptr ||
        create_process == nullptr) {
        return static_cast<NTSTATUS>(0xC0000002UL);
    }

    std::wstring nt_image_path = L"\\??\\" + executable;
    std::wstring command_line = L"\"" + executable + L"\"";
    if (!arguments.empty()) {
        command_line += L" ";
        command_line += arguments;
    }
    UNICODE_STRING image{};
    UNICODE_STRING command{};
    if (!InitializeUnicodeString(nt_image_path, image) ||
        !InitializeUnicodeString(command_line, command)) {
        return static_cast<NTSTATUS>(0xC0000106UL);
    }

    PRTL_USER_PROCESS_PARAMETERS parameters = nullptr;
    const NTSTATUS parameter_status = create_parameters(
        &parameters, &image, nullptr, nullptr, &command, nullptr, nullptr,
        nullptr, nullptr, nullptr, 1);
    if (parameter_status < 0) {
        return parameter_status;
    }

    NativePsCreateInfo create_info{};
    create_info.size = sizeof(create_info);
    NativePsAttributeList attributes{};
    attributes.total_length = sizeof(attributes);
    attributes.attributes[0].attribute = 0x00020005;
    attributes.attributes[0].size = image.Length;
    attributes.attributes[0].value_ptr = image.Buffer;
    process = nullptr;
    thread = nullptr;
    constexpr ULONG process_create_flags_inherit_handles = 0x00000004;
    constexpr ULONG thread_create_flags_create_suspended = 0x00000001;
    const NTSTATUS create_status = create_process(
        &process, &thread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, nullptr,
        nullptr,
        (inherit_handles ? process_create_flags_inherit_handles : 0) |
            additional_process_flags,
        thread_create_flags_create_suspended, parameters, &create_info,
        &attributes);
    destroy_parameters(parameters);
    return create_status;
}

void CloseNativeNtProcess(HANDLE& process, HANDLE& thread) {
    if (thread != nullptr) {
        CloseHandle(thread);
    }
    if (process != nullptr) {
        CloseHandle(process);
    }
    process = nullptr;
    thread = nullptr;
}

HANDLE CreateRestrictedPrimaryToken() {
    HANDLE process_token = nullptr;
    if (!OpenProcessToken(
            GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY,
            &process_token)) {
        return nullptr;
    }
    HANDLE restricted_token = nullptr;
    const BOOL created = CreateRestrictedToken(
        process_token, DISABLE_MAX_PRIVILEGE, 0, nullptr, 0, nullptr, 0, nullptr,
        &restricted_token);
    CloseHandle(process_token);
    return created ? restricted_token : nullptr;
}

bool WaitForSuccessfulChild(PROCESS_INFORMATION& process) {
    const DWORD wait = WaitForSingleObject(process.hProcess, 5'000);
    DWORD exit_code = 0;
    const bool succeeded =
        wait == WAIT_OBJECT_0 &&
        GetExitCodeProcess(process.hProcess, &exit_code) != FALSE &&
        exit_code == 0;
    if (wait != WAIT_OBJECT_0) {
        TerminateProcess(process.hProcess, 238);
        WaitForSingleObject(process.hProcess, 5'000);
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    process = {};
    return succeeded;
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

bool ReadAnyFilesystemViolationForPath(
    const HANDLE event_pipe,
    const std::uint32_t process_id,
    const std::wstring& expected_path) {
    bool found = false;
    for (;;) {
        std::array<std::uint8_t, bolt::protocol::kEventHeaderLength> header{};
        DWORD first_read = 0;
        if (!ReadFile(
                event_pipe, header.data(), static_cast<DWORD>(header.size()),
                &first_read, nullptr)) {
            const DWORD error = GetLastError();
            if (!found) {
                std::fprintf(
                    stderr,
                    "compatibility event stream ended without match: error=%lu pid=%lu\n",
                    static_cast<unsigned long>(error),
                    static_cast<unsigned long>(process_id));
            }
            return (error == ERROR_BROKEN_PIPE || error == ERROR_NO_DATA) &&
                   found;
        }
        if (first_read == 0) {
            return found;
        }
        if (first_read != header.size()) {
            return false;
        }
        const std::size_t payload_length = ReadU32(header.data() + 8);
        std::vector<std::uint8_t> payload(payload_length);
        if (!ReadExact(event_pipe, payload.data(), payload.size())) {
            return false;
        }
        if (payload.size() < 9 || ReadU32(payload.data()) != process_id) {
            continue;
        }
        const std::uint16_t kind =
            static_cast<std::uint16_t>(header[6]) |
            (static_cast<std::uint16_t>(header[7]) << 8U);
        if (kind != 2) {
            if (kind == 3) {
                const std::size_t key_length = ReadU32(payload.data() + 5);
                if (9 + key_length == payload.size()) {
                    const std::string key(
                        reinterpret_cast<const char*>(payload.data() + 9),
                        key_length);
                    std::fprintf(
                        stderr,
                        "compatibility unexpected registry violation: pid=%lu operation=%u key=%s\n",
                        static_cast<unsigned long>(process_id),
                        static_cast<unsigned int>(payload[4]), key.c_str());
                }
            } else {
                std::fprintf(
                    stderr,
                    "compatibility unexpected event: pid=%lu kind=%u operation=%u\n",
                    static_cast<unsigned long>(process_id),
                    static_cast<unsigned int>(kind),
                    static_cast<unsigned int>(payload[4]));
            }
            continue;
        }
        const std::size_t path_length = ReadU32(payload.data() + 5);
        if (9 + path_length * sizeof(wchar_t) != payload.size()) {
            continue;
        }
        std::wstring path(path_length, L'\0');
        std::memcpy(
            path.data(), payload.data() + 9,
            path.size() * sizeof(wchar_t));
        const bool matches = CompareStringOrdinal(
                                 path.c_str(), -1, expected_path.c_str(), -1,
                                 TRUE) == CSTR_EQUAL;
        if (!matches) {
            std::fwprintf(
                stderr,
                L"compatibility unexpected violation: pid=%lu operation=%u path=%ls\n",
                static_cast<unsigned long>(process_id),
                static_cast<unsigned int>(payload[4]), path.c_str());
        }
        found = found || matches;
    }
}

bool ReadProcessViolation(
    const HANDLE event_pipe,
    const std::uint32_t process_id,
    const bolt::protocol::ProcessOperation operation,
    const std::uint64_t sequence,
    const bool allow_later_sequence = false) {
    std::array<std::uint8_t, bolt::protocol::kProcessViolationFrameLength> expected{};
    std::size_t written = 0;
    if (bolt::protocol::EncodeProcessViolationFrame(
            process_id, operation, sequence, expected.data(), expected.size(),
            written) != bolt::protocol::FrameEncodeStatus::kSuccess ||
        written != expected.size()) {
        return false;
    }
    constexpr std::size_t maximum_skipped_frames = 64;
    constexpr std::uint32_t maximum_payload_length = 1U << 20U;
    for (std::size_t skipped = 0; skipped <= maximum_skipped_frames;
         ++skipped) {
        std::array<std::uint8_t, bolt::protocol::kEventHeaderLength> header{};
        if (!ReadExact(event_pipe, header.data(), header.size())) {
            return false;
        }
        const std::uint32_t payload_length =
            static_cast<std::uint32_t>(header[8]) |
            (static_cast<std::uint32_t>(header[9]) << 8U) |
            (static_cast<std::uint32_t>(header[10]) << 16U) |
            (static_cast<std::uint32_t>(header[11]) << 24U);
        if (payload_length > maximum_payload_length) {
            return false;
        }
        std::vector<std::uint8_t> payload(payload_length);
        if (!ReadExact(event_pipe, payload.data(), payload.size())) {
            return false;
        }
        if (payload_length !=
            bolt::protocol::kProcessViolationFrameLength -
                bolt::protocol::kEventHeaderLength) {
            continue;
        }
        std::array<std::uint8_t, bolt::protocol::kProcessViolationFrameLength>
            actual{};
        std::copy(header.begin(), header.end(), actual.begin());
        std::copy(payload.begin(), payload.end(),
                  actual.begin() + bolt::protocol::kEventHeaderLength);
        if (actual == expected) {
            return true;
        }
        if (allow_later_sequence) {
            std::uint64_t actual_sequence = 0;
            for (std::size_t index = 0; index < sizeof(actual_sequence);
                 ++index) {
                actual_sequence |=
                    static_cast<std::uint64_t>(header[12 + index])
                    << (index * 8U);
            }
            std::array<
                std::uint8_t,
                bolt::protocol::kProcessViolationFrameLength>
                later_expected{};
            std::size_t later_written = 0;
            if (actual_sequence >= sequence &&
                bolt::protocol::EncodeProcessViolationFrame(
                    process_id, operation, actual_sequence,
                    later_expected.data(), later_expected.size(),
                    later_written) ==
                    bolt::protocol::FrameEncodeStatus::kSuccess &&
                later_written == later_expected.size() &&
                actual == later_expected) {
                return true;
            }
        }
    }
    return false;
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
    if (argument_count != 42) {
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
    using InstalledFilesystemHookCountFunction = std::uint32_t (*)();
    const auto installed_filesystem_hook_count =
        reinterpret_cast<InstalledFilesystemHookCountFunction>(
            GetProcAddress(hook, "BoltSandboxInstalledFilesystemHookCount"));
    constexpr std::uint32_t required_filesystem_hook_count = 86;
    const bool copy_file_2_present =
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CopyFile2") != nullptr;
    const std::uint32_t expected_filesystem_hook_count =
        required_filesystem_hook_count + (copy_file_2_present ? 1U : 0U);
    if (installed_filesystem_hook_count == nullptr ||
        installed_filesystem_hook_count() != expected_filesystem_hook_count) {
        return 286;
    }
    if (!HasRequiredProcessMitigations()) {
        return 244;
    }
    const HANDLE inherited_policy = reinterpret_cast<HANDLE>(
        _wcstoui64(arguments[41], nullptr, 10));
    void* const readable_policy =
        MapViewOfFile(inherited_policy, FILE_MAP_READ, 0, 0, 0);
    MEMORY_BASIC_INFORMATION policy_memory{};
    const bool policy_size_known =
        readable_policy != nullptr &&
        VirtualQuery(
            readable_policy, &policy_memory, sizeof(policy_memory)) ==
            sizeof(policy_memory) &&
        policy_memory.RegionSize <= (std::numeric_limits<DWORD>::max)();
    if (readable_policy != nullptr) {
        UnmapViewOfFile(readable_policy);
    }
    SetLastError(ERROR_SUCCESS);
    void* const writable_policy =
        MapViewOfFile(inherited_policy, FILE_MAP_WRITE, 0, 0, 0);
    const DWORD writable_policy_error = GetLastError();
    if (!policy_size_known || writable_policy != nullptr ||
        writable_policy_error != ERROR_ACCESS_DENIED ||
        !CloseHandle(inherited_policy)) {
        if (writable_policy != nullptr) {
            UnmapViewOfFile(writable_policy);
        }
        return 331;
    }
    const HANDLE fake_policy = CreateFileMappingW(
        INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
        static_cast<DWORD>(policy_memory.RegionSize), nullptr);
    const auto initialize_runtime = reinterpret_cast<std::uint32_t (*)()>(
        GetProcAddress(hook, "BoltSandboxInitializeRuntime"));
    constexpr std::uint32_t already_initialized = 1;
    if (fake_policy != inherited_policy || initialize_runtime == nullptr ||
        initialize_runtime() != already_initialized || !initialized()) {
        if (fake_policy != nullptr) {
            CloseHandle(fake_policy);
        }
        return 332;
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
    constexpr DWORD native_last_error_sentinel = ERROR_INVALID_DATA;
    constexpr FILE_INFORMATION_CLASS file_end_of_file_information =
        static_cast<FILE_INFORMATION_CLASS>(20);
    SetLastError(native_last_error_sentinel);
    const NTSTATUS direct_end_of_file_result =
        zw_set_information_file == nullptr
            ? status_access_denied
            : zw_set_information_file(
                  denied_truncate_handle, &io_status, &direct_end_of_file,
                  sizeof(direct_end_of_file), file_end_of_file_information);
    if (zw_set_information_file == nullptr ||
        direct_end_of_file_result != status_access_denied ||
        GetLastError() != native_last_error_sentinel) {
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
    SetLastError(native_last_error_sentinel);
    const NTSTATUS denied_section_result =
        nt_create_section == nullptr
            ? status_access_denied
            : nt_create_section(
                  &denied_section, SECTION_MAP_READ | SECTION_MAP_WRITE, nullptr,
                  nullptr, PAGE_READWRITE, SEC_COMMIT, denied_mapping_file);
    if (nt_create_section == nullptr ||
        denied_section_result != status_access_denied ||
        denied_section != nullptr ||
        GetLastError() != native_last_error_sentinel) {
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
    SetLastError(native_last_error_sentinel);
    const NTSTATUS query_information_result =
        nt_query_information_file == nullptr
            ? status_access_denied
            : nt_query_information_file(
                  denied_mapping_file, &io_status, &queried_basic_information,
                  sizeof(queried_basic_information), file_basic_information);
    if (nt_query_information_file == nullptr ||
        query_information_result != status_access_denied ||
        GetLastError() != native_last_error_sentinel) {
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
    SetLastError(native_last_error_sentinel);
    const NTSTATUS query_attributes_result =
        nt_query_attributes_file == nullptr
            ? status_access_denied
            : nt_query_attributes_file(
                  &nt_metadata_attributes, &nt_path_basic_information);
    if (nt_query_attributes_file == nullptr ||
        query_attributes_result != status_access_denied ||
        GetLastError() != native_last_error_sentinel) {
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
    SetLastError(native_last_error_sentinel);
    const NTSTATUS query_full_attributes_result =
        nt_query_full_attributes_file == nullptr
            ? status_access_denied
            : nt_query_full_attributes_file(
                  &nt_metadata_attributes, &nt_path_full_information);
    if (nt_query_full_attributes_file == nullptr ||
        query_full_attributes_result != status_access_denied ||
        GetLastError() != native_last_error_sentinel) {
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
    SetLastError(native_last_error_sentinel);
    const NTSTATUS query_directory_result =
        nt_query_directory_file == nullptr
            ? status_access_denied
            : nt_query_directory_file(
                  denied_directory_handle, nullptr, nullptr, nullptr, &io_status,
                  directory_information.data(),
                  static_cast<ULONG>(directory_information.size()),
                  file_directory_information, FALSE, nullptr, TRUE);
    if (nt_query_directory_file == nullptr ||
        query_directory_result != status_access_denied ||
        GetLastError() != native_last_error_sentinel) {
        return 162;
    }
    constexpr ULONG restart_scan = 0x01;
    SetLastError(native_last_error_sentinel);
    const NTSTATUS query_directory_ex_result =
        nt_query_directory_file_ex == nullptr
            ? status_access_denied
            : nt_query_directory_file_ex(
                  denied_directory_handle, nullptr, nullptr, nullptr, &io_status,
                  directory_information.data(),
                  static_cast<ULONG>(directory_information.size()),
                  file_directory_information, restart_scan, nullptr);
    if (nt_query_directory_file_ex == nullptr ||
        query_directory_ex_result != status_access_denied ||
        GetLastError() != native_last_error_sentinel) {
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
    SetLastError(native_last_error_sentinel);
    const NTSTATUS nt_read_result =
        nt_read_file == nullptr
            ? status_access_denied
            : nt_read_file(
                  denied_mapping_file, nullptr, nullptr, nullptr, &io_status,
                  denied_nt_read_buffer.data(),
                  static_cast<ULONG>(denied_nt_read_buffer.size()), nullptr,
                  nullptr);
    if (nt_read_file == nullptr || nt_read_result != status_access_denied ||
        io_status.Status != status_access_denied || io_status.Information != 0 ||
        GetLastError() != native_last_error_sentinel ||
        denied_nt_read_buffer != std::array<char, 4>{'y', 'y', 'y', 'y'}) {
        return 181;
    }
    io_status.Status = 0;
    io_status.Information = 123;
    std::array<char, 4> denied_nt_write_buffer = forbidden_write;
    SetLastError(native_last_error_sentinel);
    const NTSTATUS nt_write_result =
        nt_write_file == nullptr
            ? status_access_denied
            : nt_write_file(
                  denied_mapping_file, nullptr, nullptr, nullptr, &io_status,
                  denied_nt_write_buffer.data(),
                  static_cast<ULONG>(denied_nt_write_buffer.size()), nullptr,
                  nullptr);
    if (nt_write_file == nullptr || nt_write_result != status_access_denied ||
        io_status.Status != status_access_denied || io_status.Information != 0 ||
        GetLastError() != native_last_error_sentinel) {
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
    const std::filesystem::path alias_remove_directory =
        std::filesystem::path(arguments[18]).parent_path() / L"removable-directory";
    if (RemoveDirectoryW(alias_remove_directory.c_str()) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 191;
    }
    const std::filesystem::path alias_wildcard =
        std::filesystem::path(arguments[18]).parent_path() / L"*";
    const std::string ansi_alias_wildcard = AnsiPath(alias_wildcard.c_str());
    WIN32_FIND_DATAW alias_find_data_w{};
    alias_find_data_w.dwFileAttributes = 0xA5A5A5A5;
    const WIN32_FIND_DATAW alias_find_data_w_before = alias_find_data_w;
    find = FindFirstFileW(alias_wildcard.c_str(), &alias_find_data_w);
    if (find != INVALID_HANDLE_VALUE || GetLastError() != ERROR_ACCESS_DENIED ||
        std::memcmp(
            &alias_find_data_w, &alias_find_data_w_before,
            sizeof(alias_find_data_w)) != 0) {
        if (find != INVALID_HANDLE_VALUE) {
            FindClose(find);
        }
        return 192;
    }
    WIN32_FIND_DATAA alias_find_data_a{};
    alias_find_data_a.dwFileAttributes = 0xA5A5A5A5;
    const WIN32_FIND_DATAA alias_find_data_a_before = alias_find_data_a;
    find = ansi_alias_wildcard.empty()
               ? INVALID_HANDLE_VALUE
               : FindFirstFileA(ansi_alias_wildcard.c_str(), &alias_find_data_a);
    if (find != INVALID_HANDLE_VALUE || GetLastError() != ERROR_ACCESS_DENIED ||
        std::memcmp(
            &alias_find_data_a, &alias_find_data_a_before,
            sizeof(alias_find_data_a)) != 0) {
        if (find != INVALID_HANDLE_VALUE) {
            FindClose(find);
        }
        return 193;
    }
    find = FindFirstFileExW(
        alias_wildcard.c_str(), FindExInfoBasic, &alias_find_data_w,
        FindExSearchNameMatch, nullptr, 0);
    if (find != INVALID_HANDLE_VALUE || GetLastError() != ERROR_ACCESS_DENIED ||
        std::memcmp(
            &alias_find_data_w, &alias_find_data_w_before,
            sizeof(alias_find_data_w)) != 0) {
        if (find != INVALID_HANDLE_VALUE) {
            FindClose(find);
        }
        return 194;
    }
    find = FindFirstFileExA(
        ansi_alias_wildcard.c_str(), FindExInfoBasic, &alias_find_data_a,
        FindExSearchNameMatch, nullptr, 0);
    if (find != INVALID_HANDLE_VALUE || GetLastError() != ERROR_ACCESS_DENIED ||
        std::memcmp(
            &alias_find_data_a, &alias_find_data_a_before,
            sizeof(alias_find_data_a)) != 0) {
        if (find != INVALID_HANDLE_VALUE) {
            FindClose(find);
        }
        return 195;
    }
    const std::filesystem::path alias_create_directory_a =
        std::filesystem::path(arguments[18]).parent_path() / L"created-directory-a";
    const std::string ansi_alias_create_directory =
        AnsiPath(alias_create_directory_a.c_str());
    if (ansi_alias_create_directory.empty() ||
        CreateDirectoryA(ansi_alias_create_directory.c_str(), nullptr) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 196;
    }
    const std::filesystem::path alias_remove_directory_a =
        std::filesystem::path(arguments[18]).parent_path() / L"removable-directory-a";
    const std::string ansi_alias_remove_directory =
        AnsiPath(alias_remove_directory_a.c_str());
    if (ansi_alias_remove_directory.empty() ||
        RemoveDirectoryA(ansi_alias_remove_directory.c_str()) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 197;
    }
    using NtCreateFileFunction = NTSTATUS(NTAPI*)(
        PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
        PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
    using NtOpenFileFunction = NTSTATUS(NTAPI*)(
        PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG,
        ULONG);
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto nt_create_file = reinterpret_cast<NtCreateFileFunction>(
        GetProcAddress(ntdll, "NtCreateFile"));
    const auto nt_open_file = reinterpret_cast<NtOpenFileFunction>(
        GetProcAddress(ntdll, "NtOpenFile"));
    std::wstring nt_create_path = L"\\??\\" + std::wstring(arguments[5]);
    UNICODE_STRING nt_create_name{
        static_cast<USHORT>(nt_create_path.size() * sizeof(wchar_t)),
        static_cast<USHORT>((nt_create_path.size() + 1) * sizeof(wchar_t)),
        nt_create_path.data()};
    OBJECT_ATTRIBUTES nt_create_attributes{
        sizeof(OBJECT_ATTRIBUTES), nullptr, &nt_create_name,
        OBJ_CASE_INSENSITIVE, nullptr, nullptr};
    IO_STATUS_BLOCK nt_create_status{};
    HANDLE nt_created_file = nullptr;
    SetLastError(native_last_error_sentinel);
    const NTSTATUS nt_create_result =
        nt_create_file == nullptr
            ? status_access_denied
            : nt_create_file(
                  &nt_created_file, FILE_GENERIC_WRITE | SYNCHRONIZE,
                  &nt_create_attributes, &nt_create_status, nullptr,
                  FILE_ATTRIBUTE_NORMAL,
                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                  FILE_CREATE,
                  FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                  nullptr, 0);
    const DWORD nt_create_last_error = GetLastError();
    if (nt_create_file == nullptr || nt_create_result != status_access_denied ||
        nt_created_file != nullptr ||
        nt_create_status.Status != status_access_denied ||
        nt_create_status.Information != 0 ||
        nt_create_last_error != native_last_error_sentinel) {
        if (nt_created_file != nullptr) {
            CloseHandle(nt_created_file);
        }
        return 198;
    }
    std::wstring nt_open_path = L"\\??\\" + std::wstring(arguments[6]);
    UNICODE_STRING nt_open_name{
        static_cast<USHORT>(nt_open_path.size() * sizeof(wchar_t)),
        static_cast<USHORT>((nt_open_path.size() + 1) * sizeof(wchar_t)),
        nt_open_path.data()};
    OBJECT_ATTRIBUTES nt_open_attributes{
        sizeof(OBJECT_ATTRIBUTES), nullptr, &nt_open_name,
        OBJ_CASE_INSENSITIVE, nullptr, nullptr};
    IO_STATUS_BLOCK nt_open_status{};
    HANDLE nt_opened_file = nullptr;
    SetLastError(native_last_error_sentinel);
    const NTSTATUS nt_open_result =
        nt_open_file == nullptr
            ? status_access_denied
            : nt_open_file(
                  &nt_opened_file, FILE_GENERIC_READ | SYNCHRONIZE,
                  &nt_open_attributes, &nt_open_status,
                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                  FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    const DWORD nt_open_last_error = GetLastError();
    if (nt_open_file == nullptr || nt_open_result != status_access_denied ||
        nt_opened_file != nullptr ||
        nt_open_status.Status != status_access_denied ||
        nt_open_status.Information != 0 ||
        nt_open_last_error != native_last_error_sentinel) {
        if (nt_opened_file != nullptr) {
            CloseHandle(nt_opened_file);
        }
        return 199;
    }
    std::wstring nt_relative_path =
        std::filesystem::path(arguments[6]).filename().wstring();
    UNICODE_STRING nt_relative_name{
        static_cast<USHORT>(nt_relative_path.size() * sizeof(wchar_t)),
        static_cast<USHORT>((nt_relative_path.size() + 1) * sizeof(wchar_t)),
        nt_relative_path.data()};
    OBJECT_ATTRIBUTES nt_relative_attributes{
        sizeof(OBJECT_ATTRIBUTES),
        reinterpret_cast<HANDLE>(_wcstoui64(arguments[36], nullptr, 10)),
        &nt_relative_name, OBJ_CASE_INSENSITIVE, nullptr, nullptr};
    IO_STATUS_BLOCK nt_relative_status{};
    HANDLE nt_relative_file = nullptr;
    SetLastError(native_last_error_sentinel);
    const NTSTATUS nt_relative_result = nt_open_file(
        &nt_relative_file, FILE_GENERIC_READ | SYNCHRONIZE,
        &nt_relative_attributes, &nt_relative_status,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    const DWORD nt_relative_last_error = GetLastError();
    if (nt_relative_result != status_access_denied ||
        nt_relative_file != nullptr ||
        nt_relative_status.Status != status_access_denied ||
        nt_relative_status.Information != 0 ||
        nt_relative_last_error != native_last_error_sentinel) {
        if (nt_relative_file != nullptr) {
            CloseHandle(nt_relative_file);
        }
        return 200;
    }
    std::wstring nt_allowed_path = L"\\??\\" + std::wstring(arguments[14]);
    UNICODE_STRING nt_allowed_name{
        static_cast<USHORT>(nt_allowed_path.size() * sizeof(wchar_t)),
        static_cast<USHORT>((nt_allowed_path.size() + 1) * sizeof(wchar_t)),
        nt_allowed_path.data()};
    OBJECT_ATTRIBUTES nt_allowed_attributes{
        sizeof(OBJECT_ATTRIBUTES), nullptr, &nt_allowed_name,
        OBJ_CASE_INSENSITIVE, nullptr, nullptr};
    IO_STATUS_BLOCK nt_allowed_status{};
    HANDLE nt_allowed_file = nullptr;
    SetLastError(native_last_error_sentinel);
    const NTSTATUS nt_allowed_result = nt_open_file(
        &nt_allowed_file, FILE_GENERIC_READ | SYNCHRONIZE,
        &nt_allowed_attributes, &nt_allowed_status,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    const DWORD nt_allowed_last_error = GetLastError();
    if (nt_allowed_result < 0 || nt_allowed_file == nullptr ||
        nt_allowed_status.Status < 0 ||
        nt_allowed_last_error != native_last_error_sentinel) {
        if (nt_allowed_file != nullptr) {
            CloseHandle(nt_allowed_file);
        }
        return 282;
    }
    CloseHandle(nt_allowed_file);
    std::array<std::uint8_t, 1'024> notification_buffer{};
    notification_buffer.fill(0xA5);
    const auto notification_buffer_before = notification_buffer;
    DWORD notification_bytes = 0xA5A5A5A5;
    const HANDLE notification_event =
        CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (notification_event == nullptr) {
        return 201;
    }
    OVERLAPPED notification_overlapped{};
    notification_overlapped.hEvent = notification_event;
    const HANDLE notification_directory =
        reinterpret_cast<HANDLE>(_wcstoui64(arguments[36], nullptr, 10));
    const BOOL notification_result = ReadDirectoryChangesW(
        notification_directory, notification_buffer.data(),
        static_cast<DWORD>(notification_buffer.size()), FALSE,
        FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME,
        &notification_bytes, &notification_overlapped, nullptr);
    const DWORD notification_error = GetLastError();
    if (notification_result) {
        CancelIoEx(notification_directory, &notification_overlapped);
        WaitForSingleObject(notification_event, 5'000);
    }
    const bool notification_denied =
        !notification_result && notification_error == ERROR_ACCESS_DENIED &&
        notification_bytes == 0 &&
        notification_buffer == notification_buffer_before &&
        WaitForSingleObject(notification_event, 0) == WAIT_TIMEOUT;
    CloseHandle(notification_event);
    if (!notification_denied) {
        return 202;
    }
    using NtNotifyChangeDirectoryFileFunction = NTSTATUS(NTAPI*)(
        HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG,
        ULONG, BOOLEAN);
    using NtNotifyChangeDirectoryFileExFunction = NTSTATUS(NTAPI*)(
        HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG,
        ULONG, BOOLEAN, ULONG);
    const auto nt_notify_change_directory_file =
        reinterpret_cast<NtNotifyChangeDirectoryFileFunction>(
            GetProcAddress(ntdll, "NtNotifyChangeDirectoryFile"));
    const auto nt_notify_change_directory_file_ex =
        reinterpret_cast<NtNotifyChangeDirectoryFileExFunction>(
            GetProcAddress(ntdll, "NtNotifyChangeDirectoryFileEx"));
    const HANDLE nt_notification_event =
        CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (nt_notify_change_directory_file == nullptr ||
        nt_notify_change_directory_file_ex == nullptr ||
        nt_notification_event == nullptr) {
        if (nt_notification_event != nullptr) {
            CloseHandle(nt_notification_event);
        }
        return 203;
    }
    std::array<std::uint8_t, 1'024> nt_notification_buffer{};
    nt_notification_buffer.fill(0x5A);
    const auto nt_notification_buffer_before = nt_notification_buffer;
    IO_STATUS_BLOCK nt_notification_status{};
    SetLastError(native_last_error_sentinel);
    NTSTATUS nt_notification_result = nt_notify_change_directory_file(
        notification_directory, nt_notification_event, nullptr, nullptr,
        &nt_notification_status, nt_notification_buffer.data(),
        static_cast<ULONG>(nt_notification_buffer.size()),
        FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME, FALSE);
    if (nt_notification_result != status_access_denied) {
        CancelIoEx(notification_directory, nullptr);
        WaitForSingleObject(nt_notification_event, 5'000);
    }
    const bool nt_notification_denied =
        nt_notification_result == status_access_denied &&
        nt_notification_status.Status == status_access_denied &&
        nt_notification_status.Information == 0 &&
        GetLastError() == native_last_error_sentinel &&
        nt_notification_buffer == nt_notification_buffer_before &&
        WaitForSingleObject(nt_notification_event, 0) == WAIT_TIMEOUT;
    if (!nt_notification_denied) {
        CloseHandle(nt_notification_event);
        return 204;
    }
    nt_notification_status = {};
    SetLastError(native_last_error_sentinel);
    nt_notification_result = nt_notify_change_directory_file_ex(
        notification_directory, nt_notification_event, nullptr, nullptr,
        &nt_notification_status, nt_notification_buffer.data(),
        static_cast<ULONG>(nt_notification_buffer.size()),
        FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME, FALSE, 1);
    if (nt_notification_result != status_access_denied) {
        CancelIoEx(notification_directory, nullptr);
        WaitForSingleObject(nt_notification_event, 5'000);
    }
    const bool nt_notification_ex_denied =
        nt_notification_result == status_access_denied &&
        nt_notification_status.Status == status_access_denied &&
        nt_notification_status.Information == 0 &&
        GetLastError() == native_last_error_sentinel &&
        nt_notification_buffer == nt_notification_buffer_before &&
        WaitForSingleObject(nt_notification_event, 0) == WAIT_TIMEOUT;
    CloseHandle(nt_notification_event);
    if (!nt_notification_ex_denied) {
        return 205;
    }
    FILE_ID_DESCRIPTOR denied_file_id{};
    denied_file_id.dwSize = sizeof(denied_file_id);
    denied_file_id.Type = FileIdType;
    denied_file_id.FileId.QuadPart =
        static_cast<LONGLONG>(_wcstoui64(arguments[38], nullptr, 10));
    const HANDLE id_opened_file = OpenFileById(
        notification_directory, &denied_file_id, FILE_GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, 0);
    if (id_opened_file != INVALID_HANDLE_VALUE ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        if (id_opened_file != INVALID_HANDLE_VALUE) {
            CloseHandle(id_opened_file);
        }
        return 206;
    }
    std::array<wchar_t, 512> denied_final_path_w{};
    denied_final_path_w.fill(L'Z');
    const auto denied_final_path_w_before = denied_final_path_w;
    if (GetFinalPathNameByHandleW(
            denied_mapping_file, denied_final_path_w.data(),
            static_cast<DWORD>(denied_final_path_w.size()),
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) != 0 ||
        GetLastError() != ERROR_ACCESS_DENIED ||
        denied_final_path_w != denied_final_path_w_before) {
        return 207;
    }
    std::array<char, 512> denied_final_path_a{};
    denied_final_path_a.fill('Z');
    const auto denied_final_path_a_before = denied_final_path_a;
    if (GetFinalPathNameByHandleA(
            denied_mapping_file, denied_final_path_a.data(),
            static_cast<DWORD>(denied_final_path_a.size()),
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) != 0 ||
        GetLastError() != ERROR_ACCESS_DENIED ||
        denied_final_path_a != denied_final_path_a_before) {
        return 208;
    }
    const std::wstring descendant_executable = CurrentExecutable();
    std::wstring descendant_command =
        L"\"" + descendant_executable + L"\" --job-child";
    STARTUPINFOW descendant_startup{};
    descendant_startup.cb = sizeof(descendant_startup);
    PROCESS_INFORMATION descendant_process{};
    const BOOL descendant_created = CreateProcessW(
        descendant_executable.c_str(), descendant_command.data(), nullptr,
        nullptr, FALSE, 0, nullptr, nullptr, &descendant_startup,
        &descendant_process);
    const DWORD descendant_error = GetLastError();
    if (descendant_created) {
        TerminateProcess(descendant_process.hProcess, 209);
        WaitForSingleObject(descendant_process.hProcess, 5'000);
        CloseHandle(descendant_process.hThread);
        CloseHandle(descendant_process.hProcess);
        return 209;
    }
    if (descendant_error != ERROR_ACCESS_DENIED ||
        descendant_process.hProcess != nullptr ||
        descendant_process.hThread != nullptr ||
        descendant_process.dwProcessId != 0 ||
        descendant_process.dwThreadId != 0) {
        return 210;
    }
    const std::string descendant_executable_a =
        AnsiPath(descendant_executable.c_str());
    const std::string descendant_command_a_source =
        AnsiPath(descendant_command.c_str());
    std::vector<char> descendant_command_a(
        descendant_command_a_source.begin(), descendant_command_a_source.end());
    descendant_command_a.push_back('\0');
    STARTUPINFOA descendant_startup_a{};
    descendant_startup_a.cb = sizeof(descendant_startup_a);
    PROCESS_INFORMATION descendant_process_a{};
    if (descendant_executable_a.empty() ||
        descendant_command_a_source.empty()) {
        return 211;
    }
    const BOOL descendant_created_a = CreateProcessA(
        descendant_executable_a.c_str(), descendant_command_a.data(), nullptr,
        nullptr, FALSE, 0, nullptr, nullptr, &descendant_startup_a,
        &descendant_process_a);
    const DWORD descendant_error_a = GetLastError();
    if (descendant_created_a) {
        TerminateProcess(descendant_process_a.hProcess, 211);
        WaitForSingleObject(descendant_process_a.hProcess, 5'000);
        CloseHandle(descendant_process_a.hThread);
        CloseHandle(descendant_process_a.hProcess);
        return 211;
    }
    if (descendant_error_a != ERROR_ACCESS_DENIED ||
        descendant_process_a.hProcess != nullptr ||
        descendant_process_a.hThread != nullptr ||
        descendant_process_a.dwProcessId != 0 ||
        descendant_process_a.dwThreadId != 0) {
        return 212;
    }
    PROCESS_INFORMATION as_user_process{};
    std::wstring as_user_command = descendant_command;
    const BOOL as_user_created = CreateProcessAsUserW(
        nullptr, descendant_executable.c_str(), as_user_command.data(), nullptr,
        nullptr, FALSE, 0, nullptr, nullptr, &descendant_startup,
        &as_user_process);
    const DWORD as_user_error = GetLastError();
    if (as_user_created || as_user_error != ERROR_ACCESS_DENIED ||
        as_user_process.hProcess != nullptr ||
        as_user_process.hThread != nullptr || as_user_process.dwProcessId != 0 ||
        as_user_process.dwThreadId != 0) {
        if (as_user_created) {
            TerminateProcess(as_user_process.hProcess, 215);
            WaitForSingleObject(as_user_process.hProcess, 5'000);
            CloseHandle(as_user_process.hThread);
            CloseHandle(as_user_process.hProcess);
        }
        return 215;
    }
    std::vector<char> as_user_command_a(
        descendant_command_a_source.begin(), descendant_command_a_source.end());
    as_user_command_a.push_back('\0');
    PROCESS_INFORMATION as_user_process_a{};
    const BOOL as_user_created_a = CreateProcessAsUserA(
        nullptr, descendant_executable_a.c_str(), as_user_command_a.data(), nullptr,
        nullptr, FALSE, 0, nullptr, nullptr, &descendant_startup_a,
        &as_user_process_a);
    const DWORD as_user_error_a = GetLastError();
    if (as_user_created_a || as_user_error_a != ERROR_ACCESS_DENIED ||
        as_user_process_a.hProcess != nullptr ||
        as_user_process_a.hThread != nullptr ||
        as_user_process_a.dwProcessId != 0 || as_user_process_a.dwThreadId != 0) {
        if (as_user_created_a) {
            TerminateProcess(as_user_process_a.hProcess, 216);
            WaitForSingleObject(as_user_process_a.hProcess, 5'000);
            CloseHandle(as_user_process_a.hThread);
            CloseHandle(as_user_process_a.hProcess);
        }
        return 216;
    }
    NativeRtlUserProcessInformation denied_native_process{};
    const NTSTATUS denied_native_status = CreateNativeRtlProcess(
        descendant_executable + L".missing-native-image", L"", false,
        denied_native_process);
    if (denied_native_status != status_access_denied ||
        denied_native_process.process != nullptr ||
        denied_native_process.thread != nullptr ||
        denied_native_process.client_id.UniqueProcess != nullptr ||
        denied_native_process.client_id.UniqueThread != nullptr) {
        if (denied_native_process.process != nullptr) {
            TerminateProcess(denied_native_process.process, 218);
            WaitForSingleObject(denied_native_process.process, 5'000);
        }
        CloseNativeProcessInformation(denied_native_process);
        return 218;
    }
    HANDLE denied_nt_process = nullptr;
    HANDLE denied_nt_thread = nullptr;
    const NTSTATUS denied_nt_status = CreateNativeNtProcess(
        descendant_executable + L".missing-nt-native-image", L"", false,
        denied_nt_process, denied_nt_thread);
    if (denied_nt_status != status_access_denied ||
        denied_nt_process != nullptr || denied_nt_thread != nullptr) {
        if (denied_nt_process != nullptr) {
            TerminateProcess(denied_nt_process, 219);
            WaitForSingleObject(denied_nt_process, 5'000);
        }
        CloseNativeNtProcess(denied_nt_process, denied_nt_thread);
        return 219;
    }
    std::wstring token_command = descendant_command;
    PROCESS_INFORMATION token_process{};
    const BOOL token_created = CreateProcessWithTokenW(
        nullptr, 0, descendant_executable.c_str(), token_command.data(), 0,
        nullptr, nullptr, &descendant_startup, &token_process);
    const DWORD token_error = GetLastError();
    if (token_created || token_error != ERROR_ACCESS_DENIED ||
        token_process.hProcess != nullptr || token_process.hThread != nullptr ||
        token_process.dwProcessId != 0 || token_process.dwThreadId != 0) {
        if (token_created) {
            TerminateProcess(token_process.hProcess, 213);
            WaitForSingleObject(token_process.hProcess, 5'000);
            CloseHandle(token_process.hThread);
            CloseHandle(token_process.hProcess);
        }
        return 213;
    }
    std::wstring logon_command = descendant_command;
    PROCESS_INFORMATION logon_process{};
    const BOOL logon_created = CreateProcessWithLogonW(
        L"fixture-user", L".", L"fixture-credential", 0,
        descendant_executable.c_str(), logon_command.data(), 0, nullptr,
        nullptr, &descendant_startup, &logon_process);
    const DWORD logon_error = GetLastError();
    if (logon_created || logon_error != ERROR_ACCESS_DENIED ||
        logon_process.hProcess != nullptr || logon_process.hThread != nullptr ||
        logon_process.dwProcessId != 0 || logon_process.dwThreadId != 0) {
        if (logon_created) {
            TerminateProcess(logon_process.hProcess, 214);
            WaitForSingleObject(logon_process.hProcess, 5'000);
            CloseHandle(logon_process.hThread);
            CloseHandle(logon_process.hProcess);
        }
        return 214;
    }
    const std::wstring missing_elevation_target =
        descendant_executable + L".missing-elevation-target";
    SHELLEXECUTEINFOW elevation{};
    elevation.cbSize = sizeof(elevation);
    elevation.fMask =
        SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
    elevation.hwnd = nullptr;
    elevation.lpVerb = L"RuNaS";
    elevation.lpFile = missing_elevation_target.c_str();
    elevation.nShow = SW_HIDE;
    const BOOL elevation_started = ShellExecuteExW(&elevation);
    const DWORD elevation_error = GetLastError();
    if (elevation_started || elevation_error != ERROR_ACCESS_DENIED ||
        elevation.hProcess != nullptr) {
        if (elevation.hProcess != nullptr) {
            TerminateProcess(elevation.hProcess, 217);
            WaitForSingleObject(elevation.hProcess, 5'000);
            CloseHandle(elevation.hProcess);
        }
        return 217;
    }

    const auto inherited_allowed_section = reinterpret_cast<HANDLE>(
        _wcstoui64(arguments[39], nullptr, 10));
    const auto inherited_denied_section = reinterpret_cast<HANDLE>(
        _wcstoui64(arguments[40], nullptr, 10));
    const void* inherited_allowed_view = MapViewOfFile(
        inherited_allowed_section, FILE_MAP_READ, 0, 0, 0);
    if (inherited_allowed_view == nullptr ||
        std::memcmp(
            inherited_allowed_view, "Xapping-content",
            sizeof("Xapping-content") - 1) != 0) {
        if (inherited_allowed_view != nullptr) {
            UnmapViewOfFile(inherited_allowed_view);
        }
        return 257;
    }
    UnmapViewOfFile(inherited_allowed_view);

    SetLastError(ERROR_SUCCESS);
    void* inherited_denied_view = MapViewOfFile(
        inherited_denied_section, FILE_MAP_READ, 0, 0, 0);
    const DWORD inherited_denied_error = GetLastError();
    const bool inherited_high_level_denied =
        inherited_denied_view == nullptr &&
        inherited_denied_error == ERROR_ACCESS_DENIED;
    if (inherited_denied_view != nullptr) {
        UnmapViewOfFile(inherited_denied_view);
    }

    using NtMapViewOfSectionFunction = NTSTATUS(NTAPI*)(
        HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T,
        ULONG, ULONG, ULONG);
    using NtUnmapViewOfSectionFunction = NTSTATUS(NTAPI*)(HANDLE, PVOID);
    const HMODULE mapping_ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto nt_map_view_of_section =
        reinterpret_cast<NtMapViewOfSectionFunction>(
            GetProcAddress(mapping_ntdll, "NtMapViewOfSection"));
    const auto nt_unmap_view_of_section =
        reinterpret_cast<NtUnmapViewOfSectionFunction>(
            GetProcAddress(mapping_ntdll, "NtUnmapViewOfSection"));
    PVOID direct_denied_base = nullptr;
    SIZE_T direct_denied_size = 0;
    SetLastError(native_last_error_sentinel);
    const NTSTATUS direct_denied_status =
        nt_map_view_of_section == nullptr
            ? static_cast<NTSTATUS>(0xC0000002UL)
            : nt_map_view_of_section(
                  inherited_denied_section, GetCurrentProcess(),
                  &direct_denied_base, 0, 0, nullptr, &direct_denied_size, 2,
                  0, PAGE_READWRITE);
    const bool inherited_native_denied =
        direct_denied_status == status_access_denied &&
        direct_denied_base == nullptr && direct_denied_size == 0 &&
        GetLastError() == native_last_error_sentinel;
    if (direct_denied_base != nullptr && nt_unmap_view_of_section != nullptr) {
        nt_unmap_view_of_section(GetCurrentProcess(), direct_denied_base);
    }
    if (!inherited_high_level_denied || !inherited_native_denied) {
        return 258;
    }

    struct NtFileLinkInformation {
        BOOLEAN replace_if_exists;
        HANDLE root_directory;
        ULONG file_name_length;
        WCHAR file_name[1];
    };
    struct NtFileLinkInformationEx {
        ULONG flags;
        HANDLE root_directory;
        ULONG file_name_length;
        WCHAR file_name[1];
    };
    const auto make_link_information = [](const std::wstring& nt_path) {
        const std::size_t name_bytes = nt_path.size() * sizeof(wchar_t);
        std::vector<std::uint8_t> buffer(
            offsetof(NtFileLinkInformation, file_name) + name_bytes);
        auto* information = reinterpret_cast<NtFileLinkInformation*>(buffer.data());
        information->replace_if_exists = FALSE;
        information->root_directory = nullptr;
        information->file_name_length = static_cast<ULONG>(name_bytes);
        std::memcpy(information->file_name, nt_path.data(), name_bytes);
        return buffer;
    };
    const auto make_link_information_ex = [](
                                               const std::wstring& path,
                                               const HANDLE root_directory) {
        const std::size_t name_bytes = path.size() * sizeof(wchar_t);
        std::vector<std::uint8_t> buffer(
            offsetof(NtFileLinkInformationEx, file_name) + name_bytes);
        auto* information = reinterpret_cast<NtFileLinkInformationEx*>(buffer.data());
        information->flags = 0;
        information->root_directory = root_directory;
        information->file_name_length = static_cast<ULONG>(name_bytes);
        std::memcpy(information->file_name, path.data(), name_bytes);
        return buffer;
    };
    constexpr FILE_INFORMATION_CLASS file_link_information =
        static_cast<FILE_INFORMATION_CLASS>(11);
    constexpr FILE_INFORMATION_CLASS file_link_information_ex =
        static_cast<FILE_INFORMATION_CLASS>(72);
    const std::wstring allowed_link_path = std::wstring(arguments[16]) + L".native-link";
    const std::wstring allowed_link_ex_path =
        std::wstring(arguments[16]) + L".native-link-ex";
    const std::wstring denied_link_path = std::wstring(arguments[17]) + L".native-link";
    const std::wstring denied_link_ex_path =
        std::wstring(arguments[17]) + L".native-link-ex";
    const std::wstring link_root_path =
        std::filesystem::path(arguments[16]).parent_path().wstring();
    const HANDLE link_root = CreateFileW(
        link_root_path.c_str(), FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (link_root == INVALID_HANDLE_VALUE) {
        return 259;
    }
    auto allowed_link_information =
        make_link_information(L"\\??\\" + allowed_link_path);
    auto allowed_link_information_ex =
        make_link_information_ex(
            std::filesystem::path(allowed_link_ex_path).filename().wstring(), link_root);
    const HANDLE allowed_link_source = CreateFileW(
        arguments[28], FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    IO_STATUS_BLOCK allowed_link_status{};
    IO_STATUS_BLOCK allowed_link_ex_status{};
    if (allowed_link_source == INVALID_HANDLE_VALUE ||
        zw_set_information_file(
            allowed_link_source, &allowed_link_status, allowed_link_information.data(),
            static_cast<ULONG>(allowed_link_information.size()), file_link_information) < 0 ||
        zw_set_information_file(
            allowed_link_source, &allowed_link_ex_status, allowed_link_information_ex.data(),
            static_cast<ULONG>(allowed_link_information_ex.size()),
            file_link_information_ex) < 0) {
        if (allowed_link_source != INVALID_HANDLE_VALUE) {
            CloseHandle(allowed_link_source);
        }
        CloseHandle(link_root);
        return 259;
    }
    if (GetFileAttributesW(allowed_link_path.c_str()) == INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesW(allowed_link_ex_path.c_str()) == INVALID_FILE_ATTRIBUTES ||
        !DeleteFileW(allowed_link_path.c_str()) ||
        !DeleteFileW(allowed_link_ex_path.c_str())) {
        CloseHandle(allowed_link_source);
        CloseHandle(link_root);
        return 260;
    }

    auto denied_destination_information =
        make_link_information(L"\\??\\" + std::wstring(arguments[11]));
    IO_STATUS_BLOCK denied_destination_status{};
    denied_destination_status.Status = 0;
    denied_destination_status.Information = 123;
    const NTSTATUS denied_destination_result = zw_set_information_file(
        allowed_link_source, &denied_destination_status,
        denied_destination_information.data(),
        static_cast<ULONG>(denied_destination_information.size()),
        file_link_information);
    CloseHandle(allowed_link_source);
    if (denied_destination_result != status_access_denied ||
        denied_destination_status.Status != status_access_denied ||
        denied_destination_status.Information != 0) {
        CloseHandle(link_root);
        return 261;
    }

    auto denied_link_information =
        make_link_information(L"\\??\\" + denied_link_path);
    auto denied_link_information_ex =
        make_link_information_ex(
            std::filesystem::path(denied_link_ex_path).filename().wstring(), link_root);
    IO_STATUS_BLOCK denied_link_status{};
    denied_link_status.Status = 0;
    denied_link_status.Information = 123;
    IO_STATUS_BLOCK denied_link_ex_status{};
    denied_link_ex_status.Status = 0;
    denied_link_ex_status.Information = 123;
    const NTSTATUS denied_link_result = zw_set_information_file(
        denied_disposition_handle, &denied_link_status, denied_link_information.data(),
        static_cast<ULONG>(denied_link_information.size()), file_link_information);
    const NTSTATUS denied_link_ex_result = zw_set_information_file(
        denied_disposition_handle, &denied_link_ex_status,
        denied_link_information_ex.data(),
        static_cast<ULONG>(denied_link_information_ex.size()), file_link_information_ex);
    CloseHandle(link_root);
    if (denied_link_result != status_access_denied ||
        denied_link_status.Status != status_access_denied ||
        denied_link_status.Information != 0 ||
        denied_link_ex_result != status_access_denied ||
        denied_link_ex_status.Status != status_access_denied ||
        denied_link_ex_status.Information != 0 ||
        GetFileAttributesW(denied_link_path.c_str()) != INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesW(denied_link_ex_path.c_str()) != INVALID_FILE_ATTRIBUTES) {
        return 262;
    }

    IO_STATUS_BLOCK malformed_link_status{};
    malformed_link_status.Status = 0;
    malformed_link_status.Information = 123;
    IO_STATUS_BLOCK malformed_link_ex_status{};
    malformed_link_ex_status.Status = 0;
    malformed_link_ex_status.Information = 123;
    if (zw_set_information_file(
            denied_disposition_handle, &malformed_link_status, nullptr, 0,
            file_link_information) != status_access_denied ||
        malformed_link_status.Status != status_access_denied ||
        malformed_link_status.Information != 0 ||
        zw_set_information_file(
            denied_disposition_handle, &malformed_link_ex_status, nullptr, 0,
            file_link_information_ex) != status_access_denied ||
        malformed_link_ex_status.Status != status_access_denied ||
        malformed_link_ex_status.Information != 0) {
        return 263;
    }

    const std::wstring root_rename_source =
        std::wstring(arguments[16]) + L".root-rename-source";
    const std::wstring root_rename_intermediate =
        std::wstring(arguments[16]) + L".root-rename-intermediate";
    const std::wstring root_rename_destination =
        std::wstring(arguments[16]) + L".root-rename-destination";
    if (!CopyFileW(arguments[28], root_rename_source.c_str(), TRUE)) {
        return 264;
    }
    const HANDLE rename_root = CreateFileW(
        std::filesystem::path(root_rename_source).parent_path().c_str(),
        FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    const auto make_root_rename = [rename_root](const std::wstring& leaf) {
        const std::size_t name_bytes = leaf.size() * sizeof(wchar_t);
        std::vector<std::uint8_t> buffer(
            offsetof(NtFileRenameInformation, file_name) + name_bytes);
        auto* information = reinterpret_cast<NtFileRenameInformation*>(buffer.data());
        information->replace_if_exists = FALSE;
        information->root_directory = rename_root;
        information->file_name_length = static_cast<ULONG>(name_bytes);
        std::memcpy(information->file_name, leaf.data(), name_bytes);
        return buffer;
    };
    const HANDLE root_rename_source_handle = CreateFileW(
        root_rename_source.c_str(), DELETE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    auto root_rename_information = make_root_rename(
        std::filesystem::path(root_rename_intermediate).filename().wstring());
    IO_STATUS_BLOCK root_rename_status{};
    const NTSTATUS root_rename_result =
        rename_root == INVALID_HANDLE_VALUE ||
                root_rename_source_handle == INVALID_HANDLE_VALUE
            ? status_access_denied
            : zw_set_information_file(
                  root_rename_source_handle, &root_rename_status,
                  root_rename_information.data(),
                  static_cast<ULONG>(root_rename_information.size()),
                  file_rename_information);
    if (root_rename_source_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(root_rename_source_handle);
    }
    if (root_rename_result < 0) {
        if (rename_root != INVALID_HANDLE_VALUE) {
            CloseHandle(rename_root);
        }
        return 265;
    }

    struct NtFileRenameInformationEx {
        ULONG flags;
        HANDLE root_directory;
        ULONG file_name_length;
        WCHAR file_name[1];
    };
    const std::wstring destination_leaf =
        std::filesystem::path(root_rename_destination).filename().wstring();
    const std::size_t destination_bytes = destination_leaf.size() * sizeof(wchar_t);
    std::vector<std::uint8_t> root_rename_ex_buffer(
        offsetof(NtFileRenameInformationEx, file_name) + destination_bytes);
    auto* root_rename_ex =
        reinterpret_cast<NtFileRenameInformationEx*>(root_rename_ex_buffer.data());
    root_rename_ex->flags = 0;
    root_rename_ex->root_directory = rename_root;
    root_rename_ex->file_name_length = static_cast<ULONG>(destination_bytes);
    std::memcpy(root_rename_ex->file_name, destination_leaf.data(), destination_bytes);
    const HANDLE root_rename_intermediate_handle = CreateFileW(
        root_rename_intermediate.c_str(), DELETE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    IO_STATUS_BLOCK root_rename_ex_status{};
    constexpr FILE_INFORMATION_CLASS file_rename_information_ex =
        static_cast<FILE_INFORMATION_CLASS>(65);
    const NTSTATUS root_rename_ex_result =
        root_rename_intermediate_handle == INVALID_HANDLE_VALUE
            ? status_access_denied
            : zw_set_information_file(
                  root_rename_intermediate_handle, &root_rename_ex_status,
                  root_rename_ex_buffer.data(),
                  static_cast<ULONG>(root_rename_ex_buffer.size()),
                  file_rename_information_ex);
    if (root_rename_intermediate_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(root_rename_intermediate_handle);
    }
    if (rename_root != INVALID_HANDLE_VALUE) {
        CloseHandle(rename_root);
    }
    if (root_rename_ex_result < 0 ||
        GetFileAttributesW(root_rename_source.c_str()) != INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesW(root_rename_intermediate.c_str()) != INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesW(root_rename_destination.c_str()) == INVALID_FILE_ATTRIBUTES ||
        !DeleteFileW(root_rename_destination.c_str())) {
        return 266;
    }

    const std::wstring win32_root_rename_source =
        std::wstring(arguments[16]) + L".win32-root-rename-source";
    const std::wstring win32_root_rename_intermediate =
        std::wstring(arguments[16]) + L".win32-root-rename-intermediate";
    const std::wstring win32_root_rename_destination =
        std::wstring(arguments[16]) + L".win32-root-rename-destination";
    if (!CopyFileW(arguments[28], win32_root_rename_source.c_str(), TRUE)) {
        return 267;
    }
    const HANDLE win32_rename_root = CreateFileW(
        std::filesystem::path(win32_root_rename_source).parent_path().c_str(),
        FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    const auto make_win32_root_rename = [win32_rename_root](const std::wstring& leaf) {
        const std::size_t name_bytes = leaf.size() * sizeof(wchar_t);
        std::vector<std::uint8_t> buffer(
            offsetof(FILE_RENAME_INFO, FileName) + name_bytes + sizeof(wchar_t));
        auto* information = reinterpret_cast<FILE_RENAME_INFO*>(buffer.data());
        information->Flags = 0;
        information->RootDirectory = win32_rename_root;
        information->FileNameLength = static_cast<DWORD>(name_bytes);
        std::memcpy(information->FileName, leaf.data(), name_bytes);
        return buffer;
    };
    const HANDLE win32_root_source_handle = CreateFileW(
        win32_root_rename_source.c_str(), DELETE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    auto win32_root_rename_information = make_win32_root_rename(
        std::filesystem::path(win32_root_rename_intermediate).filename().wstring());
    const BOOL win32_root_rename_result =
        win32_rename_root != INVALID_HANDLE_VALUE &&
        win32_root_source_handle != INVALID_HANDLE_VALUE &&
        SetFileInformationByHandle(
            win32_root_source_handle, FileRenameInfo,
            win32_root_rename_information.data(),
            static_cast<DWORD>(win32_root_rename_information.size()));
    const DWORD win32_root_rename_error = GetLastError();
    auto win32_root_rename_ex_information = make_win32_root_rename(
        std::filesystem::path(win32_root_rename_destination).filename().wstring());
    const BOOL win32_root_rename_ex_result =
        win32_root_source_handle != INVALID_HANDLE_VALUE &&
        SetFileInformationByHandle(
            win32_root_source_handle, FileRenameInfoEx,
            win32_root_rename_ex_information.data(),
            static_cast<DWORD>(win32_root_rename_ex_information.size()));
    const DWORD win32_root_rename_ex_error = GetLastError();
    if (win32_root_source_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(win32_root_source_handle);
    }
    if (win32_rename_root != INVALID_HANDLE_VALUE) {
        CloseHandle(win32_rename_root);
    }
    if (win32_root_rename_result ||
        win32_root_rename_error != ERROR_INVALID_PARAMETER ||
        win32_root_rename_ex_result ||
        win32_root_rename_ex_error != ERROR_INVALID_PARAMETER ||
        GetFileAttributesW(win32_root_rename_source.c_str()) == INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesW(win32_root_rename_intermediate.c_str()) !=
            INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesW(win32_root_rename_destination.c_str()) !=
            INVALID_FILE_ATTRIBUTES ||
        !DeleteFileW(win32_root_rename_source.c_str())) {
        return 269;
    }

    struct NtFileShortNameInformation {
        ULONG file_name_length;
        WCHAR file_name[13];
    };
    NtFileShortNameInformation short_name_information{};
    if (swprintf_s(
            short_name_information.file_name, L"BOLT%04X.TMP",
            GetCurrentProcessId() & 0xffffU) < 0) {
        return 270;
    }
    short_name_information.file_name_length = static_cast<ULONG>(
        std::wcslen(short_name_information.file_name) * sizeof(wchar_t));
    constexpr FILE_INFORMATION_CLASS file_short_name_information =
        static_cast<FILE_INFORMATION_CLASS>(40);
    const HANDLE allowed_short_name_handle = CreateFileW(
        arguments[26], DELETE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    IO_STATUS_BLOCK allowed_short_name_status{};
    const NTSTATUS allowed_short_name_result =
        allowed_short_name_handle == INVALID_HANDLE_VALUE
            ? status_access_denied
            : zw_set_information_file(
                  allowed_short_name_handle, &allowed_short_name_status,
                  &short_name_information,
                  offsetof(NtFileShortNameInformation, file_name) +
                      short_name_information.file_name_length,
                  file_short_name_information);
    if (allowed_short_name_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(allowed_short_name_handle);
    }
    if (allowed_short_name_result < 0) {
        return 270;
    }
    IO_STATUS_BLOCK denied_short_name_status{};
    denied_short_name_status.Status = 0;
    denied_short_name_status.Information = 123;
    if (zw_set_information_file(
            denied_disposition_handle, &denied_short_name_status,
            &short_name_information,
            offsetof(NtFileShortNameInformation, file_name) +
                short_name_information.file_name_length,
            file_short_name_information) != status_access_denied ||
        denied_short_name_status.Status != status_access_denied ||
        denied_short_name_status.Information != 0) {
        return 271;
    }

    FILE_ALLOCATION_INFO denied_allocation_information{};
    denied_allocation_information.AllocationSize.QuadPart = 1;
    if (SetFileInformationByHandle(
            denied_truncate_handle, FileAllocationInfo,
            &denied_allocation_information, sizeof(denied_allocation_information)) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 272;
    }
    FILE_END_OF_FILE_INFO denied_end_of_file_information{};
    denied_end_of_file_information.EndOfFile.QuadPart = 1;
    if (SetFileInformationByHandle(
            denied_truncate_handle, FileEndOfFileInfo,
            &denied_end_of_file_information, sizeof(denied_end_of_file_information)) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 273;
    }

    const std::filesystem::path directory_template =
        std::filesystem::path(arguments[15]).parent_path();
    const std::filesystem::path allowed_directory_ex_w =
        std::wstring(arguments[15]) + L".directory-ex-w";
    const std::filesystem::path allowed_directory_ex_a =
        std::wstring(arguments[15]) + L".directory-ex-a";
    if (!CreateDirectoryExW(
            directory_template.c_str(), allowed_directory_ex_w.c_str(), nullptr) ||
        !RemoveDirectoryW(allowed_directory_ex_w.c_str())) {
        return 274;
    }
    const std::string ansi_directory_template = AnsiPath(directory_template.c_str());
    const std::string ansi_allowed_directory_ex_a =
        AnsiPath(allowed_directory_ex_a.c_str());
    if (ansi_directory_template.empty() || ansi_allowed_directory_ex_a.empty() ||
        !CreateDirectoryExA(
            ansi_directory_template.c_str(), ansi_allowed_directory_ex_a.c_str(),
            nullptr) ||
        !RemoveDirectoryA(ansi_allowed_directory_ex_a.c_str())) {
        return 275;
    }
    const std::filesystem::path denied_directory_ex_w =
        std::wstring(arguments[7]) + L".ex-w";
    if (CreateDirectoryExW(
            directory_template.c_str(), denied_directory_ex_w.c_str(), nullptr) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 276;
    }
    const std::filesystem::path denied_directory_ex_a =
        std::wstring(arguments[7]) + L".ex-a";
    const std::string ansi_denied_directory_ex_a =
        AnsiPath(denied_directory_ex_a.c_str());
    if (ansi_denied_directory_ex_a.empty() ||
        CreateDirectoryExA(
            ansi_directory_template.c_str(), ansi_denied_directory_ex_a.c_str(),
            nullptr) ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        return 277;
    }

    const HANDLE read_only_source = reinterpret_cast<HANDLE>(
        _wcstoui64(arguments[30], nullptr, 10));
    HANDLE readable_duplicate = nullptr;
    if (!DuplicateHandle(
            GetCurrentProcess(), read_only_source, GetCurrentProcess(),
            &readable_duplicate, GENERIC_READ, FALSE, 0)) {
        return 278;
    }
    LARGE_INTEGER beginning{};
    std::array<char, 1> duplicate_read{};
    DWORD duplicate_bytes = 0;
    const bool duplicate_readable =
        SetFilePointerEx(readable_duplicate, beginning, nullptr, FILE_BEGIN) != FALSE &&
        ReadFile(
            readable_duplicate, duplicate_read.data(),
            static_cast<DWORD>(duplicate_read.size()), &duplicate_bytes,
            nullptr) != FALSE &&
        duplicate_bytes == duplicate_read.size();
    CloseHandle(readable_duplicate);
    if (!duplicate_readable) {
        return 279;
    }

    HANDLE writable_duplicate = nullptr;
    if (!DuplicateHandle(
            GetCurrentProcess(), read_only_source, GetCurrentProcess(),
            &writable_duplicate, GENERIC_WRITE, FALSE, 0)) {
        return 280;
    }
    duplicate_bytes = 123;
    const char replacement = 'X';
    SetLastError(ERROR_SUCCESS);
    const BOOL duplicate_write =
        SetFilePointerEx(writable_duplicate, beginning, nullptr, FILE_BEGIN) != FALSE
            ? WriteFile(
                  writable_duplicate, &replacement, 1, &duplicate_bytes, nullptr)
            : FALSE;
    const DWORD duplicate_write_error = GetLastError();
    CloseHandle(writable_duplicate);
    if (duplicate_write || duplicate_write_error != ERROR_ACCESS_DENIED ||
        duplicate_bytes != 0) {
        return 281;
    }

    SetLastError(native_last_error_sentinel);
    const HANDLE existing_open_always = CreateFileW(
        arguments[14], GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    const DWORD existing_open_always_error = GetLastError();
    if (existing_open_always == INVALID_HANDLE_VALUE ||
        existing_open_always_error != ERROR_ALREADY_EXISTS) {
        if (existing_open_always != INVALID_HANDLE_VALUE) {
            CloseHandle(existing_open_always);
        }
        return 283;
    }
    CloseHandle(existing_open_always);

    SetLastError(native_last_error_sentinel);
    const HANDLE created_open_always = CreateFileW(
        arguments[17], GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    const DWORD created_open_always_error = GetLastError();
    if (created_open_always == INVALID_HANDLE_VALUE ||
        created_open_always_error != ERROR_SUCCESS) {
        if (created_open_always != INVALID_HANDLE_VALUE) {
            CloseHandle(created_open_always);
        }
        return 284;
    }
    CloseHandle(created_open_always);
    if (!DeleteFileW(arguments[17])) {
        return 285;
    }

    const auto flush_events = reinterpret_cast<BOOL (*)(DWORD)>(
        GetProcAddress(hook, "BoltSandboxFlushEvents"));
    if (flush_events == nullptr || !flush_events(5'000)) {
        return 104;
    }
    return 0;
}

int RunInheritedProcessLeaf(const int argument_count, wchar_t** arguments) {
    if (argument_count != 3 && argument_count != 4 && argument_count != 5) {
        return 220;
    }
    const HMODULE hook = GetModuleHandleW(arguments[2]);
    const auto initialized = hook == nullptr
                                 ? nullptr
                                 : reinterpret_cast<BOOL (*)()>(GetProcAddress(
                                       hook, "BoltSandboxRuntimeInitialized"));
    if (initialized == nullptr || !initialized()) {
        return 221;
    }
    if (!HasRequiredProcessMitigations()) {
        return 245;
    }
    const auto initialize_runtime = reinterpret_cast<std::uint32_t (*)()>(
        GetProcAddress(hook, "BoltSandboxInitializeRuntime"));
    const auto installed_hook_count = reinterpret_cast<std::uint32_t (*)()>(
        GetProcAddress(hook, "BoltSandboxInstalledFilesystemHookCount"));
    constexpr std::uint32_t already_initialized = 1;
    const std::uint32_t hook_count_before =
        installed_hook_count == nullptr ? 0 : installed_hook_count();
    constexpr std::uint32_t required_filesystem_hook_count = 86;
    const bool copy_file_2_present =
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CopyFile2") != nullptr;
    const std::uint32_t expected_hook_count =
        required_filesystem_hook_count + (copy_file_2_present ? 1U : 0U);
    if (initialize_runtime == nullptr || installed_hook_count == nullptr ||
        initialize_runtime() != already_initialized ||
        installed_hook_count() != hook_count_before ||
        hook_count_before != expected_hook_count ||
        !initialized()) {
        return 311;
    }
    BOOL remains_in_job = FALSE;
    if (!IsProcessInJob(GetCurrentProcess(), nullptr, &remains_in_job) ||
        !remains_in_job) {
        return 286;
    }
    if (argument_count == 4) {
        const HANDLE entered = reinterpret_cast<HANDLE>(
            _wcstoui64(arguments[3], nullptr, 10));
        if (!SetEvent(entered)) {
            return 226;
        }
    }
    if (argument_count == 5) {
        const DWORD required = GetEnvironmentVariableW(arguments[3], nullptr, 0);
        if (required == 0) {
            return 327;
        }
        std::vector<wchar_t> value(required);
        const DWORD written = GetEnvironmentVariableW(
            arguments[3], value.data(), static_cast<DWORD>(value.size()));
        if (written + 1 != required || std::wstring_view(value.data(), written) !=
                                           std::wstring_view(arguments[4])) {
            return 327;
        }
    }
    return 0;
}

std::uint16_t ReadU16(const std::uint8_t* const bytes) {
    return static_cast<std::uint16_t>(bytes[0]) |
           static_cast<std::uint16_t>(bytes[1]) << 8;
}

std::uint64_t ReadU64(const std::uint8_t* const bytes) {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < 8; ++index) {
        value |= static_cast<std::uint64_t>(bytes[index]) << (index * 8);
    }
    return value;
}

bool ReadChildInjectionFailure(
    const HANDLE event_pipe,
    const std::uint32_t parent_process_id,
    const bolt::protocol::ChildInjectionFailureReason reason) {
    std::uint64_t expected_sequence = 1;
    for (;;) {
        std::array<std::uint8_t, bolt::protocol::kEventHeaderLength> header{};
        if (!ReadExact(event_pipe, header.data(), header.size())) {
            return false;
        }
        const std::size_t payload_length = ReadU32(header.data() + 8);
        if (header[0] != 'B' || header[1] != 'L' || header[2] != 'T' ||
            header[3] != '1' ||
            ReadU16(header.data() + 4) != bolt::protocol::kProtocolVersion ||
            payload_length > 1'048'576 ||
            ReadU64(header.data() + 12) != expected_sequence) {
            return false;
        }
        std::vector<std::uint8_t> frame(header.size() + payload_length);
        std::copy(header.begin(), header.end(), frame.begin());
        if (!ReadExact(
                event_pipe, frame.data() + header.size(), payload_length)) {
            return false;
        }
        auto checksum_frame = frame;
        bolt::protocol::RewriteFrameChecksum(
            checksum_frame.data(), checksum_frame.size());
        if (checksum_frame != frame) {
            return false;
        }
        const std::uint16_t kind = ReadU16(header.data() + 6);
        if (kind == 6) {
            if (payload_length != 9 ||
                ReadU32(frame.data() + header.size()) != parent_process_id) {
                return false;
            }
            const std::uint32_t child_process_id =
                ReadU32(frame.data() + header.size() + 4);
            std::array<std::uint8_t,
                       bolt::protocol::kChildInjectionFailureFrameLength>
                expected{};
            std::size_t written = 0;
            return child_process_id != 0 &&
                   bolt::protocol::EncodeChildInjectionFailureFrame(
                       parent_process_id, child_process_id, reason,
                       expected_sequence, expected.data(), expected.size(),
                       written) ==
                       bolt::protocol::FrameEncodeStatus::kSuccess &&
                   written == expected.size() && frame == std::vector<std::uint8_t>(
                                                         expected.begin(),
                                                         expected.end());
        }
        ++expected_sequence;
    }
}

int RunArgumentObservationLeaf(
    const int argument_count,
    wchar_t** arguments) {
    if (argument_count != 8) {
        return 328;
    }
    const HMODULE hook = GetModuleHandleW(arguments[2]);
    const auto initialized = hook == nullptr
                                 ? nullptr
                                 : reinterpret_cast<BOOL (*)()>(GetProcAddress(
                                       hook, "BoltSandboxRuntimeInitialized"));
    BOOL remains_in_job = FALSE;
    if (initialized == nullptr || !initialized() ||
        !HasRequiredProcessMitigations() ||
        !IsProcessInJob(GetCurrentProcess(), nullptr, &remains_in_job) ||
        !remains_in_job) {
        return 329;
    }
    constexpr std::array<std::wstring_view, 5> expected = {
        L"plain", L"space value", L"quote\"value", L"trailing\\", L""};
    for (std::size_t index = 0; index < expected.size(); ++index) {
        if (std::wstring_view(arguments[index + 3]) != expected[index]) {
            return 330;
        }
    }
    return 0;
}

int RunEntryMarkerChild(const int argument_count, wchar_t** arguments) {
    if (argument_count != 3) {
        return 337;
    }
    const HANDLE marker = reinterpret_cast<HANDLE>(
        _wcstoui64(arguments[2], nullptr, 10));
    return SetEvent(marker) ? 0 : 338;
}

int RunCreationMitigationChild(const int argument_count, wchar_t** arguments) {
    if (argument_count != 3 || !HasRequiredProcessMitigations()) {
        return 340;
    }
    const HANDLE marker = reinterpret_cast<HANDLE>(
        _wcstoui64(arguments[2], nullptr, 10));
    return SetEvent(marker) ? 0 : 341;
}

int RunFaultedDescendantParent(
    const int argument_count,
    wchar_t** arguments) {
    if (argument_count != 4) {
        return 343;
    }
    const HMODULE hook = GetModuleHandleW(arguments[2]);
    const auto initialized = hook == nullptr
                                 ? nullptr
                                 : reinterpret_cast<BOOL (*)()>(GetProcAddress(
                                       hook, "BoltSandboxRuntimeInitialized"));
    const HANDLE marker = reinterpret_cast<HANDLE>(
        _wcstoui64(arguments[3], nullptr, 10));
    if (initialized == nullptr || !initialized()) {
        return 344;
    }
    const std::wstring executable = CurrentExecutable();
    std::wstring command =
        L"\"" + executable + L"\" --entry-marker " + arguments[3];
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION child{};
    SetLastError(ERROR_SUCCESS);
    const BOOL created = CreateProcessW(
        executable.c_str(), command.data(), nullptr, nullptr, TRUE, 0, nullptr,
        nullptr, &startup, &child);
    const DWORD error = GetLastError();
    if (created) {
        TerminateProcess(child.hProcess, 345);
        WaitForSingleObject(child.hProcess, 5'000);
        CloseHandle(child.hThread);
        CloseHandle(child.hProcess);
        return 345;
    }
    const auto flush_events = reinterpret_cast<BOOL (*)(DWORD)>(
        GetProcAddress(hook, "BoltSandboxFlushEvents"));
    if (error != ERROR_DLL_INIT_FAILED) {
        return error == ERROR_SUCCESS ? 346 : static_cast<int>(error);
    }
    if (flush_events == nullptr || !flush_events(5'000)) {
        return 347;
    }
    return WaitForSingleObject(marker, 0) == WAIT_TIMEOUT ? 0 : 348;
}

int RunNestedProcess(const int argument_count, wchar_t** arguments) {
    if (argument_count != 4) {
        return 288;
    }
    const HMODULE hook = GetModuleHandleW(arguments[2]);
    const auto initialized = hook == nullptr
                                 ? nullptr
                                 : reinterpret_cast<BOOL (*)()>(GetProcAddress(
                                       hook, "BoltSandboxRuntimeInitialized"));
    BOOL remains_in_job = FALSE;
    if (initialized == nullptr || !initialized() ||
        !HasRequiredProcessMitigations() ||
        !IsProcessInJob(GetCurrentProcess(), nullptr, &remains_in_job) ||
        !remains_in_job) {
        return 289;
    }
    wchar_t* end = nullptr;
    const unsigned long remaining = std::wcstoul(arguments[3], &end, 10);
    if (end == arguments[3] || *end != L'\0' || remaining > 8) {
        return 290;
    }
    if (remaining == 0) {
        return 0;
    }
    const std::wstring executable = CurrentExecutable();
    std::wstring command =
        L"\"" + executable + L"\" --nested-process " + arguments[2] + L" " +
        std::to_wstring(remaining - 1);
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION child{};
    if (!CreateProcessW(
            executable.c_str(), command.data(), nullptr, nullptr, FALSE, 0,
            nullptr, nullptr, &startup, &child) ||
        !WaitForSuccessfulChild(child)) {
        return 291;
    }
    return 0;
}

int RunPersistentLeaf(const int argument_count, wchar_t** arguments) {
    if (argument_count != 5) {
        return 301;
    }
    const HMODULE hook = GetModuleHandleW(arguments[2]);
    const auto initialized = hook == nullptr
                                 ? nullptr
                                 : reinterpret_cast<BOOL (*)()>(GetProcAddress(
                                       hook, "BoltSandboxRuntimeInitialized"));
    BOOL remains_in_job = FALSE;
    const HANDLE ready = reinterpret_cast<HANDLE>(
        _wcstoui64(arguments[3], nullptr, 10));
    const HANDLE release = reinterpret_cast<HANDLE>(
        _wcstoui64(arguments[4], nullptr, 10));
    if (initialized == nullptr || !initialized() ||
        !HasRequiredProcessMitigations() ||
        !IsProcessInJob(GetCurrentProcess(), nullptr, &remains_in_job) ||
        !remains_in_job || !SetEvent(ready) ||
        WaitForSingleObject(release, 10'000) != WAIT_OBJECT_0) {
        return 302;
    }
    return 0;
}

int RunParentExitFixture(const int argument_count, wchar_t** arguments) {
    if (argument_count != 6) {
        return 303;
    }
    const HMODULE hook = GetModuleHandleW(arguments[2]);
    const auto initialized = hook == nullptr
                                 ? nullptr
                                 : reinterpret_cast<BOOL (*)()>(GetProcAddress(
                                       hook, "BoltSandboxRuntimeInitialized"));
    if (initialized == nullptr || !initialized()) {
        return 304;
    }
    const HANDLE child_id_mapping = reinterpret_cast<HANDLE>(
        _wcstoui64(arguments[5], nullptr, 10));
    auto* child_id = static_cast<volatile LONG*>(MapViewOfFile(
        child_id_mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(DWORD)));
    if (child_id == nullptr) {
        return 305;
    }
    const std::wstring executable = CurrentExecutable();
    std::wstring command =
        L"\"" + executable + L"\" --persistent-leaf " + arguments[2] + L" " +
        arguments[3] + L" " + arguments[4];
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION child{};
    if (!CreateProcessW(
            executable.c_str(), command.data(), nullptr, nullptr, TRUE, 0,
            nullptr, nullptr, &startup, &child)) {
        UnmapViewOfFile(const_cast<LONG*>(child_id));
        return 306;
    }
    InterlockedExchange(child_id, static_cast<LONG>(child.dwProcessId));
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);
    UnmapViewOfFile(const_cast<LONG*>(child_id));
    return 0;
}

int RunCompatibilityParent(const int argument_count, wchar_t** arguments) {
    if (argument_count != 8) {
        return 315;
    }
    const HMODULE hook = GetModuleHandleW(arguments[2]);
    const auto initialized = hook == nullptr
                                 ? nullptr
                                 : reinterpret_cast<BOOL (*)()>(GetProcAddress(
                                       hook, "BoltSandboxRuntimeInitialized"));
    if (initialized == nullptr || !initialized() ||
        !HasRequiredProcessMitigations()) {
        return 316;
    }
    const std::wstring kind = arguments[3];
    const std::wstring tool = arguments[4];
    const std::wstring denied = arguments[5];
    const auto compatibility_root =
        std::filesystem::path(denied).parent_path().parent_path();
    const auto compatibility_work = compatibility_root / L"compatibility-work";
    SetEnvironmentVariableW(L"TEMP", compatibility_work.c_str());
    SetEnvironmentVariableW(L"TMP", compatibility_work.c_str());
    SetEnvironmentVariableW(L"POWERSHELL_TELEMETRY_OPTOUT", L"1");
    SetEnvironmentVariableW(L"DOTNET_CLI_TELEMETRY_OPTOUT", L"1");
    SetEnvironmentVariableW(L"DOTNET_EnableDiagnostics", L"0");
    const HANDLE process_id_mapping = reinterpret_cast<HANDLE>(
        _wcstoui64(arguments[6], nullptr, 10));
    const HANDLE child_stdin = reinterpret_cast<HANDLE>(
        _wcstoui64(arguments[7], nullptr, 10));
    auto* process_id = static_cast<volatile LONG*>(MapViewOfFile(
        process_id_mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0,
        sizeof(DWORD) * 2));
    DWORD child_stdin_flags = 0;
    if (process_id == nullptr || child_stdin == nullptr ||
        !GetHandleInformation(child_stdin, &child_stdin_flags)) {
        return 317;
    }
    static_cast<void>(child_stdin_flags);
    const auto run = [&](const std::wstring& parameters,
                         const bool expect_success,
                         const std::size_t observation_index) {
        std::wstring command = L"\"" + tool + L"\" " + parameters;
        SECURITY_ATTRIBUTES stream_security{};
        stream_security.nLength = sizeof(stream_security);
        stream_security.bInheritHandle = TRUE;
        const std::wstring observation_name =
            kind + (expect_success ? L"-allowed" : L"-denied");
        const auto stdout_path =
            compatibility_work / (observation_name + L".stdout");
        const auto stderr_path =
            compatibility_work / (observation_name + L".stderr");
        const HANDLE child_stdout = CreateFileW(
            stdout_path.c_str(), GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_DELETE, &stream_security,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        const HANDLE child_stderr = CreateFileW(
            stderr_path.c_str(), GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_DELETE, &stream_security,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        const auto close_streams = [&] {
            for (const HANDLE handle :
                 {child_stdout, child_stderr}) {
                if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
                    CloseHandle(handle);
                }
            }
        };
        if (child_stdout == INVALID_HANDLE_VALUE ||
            child_stderr == INVALID_HANDLE_VALUE) {
            const DWORD stream_error = GetLastError();
            InterlockedExchange(
                process_id + 1,
                static_cast<LONG>(stream_error == ERROR_SUCCESS
                                      ? ERROR_INVALID_HANDLE
                                      : stream_error));
            close_streams();
            return false;
        }
        const HANDLE inherited_streams[] = {
            child_stdin, child_stdout, child_stderr};
        SIZE_T attribute_bytes = 0;
        InitializeProcThreadAttributeList(nullptr, 2, 0, &attribute_bytes);
        std::vector<std::uint8_t> attribute_storage(attribute_bytes);
        auto* attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(
            attribute_storage.data());
        std::uint64_t mitigation =
            bolt::common::kRequiredCreationMitigationPolicy;
        const bool attributes_initialized =
            InitializeProcThreadAttributeList(
                attributes, 2, 0, &attribute_bytes) != FALSE;
        const bool attributes_ready = attributes_initialized &&
            UpdateProcThreadAttribute(
                attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                const_cast<HANDLE*>(inherited_streams),
                sizeof(inherited_streams), nullptr, nullptr) != FALSE &&
            UpdateProcThreadAttribute(
                attributes, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                &mitigation, sizeof(mitigation), nullptr, nullptr) != FALSE;
        if (!attributes_ready) {
            const DWORD attribute_error = GetLastError();
            InterlockedExchange(
                process_id + 1,
                static_cast<LONG>(attribute_error == ERROR_SUCCESS
                                      ? ERROR_INVALID_PARAMETER
                                      : attribute_error));
            if (attributes_initialized) {
                DeleteProcThreadAttributeList(attributes);
            }
            close_streams();
            return false;
        }
        STARTUPINFOEXW startup{};
        startup.StartupInfo.cb = sizeof(startup);
        startup.StartupInfo.dwFlags =
            STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        startup.StartupInfo.wShowWindow = SW_HIDE;
        startup.StartupInfo.hStdInput = child_stdin;
        startup.StartupInfo.hStdOutput = child_stdout;
        startup.StartupInfo.hStdError = child_stderr;
        startup.lpAttributeList = attributes;
        PROCESS_INFORMATION process{};
        const BOOL created = CreateProcessW(
                tool.c_str(), command.data(), nullptr, nullptr, TRUE,
                CREATE_NEW_CONSOLE | EXTENDED_STARTUPINFO_PRESENT, nullptr,
                compatibility_work.c_str(), &startup.StartupInfo, &process);
        const DWORD create_error = created ? ERROR_SUCCESS : GetLastError();
        DeleteProcThreadAttributeList(attributes);
        close_streams();
        if (!created) {
            std::fwprintf(
                stderr,
                L"compatibility CreateProcessW failed: kind=%ls error=%lu command=%ls\n",
                kind.c_str(), static_cast<unsigned long>(create_error),
                command.c_str());
            InterlockedExchange(
                process_id + 1, static_cast<LONG>(create_error));
            return false;
        }
        InterlockedExchange(
            process_id, static_cast<LONG>(process.dwProcessId));
        const DWORD wait = WaitForSingleObject(process.hProcess, 15'000);
        DWORD exit_code = 0;
        const bool exited =
            wait == WAIT_OBJECT_0 &&
            GetExitCodeProcess(process.hProcess, &exit_code) != FALSE;
        InterlockedExchange(
            process_id + 2 + observation_index,
            exited ? static_cast<LONG>(exit_code) : -1);
        if (!exited) {
            TerminateProcess(process.hProcess, 318);
        }
        if (expect_success && exited && exit_code != 0) {
            InterlockedExchange(process_id + 1, static_cast<LONG>(exit_code));
        }
        if (expect_success && exited && exit_code == 0) {
            InterlockedExchange(process_id, 0);
        }
        if (!exited || (expect_success ? exit_code != 0 : exit_code == 0)) {
            std::fwprintf(
                stderr,
                L"compatibility command mismatch: kind=%ls expected_success=%d wait=%lu exited=%d exit=%lu parameters=%ls\n",
                kind.c_str(), expect_success ? 1 : 0,
                static_cast<unsigned long>(wait), exited ? 1 : 0,
                static_cast<unsigned long>(exit_code), parameters.c_str());
        }
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        return exited && (expect_success ? exit_code == 0 : exit_code != 0);
    };
    std::wstring allowed_parameters;
    std::wstring denied_parameters;
    if (kind == L"cmd") {
        allowed_parameters = L"/d /c exit 0";
        denied_parameters = L"/d /c type \"" + denied + L"\"";
    } else if (kind == L"powershell") {
        allowed_parameters = L"-NoProfile -NonInteractive -Command exit 0";
        denied_parameters =
            L"-NoProfile -NonInteractive -Command \"Get-Content -LiteralPath '" +
            denied + L"' -ErrorAction Stop | Out-Null\"";
    } else if (kind == L"node") {
        allowed_parameters = L"--version";
        denied_parameters =
            L"-e \"require('fs').readFileSync(process.argv[1])\" \"" + denied +
            L"\"";
    } else if (kind == L"python") {
        allowed_parameters = L"--version";
        denied_parameters =
            L"-c \"import pathlib,sys;pathlib.Path(sys.argv[1]).read_bytes()\" \"" +
            denied + L"\"";
    } else if (kind == L"git") {
        allowed_parameters = L"--version";
        denied_parameters = L"hash-object \"" + denied + L"\"";
    } else if (kind == L"cargo") {
        allowed_parameters = L"--version";
        denied_parameters =
            L"verify-project --manifest-path \"" + denied + L"\"";
    } else {
        return 319;
    }
    const bool passed = run(allowed_parameters, true, 0) &&
                        run(denied_parameters, false, 1);
    CloseHandle(child_stdin);
    UnmapViewOfFile(const_cast<LONG*>(process_id));
    return passed ? 0 : 320;
}

int RunInheritedProcessParent(const int argument_count, wchar_t** arguments) {
    if (argument_count != 5 && argument_count != 6) {
        return 222;
    }
    const HMODULE hook = GetModuleHandleW(arguments[2]);
    const auto initialized = hook == nullptr
                                 ? nullptr
                                 : reinterpret_cast<BOOL (*)()>(GetProcAddress(
                                       hook, "BoltSandboxRuntimeInitialized"));
    if (initialized == nullptr || !initialized()) {
        return 223;
    }
    const HANDLE inherited_policy = reinterpret_cast<HANDLE>(
        _wcstoui64(arguments[3], nullptr, 10));
    void* const readable_policy =
        MapViewOfFile(inherited_policy, FILE_MAP_READ, 0, 0, 0);
    MEMORY_BASIC_INFORMATION policy_memory{};
    const bool policy_size_known =
        readable_policy != nullptr &&
        VirtualQuery(
            readable_policy, &policy_memory, sizeof(policy_memory)) ==
            sizeof(policy_memory) &&
        policy_memory.RegionSize <= (std::numeric_limits<DWORD>::max)();
    if (readable_policy != nullptr) {
        UnmapViewOfFile(readable_policy);
    }
    if (!policy_size_known || !CloseHandle(inherited_policy)) {
        return 333;
    }
    const HANDLE fake_policy = CreateFileMappingW(
        INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
        static_cast<DWORD>(policy_memory.RegionSize), nullptr);
    if (fake_policy != inherited_policy) {
        if (fake_policy != nullptr) {
            CloseHandle(fake_policy);
        }
        return 334;
    }
    const HANDLE execution_job = reinterpret_cast<HANDLE>(
        _wcstoui64(arguments[4], nullptr, 10));
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION weakened_job{};
    SetLastError(ERROR_SUCCESS);
    const BOOL weakened_job_applied = SetInformationJobObject(
        execution_job, JobObjectExtendedLimitInformation, &weakened_job,
        sizeof(weakened_job));
    const DWORD weakened_job_error = GetLastError();
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION active_job{};
    if (weakened_job_applied || weakened_job_error != ERROR_ACCESS_DENIED ||
        !QueryInformationJobObject(
            execution_job, JobObjectExtendedLimitInformation, &active_job,
            sizeof(active_job), nullptr) ||
        (active_job.BasicLimitInformation.LimitFlags &
         JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) == 0) {
        return 335;
    }

    const std::wstring executable = CurrentExecutable();
    const std::wstring missing_breakaway_image =
        executable + L".missing-breakaway-image";
    std::wstring breakaway_command_line =
        L"\"" + missing_breakaway_image + L"\"";
    STARTUPINFOW breakaway_startup{};
    breakaway_startup.cb = sizeof(breakaway_startup);
    PROCESS_INFORMATION breakaway_process{
        INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE, 1, 1};
    SetLastError(ERROR_SUCCESS);
    const BOOL breakaway_created = CreateProcessW(
        missing_breakaway_image.c_str(), breakaway_command_line.data(), nullptr,
        nullptr, FALSE, CREATE_BREAKAWAY_FROM_JOB, nullptr, nullptr,
        &breakaway_startup, &breakaway_process);
    const DWORD breakaway_error = GetLastError();
    const auto denied_breakaway = [](
                                       const BOOL created,
                                       const DWORD error,
                                       PROCESS_INFORMATION& information,
                                       const UINT termination_code) {
        const bool denied =
            !created && error == ERROR_ACCESS_DENIED &&
            information.hProcess == nullptr && information.hThread == nullptr &&
            information.dwProcessId == 0 && information.dwThreadId == 0;
        if (created) {
            TerminateProcess(information.hProcess, termination_code);
            WaitForSingleObject(information.hProcess, 5'000);
            CloseHandle(information.hThread);
            CloseHandle(information.hProcess);
        }
        return denied;
    };
    if (!denied_breakaway(
            breakaway_created, breakaway_error, breakaway_process, 246)) {
        return 246;
    }

    const std::string missing_breakaway_image_a =
        AnsiPath(missing_breakaway_image.c_str());
    std::vector<char> breakaway_command_line_a(
        missing_breakaway_image_a.begin(), missing_breakaway_image_a.end());
    breakaway_command_line_a.push_back('\0');
    STARTUPINFOA breakaway_startup_a{};
    breakaway_startup_a.cb = sizeof(breakaway_startup_a);
    PROCESS_INFORMATION breakaway_process_a{
        INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE, 1, 1};
    SetLastError(ERROR_SUCCESS);
    const BOOL breakaway_created_a = CreateProcessA(
        missing_breakaway_image_a.c_str(), breakaway_command_line_a.data(),
        nullptr, nullptr, FALSE, CREATE_BREAKAWAY_FROM_JOB, nullptr, nullptr,
        &breakaway_startup_a, &breakaway_process_a);
    const DWORD breakaway_error_a = GetLastError();
    if (missing_breakaway_image_a.empty() ||
        !denied_breakaway(
            breakaway_created_a, breakaway_error_a, breakaway_process_a, 248)) {
        return 248;
    }

    PROCESS_INFORMATION breakaway_as_user_w{
        INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE, 1, 1};
    std::wstring breakaway_as_user_command = breakaway_command_line;
    SetLastError(ERROR_SUCCESS);
    const BOOL breakaway_as_user_created_w = CreateProcessAsUserW(
        nullptr, missing_breakaway_image.c_str(),
        breakaway_as_user_command.data(), nullptr, nullptr, FALSE,
        CREATE_BREAKAWAY_FROM_JOB, nullptr, nullptr, &breakaway_startup,
        &breakaway_as_user_w);
    const DWORD breakaway_as_user_error_w = GetLastError();
    if (!denied_breakaway(
            breakaway_as_user_created_w, breakaway_as_user_error_w,
            breakaway_as_user_w, 249)) {
        return 249;
    }

    PROCESS_INFORMATION breakaway_as_user_a{
        INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE, 1, 1};
    std::vector<char> breakaway_as_user_command_a = breakaway_command_line_a;
    SetLastError(ERROR_SUCCESS);
    const BOOL breakaway_as_user_created_a = CreateProcessAsUserA(
        nullptr, missing_breakaway_image_a.c_str(),
        breakaway_as_user_command_a.data(), nullptr, nullptr, FALSE,
        CREATE_BREAKAWAY_FROM_JOB, nullptr, nullptr, &breakaway_startup_a,
        &breakaway_as_user_a);
    const DWORD breakaway_as_user_error_a = GetLastError();
    if (!denied_breakaway(
            breakaway_as_user_created_a, breakaway_as_user_error_a,
            breakaway_as_user_a, 250)) {
        return 250;
    }

    PROCESS_INFORMATION breakaway_with_token{
        INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE, 1, 1};
    std::wstring breakaway_with_token_command = breakaway_command_line;
    SetLastError(ERROR_SUCCESS);
    const BOOL breakaway_with_token_created = CreateProcessWithTokenW(
        nullptr, 0, missing_breakaway_image.c_str(),
        breakaway_with_token_command.data(), CREATE_BREAKAWAY_FROM_JOB, nullptr,
        nullptr, &breakaway_startup, &breakaway_with_token);
    const DWORD breakaway_with_token_error = GetLastError();
    if (!denied_breakaway(
            breakaway_with_token_created, breakaway_with_token_error,
            breakaway_with_token, 251)) {
        return 251;
    }

    PROCESS_INFORMATION breakaway_with_logon{
        INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE, 1, 1};
    std::wstring breakaway_with_logon_command = breakaway_command_line;
    SetLastError(ERROR_SUCCESS);
    const BOOL breakaway_with_logon_created = CreateProcessWithLogonW(
        L"fixture-user", L".", L"fixture-credential", 0,
        missing_breakaway_image.c_str(), breakaway_with_logon_command.data(),
        CREATE_BREAKAWAY_FROM_JOB, nullptr, nullptr, &breakaway_startup,
        &breakaway_with_logon);
    const DWORD breakaway_with_logon_error = GetLastError();
    if (!denied_breakaway(
            breakaway_with_logon_created, breakaway_with_logon_error,
            breakaway_with_logon, 252)) {
        return 252;
    }

    constexpr ULONG process_create_flags_breakaway = 0x00000001;
    HANDLE breakaway_nt_process = INVALID_HANDLE_VALUE;
    HANDLE breakaway_nt_thread = INVALID_HANDLE_VALUE;
    const NTSTATUS breakaway_nt_status = CreateNativeNtProcess(
        missing_breakaway_image, L"", false, breakaway_nt_process,
        breakaway_nt_thread, process_create_flags_breakaway);
    constexpr NTSTATUS status_access_denied =
        static_cast<NTSTATUS>(0xC0000022UL);
    if (breakaway_nt_status != status_access_denied ||
        breakaway_nt_process != nullptr || breakaway_nt_thread != nullptr) {
        if (breakaway_nt_process != nullptr &&
            breakaway_nt_process != INVALID_HANDLE_VALUE) {
            TerminateProcess(breakaway_nt_process, 253);
        }
        CloseNativeNtProcess(breakaway_nt_process, breakaway_nt_thread);
        return 253;
    }

    const HANDLE nested_job = CreateJobObjectW(nullptr, nullptr);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION nested_job_defaults{};
    if (nested_job == nullptr ||
        !AssignProcessToJobObject(nested_job, GetCurrentProcess()) ||
        !SetInformationJobObject(
            nested_job, JobObjectExtendedLimitInformation,
            &nested_job_defaults, sizeof(nested_job_defaults))) {
        if (nested_job != nullptr) {
            CloseHandle(nested_job);
        }
        return 336;
    }

    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY weakened_extension{};
    SetLastError(ERROR_SUCCESS);
    const BOOL weakened_extension_applied = SetProcessMitigationPolicy(
        ProcessExtensionPointDisablePolicy, &weakened_extension,
        sizeof(weakened_extension));
    const DWORD weakened_extension_error = GetLastError();
    if (weakened_extension_applied ||
        weakened_extension_error != ERROR_ACCESS_DENIED ||
        !HasRequiredProcessMitigations()) {
        return 255;
    }

    PROCESS_MITIGATION_IMAGE_LOAD_POLICY weakened_image_load{};
    SetLastError(ERROR_SUCCESS);
    const BOOL weakened_image_load_applied = SetProcessMitigationPolicy(
        ProcessImageLoadPolicy, &weakened_image_load,
        sizeof(weakened_image_load));
    const DWORD weakened_image_load_error = GetLastError();
    if (weakened_image_load_applied ||
        weakened_image_load_error != ERROR_ACCESS_DENIED ||
        !HasRequiredProcessMitigations()) {
        return 256;
    }

    BOOL remains_in_job = FALSE;
    const BOOL job_query_succeeded =
        IsProcessInJob(GetCurrentProcess(), nullptr, &remains_in_job);
    if (!job_query_succeeded || !remains_in_job) {
        return 254;
    }
    std::array<wchar_t, MAX_PATH> system_directory{};
    const UINT system_length = GetSystemDirectoryW(
        system_directory.data(), static_cast<UINT>(system_directory.size()));
    if (system_length == 0 || system_length >= system_directory.size()) {
        return 321;
    }
    for (const wchar_t* broker_name : {
             L"schtasks.exe", L"sc.exe", L"wmic.exe", L"at.exe"}) {
        const auto broker =
            std::filesystem::path(system_directory.data()) / broker_name;
        for (const bool include_command_line : {true, false}) {
            std::wstring broker_command =
                L"\"" + broker.wstring() + L"\" /?";
            STARTUPINFOW broker_startup{};
            broker_startup.cb = sizeof(broker_startup);
            PROCESS_INFORMATION broker_process{
                INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE, 1, 1};
            SetLastError(ERROR_SUCCESS);
            const BOOL broker_created = CreateProcessW(
                broker.c_str(),
                include_command_line ? broker_command.data() : nullptr,
                nullptr, nullptr, FALSE, 0, nullptr, nullptr, &broker_startup,
                &broker_process);
            const DWORD broker_error = GetLastError();
            if (broker_created) {
                TerminateProcess(broker_process.hProcess, 323);
                WaitForSingleObject(broker_process.hProcess, 5'000);
                CloseHandle(broker_process.hThread);
                CloseHandle(broker_process.hProcess);
                return 323;
            }
            if (broker_error != ERROR_ACCESS_DENIED ||
                broker_process.hProcess != nullptr ||
                broker_process.hThread != nullptr ||
                broker_process.dwProcessId != 0 ||
                broker_process.dwThreadId != 0) {
                return 324;
            }
        }
    }
    void* local_server = nullptr;
    const HRESULT local_server_status = CoCreateInstance(
        CLSID_NULL, nullptr, CLSCTX_LOCAL_SERVER, IID_IUnknown, &local_server);
    void* class_factory = nullptr;
    const HRESULT class_factory_status = CoGetClassObject(
        CLSID_NULL, CLSCTX_LOCAL_SERVER, nullptr, IID_IUnknown,
        &class_factory);
    COSERVERINFO remote_server{};
    remote_server.pwszName = const_cast<wchar_t*>(L"localhost");
    MULTI_QI remote_query{};
    remote_query.pIID = &IID_IUnknown;
    remote_query.pItf = nullptr;
    remote_query.hr = E_PENDING;
    const HRESULT remote_server_status = CoCreateInstanceEx(
        CLSID_NULL, nullptr, CLSCTX_REMOTE_SERVER, &remote_server, 1,
        &remote_query);
    if (local_server_status != E_ACCESSDENIED || local_server != nullptr ||
        class_factory_status != E_ACCESSDENIED || class_factory != nullptr ||
        remote_server_status != E_ACCESSDENIED ||
        remote_query.pItf != nullptr || remote_query.hr != E_ACCESSDENIED) {
        return 349;
    }
    constexpr std::array<DWORD, 3> confined_flag_families = {
        DETACHED_PROCESS,
        CREATE_NEW_PROCESS_GROUP,
        CREATE_NO_WINDOW,
    };
    for (const DWORD flags : confined_flag_families) {
        std::wstring flagged_command =
            L"\"" + executable + L"\" --inherit-leaf " + arguments[2];
        STARTUPINFOW flagged_startup{};
        flagged_startup.cb = sizeof(flagged_startup);
        PROCESS_INFORMATION flagged_process{};
        if (!CreateProcessW(
                executable.c_str(), flagged_command.data(), nullptr, nullptr,
                FALSE, flags, nullptr, nullptr, &flagged_startup,
                &flagged_process) ||
            !WaitForSuccessfulChild(flagged_process)) {
            return 287;
        }
    }
    constexpr auto unicode_environment_name = L"BOLT_PROC_025_UNICODE";
    constexpr auto unicode_environment_value = L"value-\u4e2d-\U0001F680";
    if (!SetEnvironmentVariableW(
            unicode_environment_name, unicode_environment_value)) {
        return 325;
    }
    LPWCH unicode_environment = GetEnvironmentStringsW();
    std::wstring unicode_environment_command =
        L"\"" + executable + L"\" --inherit-leaf " + arguments[2] + L" " +
        unicode_environment_name + L" " + unicode_environment_value;
    STARTUPINFOW unicode_environment_startup{};
    unicode_environment_startup.cb = sizeof(unicode_environment_startup);
    PROCESS_INFORMATION unicode_environment_process{};
    const BOOL unicode_environment_created =
        unicode_environment != nullptr &&
        CreateProcessW(
            executable.c_str(), unicode_environment_command.data(), nullptr,
            nullptr, FALSE, CREATE_UNICODE_ENVIRONMENT, unicode_environment,
            nullptr, &unicode_environment_startup, &unicode_environment_process);
    if (unicode_environment != nullptr) {
        FreeEnvironmentStringsW(unicode_environment);
    }
    SetEnvironmentVariableW(unicode_environment_name, nullptr);
    if (!unicode_environment_created ||
        !WaitForSuccessfulChild(unicode_environment_process)) {
        return 326;
    }
    std::wstring nested_command =
        L"\"" + executable + L"\" --nested-process " + arguments[2] + L" 8";
    STARTUPINFOW nested_startup{};
    nested_startup.cb = sizeof(nested_startup);
    PROCESS_INFORMATION nested_process{};
    if (!CreateProcessW(
            executable.c_str(), nested_command.data(), nullptr, nullptr, FALSE,
            0, nullptr, nullptr, &nested_startup, &nested_process) ||
        !WaitForSuccessfulChild(nested_process)) {
        return 292;
    }
    constexpr std::size_t churn_threads = 4;
    constexpr std::size_t churn_children_per_thread = 4;
    std::atomic_bool churn_succeeded{true};
    std::mutex churn_ids_mutex;
    std::vector<DWORD> churn_process_ids;
    churn_process_ids.reserve(churn_threads * churn_children_per_thread);
    std::vector<std::thread> churn_workers;
    churn_workers.reserve(churn_threads);
    for (std::size_t thread_index = 0; thread_index < churn_threads;
         ++thread_index) {
        churn_workers.emplace_back([&] {
            for (std::size_t child_index = 0;
                 child_index < churn_children_per_thread; ++child_index) {
                std::wstring command =
                    L"\"" + executable + L"\" --inherit-leaf " +
                    arguments[2];
                STARTUPINFOW startup{};
                startup.cb = sizeof(startup);
                PROCESS_INFORMATION child{};
                if (!CreateProcessW(
                        executable.c_str(), command.data(), nullptr, nullptr,
                        FALSE, 0, nullptr, nullptr, &startup, &child)) {
                    churn_succeeded.store(false, std::memory_order_relaxed);
                    continue;
                }
                {
                    const std::scoped_lock lock(churn_ids_mutex);
                    churn_process_ids.push_back(child.dwProcessId);
                }
                if (!WaitForSuccessfulChild(child)) {
                    churn_succeeded.store(false, std::memory_order_relaxed);
                }
            }
        });
    }
    for (auto& worker : churn_workers) {
        worker.join();
    }
    std::sort(churn_process_ids.begin(), churn_process_ids.end());
    if (!churn_succeeded.load(std::memory_order_relaxed) ||
        churn_process_ids.size() != churn_threads * churn_children_per_thread ||
        std::adjacent_find(
            churn_process_ids.begin(), churn_process_ids.end()) !=
            churn_process_ids.end()) {
        return 300;
    }
    const auto flush_events = reinterpret_cast<BOOL (*)(DWORD)>(
        GetProcAddress(hook, "BoltSandboxFlushEvents"));
    if (flush_events == nullptr || !flush_events(5'000)) {
        return 247;
    }

    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    const HANDLE entered = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    if (entered == nullptr) {
        return 227;
    }
    std::wstring suspended_command_line =
        L"\"" + executable + L"\" --inherit-leaf " + arguments[2] + L" " +
        HandleText(entered);
    STARTUPINFOW suspended_startup{};
    suspended_startup.cb = sizeof(suspended_startup);
    PROCESS_INFORMATION suspended_process{};
    if (!CreateProcessW(
            executable.c_str(), suspended_command_line.data(), nullptr, nullptr,
            TRUE, CREATE_SUSPENDED, nullptr, nullptr, &suspended_startup,
            &suspended_process)) {
        CloseHandle(entered);
        return 228;
    }
    const bool stayed_suspended = WaitForSingleObject(entered, 100) == WAIT_TIMEOUT;
    const bool resumed = ResumeThread(suspended_process.hThread) !=
                         static_cast<DWORD>(-1);
    const bool entered_after_resume =
        resumed && WaitForSingleObject(entered, 5'000) == WAIT_OBJECT_0;
    const DWORD suspended_wait =
        WaitForSingleObject(suspended_process.hProcess, 5'000);
    DWORD suspended_exit_code = 0;
    const bool suspended_exited =
        suspended_wait == WAIT_OBJECT_0 &&
        GetExitCodeProcess(suspended_process.hProcess, &suspended_exit_code) != FALSE;
    if (!suspended_exited) {
        TerminateProcess(suspended_process.hProcess, 229);
        WaitForSingleObject(suspended_process.hProcess, 5'000);
    }
    CloseHandle(suspended_process.hThread);
    CloseHandle(suspended_process.hProcess);
    CloseHandle(entered);
    if (!stayed_suspended || !entered_after_resume || !suspended_exited ||
        suspended_exit_code != 0) {
        return 229;
    }

    const HANDLE restricted_token = CreateRestrictedPrimaryToken();
    if (restricted_token == nullptr) {
        return 236;
    }
    std::wstring as_user_wide_command =
        L"\"" + executable + L"\" --inherit-leaf " + arguments[2];
    STARTUPINFOW as_user_wide_startup{};
    as_user_wide_startup.cb = sizeof(as_user_wide_startup);
    PROCESS_INFORMATION as_user_wide_process{};
    const BOOL as_user_wide_created = CreateProcessAsUserW(
        restricted_token, executable.c_str(), as_user_wide_command.data(), nullptr,
        nullptr, FALSE, 0, nullptr, nullptr, &as_user_wide_startup,
        &as_user_wide_process);
    if (!as_user_wide_created || !WaitForSuccessfulChild(as_user_wide_process)) {
        CloseHandle(restricted_token);
        return 237;
    }

    const std::string as_user_executable_a = AnsiPath(executable.c_str());
    const std::string as_user_command_source_a =
        AnsiPath(as_user_wide_command.c_str());
    std::vector<char> as_user_command_a(
        as_user_command_source_a.begin(), as_user_command_source_a.end());
    as_user_command_a.push_back('\0');
    STARTUPINFOA as_user_startup_a{};
    as_user_startup_a.cb = sizeof(as_user_startup_a);
    PROCESS_INFORMATION as_user_process_a{};
    const BOOL as_user_created_a =
        !as_user_executable_a.empty() && !as_user_command_source_a.empty() &&
        CreateProcessAsUserA(
            restricted_token, as_user_executable_a.c_str(),
            as_user_command_a.data(), nullptr, nullptr, FALSE, 0, nullptr,
            nullptr, &as_user_startup_a, &as_user_process_a);
    CloseHandle(restricted_token);
    if (!as_user_created_a || !WaitForSuccessfulChild(as_user_process_a)) {
        return 238;
    }

    const std::wstring shell_parameters =
        L"--inherit-leaf " + std::wstring(arguments[2]);
    SHELLEXECUTEINFOW shell_execute{};
    shell_execute.cbSize = sizeof(shell_execute);
    shell_execute.fMask =
        SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
    shell_execute.hwnd = nullptr;
    shell_execute.lpVerb = L"open";
    shell_execute.lpFile = executable.c_str();
    shell_execute.lpParameters = shell_parameters.c_str();
    shell_execute.nShow = SW_HIDE;
    if (!ShellExecuteExW(&shell_execute) || shell_execute.hProcess == nullptr) {
        if (shell_execute.hProcess != nullptr) {
            CloseHandle(shell_execute.hProcess);
        }
        return 239;
    }
    const DWORD shell_wait = WaitForSingleObject(shell_execute.hProcess, 5'000);
    DWORD shell_exit_code = 0;
    const bool shell_exited =
        shell_wait == WAIT_OBJECT_0 &&
        GetExitCodeProcess(shell_execute.hProcess, &shell_exit_code) != FALSE;
    if (!shell_exited) {
        TerminateProcess(shell_execute.hProcess, 240);
        WaitForSingleObject(shell_execute.hProcess, 5'000);
    }
    CloseHandle(shell_execute.hProcess);
    if (!shell_exited || shell_exit_code != 0) {
        return 240;
    }

    if (argument_count == 6) {
        SHELLEXECUTEINFOW association{};
        association.cbSize = sizeof(association);
        association.fMask =
            SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
        association.lpVerb = L"open";
        association.lpFile = arguments[5];
        association.nShow = SW_HIDE;
        SetLastError(ERROR_SUCCESS);
        const BOOL association_started = ShellExecuteExW(&association);
        const DWORD association_error = GetLastError();
        if (association_started && association.hProcess != nullptr) {
            TerminateProcess(association.hProcess, 352);
            WaitForSingleObject(association.hProcess, 5'000);
        }
        if (association.hProcess != nullptr) {
            CloseHandle(association.hProcess);
        }
        if (association_started || association_error != ERROR_ACCESS_DENIED ||
            association.hProcess != nullptr) {
            return 351;
        }
        if (!flush_events(5'000)) {
            return 353;
        }
    }

    const HANDLE native_entered =
        CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    if (native_entered == nullptr) {
        return 241;
    }
    const std::wstring native_arguments =
        L"--inherit-leaf " + std::wstring(arguments[2]) + L" " +
        HandleText(native_entered);
    NativeRtlUserProcessInformation native_process{};
    const NTSTATUS native_status = CreateNativeRtlProcess(
        executable, native_arguments, true, native_process);
    const bool native_created = native_status >= 0 &&
                                native_process.process != nullptr &&
                                native_process.thread != nullptr;
    const bool native_stayed_suspended =
        native_created &&
        WaitForSingleObject(native_entered, 100) == WAIT_TIMEOUT;
    const bool native_resumed =
        native_created &&
        ResumeThread(native_process.thread) != static_cast<DWORD>(-1);
    const bool native_entered_after_resume =
        native_resumed &&
        WaitForSingleObject(native_entered, 5'000) == WAIT_OBJECT_0;
    const DWORD native_wait = native_created
                                  ? WaitForSingleObject(
                                        native_process.process, 5'000)
                                  : WAIT_FAILED;
    DWORD native_exit_code = 0;
    const bool native_exited =
        native_wait == WAIT_OBJECT_0 &&
        GetExitCodeProcess(native_process.process, &native_exit_code) != FALSE;
    if (native_created && !native_exited) {
        TerminateProcess(native_process.process, 242);
        WaitForSingleObject(native_process.process, 5'000);
    }
    CloseNativeProcessInformation(native_process);
    CloseHandle(native_entered);
    if (!native_stayed_suspended || !native_entered_after_resume ||
        !native_exited || native_exit_code != 0) {
        return 242;
    }

    const HANDLE nt_native_entered =
        CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    if (nt_native_entered == nullptr) {
        return 243;
    }
    const std::wstring nt_native_arguments =
        L"--inherit-leaf " + std::wstring(arguments[2]) + L" " +
        HandleText(nt_native_entered);
    HANDLE nt_native_process = nullptr;
    HANDLE nt_native_thread = nullptr;
    const NTSTATUS nt_native_status = CreateNativeNtProcess(
        executable, nt_native_arguments, true, nt_native_process,
        nt_native_thread);
    const bool nt_native_created = nt_native_status >= 0 &&
                                   nt_native_process != nullptr &&
                                   nt_native_thread != nullptr;
    const bool nt_native_stayed_suspended =
        nt_native_created &&
        WaitForSingleObject(nt_native_entered, 100) == WAIT_TIMEOUT;
    const bool nt_native_resumed =
        nt_native_created &&
        ResumeThread(nt_native_thread) != static_cast<DWORD>(-1);
    const bool nt_native_entered_after_resume =
        nt_native_resumed &&
        WaitForSingleObject(nt_native_entered, 5'000) == WAIT_OBJECT_0;
    const DWORD nt_native_wait = nt_native_created
                                     ? WaitForSingleObject(
                                           nt_native_process, 5'000)
                                     : WAIT_FAILED;
    DWORD nt_native_exit_code = 0;
    const bool nt_native_exited =
        nt_native_wait == WAIT_OBJECT_0 &&
        GetExitCodeProcess(nt_native_process, &nt_native_exit_code) != FALSE;
    if (nt_native_created && !nt_native_exited) {
        TerminateProcess(nt_native_process, 243);
        WaitForSingleObject(nt_native_process, 5'000);
    }
    CloseNativeNtProcess(nt_native_process, nt_native_thread);
    CloseHandle(nt_native_entered);
    if (!nt_native_stayed_suspended ||
        !nt_native_entered_after_resume || !nt_native_exited ||
        nt_native_exit_code != 0) {
        return 243;
    }

    const std::wstring wide_command_line =
        L"\"" + executable + L"\" --inherit-leaf " + arguments[2];
    const std::string executable_a = AnsiPath(executable.c_str());
    const std::string command_line_source_a = AnsiPath(wide_command_line.c_str());
    std::vector<char> command_line_a(
        command_line_source_a.begin(), command_line_source_a.end());
    command_line_a.push_back('\0');
    STARTUPINFOA startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (executable_a.empty() || command_line_source_a.empty() ||
        !CreateProcessA(
            executable_a.c_str(), command_line_a.data(), nullptr, nullptr, FALSE, 0,
            nullptr, nullptr, &startup, &process)) {
        return 224;
    }
    const DWORD wait = WaitForSingleObject(process.hProcess, 5'000);
    DWORD exit_code = 0;
    const bool exited = wait == WAIT_OBJECT_0 &&
                        GetExitCodeProcess(process.hProcess, &exit_code) != FALSE;
    if (!exited) {
        TerminateProcess(process.hProcess, 225);
        WaitForSingleObject(process.hProcess, 5'000);
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return exited && exit_code == 0 ? 0 : 225;
}

int RunCrossArchitectureProcessParent(
    const int argument_count,
    wchar_t** arguments) {
    if (argument_count != 4) {
        return 230;
    }
#if defined(_WIN64)
    constexpr auto current_hook_name = L"bolt-sandbox-x64.dll";
#else
    constexpr auto current_hook_name = L"bolt-sandbox-x86.dll";
#endif
    const HMODULE current_hook = GetModuleHandleW(current_hook_name);
    const auto initialized =
        current_hook == nullptr
            ? nullptr
            : reinterpret_cast<BOOL (*)()>(GetProcAddress(
                  current_hook, "BoltSandboxRuntimeInitialized"));
    if (initialized == nullptr || !initialized()) {
        return 231;
    }

    const std::wstring child_executable = arguments[2];
    std::wstring command_line =
        L"\"" + child_executable + L"\" --inherit-leaf " + arguments[3];
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(
            child_executable.c_str(), command_line.data(), nullptr, nullptr,
            FALSE, 0, nullptr, nullptr, &startup, &process)) {
        return 232;
    }
    const DWORD wait = WaitForSingleObject(process.hProcess, 2'000);
    DWORD exit_code = 0;
    const bool exited = wait == WAIT_OBJECT_0 &&
                        GetExitCodeProcess(process.hProcess, &exit_code) != FALSE;
    if (!exited) {
        TerminateProcess(process.hProcess, 233);
        WaitForSingleObject(process.hProcess, 5'000);
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return exited && exit_code == 0 ? 0 : 233;
}

namespace {

struct ParentExitProbe {
    HANDLE ready;
    HANDLE release;
    HANDLE child_id_mapping;
    volatile LONG* child_id;
};

struct CompatibilityProbe {
    HANDLE process_id_mapping;
    HANDLE stdin_read;
    volatile LONG* process_id;
    std::wstring denied_path;
    std::wstring tool_root;
};

struct InjectionFailureProbe {
    HANDLE marker;
    bolt::protocol::RuntimeStartupFault fault;
    bolt::protocol::ChildInjectionFailureReason reason;
};

struct AssociationProbe {
    std::wstring script_path;
};

bool RunStartupHandleListTest(
    const std::wstring& executable,
    const std::filesystem::path& test_root) {
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    const HANDLE included_event =
        CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    const std::filesystem::path ambient_path =
        test_root / L"ambient-inheritable-handle.txt";
    const HANDLE ambient_file = CreateFileW(
        ambient_path.c_str(), GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, &inheritable,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (included_event == nullptr || ambient_file == INVALID_HANDLE_VALUE) {
        if (included_event != nullptr) {
            CloseHandle(included_event);
        }
        if (ambient_file != INVALID_HANDLE_VALUE) {
            CloseHandle(ambient_file);
        }
        return false;
    }

    BY_HANDLE_FILE_INFORMATION ambient_identity{};
    if (!GetFileInformationByHandle(ambient_file, &ambient_identity)) {
        CloseHandle(ambient_file);
        CloseHandle(included_event);
        return false;
    }

    std::wstring command_line = L"\"" + executable + L"\" --job-child";
    const HANDLE inherited[] = {included_event};
    const bolt::common::ProcessLaunchOptions options{
        executable, command_line, L"", nullptr, inherited,
        std::size(inherited), 0};
    bolt::common::SuspendedProcess process;
    if (bolt::common::SuspendedProcess::Create(options, process) !=
        bolt::common::ProcessStatus::kSuccess) {
        CloseHandle(ambient_file);
        CloseHandle(included_event);
        return false;
    }

    HANDLE included_copy = nullptr;
    const bool included_present =
        DuplicateHandle(
            process.process_handle(), included_event, GetCurrentProcess(),
            &included_copy, EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, 0) != FALSE &&
        SetEvent(included_copy) != FALSE &&
        WaitForSingleObject(included_event, 0) == WAIT_OBJECT_0;

    HANDLE ambient_copy = nullptr;
    const BOOL ambient_duplicated = DuplicateHandle(
        process.process_handle(), ambient_file, GetCurrentProcess(),
        &ambient_copy, FILE_READ_ATTRIBUTES, FALSE, 0);
    bool ambient_file_leaked = false;
    if (ambient_duplicated && ambient_copy != nullptr) {
        BY_HANDLE_FILE_INFORMATION copied_identity{};
        ambient_file_leaked =
            GetFileInformationByHandle(ambient_copy, &copied_identity) != FALSE &&
            copied_identity.dwVolumeSerialNumber ==
                ambient_identity.dwVolumeSerialNumber &&
            copied_identity.nFileIndexHigh == ambient_identity.nFileIndexHigh &&
            copied_identity.nFileIndexLow == ambient_identity.nFileIndexLow;
    }

    if (ambient_copy != nullptr) {
        CloseHandle(ambient_copy);
    }
    if (included_copy != nullptr) {
        CloseHandle(included_copy);
    }
    process.Close();
    CloseHandle(ambient_file);
    CloseHandle(included_event);
    DeleteFileW(ambient_path.c_str());
    return included_present && !ambient_file_leaked;
}

bool RunSessionHandleIsolationTest(const std::wstring& executable) {
    const std::wstring pipe_name =
        PipeName(GetCurrentProcessId() ^ 0x5100'0017U);
    bolt::common::PrivatePipe server;
    if (bolt::common::PrivatePipe::Create(pipe_name, server) !=
        bolt::common::PipeStatus::kSuccess) {
        return false;
    }
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    const HANDLE client = CreateFileW(
        pipe_name.c_str(), FILE_WRITE_DATA, 0, &inheritable, OPEN_EXISTING, 0,
        nullptr);
    if (client == INVALID_HANDLE_VALUE ||
        server.Accept() != bolt::common::PipeStatus::kSuccess) {
        if (client != INVALID_HANDLE_VALUE) {
            CloseHandle(client);
        }
        return false;
    }

    std::wstring command = L"\"" + executable + L"\" --job-child";
    const HANDLE inherited[] = {client};
    const bolt::common::ProcessLaunchOptions options{
        executable, command, L"", nullptr, inherited, std::size(inherited), 0};
    bolt::common::SuspendedProcess process;
    if (bolt::common::SuspendedProcess::Create(options, process) !=
        bolt::common::ProcessStatus::kSuccess) {
        CloseHandle(client);
        return false;
    }

    HANDLE write_copy = nullptr;
    const bool write_only_capability_present =
        DuplicateHandle(
            process.process_handle(), client, GetCurrentProcess(), &write_copy,
            FILE_WRITE_DATA, FALSE, 0) != FALSE;
    HANDLE read_copy = nullptr;
    SetLastError(ERROR_SUCCESS);
    const BOOL read_capability_leaked = DuplicateHandle(
        process.process_handle(), client, GetCurrentProcess(), &read_copy,
        FILE_READ_DATA, FALSE, 0);
    const DWORD read_error = GetLastError();
    HANDLE server_copy = nullptr;
    SetLastError(ERROR_SUCCESS);
    const BOOL server_handle_leaked = DuplicateHandle(
        process.process_handle(), server.handle(), GetCurrentProcess(),
        &server_copy, FILE_READ_DATA, FALSE, 0);
    const DWORD server_error = GetLastError();

    SetLastError(ERROR_SUCCESS);
    const BOOL impersonated =
        write_copy != nullptr && ImpersonateNamedPipeClient(write_copy);
    const DWORD impersonation_error = GetLastError();
    if (impersonated) {
        RevertToSelf();
    }

    bolt::common::PrivatePipe second_server;
    const auto second_server_status =
        bolt::common::PrivatePipe::Create(pipe_name, second_server);
    SetLastError(ERROR_SUCCESS);
    const HANDLE second_client = CreateFileW(
        pipe_name.c_str(), FILE_WRITE_DATA, 0, nullptr, OPEN_EXISTING, 0,
        nullptr);
    const DWORD second_client_error = GetLastError();

    if (second_client != INVALID_HANDLE_VALUE) {
        CloseHandle(second_client);
    }
    if (server_copy != nullptr) {
        CloseHandle(server_copy);
    }
    if (read_copy != nullptr) {
        CloseHandle(read_copy);
    }
    if (write_copy != nullptr) {
        CloseHandle(write_copy);
    }
    process.Close();
    CloseHandle(client);
    const bool passed =
        write_only_capability_present && !read_capability_leaked &&
        read_error == ERROR_ACCESS_DENIED && !server_handle_leaked &&
        server_error == ERROR_INVALID_HANDLE && !impersonated &&
           (impersonation_error == ERROR_INVALID_FUNCTION ||
            impersonation_error == ERROR_CANNOT_IMPERSONATE ||
            impersonation_error == ERROR_ACCESS_DENIED) &&
           second_server_status == bolt::common::PipeStatus::kCreateFailed &&
           second_client == INVALID_HANDLE_VALUE &&
           second_client_error == ERROR_PIPE_BUSY;
    if (!passed) {
        std::fprintf(
            stderr,
            "session handle isolation failed: write=%d read=%d read_error=%lu server=%d server_error=%lu impersonated=%d impersonation_error=%lu second_server=%u second_client=%p second_client_error=%lu\n",
            write_only_capability_present ? 1 : 0,
            read_capability_leaked ? 1 : 0,
            static_cast<unsigned long>(read_error),
            server_handle_leaked ? 1 : 0,
            static_cast<unsigned long>(server_error), impersonated ? 1 : 0,
            static_cast<unsigned long>(impersonation_error),
            static_cast<unsigned int>(second_server_status), second_client,
            static_cast<unsigned long>(second_client_error));
    }
    return passed;
}

bool RunInheritedProcessTest(
    const std::wstring& executable,
    const std::filesystem::path& hook_path,
    const wchar_t* hook_name,
    const std::wstring& pipe_name,
    const std::wstring& parent_arguments = {},
    const std::uint8_t nonce_byte = 0x5A,
    const ParentExitProbe* parent_exit_probe = nullptr,
    const CompatibilityProbe* compatibility_probe = nullptr,
    const InjectionFailureProbe* injection_failure_probe = nullptr,
    const AssociationProbe* association_probe = nullptr) {
    std::vector<bolt::tests::FilesystemRule> policy_rules = {
        {bolt::tests::FilesystemRuleKind::kReadOnly,
         std::filesystem::path(executable).root_path()},
    };
    if (compatibility_probe != nullptr) {
        policy_rules.push_back(
            {bolt::tests::FilesystemRuleKind::kInheritUser,
             compatibility_probe->tool_root});
        policy_rules.push_back(
            {bolt::tests::FilesystemRuleKind::kReadWrite,
             std::filesystem::path(compatibility_probe->denied_path)
                 .parent_path()
                 .parent_path()});
        policy_rules.push_back(
            {bolt::tests::FilesystemRuleKind::kDeny,
             compatibility_probe->denied_path});
    }
    const auto policy_payload = bolt::tests::SealPolicy(
        policy_rules, bolt::tests::ChildProcessPolicyKind::kInherit);
    std::array<std::uint8_t, 16> nonce{};
    nonce.fill(nonce_byte);
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    const HANDLE release = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    bolt::common::ImmutablePolicyMapping policy;
    bolt::common::PrivatePipe event_pipe;
    if (release == nullptr ||
        bolt::common::ImmutablePolicyMapping::Create(
            policy_payload.data(), policy_payload.size(), policy) !=
            bolt::common::PolicyMappingStatus::kSuccess ||
        bolt::common::PrivatePipe::Create(pipe_name, event_pipe) !=
            bolt::common::PipeStatus::kSuccess) {
        if (release != nullptr) {
            CloseHandle(release);
        }
        return false;
    }
    HANDLE event_client = CreateFileW(
        pipe_name.c_str(), FILE_WRITE_DATA, 0, &inheritable, OPEN_EXISTING, 0,
        nullptr);
    if (event_client == INVALID_HANDLE_VALUE ||
        event_pipe.Accept() != bolt::common::PipeStatus::kSuccess) {
        CloseHandle(release);
        return false;
    }

    bolt::common::ExecutionJob job;
    if (bolt::common::ExecutionJob::Create(job) !=
        bolt::common::JobStatus::kSuccess) {
        CloseHandle(event_client);
        CloseHandle(release);
        return false;
    }
    HANDLE exposed_job = nullptr;
    if (parent_arguments.empty() &&
        !DuplicateHandle(
            GetCurrentProcess(), job.handle(), GetCurrentProcess(), &exposed_job,
            JOB_OBJECT_QUERY | JOB_OBJECT_SET_ATTRIBUTES, TRUE, 0)) {
        CloseHandle(event_client);
        CloseHandle(release);
        return false;
    }
    std::wstring command_line = parent_arguments.empty()
                                          ? L"\"" + executable +
                                                L"\" --inherit-parent " + hook_name +
                                                L" " + HandleText(policy.handle()) +
                                                L" " + HandleText(exposed_job)
                                           : L"\"" + executable + L"\" " +
                                                 parent_arguments;
    if (association_probe != nullptr) {
        command_line += L" \"" + association_probe->script_path + L"\"";
    }
    std::vector<HANDLE> inherited = {policy.handle(), event_client};
    if (exposed_job != nullptr) {
        inherited.push_back(exposed_job);
    }
    if (parent_exit_probe != nullptr) {
        inherited.push_back(parent_exit_probe->ready);
        inherited.push_back(parent_exit_probe->release);
        inherited.push_back(parent_exit_probe->child_id_mapping);
    }
    if (compatibility_probe != nullptr) {
        inherited.push_back(compatibility_probe->process_id_mapping);
        inherited.push_back(compatibility_probe->stdin_read);
    }
    if (injection_failure_probe != nullptr) {
        inherited.push_back(injection_failure_probe->marker);
    }
    const bolt::common::ProcessLaunchOptions options{
        executable, command_line, L"", nullptr, inherited.data(),
        inherited.size(), 0};
    bolt::common::SuspendedProcess process;
    const auto initialization_started_at = std::chrono::steady_clock::now();
    const bool initialized =
        bolt::common::SuspendedProcess::Create(options, process) ==
            bolt::common::ProcessStatus::kSuccess &&
        process.AssignTo(job) == bolt::common::ProcessStatus::kSuccess &&
        process.InstallRuntimePayload(
            policy.handle(), policy.length(), event_client, release, nonce,
            nullptr, nullptr, nullptr, 0, 0, 0,
            injection_failure_probe == nullptr
                ? bolt::protocol::RuntimeStartupFault::kNone
                : injection_failure_probe->fault) ==
            bolt::common::ProcessStatus::kSuccess &&
        process.Inject(hook_path.string()) == bolt::common::ProcessStatus::kSuccess &&
        process.BeginHookInitialization() == bolt::common::ProcessStatus::kSuccess;
    const auto initialization_finished_at = std::chrono::steady_clock::now();
    if (exposed_job != nullptr) {
        CloseHandle(exposed_job);
    }
    CloseHandle(event_client);
    std::array<std::uint8_t, bolt::protocol::kReadyFrameLength> ready{};
    DWORD bytes_read = 0;
    const bool ready_frame_ok =
        initialized &&
        ReadFile(
            event_pipe.handle(), ready.data(), static_cast<DWORD>(ready.size()),
            &bytes_read, nullptr) != FALSE &&
        bytes_read == ready.size() &&
        bolt::protocol::ValidateReadyFrame(
            ready.data(), ready.size(), nonce) ==
            bolt::protocol::ReadyFrameStatus::kSuccess;
    const auto ready_received_at = std::chrono::steady_clock::now();
    const bool released =
        ready_frame_ok &&
        process.ReleaseAfterReady() == bolt::common::ProcessStatus::kSuccess;
    const auto wait_status = released
                                 ? process.Wait(10'000)
                                 : bolt::common::ProcessStatus::kInvalidState;
    const auto process_finished_at = std::chrono::steady_clock::now();
    const bool ready_ok =
        released && wait_status == bolt::common::ProcessStatus::kSuccess;
    const auto parent_process_id = static_cast<std::uint32_t>(
        GetProcessId(process.process_handle()));
    bool parent_exit_descendant_ok = true;
    if (parent_exit_probe != nullptr) {
        parent_exit_descendant_ok =
            ready_ok &&
            WaitForSingleObject(parent_exit_probe->ready, 5'000) == WAIT_OBJECT_0;
        const DWORD child_id = static_cast<DWORD>(InterlockedCompareExchange(
            parent_exit_probe->child_id, 0, 0));
        const HANDLE child = child_id == 0
                                 ? nullptr
                                 : OpenProcess(SYNCHRONIZE, FALSE, child_id);
        parent_exit_descendant_ok =
            parent_exit_descendant_ok && child != nullptr &&
            SetEvent(parent_exit_probe->release) != FALSE &&
            WaitForSingleObject(child, 5'000) == WAIT_OBJECT_0;
        if (child != nullptr) {
            CloseHandle(child);
        }
    }
    bool compatibility_event_ok = true;
    if (compatibility_probe != nullptr) {
        const DWORD tool_process_id = static_cast<DWORD>(
            InterlockedCompareExchange(compatibility_probe->process_id, 0, 0));
        const DWORD tool_error = static_cast<DWORD>(InterlockedCompareExchange(
            compatibility_probe->process_id + 1, 0, 0));
        const LONG allowed_exit = InterlockedCompareExchange(
            compatibility_probe->process_id + 2, 0, 0);
        const LONG denied_exit = InterlockedCompareExchange(
            compatibility_probe->process_id + 3, 0, 0);
        if (tool_process_id == 0 || tool_error != 0 || allowed_exit != 0 ||
            denied_exit == 0 || denied_exit == -2) {
            std::fprintf(
                stderr,
                "compatibility probe pid=%lu error=%lu allowed_exit=%ld denied_exit=%ld ready=%d\n",
                static_cast<unsigned long>(tool_process_id),
                static_cast<unsigned long>(tool_error),
                static_cast<long>(allowed_exit),
                static_cast<long>(denied_exit), ready_ok ? 1 : 0);
        }
        const bool denied_violation_observed =
            tool_process_id != 0 &&
            ReadAnyFilesystemViolationForPath(
                event_pipe.handle(), tool_process_id,
                compatibility_probe->denied_path);
        compatibility_event_ok =
            ready_ok && tool_process_id != 0 && tool_error == 0 &&
            allowed_exit == 0 && denied_exit != 0 && denied_exit != -2 &&
            denied_violation_observed;
    }
    constexpr auto breakaway_operation =
        static_cast<bolt::protocol::ProcessOperation>(3);
    constexpr auto mitigation_weakening_operation =
        static_cast<bolt::protocol::ProcessOperation>(4);
    constexpr auto external_delegation_operation =
        static_cast<bolt::protocol::ProcessOperation>(5);
    const bool job_limit_event_ok =
        !parent_arguments.empty() ||
        ReadProcessViolation(
            event_pipe.handle(), parent_process_id,
            mitigation_weakening_operation, 1);
    bool breakaway_event_ok = true;
    if (parent_arguments.empty()) {
        for (std::uint64_t sequence = 2; sequence <= 8; ++sequence) {
            breakaway_event_ok =
                breakaway_event_ok &&
                ReadProcessViolation(
                    event_pipe.handle(), parent_process_id,
                    breakaway_operation, sequence);
        }
    }
    bool mitigation_weakening_events_ok = true;
    if (parent_arguments.empty()) {
        for (std::uint64_t sequence = 9; sequence <= 10; ++sequence) {
            mitigation_weakening_events_ok =
                mitigation_weakening_events_ok &&
                ReadProcessViolation(
                    event_pipe.handle(), parent_process_id,
                    mitigation_weakening_operation, sequence);
        }
    }
    const bool injection_failure_event_ok =
        injection_failure_probe == nullptr ||
        (ready_ok &&
         ReadChildInjectionFailure(
             event_pipe.handle(), parent_process_id,
             injection_failure_probe->reason));
    bool external_delegation_events_ok = true;
    if (parent_arguments.empty()) {
        for (std::uint64_t sequence = 11;
             sequence <= 21; ++sequence) {
            if (!ReadProcessViolation(
                    event_pipe.handle(), parent_process_id,
                    external_delegation_operation, sequence)) {
                std::fprintf(
                    stderr,
                    "external delegation event mismatch: sequence=%llu\n",
                    static_cast<unsigned long long>(sequence));
                external_delegation_events_ok = false;
                break;
            }
        }
        if (external_delegation_events_ok && association_probe != nullptr &&
            !ReadProcessViolation(
                event_pipe.handle(), parent_process_id,
                external_delegation_operation, 22, true)) {
            std::fprintf(
                stderr,
                "external delegation event mismatch: sequence>=22\n");
            external_delegation_events_ok = false;
        }
    }
    DWORD exit_code = 0;
    const auto exit_status = process.ExitCode(exit_code);
    const bool passed = ready_ok && parent_exit_descendant_ok &&
                        injection_failure_event_ok &&
                        job_limit_event_ok &&
                        compatibility_event_ok &&
                        breakaway_event_ok &&
                        mitigation_weakening_events_ok &&
                        external_delegation_events_ok &&
                        exit_status == bolt::common::ProcessStatus::kSuccess &&
                        exit_code == 0;
    if (!passed) {
        std::fprintf(
            stderr,
            "inherited process fixture failed: exit=%lu ready=%d descendant=%d compatibility=%d breakaway=%d mitigation=%d external=%d\n",
            static_cast<unsigned long>(exit_code), ready_ok ? 1 : 0,
            parent_exit_descendant_ok ? 1 : 0,
            compatibility_event_ok ? 1 : 0, breakaway_event_ok ? 1 : 0,
            mitigation_weakening_events_ok ? 1 : 0,
            external_delegation_events_ok ? 1 : 0);
        std::fprintf(
            stderr,
            "process timing: initialize=%lld ready=%lld total=%lld wait_status=%u exit_status=%u\n",
            static_cast<long long>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    initialization_finished_at - initialization_started_at)
                    .count()),
            static_cast<long long>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    ready_received_at - initialization_finished_at)
                    .count()),
            static_cast<long long>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    process_finished_at - initialization_started_at)
                    .count()),
            static_cast<unsigned>(wait_status),
            static_cast<unsigned>(exit_status));
        std::fwprintf(
            stderr, L"process fixture arguments: %ls\n",
            parent_arguments.empty() ? L"<main>" : parent_arguments.c_str());
    }
    CloseHandle(release);
    return passed;
}

bool RunMitigationFailureTest(
    const std::wstring& executable,
    const std::filesystem::path& hook_path,
    const wchar_t* hook_name) {
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    const HANDLE marker = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    if (marker == nullptr) {
        return false;
    }
    const std::wstring arguments =
        L"--faulted-descendant-parent " + std::wstring(hook_name) + L" " +
        HandleText(marker);
    const InjectionFailureProbe probe{
        marker, bolt::protocol::RuntimeStartupFault::kMitigationFailure,
        bolt::protocol::ChildInjectionFailureReason::kMitigationFailed};
    const bool passed = RunInheritedProcessTest(
        executable, hook_path, hook_name,
        PipeName(GetCurrentProcessId() ^ 0x5100'0032U), arguments, 0xA4,
        nullptr, nullptr, &probe);
    const bool marker_absent =
        WaitForSingleObject(marker, 0) == WAIT_TIMEOUT;
    CloseHandle(marker);
    return passed && marker_absent;
}

bool RunAssociationLaunchTest(
    const std::wstring& executable,
    const std::filesystem::path& hook_path,
    const wchar_t* hook_name) {
    const auto script_path =
        std::filesystem::temp_directory_path() /
        (L"bolt-sandbox-association-" +
         std::to_wstring(GetCurrentProcessId()) + L".cmd");
    if (!WriteFixture(script_path, "@echo off\r\nexit /b 0\r\n")) {
        return false;
    }
    const AssociationProbe probe{script_path.wstring()};
    const bool passed = RunInheritedProcessTest(
        executable, hook_path, hook_name,
        PipeName(GetCurrentProcessId() ^ 0x5100'0028U), {}, 0xA5, nullptr,
        nullptr, nullptr, &probe);
    std::error_code error;
    std::filesystem::remove(script_path, error);
    return passed;
}

bool RunUnicodeLaunchPathTest(
    const std::wstring& executable,
    const std::filesystem::path& hook_path,
    const wchar_t* hook_name,
    const std::filesystem::path& test_root) {
    const auto staged_directory = test_root / L"launch space \U0001F680";
    const auto staged_executable =
        staged_directory / std::filesystem::path(executable).filename();
    std::error_code error;
    if (!std::filesystem::create_directories(staged_directory, error) || error ||
        !std::filesystem::copy_file(
            executable, staged_executable,
            std::filesystem::copy_options::overwrite_existing, error) || error) {
        return false;
    }
    const std::wstring arguments =
        L"--nested-process " + std::wstring(hook_name) + L" 1";
    const bool unicode_path_passed = RunInheritedProcessTest(
        staged_executable.wstring(), hook_path, hook_name,
        PipeName(GetCurrentProcessId() ^ 0x5100'0022U), arguments, 0x64);
    std::filesystem::path long_directory = test_root / L"long launch path";
    for (std::size_t index = 0;
         long_directory.wstring().size() <= MAX_PATH + 80U; ++index) {
        long_directory /=
            L"segment-0123456789-" + std::to_wstring(index);
    }
    const std::filesystem::path extended_long_directory =
        L"\\\\?\\" + long_directory.wstring();
    const auto long_executable = extended_long_directory /
                                 std::filesystem::path(executable).filename();
    error.clear();
    const bool long_path_ready =
        std::filesystem::create_directories(extended_long_directory, error) &&
        !error &&
        std::filesystem::copy_file(
            executable, long_executable,
            std::filesystem::copy_options::overwrite_existing, error) &&
        !error;
    if (!long_path_ready) {
        std::fprintf(
            stderr, "long launch path setup failed: length=%zu error=%d\n",
            long_executable.wstring().size(), error.value());
    }
    const std::wstring complex_arguments =
        L"--argument-observation " + std::wstring(hook_name) +
        L" plain \"space value\" \"quote\\\"value\" \"trailing\\\\\" \"\"";
    const bool long_path_and_arguments_passed =
        long_path_ready &&
        RunInheritedProcessTest(
            long_executable.wstring(), hook_path, hook_name,
            PipeName(GetCurrentProcessId() ^ 0x5100'0023U),
            complex_arguments, 0x65);
    std::filesystem::remove_all(staged_directory, error);
    std::filesystem::remove_all(
        std::filesystem::path(L"\\\\?\\" +
                              (test_root / L"long launch path").wstring()),
        error);
    return unicode_path_passed && long_path_and_arguments_passed;
}

bool RunStartupLatencyTest(
    const std::wstring& executable,
    const std::filesystem::path& hook_path,
    const wchar_t* hook_name) {
    constexpr std::size_t sample_count = 6;
    constexpr auto warm_limit = std::chrono::milliseconds(100);
    std::array<std::chrono::milliseconds, sample_count> samples{};
    const std::wstring arguments =
        L"--nested-process " + std::wstring(hook_name) + L" 0";
    for (std::size_t index = 0; index < sample_count; ++index) {
        const auto start = std::chrono::steady_clock::now();
        const bool passed = RunInheritedProcessTest(
            executable, hook_path, hook_name,
            PipeName(
                GetCurrentProcessId() ^
                (0x5100'1000U + static_cast<DWORD>(index))),
            arguments, static_cast<std::uint8_t>(0x80U + index));
        samples[index] = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        if (!passed) {
            return false;
        }
    }
    const auto warm_maximum = *std::max_element(samples.begin() + 1, samples.end());
    std::fprintf(stderr, "sandbox startup samples:");
    for (const auto sample : samples) {
        std::fprintf(
            stderr, " %lld", static_cast<long long>(sample.count()));
    }
    std::fprintf(stderr, " ms (warm max=%lld ms)\n",
                 static_cast<long long>(warm_maximum.count()));
    if (warm_maximum >= warm_limit) {
        std::fprintf(stderr, "warm sandbox startup exceeded 100 ms\n");
        return false;
    }
    return true;
}

std::wstring FindCompatibilityTool(
    const wchar_t* environment_name,
    const wchar_t* executable_name) {
    std::wstring path(32'768, L'\0');
    const DWORD environment_length = GetEnvironmentVariableW(
        environment_name, path.data(), static_cast<DWORD>(path.size()));
    if (environment_length != 0 && environment_length < path.size()) {
        path.resize(environment_length);
        return std::filesystem::is_regular_file(path) ? path : std::wstring{};
    }
    const DWORD search_length = SearchPathW(
        nullptr, executable_name, nullptr, static_cast<DWORD>(path.size()),
        path.data(), nullptr);
    if (search_length == 0 || search_length >= path.size()) {
        return {};
    }
    path.resize(search_length);
    return path;
}

bool RunCompatibilityToolTests(
    const std::wstring& executable,
    const std::filesystem::path& hook_path,
    const wchar_t* hook_name,
    const std::filesystem::path& test_root) {
    std::array<wchar_t, 8> required{};
    const DWORD required_length = GetEnvironmentVariableW(
        L"BOLT_TEST_REQUIRE_COMPATIBILITY", required.data(),
        static_cast<DWORD>(required.size()));
    if (required_length != 1 || required[0] != L'1') {
        std::fprintf(
            stderr,
            "process capability BOLT_TEST_REQUIRE_COMPATIBILITY=not_present\n");
        return true;
    }
    const auto denied_directory = test_root / L"compatibility-denied";
    const auto denied_path = denied_directory / L"Cargo.toml";
    const auto denied_library = denied_directory / L"lib.rs";
    const auto compatibility_work = test_root / L"compatibility-work";
    std::error_code error;
    if (!std::filesystem::create_directories(denied_directory, error) || error ||
        !std::filesystem::create_directories(compatibility_work, error) || error ||
        !WriteFixture(
            denied_path,
            "[package]\nname='bolt-denied'\nversion='0.0.0'\n"
            "[lib]\npath='lib.rs'\n") ||
        !WriteFixture(denied_library, "pub fn fixture() {}\n")) {
        return false;
    }
    struct Tool {
        const wchar_t* kind;
        const wchar_t* environment;
        const wchar_t* executable;
    };
    constexpr std::array<Tool, 6> tools = {{
        {L"cmd", L"BOLT_TEST_CMD", L"cmd.exe"},
        {L"node", L"BOLT_TEST_NODE", L"node.exe"},
        {L"python", L"BOLT_TEST_PYTHON", L"python.exe"},
        {L"git", L"BOLT_TEST_GIT", L"git.exe"},
        {L"cargo", L"BOLT_TEST_CARGO", L"cargo.exe"},
        {L"powershell", L"BOLT_TEST_POWERSHELL", L"powershell.exe"},
    }};
    std::array<wchar_t, 32> filter{};
    const DWORD filter_length = GetEnvironmentVariableW(
        L"BOLT_TEST_COMPATIBILITY_FILTER", filter.data(),
        static_cast<DWORD>(filter.size()));
    for (std::size_t index = 0; index < tools.size(); ++index) {
        if (filter_length != 0 && filter_length < filter.size() &&
            CompareStringOrdinal(
                filter.data(), -1, tools[index].kind, -1, TRUE) !=
                CSTR_EQUAL) {
            continue;
        }
        const auto tool_path = FindCompatibilityTool(
            tools[index].environment, tools[index].executable);
        if (tool_path.empty()) {
            std::fwprintf(
                stderr, L"required compatibility tool not present: %ls\n",
                tools[index].kind);
            return false;
        }
        SECURITY_ATTRIBUTES inheritable{};
        inheritable.nLength = sizeof(inheritable);
        inheritable.bInheritHandle = TRUE;
        const HANDLE mapping = CreateFileMappingW(
            INVALID_HANDLE_VALUE, &inheritable, PAGE_READWRITE, 0,
            sizeof(DWORD) * 4, nullptr);
        auto* process_id = mapping == nullptr
                               ? nullptr
                               : static_cast<volatile LONG*>(MapViewOfFile(
                                     mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0,
                                     0, sizeof(DWORD) * 4));
        HANDLE stdin_read = nullptr;
        HANDLE stdin_write = nullptr;
        const bool stdin_ready =
            CreatePipe(
                &stdin_read, &stdin_write, &inheritable, 4'096) != FALSE &&
            SetHandleInformation(
                stdin_write, HANDLE_FLAG_INHERIT, 0) != FALSE;
        if (stdin_write != nullptr) {
            CloseHandle(stdin_write);
            stdin_write = nullptr;
        }
        if (mapping == nullptr || process_id == nullptr || !stdin_ready ||
            stdin_read == nullptr) {
            if (stdin_read != nullptr) {
                CloseHandle(stdin_read);
            }
            return false;
        }
        InterlockedExchange(process_id, 0);
        InterlockedExchange(process_id + 1, 0);
        InterlockedExchange(process_id + 2, -2);
        InterlockedExchange(process_id + 3, -2);
        const std::wstring arguments =
            L"--compatibility-parent " + std::wstring(hook_name) + L" " +
            tools[index].kind + L" \"" + tool_path + L"\" \"" +
            denied_path.wstring() + L"\" " + HandleText(mapping) + L" " +
            HandleText(stdin_read);
        const CompatibilityProbe probe{
            mapping, stdin_read, process_id, denied_path.wstring(),
            std::filesystem::path(tool_path).parent_path().wstring()};
        const bool passed = RunInheritedProcessTest(
            executable, hook_path, hook_name,
            PipeName(
                GetCurrentProcessId() ^
                (0x5100'0100U + static_cast<DWORD>(index))),
            arguments, static_cast<std::uint8_t>(0x70U + index), nullptr,
            &probe);
        UnmapViewOfFile(const_cast<LONG*>(process_id));
        CloseHandle(mapping);
        CloseHandle(stdin_read);
        if (!passed) {
            std::fwprintf(
                stderr, L"compatibility tool failed: %ls (%ls)\n",
                tools[index].kind, tool_path.c_str());
            return false;
        }
    }
    std::filesystem::remove_all(denied_directory, error);
    return true;
}

bool RunInjectionFailureBeforeEntryTest(
    const std::wstring& executable,
    const std::filesystem::path& test_root) {
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    const HANDLE marker = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    const HANDLE release = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    HANDLE event_read = nullptr;
    HANDLE event_write = nullptr;
    const auto policy_payload = bolt::tests::SealPolicy(
        {{bolt::tests::FilesystemRuleKind::kReadOnly,
          std::filesystem::path(executable).root_path()}},
        bolt::tests::ChildProcessPolicyKind::kDeny);
    bolt::common::ImmutablePolicyMapping policy;
    if (marker == nullptr || release == nullptr ||
        !CreatePipe(&event_read, &event_write, &inheritable, 4'096) ||
        !SetHandleInformation(event_read, HANDLE_FLAG_INHERIT, 0) ||
        bolt::common::ImmutablePolicyMapping::Create(
            policy_payload.data(), policy_payload.size(), policy) !=
            bolt::common::PolicyMappingStatus::kSuccess) {
        if (marker != nullptr) CloseHandle(marker);
        if (release != nullptr) CloseHandle(release);
        if (event_read != nullptr) CloseHandle(event_read);
        if (event_write != nullptr) CloseHandle(event_write);
        return false;
    }
    const std::wstring command =
        L"\"" + executable + L"\" --entry-marker " + HandleText(marker);
    const HANDLE inherited[] = {policy.handle(), event_write, marker};
    const bolt::common::ProcessLaunchOptions options{
        executable, command, L"", nullptr, inherited, std::size(inherited), 0};
    bolt::common::ExecutionJob job;
    bolt::common::SuspendedProcess process;
    std::array<std::uint8_t, 16> nonce{};
    nonce.fill(0xA4);
    const bool prepared =
        bolt::common::ExecutionJob::Create(job) ==
            bolt::common::JobStatus::kSuccess &&
        bolt::common::SuspendedProcess::Create(options, process) ==
            bolt::common::ProcessStatus::kSuccess &&
        process.AssignTo(job) == bolt::common::ProcessStatus::kSuccess &&
        process.InstallRuntimePayload(
            policy.handle(), policy.length(), event_write, release, nonce) ==
            bolt::common::ProcessStatus::kSuccess;
    const auto injection_status =
        prepared ? process.Inject((test_root / L"missing-hook.dll").string())
                 : bolt::common::ProcessStatus::kInvalidState;
    const bool absent_before_cleanup =
        WaitForSingleObject(marker, 0) == WAIT_TIMEOUT;
    const bool terminated =
        prepared && job.Terminate(336) == bolt::common::JobStatus::kSuccess &&
        process.Wait(5'000) == bolt::common::ProcessStatus::kSuccess;
    const bool never_entered = WaitForSingleObject(marker, 0) == WAIT_TIMEOUT;
    CloseHandle(event_write);
    CloseHandle(event_read);
    CloseHandle(release);
    CloseHandle(marker);
    return injection_status == bolt::common::ProcessStatus::kInvalidDllPath &&
           absent_before_cleanup && terminated && never_entered;
}

bool RunCreationMitigationTest(const std::wstring& executable) {
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    const HANDLE marker = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    if (marker == nullptr) {
        return false;
    }
    const std::wstring command =
        L"\"" + executable + L"\" --creation-mitigation-child " +
        HandleText(marker);
    const HANDLE inherited[] = {marker};
    const bolt::common::ProcessLaunchOptions options{
        executable, command, L"", nullptr, inherited, std::size(inherited), 0};
    bolt::common::ExecutionJob job;
    bolt::common::SuspendedProcess process;
    const bool created =
        bolt::common::ExecutionJob::Create(job) ==
            bolt::common::JobStatus::kSuccess &&
        bolt::common::SuspendedProcess::Create(options, process) ==
            bolt::common::ProcessStatus::kSuccess &&
        process.AssignTo(job) == bolt::common::ProcessStatus::kSuccess &&
        ResumeThread(process.thread_handle()) != static_cast<DWORD>(-1);
    const bool entered =
        created && WaitForSingleObject(marker, 5'000) == WAIT_OBJECT_0 &&
        process.Wait(5'000) == bolt::common::ProcessStatus::kSuccess;
    if (!entered) {
        static_cast<void>(job.Terminate(342));
    }
    CloseHandle(marker);
    return entered;
}

}  // namespace

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
    const std::filesystem::path allowed_directory_ex_w =
        allowed_copy_destination.wstring() + L".directory-ex-w";
    const std::filesystem::path allowed_directory_ex_a =
        allowed_copy_destination.wstring() + L".directory-ex-a";
    const std::filesystem::path denied_directory_ex_w =
        denied_create_directory.wstring() + L".ex-w";
    const std::filesystem::path denied_directory_ex_a =
        denied_create_directory.wstring() + L".ex-a";
    const std::filesystem::path missing_copy_source = allowed_root / L"missing-source.txt";
    const std::filesystem::path missing_copy_destination = allowed_root / L"missing-destination.txt";
    const std::filesystem::path allowed_native_link =
        missing_copy_source.wstring() + L".native-link";
    const std::filesystem::path allowed_native_link_ex =
        missing_copy_source.wstring() + L".native-link-ex";
    const std::filesystem::path denied_native_link =
        missing_copy_destination.wstring() + L".native-link";
    const std::filesystem::path denied_native_link_ex =
        missing_copy_destination.wstring() + L".native-link-ex";
    const std::filesystem::path root_rename_source =
        missing_copy_source.wstring() + L".root-rename-source";
    const std::filesystem::path root_rename_intermediate =
        missing_copy_source.wstring() + L".root-rename-intermediate";
    const std::filesystem::path root_rename_destination =
        missing_copy_source.wstring() + L".root-rename-destination";
    const std::filesystem::path win32_root_rename_source =
        missing_copy_source.wstring() + L".win32-root-rename-source";
    const std::filesystem::path win32_root_rename_intermediate =
        missing_copy_source.wstring() + L".win32-root-rename-intermediate";
    const std::filesystem::path win32_root_rename_destination =
        missing_copy_source.wstring() + L".win32-root-rename-destination";
    const std::filesystem::path denied_junction_target = denied_root / L"junction-target";
    const std::filesystem::path denied_alias_target = denied_junction_target / L"protected.txt";
    const std::filesystem::path allowed_junction = allowed_root / L"junction";
    const std::filesystem::path alias_copy_destination = allowed_junction / L"protected.txt";
    const std::filesystem::path denied_alias_created_directory =
        denied_junction_target / L"created-directory";
    const std::filesystem::path denied_alias_removed_directory =
        denied_junction_target / L"removable-directory";
    const std::filesystem::path denied_alias_wildcard = denied_junction_target / L"*";
    const std::filesystem::path denied_alias_created_directory_a =
        denied_junction_target / L"created-directory-a";
    const std::filesystem::path denied_alias_removed_directory_a =
        denied_junction_target / L"removable-directory-a";
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
    const std::wstring executable = CurrentExecutable();
    if (!RunCreationMitigationTest(executable)) {
        return false;
    }
    if (!RunInjectionFailureBeforeEntryTest(executable, test_root)) {
        return false;
    }
    if (!RunStartupHandleListTest(executable, test_root)) {
        return false;
    }
    if (!RunSessionHandleIsolationTest(executable)) {
        return false;
    }
    const std::filesystem::path executable_volume_root =
        std::filesystem::path(executable).root_path();
    const auto policy_payload = bolt::tests::SealPolicy({
        {bolt::tests::FilesystemRuleKind::kReadOnly, executable_volume_root},
        {bolt::tests::FilesystemRuleKind::kReadWrite, test_root},
        {bolt::tests::FilesystemRuleKind::kReadOnly, read_only_root},
        {bolt::tests::FilesystemRuleKind::kDeny, denied_root},
    }, bolt::tests::ChildProcessPolicyKind::kDeny);
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
    DeleteFileW(allowed_native_link.c_str());
    DeleteFileW(allowed_native_link_ex.c_str());
    DeleteFileW(denied_native_link.c_str());
    DeleteFileW(denied_native_link_ex.c_str());
    DeleteFileW(root_rename_source.c_str());
    DeleteFileW(root_rename_intermediate.c_str());
    DeleteFileW(root_rename_destination.c_str());
    DeleteFileW(win32_root_rename_source.c_str());
    DeleteFileW(win32_root_rename_intermediate.c_str());
    DeleteFileW(win32_root_rename_destination.c_str());
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
    RemoveDirectoryW(denied_alias_removed_directory.c_str());
    RemoveDirectoryW(denied_alias_created_directory_a.c_str());
    RemoveDirectoryW(denied_alias_removed_directory_a.c_str());
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
    const HANDLE allowed_section_file = CreateFileW(
        allowed_mapping_path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, &inheritable,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    const HANDLE inherited_allowed_section =
        allowed_section_file == INVALID_HANDLE_VALUE
            ? nullptr
            : CreateFileMappingW(
                  allowed_section_file, &inheritable, PAGE_READONLY, 0, 0,
                  nullptr);
    if (allowed_section_file != INVALID_HANDLE_VALUE) {
        CloseHandle(allowed_section_file);
    }
    const HANDLE inherited_denied_section = CreateFileMappingW(
        denied_mapping_handle, &inheritable, PAGE_READWRITE, 0, 0, nullptr);
    if (inherited_allowed_section == nullptr ||
        inherited_denied_section == nullptr) {
        if (inherited_allowed_section != nullptr) {
            CloseHandle(inherited_allowed_section);
        }
        if (inherited_denied_section != nullptr) {
            CloseHandle(inherited_denied_section);
        }
        CloseHandle(denied_mapping_handle);
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
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        nullptr);
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
    BY_HANDLE_FILE_INFORMATION denied_id_information{};
    if (!GetFileInformationByHandle(
            denied_mapping_handle, &denied_id_information)) {
        return false;
    }
    const std::uint64_t denied_file_id =
        (static_cast<std::uint64_t>(denied_id_information.nFileIndexHigh) << 32) |
        denied_id_information.nFileIndexLow;
    FILE_ID_DESCRIPTOR denied_id_probe_descriptor{};
    denied_id_probe_descriptor.dwSize = sizeof(denied_id_probe_descriptor);
    denied_id_probe_descriptor.Type = FileIdType;
    denied_id_probe_descriptor.FileId.QuadPart =
        static_cast<LONGLONG>(denied_file_id);
    const HANDLE denied_id_probe = OpenFileById(
        denied_directory_handle, &denied_id_probe_descriptor,
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, 0);
    if (denied_id_probe == INVALID_HANDLE_VALUE) {
        return false;
    }
    CloseHandle(denied_id_probe);
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
    if (!CreateDirectoryW(denied_alias_removed_directory.c_str(), nullptr)) {
        return false;
    }
    if (!CreateDirectoryW(denied_alias_removed_directory_a.c_str(), nullptr)) {
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
                                      HandleText(denied_overlapped_handle) + L" " +
                                       std::to_wstring(denied_file_id) + L" " +
                                       HandleText(inherited_allowed_section) + L" " +
                                       HandleText(inherited_denied_section) + L" " +
                                       HandleText(policy.handle());
    const HANDLE inherited[] = {
        allowed, policy.handle(), event_client, denied_disposition_handle,
        denied_truncate_handle, denied_mapping_handle, read_only_mapping_handle,
        denied_directory_handle, denied_overlapped_handle};
    const HANDLE section_inherited[] = {
        inherited_allowed_section, inherited_denied_section};
    std::vector<HANDLE> inherited_handles(std::begin(inherited), std::end(inherited));
    inherited_handles.insert(
        inherited_handles.end(), std::begin(section_inherited),
        std::end(section_inherited));
    bolt::common::ProcessLaunchOptions options{
        executable,
        command_line,
        L"",
        nullptr,
        inherited_handles.data(),
        inherited_handles.size(),
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
    HANDLE leaked_release_control = nullptr;
    const BOOL release_control_leaked = DuplicateHandle(
        process.process_handle(), release, GetCurrentProcess(),
        &leaked_release_control, EVENT_MODIFY_STATE, FALSE, 0);
    HANDLE leaked_event_read = nullptr;
    const BOOL event_read_leaked = DuplicateHandle(
        process.process_handle(), event_client, GetCurrentProcess(),
        &leaked_event_read, FILE_READ_DATA, FALSE, 0);
    if (leaked_release_control != nullptr) {
        CloseHandle(leaked_release_control);
    }
    if (leaked_event_read != nullptr) {
        CloseHandle(leaked_event_read);
    }
    const auto inject_status = process.Inject(hook_path.string());
    const auto initialization_status = process.BeginHookInitialization();
    if (!created || wait_suspended != bolt::common::ProcessStatus::kWaitTimeout ||
        early_resume != bolt::common::ProcessStatus::kInvalidState ||
        assigned != bolt::common::ProcessStatus::kSuccess ||
        assigned_resume != bolt::common::ProcessStatus::kInvalidState ||
        wrong_mapping_status != bolt::common::ProcessStatus::kInvalidRuntimePayload ||
        payload_status != bolt::common::ProcessStatus::kSuccess ||
        release_control_leaked || event_read_leaked ||
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
    std::array<wchar_t, 13> short_name{};
    const bool short_name_formatted =
        swprintf_s(
            short_name.data(), short_name.size(), L"BOLT%04X.TMP",
            child_process_id & 0xffffU) >= 0;
    const std::filesystem::path allowed_short_name_path = allowed_root / short_name.data();
    const std::filesystem::path denied_short_name_path = denied_root / short_name.data();
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
            denied_alias_created_directory.wstring(), 88) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kDelete,
            denied_alias_removed_directory.wstring(), 89) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kEnumerate,
            denied_alias_wildcard.wstring(), 90) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kEnumerate,
            denied_alias_wildcard.wstring(), 91) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kEnumerate,
            denied_alias_wildcard.wstring(), 92) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kEnumerate,
            denied_alias_wildcard.wstring(), 93) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kCreate,
            denied_alias_created_directory_a.wstring(), 94) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kDelete,
            denied_alias_removed_directory_a.wstring(), 95) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kCreate,
            denied_path.wstring(), 96) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRead,
            denied_delete_path.wstring(), 97) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRead,
            denied_delete_path.wstring(), 98) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kEnumerate,
            denied_root.wstring(), 99) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kEnumerate,
            denied_root.wstring(), 100) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kEnumerate,
            denied_root.wstring(), 101) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRead,
            denied_mapping_path.wstring(), 102) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kMetadata,
            denied_mapping_path.wstring(), 103) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kMetadata,
            denied_mapping_path.wstring(), 104) &&
        ReadProcessViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::ProcessOperation::kCreateWithToken, 105) &&
        ReadProcessViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::ProcessOperation::kCreateWithLogon, 106) &&
        ReadProcessViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::ProcessOperation::kElevation, 107) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRead,
            denied_mapping_path.wstring(), 108) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kWrite,
            denied_mapping_path.wstring(), 109) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kCreate,
            denied_hardlink_destination.wstring(), 110) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRead,
            denied_disposition_path.wstring(), 111) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kRead,
            denied_disposition_path.wstring(), 112) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kWrite,
            denied_disposition_path.wstring(), 113) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kWrite,
            denied_truncate_path.wstring(), 114) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kWrite,
            denied_truncate_path.wstring(), 115) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kCreate,
            denied_directory_ex_w.wstring(), 116) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kCreate,
            denied_directory_ex_w.wstring(), 117) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kCreate,
            denied_directory_ex_a.wstring(), 118) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kCreate,
            denied_directory_ex_a.wstring(), 119) &&
        ReadFilesystemViolation(
            event_pipe.handle(), child_process_id,
            bolt::protocol::FilesystemOperation::kWrite,
            read_only_mapping_path.wstring(), 120);
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
    CloseHandle(inherited_allowed_section);
    CloseHandle(inherited_denied_section);
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
                            !std::filesystem::exists(allowed_directory_ex_w) &&
                            !std::filesystem::exists(allowed_directory_ex_a) &&
                            !std::filesystem::exists(denied_directory_ex_w) &&
                            !std::filesystem::exists(denied_directory_ex_a) &&
                            !std::filesystem::exists(missing_copy_source) &&
                            !std::filesystem::exists(missing_copy_destination) &&
                            !std::filesystem::exists(allowed_native_link) &&
                            !std::filesystem::exists(allowed_native_link_ex) &&
                            !std::filesystem::exists(denied_native_link) &&
                            !std::filesystem::exists(denied_native_link_ex) &&
                            !std::filesystem::exists(root_rename_source) &&
                            !std::filesystem::exists(root_rename_intermediate) &&
                            !std::filesystem::exists(root_rename_destination) &&
                            !std::filesystem::exists(win32_root_rename_source) &&
                            !std::filesystem::exists(win32_root_rename_intermediate) &&
                            !std::filesystem::exists(win32_root_rename_destination) &&
                            ReadFixture(denied_alias_target) == protected_nonce &&
                            GetFileAttributesW(denied_alias_target.c_str()) ==
                                denied_alias_attributes_before &&
                            !std::filesystem::exists(denied_alias_created_directory) &&
                            std::filesystem::is_directory(denied_alias_removed_directory) &&
                            !std::filesystem::exists(denied_alias_created_directory_a) &&
                            std::filesystem::is_directory(denied_alias_removed_directory_a) &&
                            ReadFixture(allowed_alias_move_source) == move_nonce &&
                            !std::filesystem::exists(denied_alias_move_target) &&
                            ReadFixture(allowed_replace_target) == replace_target_nonce &&
                            ReadFixture(allowed_handle_rename_source) == handle_rename_nonce &&
                            !std::filesystem::exists(denied_handle_rename_destination) &&
                            !std::filesystem::exists(allowed_disposition_path) &&
                            ReadFixture(denied_disposition_path) == disposition_nonce &&
                            ReadFixture(allowed_truncate_path) == truncate_nonce.substr(0, 4) &&
                            ReadFixture(denied_truncate_path) == truncate_nonce &&
                            short_name_formatted &&
                            std::filesystem::exists(allowed_short_name_path) &&
                            !std::filesystem::exists(denied_short_name_path) &&
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
    RemoveDirectoryW(denied_alias_removed_directory.c_str());
    RemoveDirectoryW(denied_alias_removed_directory_a.c_str());
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
        std::fprintf(
            stderr, "policy process fixture failed with exit code %lu\n",
            static_cast<unsigned long>(exit_code));
        return false;
    }

    event_pipe.Close();
    if (!RunMitigationFailureTest(executable, hook_path, hook_name) ||
        !RunAssociationLaunchTest(executable, hook_path, hook_name) ||
        !RunUnicodeLaunchPathTest(executable, hook_path, hook_name, test_root) ||
        !RunInheritedProcessTest(executable, hook_path, hook_name, pipe_name)) {
        return false;
    }

    std::array<bool, 2> concurrent_session_results{};
    const std::wstring concurrent_session_arguments =
        L"--nested-process " + std::wstring(hook_name) + L" 2";
    std::array<std::thread, 2> concurrent_sessions = {
        std::thread([&] {
            concurrent_session_results[0] = RunInheritedProcessTest(
                executable, hook_path, hook_name,
                PipeName(GetCurrentProcessId() ^ 0x5100'0001U),
                concurrent_session_arguments, 0x61);
        }),
        std::thread([&] {
            concurrent_session_results[1] = RunInheritedProcessTest(
                executable, hook_path, hook_name,
                PipeName(GetCurrentProcessId() ^ 0x5100'0002U),
                concurrent_session_arguments, 0x62);
        }),
    };
    for (auto& session : concurrent_sessions) {
        session.join();
    }
    if (!concurrent_session_results[0] || !concurrent_session_results[1]) {
        return false;
    }
    SECURITY_ATTRIBUTES parent_exit_inheritable{};
    parent_exit_inheritable.nLength = sizeof(parent_exit_inheritable);
    parent_exit_inheritable.bInheritHandle = TRUE;
    const HANDLE parent_exit_ready =
        CreateEventW(&parent_exit_inheritable, TRUE, FALSE, nullptr);
    const HANDLE parent_exit_release =
        CreateEventW(&parent_exit_inheritable, TRUE, FALSE, nullptr);
    const HANDLE parent_exit_mapping = CreateFileMappingW(
        INVALID_HANDLE_VALUE, &parent_exit_inheritable, PAGE_READWRITE, 0,
        sizeof(DWORD), nullptr);
    auto* parent_exit_child_id =
        parent_exit_mapping == nullptr
            ? nullptr
            : static_cast<volatile LONG*>(MapViewOfFile(
                  parent_exit_mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0,
                  sizeof(DWORD)));
    if (parent_exit_ready == nullptr || parent_exit_release == nullptr ||
        parent_exit_mapping == nullptr || parent_exit_child_id == nullptr) {
        return false;
    }
    InterlockedExchange(parent_exit_child_id, 0);
    const std::wstring parent_exit_arguments =
        L"--parent-exit-fixture " + std::wstring(hook_name) + L" " +
        HandleText(parent_exit_ready) + L" " + HandleText(parent_exit_release) +
        L" " + HandleText(parent_exit_mapping);
    const ParentExitProbe parent_exit_probe{
        parent_exit_ready, parent_exit_release, parent_exit_mapping,
        parent_exit_child_id};
    const bool parent_exit_ok = RunInheritedProcessTest(
        executable, hook_path, hook_name,
        PipeName(GetCurrentProcessId() ^ 0x5100'0013U),
        parent_exit_arguments, 0x63, &parent_exit_probe);
    UnmapViewOfFile(const_cast<LONG*>(parent_exit_child_id));
    CloseHandle(parent_exit_mapping);
    CloseHandle(parent_exit_release);
    CloseHandle(parent_exit_ready);
    if (!parent_exit_ok) {
        return false;
    }

    const std::filesystem::path current_output_directory =
        std::filesystem::path(executable).parent_path();
    const std::filesystem::path native_target_directory =
        current_output_directory.parent_path().parent_path();
#if defined(_WIN64)
    constexpr auto opposite_architecture_directory = L"x86";
    constexpr auto opposite_hook_name = L"bolt-sandbox-x86.dll";
#else
    constexpr auto opposite_architecture_directory = L"x64";
    constexpr auto opposite_hook_name = L"bolt-sandbox-x64.dll";
#endif
    const std::filesystem::path opposite_output_directory =
        native_target_directory / opposite_architecture_directory /
#if defined(NDEBUG)
        L"Release";
#else
        L"Debug";
#endif
    const std::filesystem::path opposite_executable =
        opposite_output_directory / L"bolt-sandbox-native-tests.exe";
    const std::filesystem::path opposite_hook_source =
        opposite_output_directory / opposite_hook_name;
    const std::filesystem::path staged_opposite_hook =
        current_output_directory / opposite_hook_name;
    filesystem_error.clear();
    std::filesystem::copy_file(
        opposite_hook_source, staged_opposite_hook,
        std::filesystem::copy_options::overwrite_existing, filesystem_error);
    if (filesystem_error ||
        !std::filesystem::is_regular_file(opposite_executable)) {
        std::filesystem::remove(staged_opposite_hook, filesystem_error);
        return false;
    }
    if (!RunCompatibilityToolTests(
            executable, hook_path, hook_name, test_root)) {
        std::filesystem::remove(staged_opposite_hook, filesystem_error);
        return false;
    }
    const std::wstring cross_arguments =
        L"--cross-architecture-parent \"" + opposite_executable.wstring() +
        L"\" " + opposite_hook_name;
    const bool cross_architecture_inherited = RunInheritedProcessTest(
        executable, hook_path, hook_name, pipe_name, cross_arguments);
    std::filesystem::remove(staged_opposite_hook, filesystem_error);
    if (!cross_architecture_inherited) {
        return false;
    }

    auto breakaway = options;
    breakaway.creation_flags = CREATE_BREAKAWAY_FROM_JOB;
    bolt::common::SuspendedProcess rejected;
    const auto breakaway_status = bolt::common::SuspendedProcess::Create(breakaway, rejected);
    return breakaway_status == bolt::common::ProcessStatus::kUnsupportedFlags;
}

bool RunProcessStartupLatencyTests() {
    const std::wstring executable = CurrentExecutable();
    if (executable.empty()) {
        return false;
    }
#if defined(_WIN64)
    constexpr auto hook_name = L"bolt-sandbox-x64.dll";
#else
    constexpr auto hook_name = L"bolt-sandbox-x86.dll";
#endif
    const auto hook_path =
        std::filesystem::path(executable).parent_path() / hook_name;
    return RunStartupLatencyTest(executable, hook_path, hook_name);
}
