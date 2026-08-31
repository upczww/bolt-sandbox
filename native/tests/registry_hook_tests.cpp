#include "common/execution_job.h"
#include "common/immutable_policy_mapping.h"
#include "common/private_pipe.h"
#include "common/suspended_process.h"
#include "protocol/event_frame.h"
#include "tests/policy_fixture.h"

#include <array>
#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>

namespace {

constexpr char kRegistryValueNameCanary[] =
    "BOLT_REG_VALUE_NAME_CANARY_4F7A19D2";
constexpr char kRegistryValueDataCanary[] =
    "BOLT_REG_VALUE_DATA_CANARY_9C83E5A1";
constexpr wchar_t kRegistryValueNameCanaryWide[] =
    L"BOLT_REG_VALUE_NAME_CANARY_4F7A19D2";
constexpr wchar_t kRegistryValueDataCanaryWide[] =
    L"BOLT_REG_VALUE_DATA_CANARY_9C83E5A1";

bool ContainsRegistryCanary(
    const std::uint8_t* const bytes,
    const std::size_t length) {
    if (bytes == nullptr) {
        return false;
    }
    for (const char* const canary :
         {kRegistryValueNameCanary, kRegistryValueDataCanary}) {
        const std::size_t canary_length =
            std::char_traits<char>::length(canary);
        if (std::search(
                bytes, bytes + length,
                reinterpret_cast<const std::uint8_t*>(canary),
                reinterpret_cast<const std::uint8_t*>(canary) +
                    canary_length) != bytes + length) {
            return true;
        }
    }
    return false;
}

std::wstring CurrentExecutable() {
    std::wstring path(32'768, L'\0');
    const DWORD length = GetModuleFileNameW(
        nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (length == 0 || length == path.size()) {
        return {};
    }
    path.resize(length);
    return path;
}

std::wstring PipeName(const DWORD suffix) {
    std::wostringstream encoded;
    encoded << std::hex << std::nouppercase << std::setfill(L'0')
            << std::setw(32) << static_cast<std::uint64_t>(suffix);
    return L"\\\\.\\pipe\\bolt-sandbox-" + encoded.str();
}

std::wstring HandleText(const std::uintptr_t value) {
    return std::to_wstring(static_cast<unsigned long long>(value));
}

bool CreateKeyWithValue(
    const std::wstring& path,
    const wchar_t* const value_name,
    const wchar_t* const value) {
    HKEY key = nullptr;
    DWORD disposition = 0;
    const LSTATUS created = RegCreateKeyExW(
        HKEY_CURRENT_USER, path.c_str(), 0, nullptr, 0, KEY_ALL_ACCESS,
        nullptr, &key, &disposition);
    if (created != ERROR_SUCCESS) {
        return false;
    }
    const LSTATUS written = RegSetValueExW(
        key, value_name, 0, REG_SZ,
        reinterpret_cast<const BYTE*>(value),
        static_cast<DWORD>((std::wcslen(value) + 1) * sizeof(wchar_t)));
    RegCloseKey(key);
    return written == ERROR_SUCCESS;
}

bool CreateKeyWithValueInView(
    const std::wstring& path,
    const REGSAM view,
    const wchar_t* const value_name,
    const wchar_t* const value) {
    HKEY key = nullptr;
    DWORD disposition = 0;
    const LSTATUS created = RegCreateKeyExW(
        HKEY_CURRENT_USER, path.c_str(), 0, nullptr, 0,
        KEY_ALL_ACCESS | view, nullptr, &key, &disposition);
    if (created != ERROR_SUCCESS) {
        return false;
    }
    const LSTATUS written = RegSetValueExW(
        key, value_name, 0, REG_SZ,
        reinterpret_cast<const BYTE*>(value),
        static_cast<DWORD>((std::wcslen(value) + 1) * sizeof(wchar_t)));
    RegCloseKey(key);
    return written == ERROR_SUCCESS;
}

void DeleteKeyTreeInView(
    const std::wstring& path,
    const REGSAM view) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(
            HKEY_CURRENT_USER, path.c_str(), 0,
            KEY_ALL_ACCESS | view, &key) == ERROR_SUCCESS) {
        RegDeleteTreeW(key, nullptr);
        RegCloseKey(key);
    }
    RegDeleteKeyExW(HKEY_CURRENT_USER, path.c_str(), view, 0);
}

bool QueryNativeKeyName(
    const HKEY key,
    std::wstring& name) {
    name.clear();
    using NtQueryKeyFunction = LONG(NTAPI*)(
        HANDLE, ULONG, PVOID, ULONG, PULONG);
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto nt_query_key = ntdll == nullptr
        ? nullptr
        : reinterpret_cast<NtQueryKeyFunction>(
              GetProcAddress(ntdll, "NtQueryKey"));
    if (nt_query_key == nullptr) {
        return false;
    }
    ULONG required = 0;
    nt_query_key(key, 3, nullptr, 0, &required);
    if (required < sizeof(ULONG) || required > 64U * 1'024U) {
        return false;
    }
    std::vector<std::uint8_t> buffer(required);
    if (nt_query_key(
            key, 3, buffer.data(), required, &required) < 0 ||
        required < sizeof(ULONG)) {
        return false;
    }
    const ULONG name_bytes =
        *reinterpret_cast<const ULONG*>(buffer.data());
    if (name_bytes % sizeof(wchar_t) != 0 ||
        name_bytes > required - sizeof(ULONG)) {
        return false;
    }
    name.assign(
        reinterpret_cast<const wchar_t*>(
            buffer.data() + sizeof(ULONG)),
        name_bytes / sizeof(wchar_t));
    return !name.empty();
}

bool CreateRegistrySymbolicLink(
    const std::wstring& link_path,
    const std::wstring& target_path) {
    HKEY target = nullptr;
    std::wstring native_target;
    if (RegOpenKeyExW(
            HKEY_CURRENT_USER, target_path.c_str(), 0, KEY_READ,
            &target) != ERROR_SUCCESS ||
        !QueryNativeKeyName(target, native_target)) {
        if (target != nullptr) {
            RegCloseKey(target);
        }
        return false;
    }
    RegCloseKey(target);

    HKEY link = nullptr;
    DWORD disposition = 0;
    const LSTATUS created = RegCreateKeyExW(
        HKEY_CURRENT_USER, link_path.c_str(), 0, nullptr,
        REG_OPTION_CREATE_LINK, KEY_SET_VALUE | KEY_CREATE_LINK | DELETE,
        nullptr, &link, &disposition);
    if (created != ERROR_SUCCESS) {
        return false;
    }
    wchar_t symbolic_link_value_text[] = L"SymbolicLinkValue";
    UNICODE_STRING symbolic_link_value{};
    symbolic_link_value.Buffer = symbolic_link_value_text;
    symbolic_link_value.Length = static_cast<USHORT>(
        std::wcslen(symbolic_link_value_text) * sizeof(wchar_t));
    symbolic_link_value.MaximumLength = symbolic_link_value.Length;
    using NtSetValueKeyFunction = LONG(NTAPI*)(
        HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG);
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto nt_set_value_key = ntdll == nullptr
        ? nullptr
        : reinterpret_cast<NtSetValueKeyFunction>(
              GetProcAddress(ntdll, "NtSetValueKey"));
    const LONG linked = nt_set_value_key == nullptr
        ? static_cast<LONG>(0xC0000002L)
        : nt_set_value_key(
              link, &symbolic_link_value, 0, REG_LINK,
              native_target.data(),
              static_cast<ULONG>(
                  native_target.size() * sizeof(wchar_t)));
    RegCloseKey(link);
    return linked >= 0;
}

bool ValidateRegistrySymbolicLink(
    const std::wstring& link_path,
    const std::wstring& target_path) {
    HKEY link = nullptr;
    HKEY target = nullptr;
    std::wstring link_name;
    std::wstring target_name;
    wchar_t value[64]{};
    DWORD value_type = 0;
    DWORD value_bytes = sizeof(value);
    const LSTATUS link_open = RegOpenKeyExW(
        HKEY_CURRENT_USER, link_path.c_str(), 0, KEY_READ, &link);
    const LSTATUS target_open = RegOpenKeyExW(
        HKEY_CURRENT_USER, target_path.c_str(), 0, KEY_READ, &target);
    const LSTATUS value_query = link_open == ERROR_SUCCESS
        ? RegQueryValueExW(
              link, kRegistryValueNameCanaryWide, nullptr, &value_type,
              reinterpret_cast<BYTE*>(value), &value_bytes)
        : link_open;
    const bool link_name_read =
        link_open == ERROR_SUCCESS && QueryNativeKeyName(link, link_name);
    const bool target_name_read =
        target_open == ERROR_SUCCESS &&
        QueryNativeKeyName(target, target_name);
    const bool valid =
        link_open == ERROR_SUCCESS &&
        target_open == ERROR_SUCCESS &&
        value_query == ERROR_SUCCESS &&
        value_type == REG_SZ &&
        std::wstring(value) == kRegistryValueDataCanaryWide &&
        link_name_read && target_name_read;
    if (link != nullptr) {
        RegCloseKey(link);
    }
    if (target != nullptr) {
        RegCloseKey(target);
    }
    if (!valid || link_name != target_name) {
        std::fwprintf(
            stderr,
            L"registry symbolic-link fixture: valid=%d link_open=%ld "
            L"target_open=%ld query=%ld link_name=%d target_name=%d "
            L"link=%ls target=%ls\n",
            valid ? 1 : 0, static_cast<long>(link_open),
            static_cast<long>(target_open), static_cast<long>(value_query),
            link_name_read ? 1 : 0, target_name_read ? 1 : 0,
            link_name.c_str(), target_name.c_str());
        return false;
    }
    return true;
}

void DeleteRegistrySymbolicLink(const std::wstring& link_path) {
    HKEY link = nullptr;
    if (RegOpenKeyExW(
            HKEY_CURRENT_USER, link_path.c_str(), REG_OPTION_OPEN_LINK,
            DELETE, &link) != ERROR_SUCCESS) {
        return;
    }
    using NtDeleteKeyFunction = LONG(NTAPI*)(HANDLE);
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto nt_delete_key = ntdll == nullptr
        ? nullptr
        : reinterpret_cast<NtDeleteKeyFunction>(
              GetProcAddress(ntdll, "NtDeleteKey"));
    if (nt_delete_key != nullptr) {
        nt_delete_key(link);
    }
    RegCloseKey(link);
}

std::vector<std::string> Components(
    const DWORD process_id,
    const char* const leaf) {
    return {
        "SOFTWARE", "BOLTSANDBOXREGISTRYTESTS",
        std::to_string(process_id), leaf};
}

std::vector<std::string> Components(
    const DWORD process_id,
    const char* const parent,
    const char* const leaf) {
    return {
        "SOFTWARE", "BOLTSANDBOXREGISTRYTESTS",
        std::to_string(process_id), parent, leaf};
}

std::vector<std::string> ClassComponents(
    const DWORD process_id,
    const char* const leaf) {
    return {
        "SOFTWARE", "CLASSES", "BOLTSANDBOXREGISTRYTESTS",
        std::to_string(process_id), leaf};
}

bool ReadExact(
    const HANDLE pipe,
    std::uint8_t* bytes,
    const std::size_t length) {
    std::size_t offset = 0;
    while (offset < length) {
        DWORD read = 0;
        if (!ReadFile(
                pipe, bytes + offset,
                static_cast<DWORD>(length - offset), &read, nullptr) ||
            read == 0) {
            return false;
        }
        offset += read;
    }
    return true;
}

bool ReadRegistryViolationWithin(
    const HANDLE pipe,
    const std::uint32_t process_id,
    const std::uint64_t sequence,
    const bolt::protocol::RegistryOperation operation,
    const std::string& key,
    const DWORD timeout_milliseconds) {
    const ULONGLONG deadline = GetTickCount64() + timeout_milliseconds;
    while (GetTickCount64() < deadline) {
        DWORD available = 0;
        if (PeekNamedPipe(
                pipe, nullptr, 0, nullptr, &available, nullptr) &&
            available >= bolt::protocol::kEventHeaderLength) {
            std::array<std::uint8_t, bolt::protocol::kEventHeaderLength>
                header{};
            if (!ReadExact(pipe, header.data(), header.size())) {
                return false;
            }
            const std::size_t payload_length =
                static_cast<std::size_t>(header[8]) |
                static_cast<std::size_t>(header[9]) << 8U |
                static_cast<std::size_t>(header[10]) << 16U |
                static_cast<std::size_t>(header[11]) << 24U;
            std::vector<std::uint8_t> actual(header.begin(), header.end());
            actual.resize(header.size() + payload_length);
            const bool read = ReadExact(
                pipe, actual.data() + header.size(), payload_length);
            if (read && ContainsRegistryCanary(
                            actual.data(), actual.size())) {
                return false;
            }
            const std::size_t expected_length =
                bolt::protocol::RegistryViolationFrameLength(key.c_str());
            std::vector<std::uint8_t> expected(expected_length);
            std::size_t written = 0;
            const bool encoded = bolt::protocol::EncodeRegistryViolationFrame(
                    process_id, operation, key.c_str(), sequence,
                    expected.data(), expected.size(), written) ==
                bolt::protocol::FrameEncodeStatus::kSuccess;
            const bool matched = read && encoded &&
                written == expected.size() && actual == expected;
            if (!matched && read && actual.size() >= 33) {
                const std::uint16_t kind =
                    static_cast<std::uint16_t>(actual[6]) |
                    static_cast<std::uint16_t>(actual[7]) << 8U;
                std::uint64_t actual_sequence = 0;
                for (std::size_t index = 0; index < 8; ++index) {
                    actual_sequence |=
                        static_cast<std::uint64_t>(actual[12 + index]) <<
                        (index * 8U);
                }
                const std::size_t key_length =
                    static_cast<std::size_t>(actual[29]) |
                    static_cast<std::size_t>(actual[30]) << 8U |
                    static_cast<std::size_t>(actual[31]) << 16U |
                    static_cast<std::size_t>(actual[32]) << 24U;
                const std::string actual_key = key_length <= actual.size() - 33
                    ? std::string(
                          reinterpret_cast<const char*>(actual.data() + 33),
                          key_length)
                    : std::string("<invalid>");
                std::fprintf(
                    stderr,
                    "registry event mismatch: kind=%u sequence=%llu op=%u "
                    "key=%s expected=%s\n",
                    static_cast<unsigned int>(kind),
                    static_cast<unsigned long long>(actual_sequence),
                    static_cast<unsigned int>(actual[28]),
                    actual_key.c_str(), key.c_str());
            }
            return matched;
        }
        Sleep(10);
    }
    return false;
}

struct RegistryEventRecord {
    bolt::protocol::RegistryOperation operation =
        bolt::protocol::RegistryOperation::kOpen;
    std::string key;
};

bool ReadRegistryViolationRecordWithin(
    const HANDLE pipe,
    const std::uint32_t process_id,
    const std::uint64_t sequence,
    RegistryEventRecord& record,
    const DWORD timeout_milliseconds) {
    const ULONGLONG deadline = GetTickCount64() + timeout_milliseconds;
    while (GetTickCount64() < deadline) {
        DWORD available = 0;
        if (!PeekNamedPipe(
                pipe, nullptr, 0, nullptr, &available, nullptr) ||
            available < bolt::protocol::kEventHeaderLength) {
            Sleep(10);
            continue;
        }
        std::array<std::uint8_t, bolt::protocol::kEventHeaderLength>
            header{};
        if (!ReadExact(pipe, header.data(), header.size())) {
            return false;
        }
        const std::size_t payload_length =
            static_cast<std::size_t>(header[8]) |
            static_cast<std::size_t>(header[9]) << 8U |
            static_cast<std::size_t>(header[10]) << 16U |
            static_cast<std::size_t>(header[11]) << 24U;
        std::vector<std::uint8_t> actual(header.begin(), header.end());
        actual.resize(header.size() + payload_length);
        if (!ReadExact(
                pipe, actual.data() + header.size(), payload_length) ||
            actual.size() < 33 ||
            ContainsRegistryCanary(actual.data(), actual.size())) {
            return false;
        }
        const std::uint16_t kind =
            static_cast<std::uint16_t>(actual[6]) |
            static_cast<std::uint16_t>(actual[7]) << 8U;
        const std::size_t key_length =
            static_cast<std::size_t>(actual[29]) |
            static_cast<std::size_t>(actual[30]) << 8U |
            static_cast<std::size_t>(actual[31]) << 16U |
            static_cast<std::size_t>(actual[32]) << 24U;
        if (kind != 3 || key_length > actual.size() - 33 ||
            actual[28] > static_cast<std::uint8_t>(
                             bolt::protocol::RegistryOperation::
                                 kUnsupportedTransactional)) {
            return false;
        }
        record.operation =
            static_cast<bolt::protocol::RegistryOperation>(actual[28]);
        record.key.assign(
            reinterpret_cast<const char*>(actual.data() + 33), key_length);
        const std::size_t expected_length =
            bolt::protocol::RegistryViolationFrameLength(
                record.key.c_str());
        std::vector<std::uint8_t> expected(expected_length);
        std::size_t written = 0;
        return expected_length == actual.size() &&
            bolt::protocol::EncodeRegistryViolationFrame(
                process_id, record.operation, record.key.c_str(), sequence,
                expected.data(), expected.size(), written) ==
                bolt::protocol::FrameEncodeStatus::kSuccess &&
            written == expected.size() && actual == expected;
    }
    return false;
}

std::string CanonicalCurrentUserKey(const std::wstring& relative) {
    std::string key = "HKEY_CURRENT_USER\\";
    for (const wchar_t value : relative) {
        if (value > 0x7f) {
            return {};
        }
        key.push_back(static_cast<char>(value));
    }
    return key;
}

std::string NarrowAscii(const std::wstring& value) {
    std::string narrowed;
    narrowed.reserve(value.size());
    for (const wchar_t character : value) {
        if (character < 0 || character > 0x7f) {
            return {};
        }
        narrowed.push_back(static_cast<char>(character));
    }
    return narrowed;
}

bool ValueEquals(
    const std::wstring& key_path,
    const wchar_t* value_name,
    const wchar_t* expected) {
    HKEY key = nullptr;
    wchar_t value[64]{};
    DWORD type = 0;
    DWORD bytes = sizeof(value);
    const bool matched = RegOpenKeyExW(
                             HKEY_CURRENT_USER, key_path.c_str(), 0, KEY_READ,
                             &key) == ERROR_SUCCESS &&
        RegQueryValueExW(
            key, value_name, nullptr, &type,
            reinterpret_cast<BYTE*>(value), &bytes) == ERROR_SUCCESS &&
        type == REG_SZ && std::wstring(value) == expected;
    if (key != nullptr) {
        RegCloseKey(key);
    }
    return matched;
}

bool KeyMissing(const std::wstring& key_path) {
    HKEY key = nullptr;
    const LSTATUS status = RegOpenKeyExW(
        HKEY_CURRENT_USER, key_path.c_str(), 0, KEY_READ, &key);
    if (key != nullptr) {
        RegCloseKey(key);
    }
    return status == ERROR_FILE_NOT_FOUND;
}

}  // namespace

int RunRegistryHookChild(const int argument_count, wchar_t** arguments) {
    if (argument_count != 7) {
        return 700;
    }
    const std::wstring root = arguments[2];
    const auto inherited_denied = reinterpret_cast<HKEY>(
        static_cast<std::uintptr_t>(_wcstoui64(arguments[3], nullptr, 10)));
    const auto inherited_read_only = reinterpret_cast<HKEY>(
        static_cast<std::uintptr_t>(_wcstoui64(arguments[4], nullptr, 10)));
    const auto inherited_race_allowed = reinterpret_cast<HKEY>(
        static_cast<std::uintptr_t>(_wcstoui64(arguments[5], nullptr, 10)));
    const auto inherited_race_denied = reinterpret_cast<HKEY>(
        static_cast<std::uintptr_t>(_wcstoui64(arguments[6], nullptr, 10)));
    const std::wstring read_only = root + L"\\ReadOnly";
    const std::wstring denied = root + L"\\Broad\\Sensitive";
    const std::wstring allowed = root + L"\\Allowed";
    const std::wstring inherited = root + L"\\Inherited";
    const std::wstring outside = root + L"\\Outside";
    const std::wstring link_to_sensitive =
        root + L"\\Allowed\\LinkToSensitive";
    const std::wstring root_id =
        root.substr(root.find_last_of(L'\\') + 1);
    const std::wstring wow64_read_only =
        L"Software\\Classes\\BoltSandboxRegistryTests\\" + root_id +
        L"\\Wow64ReadOnly";
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    using NtRenameKeyFunction = LONG(NTAPI*)(HANDLE, PUNICODE_STRING);
    const auto nt_rename_key = reinterpret_cast<NtRenameKeyFunction>(
        GetProcAddress(ntdll, "NtRenameKey"));
    using NtCreateKeyFunction = LONG(NTAPI*)(
        PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING,
        ULONG, PULONG);
    const auto nt_create_key = reinterpret_cast<NtCreateKeyFunction>(
        GetProcAddress(ntdll, "NtCreateKey"));
    using NtDeleteKeyFunction = LONG(NTAPI*)(HANDLE);
    const auto nt_delete_key = reinterpret_cast<NtDeleteKeyFunction>(
        GetProcAddress(ntdll, "NtDeleteKey"));
    using NtDeleteValueKeyFunction = LONG(NTAPI*)(
        HANDLE, PUNICODE_STRING);
    const auto nt_delete_value_key =
        reinterpret_cast<NtDeleteValueKeyFunction>(
            GetProcAddress(ntdll, "NtDeleteValueKey"));
    using NtQueryKeyFunction = LONG(NTAPI*)(
        HANDLE, ULONG, PVOID, ULONG, PULONG);
    const auto nt_query_key = reinterpret_cast<NtQueryKeyFunction>(
        GetProcAddress(ntdll, "NtQueryKey"));
    using NtQueryValueKeyFunction = LONG(NTAPI*)(
        HANDLE, PUNICODE_STRING, ULONG, PVOID, ULONG, PULONG);
    const auto nt_query_value_key =
        reinterpret_cast<NtQueryValueKeyFunction>(
            GetProcAddress(ntdll, "NtQueryValueKey"));
    using NtEnumerateKeyFunction = LONG(NTAPI*)(
        HANDLE, ULONG, ULONG, PVOID, ULONG, PULONG);
    const auto nt_enumerate_key =
        reinterpret_cast<NtEnumerateKeyFunction>(
            GetProcAddress(ntdll, "NtEnumerateKey"));
    using NtEnumerateValueKeyFunction = LONG(NTAPI*)(
        HANDLE, ULONG, ULONG, PVOID, ULONG, PULONG);
    const auto nt_enumerate_value_key =
        reinterpret_cast<NtEnumerateValueKeyFunction>(
            GetProcAddress(ntdll, "NtEnumerateValueKey"));
    using NtSetValueKeyFunction = LONG(NTAPI*)(
        HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG);
    const auto nt_set_value_key =
        reinterpret_cast<NtSetValueKeyFunction>(
            GetProcAddress(ntdll, "NtSetValueKey"));

    HKEY read_key = nullptr;
    wchar_t value[16]{};
    DWORD value_bytes = sizeof(value);
    DWORD value_type = 0;
    const LSTATUS read_open_status = RegOpenKeyExW(
        HKEY_CURRENT_USER, read_only.c_str(), 0, KEY_READ, &read_key);
    const LSTATUS read_query_status = read_open_status == ERROR_SUCCESS
        ? RegQueryValueExW(
              read_key, L"Seed", nullptr, &value_type,
              reinterpret_cast<BYTE*>(value), &value_bytes)
        : read_open_status;
    const bool read_allowed = read_open_status == ERROR_SUCCESS &&
        read_query_status == ERROR_SUCCESS &&
        value_type == REG_SZ && std::wstring(value) == L"seed";
    if (!read_allowed) {
        if (read_open_status != ERROR_SUCCESS) {
            return 711;
        }
        return read_query_status == ERROR_SUCCESS ? 713 : 712;
    }
    wchar_t enumerated_value[32]{};
    DWORD enumerated_value_length =
        static_cast<DWORD>(std::size(enumerated_value));
    const bool value_enumerated = RegEnumValueW(
        read_key, 0, enumerated_value, &enumerated_value_length, nullptr,
        nullptr, nullptr, nullptr) == ERROR_SUCCESS;
    wchar_t enumerated_key[32]{};
    DWORD enumerated_key_length =
        static_cast<DWORD>(std::size(enumerated_key));
    FILETIME last_write{};
    const bool key_enumerated = RegEnumKeyExW(
        read_key, 0, enumerated_key, &enumerated_key_length, nullptr, nullptr,
        nullptr, &last_write) == ERROR_SUCCESS;

    HKEY write_intent = nullptr;
    const LSTATUS read_only_write_open = RegOpenKeyExW(
        HKEY_CURRENT_USER, read_only.c_str(), 0,
        KEY_READ | KEY_SET_VALUE, &write_intent);
    if (write_intent != nullptr) {
        RegCloseKey(write_intent);
    }
    const wchar_t changed[] = L"changed";
    const LSTATUS read_only_set = RegSetValueExW(
        read_key, L"Seed", 0, REG_SZ,
        reinterpret_cast<const BYTE*>(changed), sizeof(changed));
    const LSTATUS read_only_delete_value =
        RegDeleteValueW(read_key, L"Seed");
    HKEY blocked_child = nullptr;
    DWORD blocked_disposition = 99;
    wchar_t blocked_child_text[] = L"BlockedChild";
    UNICODE_STRING blocked_child_name{};
    blocked_child_name.Buffer = blocked_child_text;
    blocked_child_name.Length = static_cast<USHORT>(
        std::wcslen(blocked_child_text) * sizeof(wchar_t));
    blocked_child_name.MaximumLength = blocked_child_name.Length;
    OBJECT_ATTRIBUTES blocked_child_attributes{};
    blocked_child_attributes.Length = sizeof(blocked_child_attributes);
    blocked_child_attributes.RootDirectory = read_key;
    blocked_child_attributes.ObjectName = &blocked_child_name;
    blocked_child_attributes.Attributes = OBJ_CASE_INSENSITIVE;
    const LONG read_only_create = nt_create_key == nullptr
        ? 0
        : nt_create_key(
              reinterpret_cast<PHANDLE>(&blocked_child), KEY_ALL_ACCESS,
              &blocked_child_attributes, 0, nullptr, 0,
              &blocked_disposition);
    if (blocked_child != nullptr) {
        RegCloseKey(blocked_child);
    }
    wchar_t renamed_read_only_text[] = L"RenamedReadOnly";
    UNICODE_STRING renamed_read_only_name{};
    renamed_read_only_name.Buffer = renamed_read_only_text;
    renamed_read_only_name.Length = static_cast<USHORT>(
        std::wcslen(renamed_read_only_text) * sizeof(wchar_t));
    renamed_read_only_name.MaximumLength = renamed_read_only_name.Length;
    const LONG read_only_rename = nt_rename_key == nullptr
        ? 0
        : nt_rename_key(read_key, &renamed_read_only_name);
    RegCloseKey(read_key);

    bool wow64_views_read = true;
    std::array<LSTATUS, 2> wow64_write_statuses{};
    const std::array<REGSAM, 2> wow64_views = {
        KEY_WOW64_32KEY, KEY_WOW64_64KEY};
    for (std::size_t index = 0; index < wow64_views.size(); ++index) {
        HKEY view_key = nullptr;
        wchar_t view_value[16]{};
        DWORD view_bytes = sizeof(view_value);
        DWORD view_type = 0;
        const LSTATUS view_open = RegOpenKeyExW(
            HKEY_CURRENT_USER, wow64_read_only.c_str(), 0,
            KEY_READ | wow64_views[index], &view_key);
        const LSTATUS view_query = view_open == ERROR_SUCCESS
            ? RegQueryValueExW(
                  view_key, L"Seed", nullptr, &view_type,
                  reinterpret_cast<BYTE*>(view_value), &view_bytes)
            : view_open;
        wow64_views_read = wow64_views_read &&
            view_open == ERROR_SUCCESS &&
            view_query == ERROR_SUCCESS &&
            view_type == REG_SZ && std::wstring(view_value) == L"seed";
        if (view_key != nullptr) {
            RegCloseKey(view_key);
        }
        HKEY view_write_key = nullptr;
        wow64_write_statuses[index] = RegOpenKeyExW(
            HKEY_CURRENT_USER, wow64_read_only.c_str(), 0,
            KEY_SET_VALUE | wow64_views[index], &view_write_key);
        if (view_write_key != nullptr) {
            RegCloseKey(view_write_key);
            wow64_views_read = false;
        }
    }

    HANDLE duplicated_read_only = nullptr;
    const bool duplicated = DuplicateHandle(
        GetCurrentProcess(), inherited_read_only, GetCurrentProcess(),
        &duplicated_read_only, KEY_ALL_ACCESS, FALSE, 0) != FALSE;
    wchar_t duplicated_value[16]{};
    DWORD duplicated_value_bytes = sizeof(duplicated_value);
    DWORD duplicated_value_type = 0;
    const LSTATUS duplicated_query = duplicated
        ? RegQueryValueExW(
              static_cast<HKEY>(duplicated_read_only), L"Seed", nullptr,
              &duplicated_value_type,
              reinterpret_cast<BYTE*>(duplicated_value),
              &duplicated_value_bytes)
        : ERROR_INVALID_HANDLE;
    const wchar_t duplicated_changed[] = L"duplicated";
    const LSTATUS duplicated_set = duplicated
        ? RegSetValueExW(
              static_cast<HKEY>(duplicated_read_only), L"Seed", 0, REG_SZ,
              reinterpret_cast<const BYTE*>(duplicated_changed),
              sizeof(duplicated_changed))
        : ERROR_INVALID_HANDLE;
    const LSTATUS duplicated_delete = duplicated
        ? RegDeleteValueW(
              static_cast<HKEY>(duplicated_read_only), L"Seed")
        : ERROR_INVALID_HANDLE;
    wchar_t duplicated_rename_text[] = L"DuplicatedReadOnly";
    UNICODE_STRING duplicated_rename_name{};
    duplicated_rename_name.Buffer = duplicated_rename_text;
    duplicated_rename_name.Length = static_cast<USHORT>(
        std::wcslen(duplicated_rename_text) * sizeof(wchar_t));
    duplicated_rename_name.MaximumLength = duplicated_rename_name.Length;
    const LONG duplicated_rename =
        duplicated && nt_rename_key != nullptr
        ? nt_rename_key(duplicated_read_only, &duplicated_rename_name)
        : 0;
    if (duplicated_read_only != nullptr) {
        CloseHandle(duplicated_read_only);
    }

    HKEY denied_key = nullptr;
    const LSTATUS denied_open = RegOpenKeyExW(
        HKEY_CURRENT_USER, denied.c_str(), 0, KEY_READ, &denied_key);
    if (denied_key != nullptr) {
        RegCloseKey(denied_key);
    }
    HKEY outside_key = nullptr;
    const LSTATUS outside_open = RegOpenKeyExW(
        HKEY_CURRENT_USER, outside.c_str(), 0, KEY_READ, &outside_key);
    if (outside_key != nullptr) {
        RegCloseKey(outside_key);
    }
    HKEY linked_sensitive_key = nullptr;
    const LSTATUS linked_sensitive_open = RegOpenKeyExW(
        HKEY_CURRENT_USER, link_to_sensitive.c_str(), 0, KEY_READ,
        &linked_sensitive_key);
    if (linked_sensitive_key != nullptr) {
        RegCloseKey(linked_sensitive_key);
    }

    wchar_t inherited_value[16]{};
    DWORD inherited_value_bytes = sizeof(inherited_value);
    DWORD inherited_value_type = 0;
    const LSTATUS inherited_denied_query = RegQueryValueExW(
        inherited_denied, kRegistryValueNameCanaryWide, nullptr,
        &inherited_value_type,
        reinterpret_cast<BYTE*>(inherited_value), &inherited_value_bytes);
    const LSTATUS inherited_denied_set = RegSetValueExW(
        inherited_denied, L"Changed", 0, REG_SZ,
        reinterpret_cast<const BYTE*>(changed), sizeof(changed));
    wchar_t inherited_enumerated[32]{};
    DWORD inherited_enumerated_length =
        static_cast<DWORD>(std::size(inherited_enumerated));
    const LSTATUS inherited_denied_enumerate = RegEnumValueW(
        inherited_denied, 0, inherited_enumerated,
        &inherited_enumerated_length, nullptr, nullptr, nullptr, nullptr);
    UNICODE_STRING denied_value_name{};
    denied_value_name.Buffer =
        const_cast<PWSTR>(kRegistryValueNameCanaryWide);
    denied_value_name.Length = static_cast<USHORT>(
        std::wcslen(kRegistryValueNameCanaryWide) * sizeof(wchar_t));
    denied_value_name.MaximumLength = denied_value_name.Length;
    const LONG inherited_denied_delete_value =
        nt_delete_value_key == nullptr
        ? 0
        : nt_delete_value_key(inherited_denied, &denied_value_name);
    const LONG inherited_denied_delete_key =
        nt_delete_key == nullptr ? 0 : nt_delete_key(inherited_denied);
    wchar_t renamed_denied_text[] = L"RenamedSensitive";
    UNICODE_STRING renamed_denied_name{};
    renamed_denied_name.Buffer = renamed_denied_text;
    renamed_denied_name.Length = static_cast<USHORT>(
        std::wcslen(renamed_denied_text) * sizeof(wchar_t));
    renamed_denied_name.MaximumLength = renamed_denied_name.Length;
    const LONG inherited_denied_rename = nt_rename_key == nullptr
        ? 0
        : nt_rename_key(inherited_denied, &renamed_denied_name);
    HKEY denied_blocked_child = nullptr;
    DWORD denied_blocked_disposition = 99;
    wchar_t denied_blocked_child_text[] = L"BlockedChild";
    UNICODE_STRING denied_blocked_child_name{};
    denied_blocked_child_name.Buffer = denied_blocked_child_text;
    denied_blocked_child_name.Length = static_cast<USHORT>(
        std::wcslen(denied_blocked_child_text) * sizeof(wchar_t));
    denied_blocked_child_name.MaximumLength =
        denied_blocked_child_name.Length;
    OBJECT_ATTRIBUTES denied_blocked_child_attributes{};
    denied_blocked_child_attributes.Length =
        sizeof(denied_blocked_child_attributes);
    denied_blocked_child_attributes.RootDirectory = inherited_denied;
    denied_blocked_child_attributes.ObjectName =
        &denied_blocked_child_name;
    denied_blocked_child_attributes.Attributes = OBJ_CASE_INSENSITIVE;
    const LONG inherited_denied_create = nt_create_key == nullptr
        ? 0
        : nt_create_key(
              reinterpret_cast<PHANDLE>(&denied_blocked_child),
              KEY_ALL_ACCESS, &denied_blocked_child_attributes, 0, nullptr,
              0, &denied_blocked_disposition);
    if (denied_blocked_child != nullptr) {
        RegCloseKey(denied_blocked_child);
    }
    std::array<std::uint8_t, 256> native_information{};
    ULONG native_result_length = 0;
    const LONG direct_denied_query_key = nt_query_key == nullptr
        ? 0
        : nt_query_key(
              inherited_denied, 0, native_information.data(),
              static_cast<ULONG>(native_information.size()),
              &native_result_length);
    const LONG direct_denied_query_value =
        nt_query_value_key == nullptr
        ? 0
        : nt_query_value_key(
              inherited_denied, &denied_value_name, 2,
              native_information.data(),
              static_cast<ULONG>(native_information.size()),
              &native_result_length);
    const LONG direct_denied_enumerate_key =
        nt_enumerate_key == nullptr
        ? 0
        : nt_enumerate_key(
              inherited_denied, 0, 0, native_information.data(),
              static_cast<ULONG>(native_information.size()),
              &native_result_length);
    const LONG direct_denied_enumerate_value =
        nt_enumerate_value_key == nullptr
        ? 0
        : nt_enumerate_value_key(
              inherited_denied, 0, 0, native_information.data(),
              static_cast<ULONG>(native_information.size()),
              &native_result_length);
    const LONG direct_denied_set_value = nt_set_value_key == nullptr
        ? 0
        : nt_set_value_key(
              inherited_denied, &denied_value_name, 0, REG_SZ,
              const_cast<wchar_t*>(changed),
              static_cast<ULONG>(sizeof(changed)));

    HKEY current_user = nullptr;
    const LSTATUS current_user_status =
        RegOpenCurrentUser(KEY_READ, &current_user);
    using NtOpenKeyFunction = LONG(NTAPI*)(
        PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
    const auto nt_open_key = reinterpret_cast<NtOpenKeyFunction>(
        GetProcAddress(ntdll, "NtOpenKey"));
    UNICODE_STRING denied_name{};
    denied_name.Buffer = const_cast<PWSTR>(denied.c_str());
    denied_name.Length = static_cast<USHORT>(denied.size() * sizeof(wchar_t));
    denied_name.MaximumLength = denied_name.Length;
    OBJECT_ATTRIBUTES denied_attributes{};
    denied_attributes.Length = sizeof(denied_attributes);
    denied_attributes.RootDirectory = current_user;
    denied_attributes.ObjectName = &denied_name;
    denied_attributes.Attributes = OBJ_CASE_INSENSITIVE;
    HANDLE direct_denied_key = nullptr;
    const LONG direct_denied_open =
        current_user_status == ERROR_SUCCESS && nt_open_key != nullptr
        ? nt_open_key(&direct_denied_key, KEY_READ, &denied_attributes)
        : 0;
    if (direct_denied_key != nullptr) {
        RegCloseKey(static_cast<HKEY>(direct_denied_key));
    }
    if (current_user != nullptr) {
        RegCloseKey(current_user);
    }

    HKEY allowed_key = nullptr;
    bool write_allowed =
        RegOpenKeyExW(
            HKEY_CURRENT_USER, allowed.c_str(), 0,
            KEY_ALL_ACCESS, &allowed_key) == ERROR_SUCCESS &&
        RegSetValueExW(
            allowed_key, L"Changed", 0, REG_SZ,
            reinterpret_cast<const BYTE*>(changed),
            sizeof(changed)) == ERROR_SUCCESS;
    DWORD missing_bytes = 0;
    const LSTATUS missing_value_error = write_allowed
        ? RegQueryValueExW(
              allowed_key, L"Missing", nullptr, nullptr, nullptr,
              &missing_bytes)
        : ERROR_INVALID_HANDLE;
    HKEY temporary = nullptr;
    DWORD temporary_disposition = 0;
    write_allowed = write_allowed && missing_value_error == ERROR_FILE_NOT_FOUND &&
        RegCreateKeyExW(
            allowed_key, L"Temp", 0, nullptr, 0, KEY_ALL_ACCESS, nullptr,
            &temporary, &temporary_disposition) == ERROR_SUCCESS &&
        RegSetValueExW(
            temporary, L"Temporary", 0, REG_SZ,
            reinterpret_cast<const BYTE*>(changed), sizeof(changed)) ==
            ERROR_SUCCESS &&
        RegDeleteValueW(temporary, L"Temporary") == ERROR_SUCCESS;
    if (temporary != nullptr) {
        RegCloseKey(temporary);
    }
    write_allowed = write_allowed &&
        RegRenameKey(allowed_key, L"Temp", L"Renamed") == ERROR_SUCCESS &&
        RegDeleteKeyW(allowed_key, L"Renamed") == ERROR_SUCCESS;
    if (allowed_key != nullptr) {
        RegCloseKey(allowed_key);
    }

    HKEY inherited_key = nullptr;
    const bool inherit_user_allowed =
        RegOpenKeyExW(
            HKEY_CURRENT_USER, inherited.c_str(), 0,
            KEY_READ | KEY_SET_VALUE, &inherited_key) == ERROR_SUCCESS &&
        RegSetValueExW(
            inherited_key, L"Changed", 0, REG_SZ,
            reinterpret_cast<const BYTE*>(changed),
            sizeof(changed)) == ERROR_SUCCESS;
    if (inherited_key != nullptr) {
        RegCloseKey(inherited_key);
    }

    const HMODULE advapi32 = GetModuleHandleW(L"advapi32.dll");
    using RegConnectRegistryWFunction = LSTATUS(WINAPI*)(
        LPCWSTR, HKEY, PHKEY);
    using RegConnectRegistryAFunction = LSTATUS(WINAPI*)(
        LPCSTR, HKEY, PHKEY);
    const auto reg_connect_registry_w = advapi32 == nullptr
        ? nullptr
        : reinterpret_cast<RegConnectRegistryWFunction>(
              GetProcAddress(advapi32, "RegConnectRegistryW"));
    const auto reg_connect_registry_a = advapi32 == nullptr
        ? nullptr
        : reinterpret_cast<RegConnectRegistryAFunction>(
              GetProcAddress(advapi32, "RegConnectRegistryA"));
    HKEY remote_key = reinterpret_cast<HKEY>(
        static_cast<std::uintptr_t>(1));
    const LSTATUS remote_status = reg_connect_registry_w == nullptr
        ? ERROR_PROC_NOT_FOUND
        : reg_connect_registry_w(
              nullptr, HKEY_CURRENT_USER, &remote_key);
    if (remote_status == ERROR_SUCCESS && remote_key != nullptr) {
        RegCloseKey(remote_key);
    }
    HKEY remote_key_a = reinterpret_cast<HKEY>(
        static_cast<std::uintptr_t>(1));
    const LSTATUS remote_status_a = reg_connect_registry_a == nullptr
        ? ERROR_PROC_NOT_FOUND
        : reg_connect_registry_a(
              nullptr, HKEY_CURRENT_USER, &remote_key_a);
    if (remote_status_a == ERROR_SUCCESS && remote_key_a != nullptr) {
        RegCloseKey(remote_key_a);
    }

    using RegOpenKeyTransactedWFunction = LSTATUS(WINAPI*)(
        HKEY, LPCWSTR, DWORD, REGSAM, PHKEY, HANDLE, PVOID);
    using RegCreateKeyTransactedWFunction = LSTATUS(WINAPI*)(
        HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM,
        const SECURITY_ATTRIBUTES*, PHKEY, LPDWORD, HANDLE, PVOID);
    using RegDeleteKeyTransactedWFunction = LSTATUS(WINAPI*)(
        HKEY, LPCWSTR, REGSAM, DWORD, HANDLE, PVOID);
    using RegOpenKeyTransactedAFunction = LSTATUS(WINAPI*)(
        HKEY, LPCSTR, DWORD, REGSAM, PHKEY, HANDLE, PVOID);
    using RegCreateKeyTransactedAFunction = LSTATUS(WINAPI*)(
        HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM,
        const SECURITY_ATTRIBUTES*, PHKEY, LPDWORD, HANDLE, PVOID);
    using RegDeleteKeyTransactedAFunction = LSTATUS(WINAPI*)(
        HKEY, LPCSTR, REGSAM, DWORD, HANDLE, PVOID);
    const auto reg_open_key_transacted_w = advapi32 == nullptr
        ? nullptr
        : reinterpret_cast<RegOpenKeyTransactedWFunction>(
              GetProcAddress(advapi32, "RegOpenKeyTransactedW"));
    const auto reg_create_key_transacted_w = advapi32 == nullptr
        ? nullptr
        : reinterpret_cast<RegCreateKeyTransactedWFunction>(
              GetProcAddress(advapi32, "RegCreateKeyTransactedW"));
    const auto reg_delete_key_transacted_w = advapi32 == nullptr
        ? nullptr
        : reinterpret_cast<RegDeleteKeyTransactedWFunction>(
              GetProcAddress(advapi32, "RegDeleteKeyTransactedW"));
    const auto reg_open_key_transacted_a = advapi32 == nullptr
        ? nullptr
        : reinterpret_cast<RegOpenKeyTransactedAFunction>(
              GetProcAddress(advapi32, "RegOpenKeyTransactedA"));
    const auto reg_create_key_transacted_a = advapi32 == nullptr
        ? nullptr
        : reinterpret_cast<RegCreateKeyTransactedAFunction>(
              GetProcAddress(advapi32, "RegCreateKeyTransactedA"));
    const auto reg_delete_key_transacted_a = advapi32 == nullptr
        ? nullptr
        : reinterpret_cast<RegDeleteKeyTransactedAFunction>(
              GetProcAddress(advapi32, "RegDeleteKeyTransactedA"));
    const HANDLE invalid_transaction = INVALID_HANDLE_VALUE;
    HKEY transacted_open_key = reinterpret_cast<HKEY>(
        static_cast<std::uintptr_t>(1));
    const LSTATUS transacted_open_status =
        reg_open_key_transacted_w == nullptr
        ? ERROR_PROC_NOT_FOUND
        : reg_open_key_transacted_w(
              HKEY_CURRENT_USER, allowed.c_str(), 0, KEY_READ,
              &transacted_open_key, invalid_transaction, nullptr);
    if (transacted_open_status == ERROR_SUCCESS &&
        transacted_open_key != nullptr) {
        RegCloseKey(transacted_open_key);
    }
    const std::wstring unsupported_create =
        root + L"\\Allowed\\UnsupportedCreate";
    HKEY transacted_create_key = reinterpret_cast<HKEY>(
        static_cast<std::uintptr_t>(1));
    DWORD transacted_disposition = 99;
    const LSTATUS transacted_create_status =
        reg_create_key_transacted_w == nullptr
        ? ERROR_PROC_NOT_FOUND
        : reg_create_key_transacted_w(
              HKEY_CURRENT_USER, unsupported_create.c_str(), 0, nullptr, 0,
              KEY_ALL_ACCESS, nullptr, &transacted_create_key,
              &transacted_disposition, invalid_transaction, nullptr);
    if (transacted_create_status == ERROR_SUCCESS &&
        transacted_create_key != nullptr) {
        RegCloseKey(transacted_create_key);
    }
    const LSTATUS transacted_delete_status =
        reg_delete_key_transacted_w == nullptr
        ? ERROR_PROC_NOT_FOUND
        : reg_delete_key_transacted_w(
              HKEY_CURRENT_USER, allowed.c_str(), 0, 0,
              invalid_transaction, nullptr);
    const std::string allowed_a = NarrowAscii(allowed);
    const std::string unsupported_create_a =
        NarrowAscii(unsupported_create);
    HKEY transacted_open_key_a = reinterpret_cast<HKEY>(
        static_cast<std::uintptr_t>(1));
    const LSTATUS transacted_open_status_a =
        reg_open_key_transacted_a == nullptr
        ? ERROR_PROC_NOT_FOUND
        : reg_open_key_transacted_a(
              HKEY_CURRENT_USER, allowed_a.c_str(), 0, KEY_READ,
              &transacted_open_key_a, invalid_transaction, nullptr);
    if (transacted_open_status_a == ERROR_SUCCESS &&
        transacted_open_key_a != nullptr) {
        RegCloseKey(transacted_open_key_a);
    }
    HKEY transacted_create_key_a = reinterpret_cast<HKEY>(
        static_cast<std::uintptr_t>(1));
    DWORD transacted_disposition_a = 99;
    const LSTATUS transacted_create_status_a =
        reg_create_key_transacted_a == nullptr
        ? ERROR_PROC_NOT_FOUND
        : reg_create_key_transacted_a(
              HKEY_CURRENT_USER, unsupported_create_a.c_str(), 0, nullptr,
              0, KEY_ALL_ACCESS, nullptr, &transacted_create_key_a,
              &transacted_disposition_a, invalid_transaction, nullptr);
    if (transacted_create_status_a == ERROR_SUCCESS &&
        transacted_create_key_a != nullptr) {
        RegCloseKey(transacted_create_key_a);
    }
    const LSTATUS transacted_delete_status_a =
        reg_delete_key_transacted_a == nullptr
        ? ERROR_PROC_NOT_FOUND
        : reg_delete_key_transacted_a(
              HKEY_CURRENT_USER, allowed_a.c_str(), 0, 0,
              invalid_transaction, nullptr);

    using NtOpenKeyTransactedFunction = LONG(NTAPI*)(
        PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE);
    using NtOpenKeyTransactedExFunction = LONG(NTAPI*)(
        PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, HANDLE);
    using NtCreateKeyTransactedFunction = LONG(NTAPI*)(
        PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING,
        ULONG, HANDLE, PULONG);
    const auto nt_open_key_transacted =
        reinterpret_cast<NtOpenKeyTransactedFunction>(
            GetProcAddress(ntdll, "NtOpenKeyTransacted"));
    const auto nt_open_key_transacted_ex =
        reinterpret_cast<NtOpenKeyTransactedExFunction>(
            GetProcAddress(ntdll, "NtOpenKeyTransactedEx"));
    const auto nt_create_key_transacted =
        reinterpret_cast<NtCreateKeyTransactedFunction>(
            GetProcAddress(ntdll, "NtCreateKeyTransacted"));
    HKEY transaction_current_user = nullptr;
    const LSTATUS transaction_current_user_status =
        RegOpenCurrentUser(KEY_READ, &transaction_current_user);
    UNICODE_STRING transacted_allowed_name{};
    transacted_allowed_name.Buffer = const_cast<PWSTR>(allowed.c_str());
    transacted_allowed_name.Length = static_cast<USHORT>(
        allowed.size() * sizeof(wchar_t));
    transacted_allowed_name.MaximumLength =
        transacted_allowed_name.Length;
    OBJECT_ATTRIBUTES transacted_allowed_attributes{};
    transacted_allowed_attributes.Length =
        sizeof(transacted_allowed_attributes);
    transacted_allowed_attributes.RootDirectory =
        transaction_current_user;
    transacted_allowed_attributes.ObjectName =
        &transacted_allowed_name;
    transacted_allowed_attributes.Attributes = OBJ_CASE_INSENSITIVE;
    HANDLE native_transacted_open = reinterpret_cast<HANDLE>(
        static_cast<std::uintptr_t>(1));
    const LONG native_transacted_open_status =
        transaction_current_user_status == ERROR_SUCCESS &&
            nt_open_key_transacted != nullptr
        ? nt_open_key_transacted(
              &native_transacted_open, KEY_READ,
              &transacted_allowed_attributes, invalid_transaction)
        : 0;
    if (native_transacted_open_status >= 0 &&
        native_transacted_open != nullptr) {
        CloseHandle(native_transacted_open);
    }
    HANDLE native_transacted_open_ex = reinterpret_cast<HANDLE>(
        static_cast<std::uintptr_t>(1));
    const LONG native_transacted_open_ex_status =
        transaction_current_user_status == ERROR_SUCCESS &&
            nt_open_key_transacted_ex != nullptr
        ? nt_open_key_transacted_ex(
              &native_transacted_open_ex, KEY_READ,
              &transacted_allowed_attributes, 0, invalid_transaction)
        : 0;
    if (native_transacted_open_ex_status >= 0 &&
        native_transacted_open_ex != nullptr) {
        CloseHandle(native_transacted_open_ex);
    }
    HANDLE native_transacted_create = reinterpret_cast<HANDLE>(
        static_cast<std::uintptr_t>(1));
    ULONG native_transacted_disposition = 99;
    const LONG native_transacted_create_status =
        transaction_current_user_status == ERROR_SUCCESS &&
            nt_create_key_transacted != nullptr
        ? nt_create_key_transacted(
              &native_transacted_create, KEY_ALL_ACCESS,
              &transacted_allowed_attributes, 0, nullptr, 0,
              invalid_transaction, &native_transacted_disposition)
        : 0;
    if (native_transacted_create_status >= 0 &&
        native_transacted_create != nullptr) {
        CloseHandle(native_transacted_create);
    }
    if (transaction_current_user != nullptr) {
        RegCloseKey(transaction_current_user);
    }

    constexpr std::size_t race_attempt_count = 16;
    std::array<LONG, race_attempt_count> race_rename_statuses{};
    std::array<LONG, race_attempt_count> race_set_statuses{};
    const HANDLE race_start = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (race_start != nullptr && nt_rename_key != nullptr &&
        nt_set_value_key != nullptr) {
        wchar_t race_denied_text[] = L"Denied";
        UNICODE_STRING race_denied_name{};
        race_denied_name.Buffer = race_denied_text;
        race_denied_name.Length = static_cast<USHORT>(
            std::wcslen(race_denied_text) * sizeof(wchar_t));
        race_denied_name.MaximumLength = race_denied_name.Length;
        std::thread rename_thread([&] {
            WaitForSingleObject(race_start, INFINITE);
            for (std::size_t index = 0;
                 index < race_rename_statuses.size(); ++index) {
                race_rename_statuses[index] = nt_rename_key(
                    inherited_race_allowed, &race_denied_name);
            }
        });
        std::thread set_thread([&] {
            WaitForSingleObject(race_start, INFINITE);
            for (std::size_t index = 0;
                 index < race_set_statuses.size(); ++index) {
                race_set_statuses[index] = nt_set_value_key(
                    inherited_race_denied, &denied_value_name, 0, REG_SZ,
                    const_cast<wchar_t*>(changed),
                    static_cast<ULONG>(sizeof(changed)));
            }
        });
        SetEvent(race_start);
        rename_thread.join();
        set_thread.join();
    }
    if (race_start != nullptr) {
        CloseHandle(race_start);
    }
    const bool race_operations_denied =
        std::all_of(
            race_rename_statuses.begin(), race_rename_statuses.end(),
            [](const LONG status) {
                return status == static_cast<LONG>(0xC0000022L);
            }) &&
        std::all_of(
            race_set_statuses.begin(), race_set_statuses.end(),
            [](const LONG status) {
                return status == static_cast<LONG>(0xC0000022L);
            });

    if (!value_enumerated || !key_enumerated) {
        return 716;
    }
    if (!wow64_views_read ||
        wow64_write_statuses[0] != ERROR_ACCESS_DENIED ||
        wow64_write_statuses[1] != ERROR_ACCESS_DENIED) {
        return 720;
    }
    if (!duplicated || duplicated_query != ERROR_SUCCESS ||
        duplicated_value_type != REG_SZ ||
        std::wstring(duplicated_value) != L"seed" ||
        duplicated_set != ERROR_ACCESS_DENIED ||
        duplicated_delete != ERROR_ACCESS_DENIED ||
        duplicated_rename != static_cast<LONG>(0xC0000022L)) {
        return 722;
    }
    if (read_only_write_open != ERROR_ACCESS_DENIED || write_intent != nullptr) {
        return 702;
    }
    if (read_only_set != ERROR_ACCESS_DENIED ||
        read_only_delete_value != ERROR_ACCESS_DENIED ||
        read_only_create != static_cast<LONG>(0xC0000022L) ||
        blocked_child != nullptr ||
        blocked_disposition != 99 ||
        read_only_rename != static_cast<LONG>(0xC0000022L)) {
        return 717;
    }
    if (denied_open != ERROR_ACCESS_DENIED) {
        return denied_open == ERROR_SUCCESS ? 703 : 714;
    }
    if (denied_key != nullptr) {
        return 715;
    }
    if (outside_open != ERROR_ACCESS_DENIED || outside_key != nullptr) {
        return 704;
    }
    if (linked_sensitive_open != ERROR_ACCESS_DENIED ||
        linked_sensitive_key != nullptr) {
        std::fprintf(
            stderr,
            "registry symbolic-link open status=%ld handle=%d\n",
            static_cast<long>(linked_sensitive_open),
            linked_sensitive_key != nullptr ? 1 : 0);
        return 721;
    }
    if (inherited_denied_query != ERROR_ACCESS_DENIED ||
        inherited_denied_set != ERROR_ACCESS_DENIED ||
        inherited_denied_enumerate != ERROR_ACCESS_DENIED ||
        inherited_denied_delete_value != static_cast<LONG>(0xC0000022L) ||
        inherited_denied_delete_key != static_cast<LONG>(0xC0000022L) ||
        inherited_denied_rename != static_cast<LONG>(0xC0000022L) ||
        inherited_denied_create != static_cast<LONG>(0xC0000022L) ||
        denied_blocked_child != nullptr ||
        denied_blocked_disposition != 99 ||
        direct_denied_query_key != static_cast<LONG>(0xC0000022L) ||
        direct_denied_query_value != static_cast<LONG>(0xC0000022L) ||
        direct_denied_enumerate_key != static_cast<LONG>(0xC0000022L) ||
        direct_denied_enumerate_value !=
            static_cast<LONG>(0xC0000022L) ||
        direct_denied_set_value != static_cast<LONG>(0xC0000022L)) {
        return 718;
    }
    if (direct_denied_open != static_cast<LONG>(0xC0000022L) ||
        direct_denied_key != nullptr) {
        return 719;
    }
    if (!write_allowed) {
        return 705;
    }
    if (!inherit_user_allowed) {
        return 706;
    }
    if (!race_operations_denied ||
        allowed_a.empty() || unsupported_create_a.empty() ||
        remote_status != ERROR_ACCESS_DENIED || remote_key != nullptr ||
        remote_status_a != ERROR_ACCESS_DENIED ||
        remote_key_a != nullptr ||
        transacted_open_status != ERROR_ACCESS_DENIED ||
        transacted_open_key != nullptr ||
        transacted_create_status != ERROR_ACCESS_DENIED ||
        transacted_create_key != nullptr ||
        transacted_disposition != 99 ||
        transacted_delete_status != ERROR_ACCESS_DENIED ||
        transacted_open_status_a != ERROR_ACCESS_DENIED ||
        transacted_open_key_a != nullptr ||
        transacted_create_status_a != ERROR_ACCESS_DENIED ||
        transacted_create_key_a != nullptr ||
        transacted_disposition_a != 99 ||
        transacted_delete_status_a != ERROR_ACCESS_DENIED ||
        native_transacted_open_status !=
            static_cast<LONG>(0xC0000022L) ||
        native_transacted_open != nullptr ||
        native_transacted_open_ex_status !=
            static_cast<LONG>(0xC0000022L) ||
        native_transacted_open_ex != nullptr ||
        native_transacted_create_status !=
            static_cast<LONG>(0xC0000022L) ||
        native_transacted_create != nullptr ||
        native_transacted_disposition != 99) {
        return 723;
    }
    const HMODULE hook = GetModuleHandleW(
#if defined(_WIN64)
        L"bolt-sandbox-x64.dll"
#else
        L"bolt-sandbox-x86.dll"
#endif
    );
    const auto flush_events = hook == nullptr
        ? nullptr
        : reinterpret_cast<BOOL (*)(DWORD)>(
              GetProcAddress(hook, "BoltSandboxFlushEvents"));
    return flush_events != nullptr && flush_events(2'000) ? 0 : 707;
}

bool RunRegistryHookTests() {
    const DWORD process_id = GetCurrentProcessId();
    const std::wstring root =
        L"Software\\BoltSandboxRegistryTests\\" +
        std::to_wstring(process_id);
    const std::wstring wow64_root =
        L"Software\\Classes\\BoltSandboxRegistryTests\\" +
        std::to_wstring(process_id);
    const std::wstring wow64_read_only =
        wow64_root + L"\\Wow64ReadOnly";
    const std::wstring link_to_sensitive =
        root + L"\\Allowed\\LinkToSensitive";
    DeleteRegistrySymbolicLink(link_to_sensitive);
    RegDeleteTreeW(HKEY_CURRENT_USER, root.c_str());
    DeleteKeyTreeInView(wow64_root, KEY_WOW64_32KEY);
    DeleteKeyTreeInView(wow64_root, KEY_WOW64_64KEY);
    const bool prepared =
        CreateKeyWithValue(root + L"\\ReadOnly", L"Seed", L"seed") &&
        CreateKeyWithValue(
            root + L"\\ReadOnly\\ExistingChild", L"Seed", L"seed") &&
        CreateKeyWithValue(
            root + L"\\Broad\\Sensitive",
            kRegistryValueNameCanaryWide,
            kRegistryValueDataCanaryWide) &&
        CreateKeyWithValue(root + L"\\Allowed", L"Seed", L"seed") &&
        CreateKeyWithValue(root + L"\\Inherited", L"Seed", L"seed") &&
        CreateKeyWithValue(root + L"\\Outside", L"Seed", L"outside") &&
        CreateKeyWithValue(root + L"\\Race\\Allowed", L"Seed", L"seed") &&
        CreateKeyWithValue(
            root + L"\\Race\\Denied",
            kRegistryValueNameCanaryWide,
            kRegistryValueDataCanaryWide) &&
        CreateKeyWithValueInView(
            wow64_read_only, KEY_WOW64_32KEY, L"Seed", L"seed") &&
        CreateKeyWithValueInView(
            wow64_read_only, KEY_WOW64_64KEY, L"Seed", L"seed") &&
        CreateRegistrySymbolicLink(
            link_to_sensitive, root + L"\\Broad\\Sensitive") &&
        ValidateRegistrySymbolicLink(
            link_to_sensitive, root + L"\\Broad\\Sensitive");
    if (!prepared) {
        DeleteRegistrySymbolicLink(link_to_sensitive);
        RegDeleteTreeW(HKEY_CURRENT_USER, root.c_str());
        DeleteKeyTreeInView(wow64_root, KEY_WOW64_32KEY);
        DeleteKeyTreeInView(wow64_root, KEY_WOW64_64KEY);
        return false;
    }
    HKEY inherited_denied_handle = nullptr;
    HKEY inherited_read_only_handle = nullptr;
    HKEY inherited_race_allowed_handle = nullptr;
    HKEY inherited_race_denied_handle = nullptr;
    if (RegOpenKeyExW(
            HKEY_CURRENT_USER, (root + L"\\Broad\\Sensitive").c_str(), 0,
            KEY_ALL_ACCESS, &inherited_denied_handle) != ERROR_SUCCESS ||
        SetHandleInformation(
            inherited_denied_handle, HANDLE_FLAG_INHERIT,
            HANDLE_FLAG_INHERIT) == FALSE ||
        RegOpenKeyExW(
            HKEY_CURRENT_USER, (root + L"\\ReadOnly").c_str(), 0,
            KEY_ALL_ACCESS, &inherited_read_only_handle) != ERROR_SUCCESS ||
        SetHandleInformation(
            inherited_read_only_handle, HANDLE_FLAG_INHERIT,
            HANDLE_FLAG_INHERIT) == FALSE ||
        RegOpenKeyExW(
            HKEY_CURRENT_USER, (root + L"\\Race\\Allowed").c_str(), 0,
            KEY_ALL_ACCESS, &inherited_race_allowed_handle) !=
            ERROR_SUCCESS ||
        SetHandleInformation(
            inherited_race_allowed_handle, HANDLE_FLAG_INHERIT,
            HANDLE_FLAG_INHERIT) == FALSE ||
        RegOpenKeyExW(
            HKEY_CURRENT_USER, (root + L"\\Race\\Denied").c_str(), 0,
            KEY_ALL_ACCESS, &inherited_race_denied_handle) != ERROR_SUCCESS ||
        SetHandleInformation(
            inherited_race_denied_handle, HANDLE_FLAG_INHERIT,
            HANDLE_FLAG_INHERIT) == FALSE) {
        if (inherited_denied_handle != nullptr) {
            RegCloseKey(inherited_denied_handle);
        }
        if (inherited_read_only_handle != nullptr) {
            RegCloseKey(inherited_read_only_handle);
        }
        if (inherited_race_allowed_handle != nullptr) {
            RegCloseKey(inherited_race_allowed_handle);
        }
        if (inherited_race_denied_handle != nullptr) {
            RegCloseKey(inherited_race_denied_handle);
        }
        RegDeleteTreeW(HKEY_CURRENT_USER, root.c_str());
        return false;
    }
    const std::vector<bolt::tests::RegistryRule> registry_rules = {
        {bolt::tests::RegistryRuleKind::kReadOnly,
         bolt::tests::RegistryHive::kCurrentUser,
         Components(process_id, "READONLY")},
        {bolt::tests::RegistryRuleKind::kNoAccess,
         bolt::tests::RegistryHive::kCurrentUser,
         Components(process_id, "BROAD", "SENSITIVE")},
        {bolt::tests::RegistryRuleKind::kReadWrite,
         bolt::tests::RegistryHive::kCurrentUser,
         Components(process_id, "BROAD")},
        {bolt::tests::RegistryRuleKind::kReadWrite,
         bolt::tests::RegistryHive::kCurrentUser,
         Components(process_id, "ALLOWED")},
        {bolt::tests::RegistryRuleKind::kInheritUser,
         bolt::tests::RegistryHive::kCurrentUser,
         Components(process_id, "INHERITED")},
        {bolt::tests::RegistryRuleKind::kReadOnly,
         bolt::tests::RegistryHive::kCurrentUser,
         ClassComponents(process_id, "WOW64READONLY")},
        {bolt::tests::RegistryRuleKind::kReadWrite,
         bolt::tests::RegistryHive::kCurrentUser,
         Components(process_id, "RACE")},
        {bolt::tests::RegistryRuleKind::kNoAccess,
         bolt::tests::RegistryHive::kCurrentUser,
         Components(process_id, "RACE", "DENIED")},
    };
    const std::wstring executable = CurrentExecutable();
    const auto payload = bolt::tests::SealPolicy(
        {{bolt::tests::FilesystemRuleKind::kReadWrite,
          std::filesystem::path(executable).root_path()}},
        bolt::tests::ChildProcessPolicyKind::kDeny,
        bolt::tests::NetworkPolicyKind::kUnrestricted, {}, registry_rules);
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    const HANDLE release = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    bolt::common::ImmutablePolicyMapping policy;
    bolt::common::PrivatePipe event_pipe;
    const std::wstring pipe_name = PipeName(process_id ^ 0x52454731U);
    if (release == nullptr || payload.empty() ||
        ContainsRegistryCanary(payload.data(), payload.size()) ||
        bolt::common::ImmutablePolicyMapping::Create(
            payload.data(), payload.size(), policy) !=
            bolt::common::PolicyMappingStatus::kSuccess ||
        bolt::common::PrivatePipe::Create(pipe_name, event_pipe) !=
            bolt::common::PipeStatus::kSuccess) {
        if (release != nullptr) {
            CloseHandle(release);
        }
        RegDeleteTreeW(HKEY_CURRENT_USER, root.c_str());
        return false;
    }
    HANDLE event_client = CreateFileW(
        pipe_name.c_str(), FILE_WRITE_DATA, 0, &inheritable, OPEN_EXISTING, 0,
        nullptr);
    if (event_client == INVALID_HANDLE_VALUE ||
        event_pipe.Accept() != bolt::common::PipeStatus::kSuccess) {
        if (event_client != INVALID_HANDLE_VALUE) {
            CloseHandle(event_client);
        }
        CloseHandle(release);
        RegDeleteTreeW(HKEY_CURRENT_USER, root.c_str());
        return false;
    }
#if defined(_WIN64)
    constexpr auto hook_name = L"bolt-sandbox-x64.dll";
#else
    constexpr auto hook_name = L"bolt-sandbox-x86.dll";
#endif
    const auto hook_path =
        std::filesystem::path(executable).parent_path() / hook_name;
    const std::wstring command =
        L"\"" + executable + L"\" --registry-hook-child \"" + root +
        L"\" " + HandleText(reinterpret_cast<std::uintptr_t>(
                       inherited_denied_handle)) +
        L" " + HandleText(reinterpret_cast<std::uintptr_t>(
                     inherited_read_only_handle)) +
        L" " + HandleText(reinterpret_cast<std::uintptr_t>(
                     inherited_race_allowed_handle)) +
        L" " + HandleText(reinterpret_cast<std::uintptr_t>(
                     inherited_race_denied_handle));
    const HANDLE inherited_handles[] = {
        policy.handle(), event_client, release, inherited_denied_handle,
        inherited_read_only_handle, inherited_race_allowed_handle,
        inherited_race_denied_handle};
    const bolt::common::ProcessLaunchOptions options{
        executable, command, L"", nullptr, inherited_handles,
        std::size(inherited_handles), 0};
    constexpr std::array<std::uint8_t, 16> nonce = {0x52};
    bolt::common::SuspendedProcess process;
    bolt::common::ExecutionJob job;
    const bool initialized =
        bolt::common::ExecutionJob::Create(job) ==
            bolt::common::JobStatus::kSuccess &&
        bolt::common::SuspendedProcess::Create(options, process) ==
            bolt::common::ProcessStatus::kSuccess &&
        process.AssignTo(job) == bolt::common::ProcessStatus::kSuccess &&
        process.InstallRuntimePayload(
            policy.handle(), policy.length(), event_client, release, nonce) ==
            bolt::common::ProcessStatus::kSuccess &&
        process.Inject(hook_path.string()) ==
            bolt::common::ProcessStatus::kSuccess &&
        process.BeginHookInitialization() ==
            bolt::common::ProcessStatus::kSuccess;
    CloseHandle(event_client);
    std::array<std::uint8_t, bolt::protocol::kReadyFrameLength> ready{};
    DWORD read = 0;
    const bool ready_ok = initialized &&
        ReadFile(
            event_pipe.handle(), ready.data(), static_cast<DWORD>(ready.size()),
            &read, nullptr) != FALSE &&
        read == ready.size() &&
        bolt::protocol::ValidateReadyFrame(
            ready.data(), ready.size(), nonce) ==
            bolt::protocol::ReadyFrameStatus::kSuccess &&
        process.ReleaseAfterReady() ==
            bolt::common::ProcessStatus::kSuccess;
    DWORD exit_code = 0;
    const bool child_passed = ready_ok &&
        process.Wait(3'000) == bolt::common::ProcessStatus::kSuccess &&
        process.ExitCode(exit_code) == bolt::common::ProcessStatus::kSuccess &&
        exit_code == 0;
    const auto child_process_id = static_cast<std::uint32_t>(
        GetProcessId(process.process_handle()));
    struct ExpectedEvent {
        bolt::protocol::RegistryOperation operation;
        std::string key;
    };
    const std::vector<ExpectedEvent> expected_events = {
        {bolt::protocol::RegistryOperation::kOpen,
         CanonicalCurrentUserKey(root + L"\\ReadOnly")},
        {bolt::protocol::RegistryOperation::kSetValue,
         CanonicalCurrentUserKey(root + L"\\ReadOnly")},
        {bolt::protocol::RegistryOperation::kDelete,
         CanonicalCurrentUserKey(root + L"\\ReadOnly")},
        {bolt::protocol::RegistryOperation::kCreate,
         CanonicalCurrentUserKey(root + L"\\ReadOnly\\BlockedChild")},
        {bolt::protocol::RegistryOperation::kRename,
         CanonicalCurrentUserKey(root + L"\\RenamedReadOnly")},
        {bolt::protocol::RegistryOperation::kOpen,
         CanonicalCurrentUserKey(wow64_read_only)},
        {bolt::protocol::RegistryOperation::kOpen,
         CanonicalCurrentUserKey(wow64_read_only)},
        {bolt::protocol::RegistryOperation::kSetValue,
         CanonicalCurrentUserKey(root + L"\\ReadOnly")},
        {bolt::protocol::RegistryOperation::kDelete,
         CanonicalCurrentUserKey(root + L"\\ReadOnly")},
        {bolt::protocol::RegistryOperation::kRename,
         CanonicalCurrentUserKey(root + L"\\DuplicatedReadOnly")},
        {bolt::protocol::RegistryOperation::kOpen,
         CanonicalCurrentUserKey(root + L"\\Broad\\Sensitive")},
        {bolt::protocol::RegistryOperation::kOpen,
         CanonicalCurrentUserKey(root + L"\\Outside")},
        {bolt::protocol::RegistryOperation::kOpen,
         CanonicalCurrentUserKey(root + L"\\Broad\\Sensitive")},
        {bolt::protocol::RegistryOperation::kQuery,
         CanonicalCurrentUserKey(root + L"\\Broad\\Sensitive")},
        {bolt::protocol::RegistryOperation::kSetValue,
         CanonicalCurrentUserKey(root + L"\\Broad\\Sensitive")},
        {bolt::protocol::RegistryOperation::kEnumerate,
         CanonicalCurrentUserKey(root + L"\\Broad\\Sensitive")},
        {bolt::protocol::RegistryOperation::kDelete,
         CanonicalCurrentUserKey(root + L"\\Broad\\Sensitive")},
        {bolt::protocol::RegistryOperation::kDelete,
         CanonicalCurrentUserKey(root + L"\\Broad\\Sensitive")},
        {bolt::protocol::RegistryOperation::kRename,
         CanonicalCurrentUserKey(root + L"\\Broad\\RenamedSensitive")},
        {bolt::protocol::RegistryOperation::kCreate,
         CanonicalCurrentUserKey(
             root + L"\\Broad\\Sensitive\\BlockedChild")},
        {bolt::protocol::RegistryOperation::kQuery,
         CanonicalCurrentUserKey(root + L"\\Broad\\Sensitive")},
        {bolt::protocol::RegistryOperation::kQuery,
         CanonicalCurrentUserKey(root + L"\\Broad\\Sensitive")},
        {bolt::protocol::RegistryOperation::kEnumerate,
         CanonicalCurrentUserKey(root + L"\\Broad\\Sensitive")},
        {bolt::protocol::RegistryOperation::kEnumerate,
         CanonicalCurrentUserKey(root + L"\\Broad\\Sensitive")},
        {bolt::protocol::RegistryOperation::kSetValue,
         CanonicalCurrentUserKey(root + L"\\Broad\\Sensitive")},
        {bolt::protocol::RegistryOperation::kOpen,
         CanonicalCurrentUserKey(root + L"\\Broad\\Sensitive")},
        {bolt::protocol::RegistryOperation::kUnsupportedRemote,
         "HKEY_REMOTE"},
        {bolt::protocol::RegistryOperation::kUnsupportedRemote,
         "HKEY_REMOTE"},
        {bolt::protocol::RegistryOperation::kUnsupportedTransactional,
         "HKEY_TRANSACTIONAL"},
        {bolt::protocol::RegistryOperation::kUnsupportedTransactional,
         "HKEY_TRANSACTIONAL"},
        {bolt::protocol::RegistryOperation::kUnsupportedTransactional,
         "HKEY_TRANSACTIONAL"},
        {bolt::protocol::RegistryOperation::kUnsupportedTransactional,
         "HKEY_TRANSACTIONAL"},
        {bolt::protocol::RegistryOperation::kUnsupportedTransactional,
         "HKEY_TRANSACTIONAL"},
        {bolt::protocol::RegistryOperation::kUnsupportedTransactional,
         "HKEY_TRANSACTIONAL"},
        {bolt::protocol::RegistryOperation::kUnsupportedTransactional,
         "HKEY_TRANSACTIONAL"},
        {bolt::protocol::RegistryOperation::kUnsupportedTransactional,
         "HKEY_TRANSACTIONAL"},
        {bolt::protocol::RegistryOperation::kUnsupportedTransactional,
         "HKEY_TRANSACTIONAL"},
    };
    bool events_passed = child_passed && child_process_id != 0;
    for (std::size_t index = 0;
         events_passed && index < expected_events.size(); ++index) {
        events_passed = ReadRegistryViolationWithin(
            event_pipe.handle(), child_process_id, index + 1,
            expected_events[index].operation, expected_events[index].key,
            1'000);
    }
    constexpr std::size_t expected_race_events = 32;
    std::size_t race_rename_events = 0;
    std::size_t race_set_events = 0;
    const std::string race_denied_key =
        CanonicalCurrentUserKey(root + L"\\Race\\Denied");
    bool race_events_passed = events_passed;
    for (std::size_t index = 0;
         race_events_passed && index < expected_race_events; ++index) {
        RegistryEventRecord record{};
        race_events_passed = ReadRegistryViolationRecordWithin(
            event_pipe.handle(), child_process_id,
            expected_events.size() + index + 1, record, 1'000);
        if (!race_events_passed || record.key != race_denied_key) {
            race_events_passed = false;
            break;
        }
        if (record.operation ==
            bolt::protocol::RegistryOperation::kRename) {
            ++race_rename_events;
        } else if (
            record.operation ==
            bolt::protocol::RegistryOperation::kSetValue) {
            ++race_set_events;
        } else {
            race_events_passed = false;
        }
    }
    race_events_passed = race_events_passed &&
        race_rename_events == expected_race_events / 2 &&
        race_set_events == expected_race_events / 2;
    DWORD remaining_event_bytes = 0;
    const bool no_extra_events = race_events_passed &&
        (!PeekNamedPipe(
             event_pipe.handle(), nullptr, 0, nullptr,
             &remaining_event_bytes, nullptr) ||
         remaining_event_bytes == 0);
    const bool side_effects_ok =
        ValueEquals(root + L"\\ReadOnly", L"Seed", L"seed") &&
        KeyMissing(root + L"\\ReadOnly\\BlockedChild") &&
        KeyMissing(root + L"\\DuplicatedReadOnly") &&
        !KeyMissing(root + L"\\ReadOnly") &&
        ValueEquals(
            root + L"\\Broad\\Sensitive",
            kRegistryValueNameCanaryWide,
            kRegistryValueDataCanaryWide) &&
        KeyMissing(root + L"\\Broad\\Sensitive\\BlockedChild") &&
        KeyMissing(root + L"\\Broad\\RenamedSensitive") &&
        ValueEquals(root + L"\\Allowed", L"Changed", L"changed") &&
        KeyMissing(root + L"\\Allowed\\Renamed") &&
        ValueEquals(root + L"\\Race\\Allowed", L"Seed", L"seed") &&
        ValueEquals(
            root + L"\\Race\\Denied",
            kRegistryValueNameCanaryWide,
            kRegistryValueDataCanaryWide);
    const bool unsupported_side_effects_absent =
        KeyMissing(root + L"\\Allowed\\UnsupportedCreate");
    const bool passed =
        child_passed && events_passed && race_events_passed &&
        no_extra_events && side_effects_ok &&
        unsupported_side_effects_absent;
    if (!passed) {
        std::fprintf(
            stderr,
            "registry hook fixture failed: initialized=%d ready=%d exit=%lu "
            "events=%d extra=%d side_effects=%d\n",
            initialized ? 1 : 0, ready_ok ? 1 : 0,
            static_cast<unsigned long>(exit_code), events_passed ? 1 : 0,
            no_extra_events ? 0 : 1, side_effects_ok ? 1 : 0);
    }
    process.Close();
    CloseHandle(release);
    event_pipe.Close();
    RegCloseKey(inherited_denied_handle);
    RegCloseKey(inherited_read_only_handle);
    RegCloseKey(inherited_race_allowed_handle);
    RegCloseKey(inherited_race_denied_handle);
    DeleteRegistrySymbolicLink(link_to_sensitive);
    RegDeleteTreeW(HKEY_CURRENT_USER, root.c_str());
    DeleteKeyTreeInView(wow64_root, KEY_WOW64_32KEY);
    DeleteKeyTreeInView(wow64_root, KEY_WOW64_64KEY);
    return passed;
}
