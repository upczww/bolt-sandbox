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
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>

namespace {

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
    if (argument_count != 4) {
        return 700;
    }
    const std::wstring root = arguments[2];
    const auto inherited_denied = reinterpret_cast<HKEY>(
        static_cast<std::uintptr_t>(_wcstoui64(arguments[3], nullptr, 10)));
    const std::wstring read_only = root + L"\\ReadOnly";
    const std::wstring denied = root + L"\\Broad\\Sensitive";
    const std::wstring allowed = root + L"\\Allowed";
    const std::wstring inherited = root + L"\\Inherited";
    const std::wstring outside = root + L"\\Outside";
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

    wchar_t inherited_value[16]{};
    DWORD inherited_value_bytes = sizeof(inherited_value);
    DWORD inherited_value_type = 0;
    const LSTATUS inherited_denied_query = RegQueryValueExW(
        inherited_denied, L"Seed", nullptr, &inherited_value_type,
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
    wchar_t denied_value_text[] = L"Seed";
    UNICODE_STRING denied_value_name{};
    denied_value_name.Buffer = denied_value_text;
    denied_value_name.Length = static_cast<USHORT>(
        std::wcslen(denied_value_text) * sizeof(wchar_t));
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

    if (!value_enumerated || !key_enumerated) {
        return 716;
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
    if (inherited_denied_query != ERROR_ACCESS_DENIED ||
        inherited_denied_set != ERROR_ACCESS_DENIED ||
        inherited_denied_enumerate != ERROR_ACCESS_DENIED ||
        inherited_denied_delete_value != static_cast<LONG>(0xC0000022L) ||
        inherited_denied_delete_key != static_cast<LONG>(0xC0000022L) ||
        inherited_denied_rename != static_cast<LONG>(0xC0000022L) ||
        inherited_denied_create != static_cast<LONG>(0xC0000022L) ||
        denied_blocked_child != nullptr ||
        denied_blocked_disposition != 99) {
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
    RegDeleteTreeW(HKEY_CURRENT_USER, root.c_str());
    const bool prepared =
        CreateKeyWithValue(root + L"\\ReadOnly", L"Seed", L"seed") &&
        CreateKeyWithValue(
            root + L"\\ReadOnly\\ExistingChild", L"Seed", L"seed") &&
        CreateKeyWithValue(
            root + L"\\Broad\\Sensitive", L"Seed", L"secret") &&
        CreateKeyWithValue(root + L"\\Allowed", L"Seed", L"seed") &&
        CreateKeyWithValue(root + L"\\Inherited", L"Seed", L"seed") &&
        CreateKeyWithValue(root + L"\\Outside", L"Seed", L"outside");
    if (!prepared) {
        RegDeleteTreeW(HKEY_CURRENT_USER, root.c_str());
        return false;
    }
    HKEY inherited_denied_handle = nullptr;
    if (RegOpenKeyExW(
            HKEY_CURRENT_USER, (root + L"\\Broad\\Sensitive").c_str(), 0,
            KEY_ALL_ACCESS, &inherited_denied_handle) != ERROR_SUCCESS ||
        SetHandleInformation(
            inherited_denied_handle, HANDLE_FLAG_INHERIT,
            HANDLE_FLAG_INHERIT) == FALSE) {
        if (inherited_denied_handle != nullptr) {
            RegCloseKey(inherited_denied_handle);
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
                       inherited_denied_handle));
    const HANDLE inherited_handles[] = {
        policy.handle(), event_client, release, inherited_denied_handle};
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
         CanonicalCurrentUserKey(root + L"\\Broad\\Sensitive")},
        {bolt::protocol::RegistryOperation::kOpen,
         CanonicalCurrentUserKey(root + L"\\Outside")},
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
        {bolt::protocol::RegistryOperation::kOpen,
         CanonicalCurrentUserKey(root + L"\\Broad\\Sensitive")},
    };
    bool events_passed = child_passed && child_process_id != 0;
    for (std::size_t index = 0;
         events_passed && index < expected_events.size(); ++index) {
        events_passed = ReadRegistryViolationWithin(
            event_pipe.handle(), child_process_id, index + 1,
            expected_events[index].operation, expected_events[index].key,
            1'000);
    }
    DWORD remaining_event_bytes = 0;
    const bool no_extra_events = events_passed &&
        (!PeekNamedPipe(
             event_pipe.handle(), nullptr, 0, nullptr,
             &remaining_event_bytes, nullptr) ||
         remaining_event_bytes == 0);
    const bool side_effects_ok =
        ValueEquals(root + L"\\ReadOnly", L"Seed", L"seed") &&
        KeyMissing(root + L"\\ReadOnly\\BlockedChild") &&
        !KeyMissing(root + L"\\ReadOnly") &&
        ValueEquals(
            root + L"\\Broad\\Sensitive", L"Seed", L"secret") &&
        KeyMissing(root + L"\\Broad\\Sensitive\\BlockedChild") &&
        KeyMissing(root + L"\\Broad\\RenamedSensitive") &&
        ValueEquals(root + L"\\Allowed", L"Changed", L"changed") &&
        KeyMissing(root + L"\\Allowed\\Renamed");
    const bool passed =
        child_passed && events_passed && no_extra_events && side_effects_ok;
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
    RegDeleteTreeW(HKEY_CURRENT_USER, root.c_str());
    return passed;
}
