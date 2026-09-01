#include "hook/registry/registry_hooks.h"

#include "hook/event_sink.h"
#include "hook/registry/registry_policy.h"

#include <algorithm>
#include <array>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>
#include <winternl.h>

#include <detours.h>

namespace bolt::registry {
namespace {

constexpr NTSTATUS kStatusAccessDenied =
    static_cast<NTSTATUS>(0xC0000022L);
constexpr NTSTATUS kStatusObjectNameNotFound =
    static_cast<NTSTATUS>(0xC0000034L);
constexpr NTSTATUS kStatusBufferOverflow =
    static_cast<NTSTATUS>(0x80000005L);
constexpr NTSTATUS kStatusBufferTooSmall =
    static_cast<NTSTATUS>(0xC0000023L);
constexpr NTSTATUS kStatusInfoLengthMismatch =
    static_cast<NTSTATUS>(0xC0000004L);
constexpr ULONG kKeyNameInformation = 3;
constexpr ULONG kKeyHandleTagsInformation = 7;
constexpr char kRemoteRegistryEventKey[] = "HKEY_REMOTE";
constexpr char kTransactionalRegistryEventKey[] =
    "HKEY_TRANSACTIONAL";

using NtOpenKeyFunction = NTSTATUS(NTAPI*)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
using NtOpenKeyExFunction = NTSTATUS(NTAPI*)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
using NtCreateKeyFunction = NTSTATUS(NTAPI*)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG,
    PULONG);
using NtOpenKeyTransactedFunction = NTSTATUS(NTAPI*)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE);
using NtOpenKeyTransactedExFunction = NTSTATUS(NTAPI*)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, HANDLE);
using NtCreateKeyTransactedFunction = NTSTATUS(NTAPI*)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG,
    HANDLE, PULONG);
using NtQueryKeyFunction = NTSTATUS(NTAPI*)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtQueryValueKeyFunction = NTSTATUS(NTAPI*)(
    HANDLE, PUNICODE_STRING, ULONG, PVOID, ULONG,
    PULONG);
using NtEnumerateKeyFunction = NTSTATUS(NTAPI*)(
    HANDLE, ULONG, ULONG, PVOID, ULONG, PULONG);
using NtEnumerateValueKeyFunction = NTSTATUS(NTAPI*)(
    HANDLE, ULONG, ULONG, PVOID, ULONG, PULONG);
using NtSetValueKeyFunction = NTSTATUS(NTAPI*)(
    HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG);
using NtDeleteKeyFunction = NTSTATUS(NTAPI*)(HANDLE);
using NtDeleteValueKeyFunction = NTSTATUS(NTAPI*)(HANDLE, PUNICODE_STRING);
using NtRenameKeyFunction = NTSTATUS(NTAPI*)(HANDLE, PUNICODE_STRING);
using NtCloseFunction = NTSTATUS(NTAPI*)(HANDLE);
using RegConnectRegistryAFunction = LSTATUS(WINAPI*)(
    LPCSTR, HKEY, PHKEY);
using RegConnectRegistryWFunction = LSTATUS(WINAPI*)(
    LPCWSTR, HKEY, PHKEY);
using RegOpenKeyTransactedAFunction = LSTATUS(WINAPI*)(
    HKEY, LPCSTR, DWORD, REGSAM, PHKEY, HANDLE, PVOID);
using RegOpenKeyTransactedWFunction = LSTATUS(WINAPI*)(
    HKEY, LPCWSTR, DWORD, REGSAM, PHKEY, HANDLE, PVOID);
using RegCreateKeyTransactedAFunction = LSTATUS(WINAPI*)(
    HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM,
    const SECURITY_ATTRIBUTES*, PHKEY, LPDWORD, HANDLE, PVOID);
using RegCreateKeyTransactedWFunction = LSTATUS(WINAPI*)(
    HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM,
    const SECURITY_ATTRIBUTES*, PHKEY, LPDWORD, HANDLE, PVOID);
using RegDeleteKeyTransactedAFunction = LSTATUS(WINAPI*)(
    HKEY, LPCSTR, REGSAM, DWORD, HANDLE, PVOID);
using RegDeleteKeyTransactedWFunction = LSTATUS(WINAPI*)(
    HKEY, LPCWSTR, REGSAM, DWORD, HANDLE, PVOID);

NtOpenKeyFunction g_nt_open_key = nullptr;
NtOpenKeyExFunction g_nt_open_key_ex = nullptr;
NtCreateKeyFunction g_nt_create_key = nullptr;
NtOpenKeyTransactedFunction g_nt_open_key_transacted = nullptr;
NtOpenKeyTransactedExFunction g_nt_open_key_transacted_ex = nullptr;
NtCreateKeyTransactedFunction g_nt_create_key_transacted = nullptr;
NtQueryKeyFunction g_nt_query_key = nullptr;
NtQueryValueKeyFunction g_nt_query_value_key = nullptr;
NtEnumerateKeyFunction g_nt_enumerate_key = nullptr;
NtEnumerateValueKeyFunction g_nt_enumerate_value_key = nullptr;
NtSetValueKeyFunction g_nt_set_value_key = nullptr;
NtDeleteKeyFunction g_nt_delete_key = nullptr;
NtDeleteValueKeyFunction g_nt_delete_value_key = nullptr;
NtRenameKeyFunction g_nt_rename_key = nullptr;
NtCloseFunction g_nt_close = nullptr;
RegConnectRegistryAFunction g_reg_connect_registry_a = nullptr;
RegConnectRegistryWFunction g_reg_connect_registry_w = nullptr;
RegOpenKeyTransactedAFunction g_reg_open_key_transacted_a = nullptr;
RegOpenKeyTransactedWFunction g_reg_open_key_transacted_w = nullptr;
RegCreateKeyTransactedAFunction g_reg_create_key_transacted_a = nullptr;
RegCreateKeyTransactedWFunction g_reg_create_key_transacted_w = nullptr;
RegDeleteKeyTransactedAFunction g_reg_delete_key_transacted_a = nullptr;
RegDeleteKeyTransactedWFunction g_reg_delete_key_transacted_w = nullptr;
std::unique_ptr<RegistryPolicy> g_policy;
std::wstring g_current_user_prefix;
std::wstring g_current_user_classes_prefix;
std::wstring g_active_control_set;
std::wstring g_private_user_prefix;
HKEY g_private_user_hive = nullptr;

bool NtSuccess(const NTSTATUS status) noexcept {
    return status >= 0;
}

bool EqualPrefixIgnoreCase(
    const std::wstring& value,
    const std::wstring& prefix) noexcept {
    return value.size() >= prefix.size() &&
           prefix.size() <= static_cast<std::size_t>(INT_MAX) &&
           CompareStringOrdinal(
               value.data(), static_cast<int>(prefix.size()), prefix.data(),
               static_cast<int>(prefix.size()), TRUE) == CSTR_EQUAL;
}

bool RewritePrivateUserAttributes(
    const OBJECT_ATTRIBUTES* source,
    std::wstring& path,
    UNICODE_STRING& name,
    OBJECT_ATTRIBUTES& rewritten,
    const OBJECT_ATTRIBUTES*& selected);

bool ProbeUnicodeString(
    const UNICODE_STRING* source,
    const wchar_t*& buffer,
    USHORT& length) noexcept {
    buffer = nullptr;
    length = 0;
    if (source == nullptr) {
        return false;
    }
    __try {
        if (source->Length == 0) {
            return true;
        }
        if (source->Buffer == nullptr ||
            source->Length % sizeof(wchar_t) != 0 ||
            source->Length > source->MaximumLength) {
            return false;
        }
        buffer = source->Buffer;
        length = source->Length;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool ReadUnicodeString(
    const UNICODE_STRING* source,
    std::wstring& value) {
    value.clear();
    const wchar_t* buffer = nullptr;
    USHORT length = 0;
    if (!ProbeUnicodeString(source, buffer, length)) {
        return false;
    }
    value.assign(buffer, length / sizeof(wchar_t));
    return value.find(L'\0') == std::wstring::npos;
}

bool WriteNullHandle(PHANDLE output) noexcept {
    if (output == nullptr) {
        return false;
    }
    __try {
        *output = nullptr;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool WriteOpenedExistingDisposition(PULONG output) noexcept {
    if (output == nullptr) {
        return true;
    }
    __try {
        *output = REG_OPENED_EXISTING_KEY;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool WriteNullRegistryKey(PHKEY output) noexcept {
    return WriteNullHandle(reinterpret_cast<PHANDLE>(output));
}

bool QueryHandleName(const HANDLE key, std::wstring& name) {
    name.clear();
    if (key == nullptr || key == INVALID_HANDLE_VALUE ||
        g_nt_query_key == nullptr) {
        return false;
    }
    ULONG required = 0;
    const NTSTATUS size_status =
        g_nt_query_key(key, kKeyNameInformation, nullptr, 0, &required);
    if (size_status != kStatusBufferTooSmall &&
        size_status != kStatusBufferOverflow &&
        size_status != kStatusInfoLengthMismatch) {
        return false;
    }
    if (required < sizeof(ULONG) || required > 64U * 1'024U) {
        return false;
    }
    std::vector<std::uint8_t> buffer(required);
    const NTSTATUS query_status = g_nt_query_key(
        key, kKeyNameInformation, buffer.data(), required, &required);
    if (!NtSuccess(query_status) || required < sizeof(ULONG)) {
        return false;
    }
    const ULONG name_bytes =
        *reinterpret_cast<const ULONG*>(buffer.data());
    if (name_bytes % sizeof(wchar_t) != 0 ||
        name_bytes > required - sizeof(ULONG)) {
        return false;
    }
    name.assign(
        reinterpret_cast<const wchar_t*>(buffer.data() + sizeof(ULONG)),
        name_bytes / sizeof(wchar_t));
    return !name.empty();
}

bool ProbeObjectAttributes(
    const OBJECT_ATTRIBUTES* attributes,
    HANDLE& root,
    UNICODE_STRING*& object_name) noexcept {
    root = nullptr;
    object_name = nullptr;
    if (attributes == nullptr) {
        return false;
    }
    __try {
        if (attributes->Length < sizeof(OBJECT_ATTRIBUTES)) {
            return false;
        }
        root = attributes->RootDirectory;
        object_name = attributes->ObjectName;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}

bool ReadObjectAttributesName(
    const OBJECT_ATTRIBUTES* attributes,
    std::wstring& name) {
    name.clear();
    HANDLE root = nullptr;
    UNICODE_STRING* object_name = nullptr;
    if (!ProbeObjectAttributes(attributes, root, object_name)) {
        return false;
    }
    std::wstring relative;
    if (!ReadUnicodeString(object_name, relative)) {
        return false;
    }
    if (!relative.empty() && relative.front() == L'\\') {
        name = std::move(relative);
        return true;
    }
    if (!QueryHandleName(root, name)) {
        return false;
    }
    if (!relative.empty()) {
        if (name.back() != L'\\') {
            name.push_back(L'\\');
        }
        name.append(relative);
    }
    return true;
}

bool ReadHandleOutput(PHANDLE output, HANDLE& value) noexcept {
    value = nullptr;
    if (output == nullptr) {
        return false;
    }
    __try {
        value = *output;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool CurrentUserPrefix(std::wstring& prefix) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return false;
    }
    DWORD length = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &length);
    std::vector<std::uint8_t> buffer(length);
    const bool queried = length != 0 && GetTokenInformation(
        token, TokenUser, buffer.data(), length, &length) != FALSE;
    CloseHandle(token);
    if (!queried) {
        return false;
    }
    const auto* user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
    LPWSTR sid = nullptr;
    if (!ConvertSidToStringSidW(user->User.Sid, &sid)) {
        return false;
    }
    prefix = L"\\REGISTRY\\USER\\";
    prefix.append(sid);
    LocalFree(sid);
    return true;
}

bool ActiveControlSet(std::wstring& component) {
    DWORD current = 0;
    DWORD bytes = sizeof(current);
    const LSTATUS status = RegGetValueW(
        HKEY_LOCAL_MACHINE, L"SYSTEM\\Select", L"Current", RRF_RT_REG_DWORD,
        nullptr, &current, &bytes);
    if (status != ERROR_SUCCESS || current == 0 || current > 999) {
        return false;
    }
    wchar_t formatted[14]{};
    if (swprintf_s(
            formatted, std::size(formatted), L"ControlSet%03lu",
            static_cast<unsigned long>(current)) < 0) {
        return false;
    }
    component = formatted;
    return true;
}

void NormalizeActiveControlSet(std::wstring& relative) {
    static const std::wstring system_prefix = L"SYSTEM\\";
    if (g_active_control_set.empty() ||
        !EqualPrefixIgnoreCase(relative, system_prefix) ||
        relative.size() <= system_prefix.size()) {
        return;
    }
    const std::size_t component_end =
        relative.find(L'\\', system_prefix.size());
    const std::size_t component_length =
        component_end == std::wstring::npos
            ? relative.size() - system_prefix.size()
            : component_end - system_prefix.size();
    if (component_length != g_active_control_set.size() ||
        CompareStringOrdinal(
            relative.data() + system_prefix.size(),
            static_cast<int>(component_length), g_active_control_set.data(),
            static_cast<int>(g_active_control_set.size()), TRUE) != CSTR_EQUAL) {
        return;
    }
    relative.replace(
        system_prefix.size(), component_length, L"CURRENTCONTROLSET");
}

bool MapNativeName(
    const std::wstring& native_name,
    RegistryHive& hive,
    std::wstring& relative) {
    static const std::wstring machine = L"\\REGISTRY\\MACHINE";
    static const std::wstring users = L"\\REGISTRY\\USER";
    if (!g_private_user_prefix.empty() &&
        EqualPrefixIgnoreCase(native_name, g_private_user_prefix) &&
        (native_name.size() == g_private_user_prefix.size() ||
         native_name[g_private_user_prefix.size()] == L'\\')) {
        hive = RegistryHive::kCurrentUser;
        relative = native_name.size() == g_private_user_prefix.size()
                       ? L""
                       : native_name.substr(g_private_user_prefix.size() + 1);
        return true;
    }
    if (!g_current_user_classes_prefix.empty() &&
        EqualPrefixIgnoreCase(native_name, g_current_user_classes_prefix) &&
        (native_name.size() == g_current_user_classes_prefix.size() ||
         native_name[g_current_user_classes_prefix.size()] == L'\\')) {
        hive = RegistryHive::kCurrentUser;
        relative = L"Software\\Classes";
        if (native_name.size() > g_current_user_classes_prefix.size()) {
            relative.push_back(L'\\');
            relative.append(
                native_name.substr(g_current_user_classes_prefix.size() + 1));
        }
        return true;
    }
    if (!g_current_user_prefix.empty() &&
        EqualPrefixIgnoreCase(native_name, g_current_user_prefix) &&
        (native_name.size() == g_current_user_prefix.size() ||
         native_name[g_current_user_prefix.size()] == L'\\')) {
        hive = RegistryHive::kCurrentUser;
        relative = native_name.size() == g_current_user_prefix.size()
                       ? L""
                       : native_name.substr(g_current_user_prefix.size() + 1);
        return true;
    }
    if (EqualPrefixIgnoreCase(native_name, machine) &&
        (native_name.size() == machine.size() ||
         native_name[machine.size()] == L'\\')) {
        hive = RegistryHive::kLocalMachine;
        relative = native_name.size() == machine.size()
                       ? L""
                       : native_name.substr(machine.size() + 1);
        NormalizeActiveControlSet(relative);
        return true;
    }
    if (EqualPrefixIgnoreCase(native_name, users) &&
        (native_name.size() == users.size() ||
         native_name[users.size()] == L'\\')) {
        hive = RegistryHive::kUsers;
        relative = native_name.size() == users.size()
                       ? L""
                       : native_name.substr(users.size() + 1);
        return true;
    }
    return false;
}

RegistryAccess AccessForMask(const ACCESS_MASK desired_access) noexcept {
    constexpr ACCESS_MASK write_mask =
        KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK | DELETE |
        WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL;
    if ((desired_access & write_mask) != 0) {
        return RegistryAccess::kWrite;
    }
    constexpr ACCESS_MASK enumerate_mask =
        KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY;
    return (desired_access & enumerate_mask) != 0
               ? RegistryAccess::kEnumerate
               : RegistryAccess::kRead;
}

bool DecideNativeName(
    const std::wstring& name,
    const RegistryAccess access,
    RegistryDecision& decision) {
    decision = RegistryDecision::kDeny;
    if (!g_private_user_prefix.empty() &&
        EqualPrefixIgnoreCase(name, g_private_user_prefix) &&
        (name.size() == g_private_user_prefix.size() ||
         name[g_private_user_prefix.size()] == L'\\')) {
        decision = RegistryDecision::kAllow;
        return true;
    }
    RegistryHive hive{};
    std::wstring relative;
    if (!MapNativeName(name, hive, relative) || g_policy == nullptr) {
        return false;
    }
    decision = g_policy->Decide(hive, relative.c_str(), access);
    return true;
}

bool AllowedNativeName(
    const std::wstring& name,
    const RegistryAccess access) {
    RegistryDecision decision = RegistryDecision::kDeny;
    if (!DecideNativeName(name, access, decision)) {
        return false;
    }
    return decision == RegistryDecision::kAllow ||
           decision == RegistryDecision::kAllowExactReadOnly ||
           decision == RegistryDecision::kInheritUser;
}

bool AllowedNativeOpen(
    const std::wstring& name,
    const RegistryAccess access) {
    if (!g_private_user_prefix.empty() &&
        EqualPrefixIgnoreCase(name, g_private_user_prefix) &&
        (name.size() == g_private_user_prefix.size() ||
         name[g_private_user_prefix.size()] == L'\\')) {
        return true;
    }
    RegistryHive hive{};
    std::wstring relative;
    if (!MapNativeName(name, hive, relative) || g_policy == nullptr) {
        return false;
    }
    const RegistryDecision decision =
        g_policy->Decide(hive, relative.c_str(), access);
    if (decision == RegistryDecision::kAllow ||
        decision == RegistryDecision::kAllowExactReadOnly ||
        decision == RegistryDecision::kInheritUser) {
        return true;
    }
    if (decision == RegistryDecision::kNotFound) {
        return false;
    }
    return access != RegistryAccess::kWrite &&
           g_policy->MayTraverse(hive, relative.c_str());
}

bool AllowedHandle(const HANDLE key, const RegistryAccess access) {
    std::wstring name;
    return QueryHandleName(key, name) && AllowedNativeName(name, access);
}

const wchar_t* HiveName(const RegistryHive hive) noexcept {
    switch (hive) {
        case RegistryHive::kClassesRoot:
            return L"HKEY_CLASSES_ROOT";
        case RegistryHive::kCurrentUser:
            return L"HKEY_CURRENT_USER";
        case RegistryHive::kLocalMachine:
            return L"HKEY_LOCAL_MACHINE";
        case RegistryHive::kUsers:
            return L"HKEY_USERS";
        case RegistryHive::kCurrentConfig:
            return L"HKEY_CURRENT_CONFIG";
    }
    return nullptr;
}

bool CanonicalEventKey(
    const std::wstring& native_name,
    std::string& encoded) {
    encoded.clear();
    RegistryHive hive{};
    std::wstring relative;
    if (!MapNativeName(native_name, hive, relative)) {
        return false;
    }
    const wchar_t* const hive_name = HiveName(hive);
    if (hive_name == nullptr) {
        return false;
    }
    std::wstring canonical(hive_name);
    if (!relative.empty()) {
        canonical.push_back(L'\\');
        canonical.append(relative);
    }
    const int required = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, canonical.data(),
        static_cast<int>(canonical.size()), nullptr, 0, nullptr, nullptr);
    if (required <= 0 || required > 4'096) {
        return false;
    }
    encoded.resize(static_cast<std::size_t>(required));
    return WideCharToMultiByte(
               CP_UTF8, WC_ERR_INVALID_CHARS, canonical.data(),
               static_cast<int>(canonical.size()), encoded.data(), required,
               nullptr, nullptr) == required;
}

void ReportRegistryViolation(
    const std::wstring& native_name,
    const protocol::RegistryOperation operation) noexcept {
    try {
        std::string key;
        if (CanonicalEventKey(native_name, key)) {
            hook::TryReportRegistryViolation(operation, key.c_str());
        }
    } catch (...) {
    }
}

void ReportHandleViolation(
    const HANDLE key,
    const protocol::RegistryOperation operation) noexcept {
    try {
        std::wstring name;
        if (QueryHandleName(key, name)) {
            ReportRegistryViolation(name, operation);
        }
    } catch (...) {
    }
}

void ReportUnsupportedRegistryOperation(
    const protocol::RegistryOperation operation) noexcept {
    const char* const key =
        operation == protocol::RegistryOperation::kUnsupportedRemote
        ? kRemoteRegistryEventKey
        : kTransactionalRegistryEventKey;
    hook::TryReportRegistryViolation(operation, key);
}

template <typename OpenCall>
NTSTATUS GuardOpen(
    PHANDLE key,
    const ACCESS_MASK desired_access,
    const OBJECT_ATTRIBUTES* attributes,
    const protocol::RegistryOperation operation,
    const bool allow_read_attenuation,
    OpenCall&& call) {
    std::wstring requested;
    RegistryAccess access = AccessForMask(desired_access);
    ACCESS_MASK effective_access = desired_access;
    if (!ReadObjectAttributesName(attributes, requested)) {
        WriteNullHandle(key);
        return kStatusAccessDenied;
    }
    RegistryDecision requested_decision = RegistryDecision::kDeny;
    if (!DecideNativeName(requested, access, requested_decision)) {
        ReportRegistryViolation(requested, operation);
        WriteNullHandle(key);
        return kStatusAccessDenied;
    }
    if (requested_decision == RegistryDecision::kNotFound) {
        ReportRegistryViolation(requested, operation);
        WriteNullHandle(key);
        return kStatusObjectNameNotFound;
    }
    if (requested_decision == RegistryDecision::kDeny &&
        !AllowedNativeOpen(requested, access)) {
        RegistryDecision read_decision = RegistryDecision::kDeny;
        const bool read_visible_write_probe =
            access == RegistryAccess::kWrite &&
            DecideNativeName(
                requested, RegistryAccess::kRead, read_decision) &&
            read_decision == RegistryDecision::kAllowExactReadOnly;
        if (!allow_read_attenuation || !read_visible_write_probe) {
            ReportRegistryViolation(requested, operation);
            WriteNullHandle(key);
            return kStatusAccessDenied;
        }
        effective_access = KEY_READ |
            (desired_access & (KEY_WOW64_32KEY | KEY_WOW64_64KEY));
        access = RegistryAccess::kEnumerate;
    }
    const NTSTATUS status = call(effective_access);
    if (!NtSuccess(status)) {
        return status;
    }
    HANDLE opened = nullptr;
    if (!ReadHandleOutput(key, opened)) {
        return status;
    }
    std::wstring final_name;
    if (QueryHandleName(opened, final_name) &&
        AllowedNativeOpen(final_name, access)) {
        return status;
    }
    g_nt_close(opened);
    WriteNullHandle(key);
    ReportRegistryViolation(
        final_name.empty() ? requested : final_name, operation);
    return kStatusAccessDenied;
}

NTSTATUS NTAPI DetouredNtOpenKey(
    PHANDLE key,
    const ACCESS_MASK desired_access,
    POBJECT_ATTRIBUTES attributes) {
    std::wstring private_path;
    UNICODE_STRING private_name{};
    OBJECT_ATTRIBUTES private_attributes{};
    const OBJECT_ATTRIBUTES* selected = attributes;
    if (!RewritePrivateUserAttributes(
            attributes, private_path, private_name,
            private_attributes, selected)) {
        return kStatusAccessDenied;
    }
    return GuardOpen(
        key, desired_access, selected, protocol::RegistryOperation::kOpen,
        true, [&](const ACCESS_MASK effective_access) {
        return g_nt_open_key(
            key, effective_access,
            const_cast<POBJECT_ATTRIBUTES>(selected));
        });
}

NTSTATUS NTAPI DetouredNtOpenKeyEx(
    PHANDLE key,
    const ACCESS_MASK desired_access,
    POBJECT_ATTRIBUTES attributes,
    const ULONG open_options) {
    std::wstring private_path;
    UNICODE_STRING private_name{};
    OBJECT_ATTRIBUTES private_attributes{};
    const OBJECT_ATTRIBUTES* selected = attributes;
    if (!RewritePrivateUserAttributes(
            attributes, private_path, private_name,
            private_attributes, selected)) {
        return kStatusAccessDenied;
    }
    return GuardOpen(
        key, desired_access, selected, protocol::RegistryOperation::kOpen,
        true, [&](const ACCESS_MASK effective_access) {
        return g_nt_open_key_ex(
            key, effective_access,
            const_cast<POBJECT_ATTRIBUTES>(selected), open_options);
        });
}

NTSTATUS NTAPI DetouredNtCreateKey(
    PHANDLE key,
    const ACCESS_MASK desired_access,
    POBJECT_ATTRIBUTES attributes,
    const ULONG title_index,
    PUNICODE_STRING class_name,
    const ULONG create_options,
    PULONG disposition) {
    std::wstring private_path;
    UNICODE_STRING private_name{};
    OBJECT_ATTRIBUTES private_attributes{};
    const OBJECT_ATTRIBUTES* selected = attributes;
    if (!RewritePrivateUserAttributes(
            attributes, private_path, private_name,
            private_attributes, selected)) {
        return kStatusAccessDenied;
    }
    std::wstring requested;
    RegistryDecision read_decision = RegistryDecision::kDeny;
    if (ReadObjectAttributesName(selected, requested) &&
        DecideNativeName(
            requested, RegistryAccess::kRead, read_decision) &&
        read_decision == RegistryDecision::kAllowExactReadOnly) {
        const ACCESS_MASK read_access = KEY_READ |
            (desired_access & (KEY_WOW64_32KEY | KEY_WOW64_64KEY));
        const NTSTATUS status = GuardOpen(
            key, read_access, selected,
            protocol::RegistryOperation::kCreate, true,
            [&](const ACCESS_MASK effective_access) {
                return g_nt_open_key(
                    key, effective_access,
                    const_cast<POBJECT_ATTRIBUTES>(selected));
            });
        if (NtSuccess(status) &&
            !WriteOpenedExistingDisposition(disposition)) {
            HANDLE opened = nullptr;
            if (ReadHandleOutput(key, opened)) {
                g_nt_close(opened);
            }
            WriteNullHandle(key);
            return kStatusAccessDenied;
        }
        return status;
    }
    return GuardOpen(
        key,
        RegistryAccess::kWrite == AccessForMask(desired_access)
            ? desired_access
            : desired_access | KEY_CREATE_SUB_KEY,
        selected, protocol::RegistryOperation::kCreate, false,
        [&](const ACCESS_MASK) {
                         return g_nt_create_key(
                             key, desired_access,
                             const_cast<POBJECT_ATTRIBUTES>(selected), title_index,
                             class_name, create_options, disposition);
                     });
}

NTSTATUS NTAPI DetouredNtOpenKeyTransacted(
    PHANDLE key,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    HANDLE) {
    WriteNullHandle(key);
    ReportUnsupportedRegistryOperation(
        protocol::RegistryOperation::kUnsupportedTransactional);
    return kStatusAccessDenied;
}

NTSTATUS NTAPI DetouredNtOpenKeyTransactedEx(
    PHANDLE key,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    ULONG,
    HANDLE) {
    WriteNullHandle(key);
    ReportUnsupportedRegistryOperation(
        protocol::RegistryOperation::kUnsupportedTransactional);
    return kStatusAccessDenied;
}

NTSTATUS NTAPI DetouredNtCreateKeyTransacted(
    PHANDLE key,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    ULONG,
    PUNICODE_STRING,
    ULONG,
    HANDLE,
    PULONG) {
    WriteNullHandle(key);
    ReportUnsupportedRegistryOperation(
        protocol::RegistryOperation::kUnsupportedTransactional);
    return kStatusAccessDenied;
}

NTSTATUS NTAPI DetouredNtQueryKey(
    const HANDLE key,
    const ULONG information_class,
    PVOID information,
    const ULONG length,
    PULONG result_length) {
    bool allowed = AllowedHandle(key, RegistryAccess::kRead);
    if (!allowed &&
        (information_class == kKeyNameInformation ||
         information_class == kKeyHandleTagsInformation)) {
        std::wstring name;
        allowed = QueryHandleName(key, name) &&
                  AllowedNativeOpen(name, RegistryAccess::kRead);
    }
    if (!allowed) {
        ReportHandleViolation(key, protocol::RegistryOperation::kQuery);
        return kStatusAccessDenied;
    }
    return g_nt_query_key(
        key, information_class, information, length, result_length);
}

NTSTATUS NTAPI DetouredNtQueryValueKey(
    const HANDLE key,
    PUNICODE_STRING value_name,
    const ULONG information_class,
    PVOID information,
    const ULONG length,
    PULONG result_length) {
    if (!AllowedHandle(key, RegistryAccess::kRead)) {
        ReportHandleViolation(key, protocol::RegistryOperation::kQuery);
        return kStatusAccessDenied;
    }
    return g_nt_query_value_key(
        key, value_name, information_class, information, length,
        result_length);
}

NTSTATUS NTAPI DetouredNtEnumerateKey(
    const HANDLE key,
    const ULONG index,
    const ULONG information_class,
    PVOID information,
    const ULONG length,
    PULONG result_length) {
    if (!AllowedHandle(key, RegistryAccess::kEnumerate)) {
        ReportHandleViolation(key, protocol::RegistryOperation::kEnumerate);
        return kStatusAccessDenied;
    }
    return g_nt_enumerate_key(
        key, index, information_class, information, length, result_length);
}

NTSTATUS NTAPI DetouredNtEnumerateValueKey(
    const HANDLE key,
    const ULONG index,
    const ULONG information_class,
    PVOID information,
    const ULONG length,
    PULONG result_length) {
    if (!AllowedHandle(key, RegistryAccess::kEnumerate)) {
        ReportHandleViolation(key, protocol::RegistryOperation::kEnumerate);
        return kStatusAccessDenied;
    }
    return g_nt_enumerate_value_key(
        key, index, information_class, information, length, result_length);
}

NTSTATUS NTAPI DetouredNtSetValueKey(
    const HANDLE key,
    PUNICODE_STRING value_name,
    const ULONG title_index,
    const ULONG type,
    PVOID data,
    const ULONG data_size) {
    if (!AllowedHandle(key, RegistryAccess::kWrite)) {
        ReportHandleViolation(key, protocol::RegistryOperation::kSetValue);
        return kStatusAccessDenied;
    }
    return g_nt_set_value_key(
        key, value_name, title_index, type, data, data_size);
}

NTSTATUS NTAPI DetouredNtDeleteKey(const HANDLE key) {
    if (!AllowedHandle(key, RegistryAccess::kWrite)) {
        ReportHandleViolation(key, protocol::RegistryOperation::kDelete);
        return kStatusAccessDenied;
    }
    return g_nt_delete_key(key);
}

NTSTATUS NTAPI DetouredNtDeleteValueKey(
    const HANDLE key,
    PUNICODE_STRING value_name) {
    if (!AllowedHandle(key, RegistryAccess::kWrite)) {
        ReportHandleViolation(key, protocol::RegistryOperation::kDelete);
        return kStatusAccessDenied;
    }
    return g_nt_delete_value_key(key, value_name);
}

NTSTATUS NTAPI DetouredNtRenameKey(
    const HANDLE key,
    PUNICODE_STRING new_name) {
    std::wstring current;
    std::wstring leaf;
    if (!QueryHandleName(key, current) || !ReadUnicodeString(new_name, leaf) ||
        leaf.empty() || leaf.find(L'\\') != std::wstring::npos) {
        ReportHandleViolation(key, protocol::RegistryOperation::kRename);
        return kStatusAccessDenied;
    }
    const std::size_t separator = current.find_last_of(L'\\');
    if (separator == std::wstring::npos) {
        return kStatusAccessDenied;
    }
    const std::wstring target = current.substr(0, separator + 1) + leaf;
    if (!AllowedNativeName(current, RegistryAccess::kWrite) ||
        !AllowedNativeName(target, RegistryAccess::kWrite)) {
        ReportRegistryViolation(target, protocol::RegistryOperation::kRename);
        return kStatusAccessDenied;
    }
    return g_nt_rename_key(key, new_name);
}

LSTATUS WINAPI DetouredRegConnectRegistryA(
    LPCSTR,
    HKEY,
    PHKEY result) {
    WriteNullRegistryKey(result);
    ReportUnsupportedRegistryOperation(
        protocol::RegistryOperation::kUnsupportedRemote);
    return ERROR_ACCESS_DENIED;
}

LSTATUS WINAPI DetouredRegConnectRegistryW(
    LPCWSTR,
    HKEY,
    PHKEY result) {
    WriteNullRegistryKey(result);
    ReportUnsupportedRegistryOperation(
        protocol::RegistryOperation::kUnsupportedRemote);
    return ERROR_ACCESS_DENIED;
}

LSTATUS WINAPI DetouredRegOpenKeyTransactedA(
    HKEY,
    LPCSTR,
    DWORD,
    REGSAM,
    PHKEY result,
    HANDLE,
    PVOID) {
    WriteNullRegistryKey(result);
    ReportUnsupportedRegistryOperation(
        protocol::RegistryOperation::kUnsupportedTransactional);
    return ERROR_ACCESS_DENIED;
}

LSTATUS WINAPI DetouredRegOpenKeyTransactedW(
    HKEY,
    LPCWSTR,
    DWORD,
    REGSAM,
    PHKEY result,
    HANDLE,
    PVOID) {
    WriteNullRegistryKey(result);
    ReportUnsupportedRegistryOperation(
        protocol::RegistryOperation::kUnsupportedTransactional);
    return ERROR_ACCESS_DENIED;
}

LSTATUS WINAPI DetouredRegCreateKeyTransactedA(
    HKEY,
    LPCSTR,
    DWORD,
    LPSTR,
    DWORD,
    REGSAM,
    const SECURITY_ATTRIBUTES*,
    PHKEY result,
    LPDWORD,
    HANDLE,
    PVOID) {
    WriteNullRegistryKey(result);
    ReportUnsupportedRegistryOperation(
        protocol::RegistryOperation::kUnsupportedTransactional);
    return ERROR_ACCESS_DENIED;
}

LSTATUS WINAPI DetouredRegCreateKeyTransactedW(
    HKEY,
    LPCWSTR,
    DWORD,
    LPWSTR,
    DWORD,
    REGSAM,
    const SECURITY_ATTRIBUTES*,
    PHKEY result,
    LPDWORD,
    HANDLE,
    PVOID) {
    WriteNullRegistryKey(result);
    ReportUnsupportedRegistryOperation(
        protocol::RegistryOperation::kUnsupportedTransactional);
    return ERROR_ACCESS_DENIED;
}

LSTATUS WINAPI DetouredRegDeleteKeyTransactedA(
    HKEY,
    LPCSTR,
    REGSAM,
    DWORD,
    HANDLE,
    PVOID) {
    ReportUnsupportedRegistryOperation(
        protocol::RegistryOperation::kUnsupportedTransactional);
    return ERROR_ACCESS_DENIED;
}

LSTATUS WINAPI DetouredRegDeleteKeyTransactedW(
    HKEY,
    LPCWSTR,
    REGSAM,
    DWORD,
    HANDLE,
    PVOID) {
    ReportUnsupportedRegistryOperation(
        protocol::RegistryOperation::kUnsupportedTransactional);
    return ERROR_ACCESS_DENIED;
}

template <typename Function>
bool ResolveFunction(
    const HMODULE ntdll,
    const char* name,
    Function& function) noexcept {
    function = reinterpret_cast<Function>(GetProcAddress(ntdll, name));
    return function != nullptr;
}

}  // namespace

PrivateUserRegistryStatus ConfigurePrivateUserRegistry(
    const wchar_t* const hive_path) noexcept {
    if (hive_path == nullptr || *hive_path == L'\0' ||
        g_private_user_hive != nullptr) {
        return PrivateUserRegistryStatus::kInvalidPath;
    }
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr ||
        !ResolveFunction(ntdll, "NtQueryKey", g_nt_query_key)) {
        return PrivateUserRegistryStatus::kLoadFailed;
    }
    HKEY hive = nullptr;
    if (RegLoadAppKeyW(
            hive_path, &hive, KEY_ALL_ACCESS, 0, 0) != ERROR_SUCCESS ||
        hive == nullptr) {
        return PrivateUserRegistryStatus::kLoadFailed;
    }
    HKEY user_root = nullptr;
    DWORD disposition = 0;
    if (RegCreateKeyExW(
            hive, L"HKCU", 0, nullptr, REG_OPTION_NON_VOLATILE,
            KEY_ALL_ACCESS, nullptr, &user_root, &disposition) !=
            ERROR_SUCCESS ||
        user_root == nullptr) {
        RegCloseKey(hive);
        return PrivateUserRegistryStatus::kLoadFailed;
    }
    std::wstring prefix;
    if (!QueryHandleName(user_root, prefix)) {
        RegCloseKey(user_root);
        RegCloseKey(hive);
        return PrivateUserRegistryStatus::kOverrideFailed;
    }
    RegCloseKey(user_root);
    g_private_user_prefix = std::move(prefix);
    g_private_user_hive = hive;
    return PrivateUserRegistryStatus::kSuccess;
}

namespace {

bool RewritePrivateUserAttributes(
    const OBJECT_ATTRIBUTES* source,
    std::wstring& path,
    UNICODE_STRING& name,
    OBJECT_ATTRIBUTES& rewritten,
    const OBJECT_ATTRIBUTES*& selected) {
    selected = source;
    if (g_private_user_prefix.empty() ||
        g_current_user_prefix.empty()) {
        return true;
    }
    std::wstring requested;
    if (!ReadObjectAttributesName(source, requested)) {
        return false;
    }
    std::wstring relative;
    if (!g_current_user_classes_prefix.empty() &&
        EqualPrefixIgnoreCase(requested, g_current_user_classes_prefix) &&
        (requested.size() == g_current_user_classes_prefix.size() ||
         requested[g_current_user_classes_prefix.size()] == L'\\')) {
        relative = L"Software\\Classes";
        if (requested.size() > g_current_user_classes_prefix.size()) {
            relative.push_back(L'\\');
            relative.append(
                requested.substr(g_current_user_classes_prefix.size() + 1));
        }
    } else if (
        EqualPrefixIgnoreCase(requested, g_current_user_prefix) &&
        (requested.size() == g_current_user_prefix.size() ||
         requested[g_current_user_prefix.size()] == L'\\')) {
        if (requested.size() > g_current_user_prefix.size()) {
            relative = requested.substr(g_current_user_prefix.size() + 1);
        }
    } else {
        return true;
    }
    path = g_private_user_prefix;
    if (!relative.empty()) {
        path.push_back(L'\\');
        path.append(relative);
    }
    if (path.size() > USHRT_MAX / sizeof(wchar_t)) {
        return false;
    }
    name.Buffer = path.data();
    name.Length = static_cast<USHORT>(path.size() * sizeof(wchar_t));
    name.MaximumLength = name.Length;
    rewritten = *source;
    rewritten.RootDirectory = nullptr;
    rewritten.ObjectName = &name;
    selected = &rewritten;
    return true;
}

}  // namespace

RegistryHookInstallStatus InstallRegistryHooks(
    const std::uint8_t* policy_payload,
    const std::size_t policy_length) noexcept {
    if (g_policy != nullptr) {
        return RegistryHookInstallStatus::kTransactionFailed;
    }
    std::unique_ptr<RegistryPolicy> policy;
    if (RegistryPolicy::Load(policy_payload, policy_length, policy) !=
        RegistryPolicyLoadStatus::kValid) {
        return RegistryHookInstallStatus::kInvalidPolicy;
    }
    std::wstring current_user_prefix;
    std::wstring active_control_set;
    if (!CurrentUserPrefix(current_user_prefix) ||
        !ActiveControlSet(active_control_set)) {
        return RegistryHookInstallStatus::kInvalidPolicy;
    }
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const HMODULE advapi32 = GetModuleHandleW(L"advapi32.dll");
    if (ntdll == nullptr || advapi32 == nullptr ||
        !ResolveFunction(ntdll, "NtOpenKey", g_nt_open_key) ||
        !ResolveFunction(ntdll, "NtOpenKeyEx", g_nt_open_key_ex) ||
        !ResolveFunction(ntdll, "NtCreateKey", g_nt_create_key) ||
        !ResolveFunction(
            ntdll, "NtOpenKeyTransacted", g_nt_open_key_transacted) ||
        !ResolveFunction(
            ntdll, "NtOpenKeyTransactedEx",
            g_nt_open_key_transacted_ex) ||
        !ResolveFunction(
            ntdll, "NtCreateKeyTransacted",
            g_nt_create_key_transacted) ||
        !ResolveFunction(ntdll, "NtQueryKey", g_nt_query_key) ||
        !ResolveFunction(ntdll, "NtQueryValueKey", g_nt_query_value_key) ||
        !ResolveFunction(ntdll, "NtEnumerateKey", g_nt_enumerate_key) ||
        !ResolveFunction(
            ntdll, "NtEnumerateValueKey", g_nt_enumerate_value_key) ||
        !ResolveFunction(ntdll, "NtSetValueKey", g_nt_set_value_key) ||
        !ResolveFunction(ntdll, "NtDeleteKey", g_nt_delete_key) ||
        !ResolveFunction(ntdll, "NtDeleteValueKey", g_nt_delete_value_key) ||
        !ResolveFunction(ntdll, "NtRenameKey", g_nt_rename_key) ||
        !ResolveFunction(ntdll, "NtClose", g_nt_close) ||
        !ResolveFunction(
            advapi32, "RegConnectRegistryA",
            g_reg_connect_registry_a) ||
        !ResolveFunction(
            advapi32, "RegConnectRegistryW",
            g_reg_connect_registry_w) ||
        !ResolveFunction(
            advapi32, "RegOpenKeyTransactedA",
            g_reg_open_key_transacted_a) ||
        !ResolveFunction(
            advapi32, "RegOpenKeyTransactedW",
            g_reg_open_key_transacted_w) ||
        !ResolveFunction(
            advapi32, "RegCreateKeyTransactedA",
            g_reg_create_key_transacted_a) ||
        !ResolveFunction(
            advapi32, "RegCreateKeyTransactedW",
            g_reg_create_key_transacted_w) ||
        !ResolveFunction(
            advapi32, "RegDeleteKeyTransactedA",
            g_reg_delete_key_transacted_a) ||
        !ResolveFunction(
            advapi32, "RegDeleteKeyTransactedW",
            g_reg_delete_key_transacted_w)) {
        return RegistryHookInstallStatus::kMissingFunction;
    }
    if (DetourTransactionBegin() != NO_ERROR ||
        DetourUpdateThread(GetCurrentThread()) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_nt_open_key),
            reinterpret_cast<PVOID>(DetouredNtOpenKey)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_nt_open_key_ex),
            reinterpret_cast<PVOID>(DetouredNtOpenKeyEx)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_nt_create_key),
            reinterpret_cast<PVOID>(DetouredNtCreateKey)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_nt_open_key_transacted),
            reinterpret_cast<PVOID>(
                DetouredNtOpenKeyTransacted)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_nt_open_key_transacted_ex),
            reinterpret_cast<PVOID>(
                DetouredNtOpenKeyTransactedEx)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_nt_create_key_transacted),
            reinterpret_cast<PVOID>(
                DetouredNtCreateKeyTransacted)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_nt_query_key),
            reinterpret_cast<PVOID>(DetouredNtQueryKey)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_nt_query_value_key),
            reinterpret_cast<PVOID>(DetouredNtQueryValueKey)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_nt_enumerate_key),
            reinterpret_cast<PVOID>(DetouredNtEnumerateKey)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_nt_enumerate_value_key),
            reinterpret_cast<PVOID>(DetouredNtEnumerateValueKey)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_nt_set_value_key),
            reinterpret_cast<PVOID>(DetouredNtSetValueKey)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_nt_delete_key),
            reinterpret_cast<PVOID>(DetouredNtDeleteKey)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_nt_delete_value_key),
            reinterpret_cast<PVOID>(DetouredNtDeleteValueKey)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_nt_rename_key),
            reinterpret_cast<PVOID>(DetouredNtRenameKey)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_reg_connect_registry_a),
            reinterpret_cast<PVOID>(
                DetouredRegConnectRegistryA)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_reg_connect_registry_w),
            reinterpret_cast<PVOID>(
                DetouredRegConnectRegistryW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_reg_open_key_transacted_a),
            reinterpret_cast<PVOID>(
                DetouredRegOpenKeyTransactedA)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_reg_open_key_transacted_w),
            reinterpret_cast<PVOID>(
                DetouredRegOpenKeyTransactedW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_reg_create_key_transacted_a),
            reinterpret_cast<PVOID>(
                DetouredRegCreateKeyTransactedA)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_reg_create_key_transacted_w),
            reinterpret_cast<PVOID>(
                DetouredRegCreateKeyTransactedW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_reg_delete_key_transacted_a),
            reinterpret_cast<PVOID>(
                DetouredRegDeleteKeyTransactedA)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_reg_delete_key_transacted_w),
            reinterpret_cast<PVOID>(
                DetouredRegDeleteKeyTransactedW)) != NO_ERROR ||
        DetourTransactionCommit() != NO_ERROR) {
        DetourTransactionAbort();
        return RegistryHookInstallStatus::kTransactionFailed;
    }
    g_current_user_prefix = std::move(current_user_prefix);
    g_current_user_classes_prefix = g_current_user_prefix + L"_Classes";
    g_active_control_set = std::move(active_control_set);
    g_policy = std::move(policy);
    return RegistryHookInstallStatus::kSuccess;
}

}  // namespace bolt::registry
