#include "hook/registry/registry_hooks.h"

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
constexpr NTSTATUS kStatusBufferOverflow =
    static_cast<NTSTATUS>(0x80000005L);
constexpr NTSTATUS kStatusBufferTooSmall =
    static_cast<NTSTATUS>(0xC0000023L);
constexpr NTSTATUS kStatusInfoLengthMismatch =
    static_cast<NTSTATUS>(0xC0000004L);
constexpr ULONG kKeyNameInformation = 3;
constexpr ULONG kKeyHandleTagsInformation = 7;

using NtOpenKeyFunction = NTSTATUS(NTAPI*)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
using NtOpenKeyExFunction = NTSTATUS(NTAPI*)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
using NtCreateKeyFunction = NTSTATUS(NTAPI*)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG,
    PULONG);
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

NtOpenKeyFunction g_nt_open_key = nullptr;
NtOpenKeyExFunction g_nt_open_key_ex = nullptr;
NtCreateKeyFunction g_nt_create_key = nullptr;
NtQueryKeyFunction g_nt_query_key = nullptr;
NtQueryValueKeyFunction g_nt_query_value_key = nullptr;
NtEnumerateKeyFunction g_nt_enumerate_key = nullptr;
NtEnumerateValueKeyFunction g_nt_enumerate_value_key = nullptr;
NtSetValueKeyFunction g_nt_set_value_key = nullptr;
NtDeleteKeyFunction g_nt_delete_key = nullptr;
NtDeleteValueKeyFunction g_nt_delete_value_key = nullptr;
NtRenameKeyFunction g_nt_rename_key = nullptr;
NtCloseFunction g_nt_close = nullptr;
std::unique_ptr<RegistryPolicy> g_policy;
std::wstring g_current_user_prefix;
std::wstring g_active_control_set;

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
           decision == RegistryDecision::kInheritUser;
}

bool AllowedNativeOpen(
    const std::wstring& name,
    const RegistryAccess access) {
    RegistryHive hive{};
    std::wstring relative;
    if (!MapNativeName(name, hive, relative) || g_policy == nullptr) {
        return false;
    }
    const RegistryDecision decision =
        g_policy->Decide(hive, relative.c_str(), access);
    if (decision == RegistryDecision::kAllow ||
        decision == RegistryDecision::kInheritUser) {
        return true;
    }
    return access != RegistryAccess::kWrite &&
           g_policy->MayTraverse(hive, relative.c_str());
}

bool AllowedHandle(const HANDLE key, const RegistryAccess access) {
    std::wstring name;
    return QueryHandleName(key, name) && AllowedNativeName(name, access);
}

template <typename OpenCall>
NTSTATUS GuardOpen(
    PHANDLE key,
    const ACCESS_MASK desired_access,
    const OBJECT_ATTRIBUTES* attributes,
    OpenCall&& call) {
    std::wstring requested;
    const RegistryAccess access = AccessForMask(desired_access);
    if (!ReadObjectAttributesName(attributes, requested)) {
        WriteNullHandle(key);
        return kStatusAccessDenied;
    }
    RegistryDecision requested_decision = RegistryDecision::kDeny;
    if (!DecideNativeName(requested, access, requested_decision)) {
        WriteNullHandle(key);
        return kStatusAccessDenied;
    }
    if (requested_decision == RegistryDecision::kDeny &&
        !AllowedNativeOpen(requested, access)) {
        WriteNullHandle(key);
        return kStatusAccessDenied;
    }
    const NTSTATUS status = call();
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
    return kStatusAccessDenied;
}

NTSTATUS NTAPI DetouredNtOpenKey(
    PHANDLE key,
    const ACCESS_MASK desired_access,
    POBJECT_ATTRIBUTES attributes) {
    return GuardOpen(key, desired_access, attributes, [&] {
        return g_nt_open_key(key, desired_access, attributes);
    });
}

NTSTATUS NTAPI DetouredNtOpenKeyEx(
    PHANDLE key,
    const ACCESS_MASK desired_access,
    POBJECT_ATTRIBUTES attributes,
    const ULONG open_options) {
    return GuardOpen(key, desired_access, attributes, [&] {
        return g_nt_open_key_ex(
            key, desired_access, attributes, open_options);
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
    return GuardOpen(key, RegistryAccess::kWrite == AccessForMask(desired_access)
                              ? desired_access
                              : desired_access | KEY_CREATE_SUB_KEY,
                     attributes, [&] {
                         return g_nt_create_key(
                             key, desired_access, attributes, title_index,
                             class_name, create_options, disposition);
                     });
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
    return AllowedHandle(key, RegistryAccess::kWrite)
               ? g_nt_set_value_key(
                     key, value_name, title_index, type, data, data_size)
               : kStatusAccessDenied;
}

NTSTATUS NTAPI DetouredNtDeleteKey(const HANDLE key) {
    return AllowedHandle(key, RegistryAccess::kWrite)
               ? g_nt_delete_key(key)
               : kStatusAccessDenied;
}

NTSTATUS NTAPI DetouredNtDeleteValueKey(
    const HANDLE key,
    PUNICODE_STRING value_name) {
    return AllowedHandle(key, RegistryAccess::kWrite)
               ? g_nt_delete_value_key(key, value_name)
               : kStatusAccessDenied;
}

NTSTATUS NTAPI DetouredNtRenameKey(
    const HANDLE key,
    PUNICODE_STRING new_name) {
    std::wstring current;
    std::wstring leaf;
    if (!QueryHandleName(key, current) || !ReadUnicodeString(new_name, leaf) ||
        leaf.empty() || leaf.find(L'\\') != std::wstring::npos) {
        return kStatusAccessDenied;
    }
    const std::size_t separator = current.find_last_of(L'\\');
    if (separator == std::wstring::npos) {
        return kStatusAccessDenied;
    }
    const std::wstring target = current.substr(0, separator + 1) + leaf;
    return AllowedNativeName(current, RegistryAccess::kWrite) &&
            AllowedNativeName(target, RegistryAccess::kWrite)
        ? g_nt_rename_key(key, new_name)
        : kStatusAccessDenied;
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
    if (ntdll == nullptr ||
        !ResolveFunction(ntdll, "NtOpenKey", g_nt_open_key) ||
        !ResolveFunction(ntdll, "NtOpenKeyEx", g_nt_open_key_ex) ||
        !ResolveFunction(ntdll, "NtCreateKey", g_nt_create_key) ||
        !ResolveFunction(ntdll, "NtQueryKey", g_nt_query_key) ||
        !ResolveFunction(ntdll, "NtQueryValueKey", g_nt_query_value_key) ||
        !ResolveFunction(ntdll, "NtEnumerateKey", g_nt_enumerate_key) ||
        !ResolveFunction(
            ntdll, "NtEnumerateValueKey", g_nt_enumerate_value_key) ||
        !ResolveFunction(ntdll, "NtSetValueKey", g_nt_set_value_key) ||
        !ResolveFunction(ntdll, "NtDeleteKey", g_nt_delete_key) ||
        !ResolveFunction(ntdll, "NtDeleteValueKey", g_nt_delete_value_key) ||
        !ResolveFunction(ntdll, "NtRenameKey", g_nt_rename_key) ||
        !ResolveFunction(ntdll, "NtClose", g_nt_close)) {
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
        DetourTransactionCommit() != NO_ERROR) {
        DetourTransactionAbort();
        return RegistryHookInstallStatus::kTransactionFailed;
    }
    g_current_user_prefix = std::move(current_user_prefix);
    g_active_control_set = std::move(active_control_set);
    g_policy = std::move(policy);
    return RegistryHookInstallStatus::kSuccess;
}

}  // namespace bolt::registry
