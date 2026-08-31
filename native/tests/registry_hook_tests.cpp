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

std::wstring NativeKeyName(const std::wstring& path) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(
            HKEY_CURRENT_USER, path.c_str(), 0, KEY_READ, &key) !=
        ERROR_SUCCESS) {
        return {};
    }
    using NtQueryKeyFunction = LONG(NTAPI*)(
        HANDLE, ULONG, PVOID, ULONG, PULONG);
    const auto query = reinterpret_cast<NtQueryKeyFunction>(GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtQueryKey"));
    ULONG required = 0;
    if (query == nullptr) {
        RegCloseKey(key);
        return {};
    }
    query(key, 3, nullptr, 0, &required);
    std::vector<std::uint8_t> buffer(required);
    const LONG status = query(
        key, 3, buffer.data(), required, &required);
    RegCloseKey(key);
    if (status < 0 || required < sizeof(ULONG)) {
        return {};
    }
    const ULONG bytes = *reinterpret_cast<const ULONG*>(buffer.data());
    return std::wstring(
        reinterpret_cast<const wchar_t*>(buffer.data() + sizeof(ULONG)),
        bytes / sizeof(wchar_t));
}

std::vector<std::string> Components(
    const DWORD process_id,
    const char* const leaf) {
    return {
        "SOFTWARE", "BOLTSANDBOXREGISTRYTESTS",
        std::to_string(process_id), leaf};
}

int RegistryReadFailureCode(
    const wchar_t* diagnostic_path,
    const std::wstring& expected_suffix,
    const LSTATUS open_status,
    const LSTATUS query_status) {
    if (open_status == ERROR_SUCCESS) {
        return query_status == ERROR_SUCCESS ? 713 : 712;
    }
    const HMODULE hook = GetModuleHandleW(
#if defined(_WIN64)
        L"bolt-sandbox-x64.dll"
#else
        L"bolt-sandbox-x86.dll"
#endif
    );
    const auto denial_reason = hook == nullptr
        ? nullptr
        : reinterpret_cast<std::uint32_t (*)()>(GetProcAddress(
              hook, "BoltSandboxLastRegistryDenialReason"));
    const auto denial_details = hook == nullptr
        ? nullptr
        : reinterpret_cast<std::uint32_t (*)()>(GetProcAddress(
              hook, "BoltSandboxLastRegistryDenialDetails"));
    const auto denial_matches = hook == nullptr
        ? nullptr
        : reinterpret_cast<BOOL (*)(const wchar_t*)>(GetProcAddress(
              hook, "BoltSandboxLastRegistryDenialMatchesSuffix"));
    const auto copy_denial_name = hook == nullptr
        ? nullptr
        : reinterpret_cast<std::uint32_t (*)(wchar_t*, std::uint32_t)>(
              GetProcAddress(hook, "BoltSandboxCopyLastRegistryDenialName"));
    if (copy_denial_name != nullptr) {
        std::array<wchar_t, 1'024> denied_name{};
        const std::uint32_t denied_length = copy_denial_name(
            denied_name.data(),
            static_cast<std::uint32_t>(denied_name.size()));
        const HANDLE diagnostic = CreateFileW(
            diagnostic_path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        if (diagnostic != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            WriteFile(
                diagnostic, denied_name.data(),
                denied_length * sizeof(wchar_t), &written, nullptr);
            CloseHandle(diagnostic);
        }
    }
    return denial_reason == nullptr
               ? 711
               : denial_details == nullptr
                     ? 720 + static_cast<int>(denial_reason())
                     : 1'000 + 100 * static_cast<int>(denial_reason()) +
                           static_cast<int>(denial_details()) +
                           (denial_matches != nullptr &&
                                    denial_matches(expected_suffix.c_str())
                                ? 10'000
                                : 0);
}

}  // namespace

int RunRegistryHookChild(const int argument_count, wchar_t** arguments) {
    if (argument_count != 4) {
        return 700;
    }
    const std::wstring root = arguments[2];
    const std::wstring read_only = root + L"\\ReadOnly";
    const std::wstring denied = root + L"\\Denied";
    const std::wstring allowed = root + L"\\Allowed";
    const std::wstring inherited = root + L"\\Inherited";
    const std::wstring outside = root + L"\\Outside";

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
    if (read_key != nullptr) {
        RegCloseKey(read_key);
    }
    if (!read_allowed) {
        return RegistryReadFailureCode(
            arguments[3], read_only, read_open_status, read_query_status);
    }

    HKEY write_intent = nullptr;
    const LSTATUS read_only_write_open = RegOpenKeyExW(
        HKEY_CURRENT_USER, read_only.c_str(), 0,
        KEY_READ | KEY_SET_VALUE, &write_intent);
    if (write_intent != nullptr) {
        RegCloseKey(write_intent);
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

    HKEY allowed_key = nullptr;
    const wchar_t changed[] = L"changed";
    const bool write_allowed =
        RegOpenKeyExW(
            HKEY_CURRENT_USER, allowed.c_str(), 0,
            KEY_READ | KEY_SET_VALUE, &allowed_key) == ERROR_SUCCESS &&
        RegSetValueExW(
            allowed_key, L"Changed", 0, REG_SZ,
            reinterpret_cast<const BYTE*>(changed),
            sizeof(changed)) == ERROR_SUCCESS;
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

    if (!read_allowed) {
        if (read_open_status != ERROR_SUCCESS) {
            const HMODULE hook = GetModuleHandleW(
#if defined(_WIN64)
                L"bolt-sandbox-x64.dll"
#else
                L"bolt-sandbox-x86.dll"
#endif
            );
            const auto denial_reason = hook == nullptr
                ? nullptr
                : reinterpret_cast<std::uint32_t (*)()>(GetProcAddress(
                      hook, "BoltSandboxLastRegistryDenialReason"));
            const auto denial_details = hook == nullptr
                ? nullptr
                : reinterpret_cast<std::uint32_t (*)()>(GetProcAddress(
                      hook, "BoltSandboxLastRegistryDenialDetails"));
            const auto denial_matches = hook == nullptr
                ? nullptr
                : reinterpret_cast<BOOL (*)(const wchar_t*)>(GetProcAddress(
                      hook,
                      "BoltSandboxLastRegistryDenialMatchesSuffix"));
            const auto copy_denial_name = hook == nullptr
                ? nullptr
                : reinterpret_cast<std::uint32_t (*)(wchar_t*, std::uint32_t)>(
                      GetProcAddress(
                          hook, "BoltSandboxCopyLastRegistryDenialName"));
            if (copy_denial_name != nullptr) {
                std::array<wchar_t, 1'024> denied_name{};
                const std::uint32_t denied_length = copy_denial_name(
                    denied_name.data(),
                    static_cast<std::uint32_t>(denied_name.size()));
                const HANDLE diagnostic = CreateFileW(
                    arguments[3], GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, nullptr);
                if (diagnostic != INVALID_HANDLE_VALUE) {
                    DWORD written = 0;
                    WriteFile(
                        diagnostic, denied_name.data(),
                        denied_length * sizeof(wchar_t), &written, nullptr);
                    CloseHandle(diagnostic);
                }
            }
            return denial_reason == nullptr
                       ? 711
                       : denial_details == nullptr
                             ? 720 + static_cast<int>(denial_reason())
                             : 1'000 +
                                   100 * static_cast<int>(denial_reason()) +
                                   static_cast<int>(denial_details()) +
                                   (denial_matches != nullptr &&
                                            denial_matches(read_only.c_str())
                                        ? 10'000
                                        : 0);
        }
        if (read_query_status != ERROR_SUCCESS) {
            return 712;
        }
        return 713;
    }
    if (read_only_write_open != ERROR_ACCESS_DENIED || write_intent != nullptr) {
        return 702;
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
    if (!write_allowed) {
        return 705;
    }
    return inherit_user_allowed ? 0 : 706;
}

bool RunRegistryHookTests() {
    const DWORD process_id = GetCurrentProcessId();
    const std::wstring root =
        L"Software\\BoltSandboxRegistryTests\\" +
        std::to_wstring(process_id);
    RegDeleteTreeW(HKEY_CURRENT_USER, root.c_str());
    const bool prepared =
        CreateKeyWithValue(root + L"\\ReadOnly", L"Seed", L"seed") &&
        CreateKeyWithValue(root + L"\\Denied", L"Seed", L"secret") &&
        CreateKeyWithValue(root + L"\\Allowed", L"Seed", L"seed") &&
        CreateKeyWithValue(root + L"\\Inherited", L"Seed", L"seed") &&
        CreateKeyWithValue(root + L"\\Outside", L"Seed", L"outside");
    if (!prepared) {
        RegDeleteTreeW(HKEY_CURRENT_USER, root.c_str());
        return false;
    }
    const std::wstring native_read_only =
        NativeKeyName(root + L"\\ReadOnly");
    std::fwprintf(
        stderr, L"registry fixture native path: %ls\n",
        native_read_only.c_str());

    const std::vector<bolt::tests::RegistryRule> registry_rules = {
        {bolt::tests::RegistryRuleKind::kReadOnly,
         bolt::tests::RegistryHive::kCurrentUser,
         Components(process_id, "READONLY")},
        {bolt::tests::RegistryRuleKind::kNoAccess,
         bolt::tests::RegistryHive::kCurrentUser,
         Components(process_id, "DENIED")},
        {bolt::tests::RegistryRuleKind::kReadWrite,
         bolt::tests::RegistryHive::kCurrentUser,
         Components(process_id, "ALLOWED")},
        {bolt::tests::RegistryRuleKind::kInheritUser,
         bolt::tests::RegistryHive::kCurrentUser,
         Components(process_id, "INHERITED")},
        {bolt::tests::RegistryRuleKind::kInheritUser,
         bolt::tests::RegistryHive::kLocalMachine,
         {"SYSTEM", "CURRENTCONTROLSET", "CONTROL", "SESSION MANAGER"}},
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
        L"\" \"" +
        (std::filesystem::temp_directory_path() /
         (L"bolt-registry-diagnostic-" + std::to_wstring(process_id) +
          L".txt"))
            .wstring() +
        L"\"";
    const HANDLE inherited_handles[] = {
        policy.handle(), event_client, release};
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
    const bool passed = ready_ok &&
        process.Wait(3'000) == bolt::common::ProcessStatus::kSuccess &&
        process.ExitCode(exit_code) == bolt::common::ProcessStatus::kSuccess &&
        exit_code == 0;
    if (!passed) {
        std::fprintf(
            stderr,
            "registry hook fixture failed: initialized=%d ready=%d exit=%lu\n",
            initialized ? 1 : 0, ready_ok ? 1 : 0,
            static_cast<unsigned long>(exit_code));
        const auto diagnostic_path =
            std::filesystem::temp_directory_path() /
            (L"bolt-registry-diagnostic-" + std::to_wstring(process_id) +
             L".txt");
        const HANDLE diagnostic = CreateFileW(
            diagnostic_path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (diagnostic != INVALID_HANDLE_VALUE) {
            std::array<wchar_t, 1'024> denied_name{};
            DWORD bytes = 0;
            ReadFile(
                diagnostic, denied_name.data(),
                static_cast<DWORD>((denied_name.size() - 1) * sizeof(wchar_t)),
                &bytes, nullptr);
            CloseHandle(diagnostic);
            std::fwprintf(
                stderr, L"registry denied native path: %ls\n",
                denied_name.data());
            DeleteFileW(diagnostic_path.c_str());
        }
    }
    process.Close();
    CloseHandle(release);
    event_pipe.Close();
    RegDeleteTreeW(HKEY_CURRENT_USER, root.c_str());
    return passed;
}
