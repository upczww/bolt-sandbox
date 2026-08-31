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

std::vector<std::string> Components(
    const DWORD process_id,
    const char* const leaf) {
    return {
        "SOFTWARE", "BOLTSANDBOXREGISTRYTESTS",
        std::to_string(process_id), leaf};
}

}  // namespace

int RunRegistryHookChild(const int argument_count, wchar_t** arguments) {
    if (argument_count != 3) {
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
    const bool read_allowed =
        RegOpenKeyExW(
            HKEY_CURRENT_USER, read_only.c_str(), 0, KEY_READ, &read_key) ==
            ERROR_SUCCESS &&
        RegQueryValueExW(
            read_key, L"Seed", nullptr, &value_type,
            reinterpret_cast<BYTE*>(value), &value_bytes) == ERROR_SUCCESS &&
        value_type == REG_SZ && std::wstring(value) == L"seed";
    if (read_key != nullptr) {
        RegCloseKey(read_key);
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
        return 701;
    }
    if (read_only_write_open != ERROR_ACCESS_DENIED || write_intent != nullptr) {
        return 702;
    }
    if (denied_open != ERROR_ACCESS_DENIED || denied_key != nullptr) {
        return 703;
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
    process.Close();
    CloseHandle(release);
    event_pipe.Close();
    RegDeleteTreeW(HKEY_CURRENT_USER, root.c_str());
    return passed;
}
