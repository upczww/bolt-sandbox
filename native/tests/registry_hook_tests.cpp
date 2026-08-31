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
        if (read_open_status != ERROR_SUCCESS) {
            return 711;
        }
        return read_query_status == ERROR_SUCCESS ? 713 : 712;
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
        {bolt::tests::RegistryRuleKind::kInheritUser,
         bolt::tests::RegistryHive::kLocalMachine,
         {"SYSTEM", "CURRENTCONTROLSET", "CONTROL", "SESSION MANAGER"}},
        {bolt::tests::RegistryRuleKind::kInheritUser,
         bolt::tests::RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "OLE"}},
        {bolt::tests::RegistryRuleKind::kInheritUser,
         bolt::tests::RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "APPMODEL", "LOOKASIDE", "MACHINE"}},
        {bolt::tests::RegistryRuleKind::kInheritUser,
         bolt::tests::RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "APPMODEL", "LOOKASIDE", "USER"}},
        {bolt::tests::RegistryRuleKind::kInheritUser,
         bolt::tests::RegistryHive::kCurrentUser,
         {"SOFTWARE", "CLASSES", "LOCAL SETTINGS"}},
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
    const bool child_passed = ready_ok &&
        process.Wait(3'000) == bolt::common::ProcessStatus::kSuccess &&
        process.ExitCode(exit_code) == bolt::common::ProcessStatus::kSuccess &&
        exit_code == 0;
    const auto child_process_id = static_cast<std::uint32_t>(
        GetProcessId(process.process_handle()));
    const bool events_passed = child_passed && child_process_id != 0 &&
        ReadRegistryViolationWithin(
            event_pipe.handle(), child_process_id, 1,
            bolt::protocol::RegistryOperation::kOpen,
            CanonicalCurrentUserKey(root + L"\\ReadOnly"), 1'000) &&
        ReadRegistryViolationWithin(
            event_pipe.handle(), child_process_id, 2,
            bolt::protocol::RegistryOperation::kOpen,
            CanonicalCurrentUserKey(root + L"\\Denied"), 1'000) &&
        ReadRegistryViolationWithin(
            event_pipe.handle(), child_process_id, 3,
            bolt::protocol::RegistryOperation::kOpen,
            CanonicalCurrentUserKey(root + L"\\Outside"), 1'000);
    const bool passed = child_passed && events_passed;
    if (!passed) {
        std::fprintf(
            stderr,
            "registry hook fixture failed: initialized=%d ready=%d exit=%lu "
            "events=%d\n",
            initialized ? 1 : 0, ready_ok ? 1 : 0,
            static_cast<unsigned long>(exit_code), events_passed ? 1 : 0);
    }
    process.Close();
    CloseHandle(release);
    event_pipe.Close();
    RegDeleteTreeW(HKEY_CURRENT_USER, root.c_str());
    return passed;
}
