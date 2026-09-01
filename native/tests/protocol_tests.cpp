#include "protocol/version.h"
#include "protocol/dns_proxy_startup.h"
#include "common/immutable_policy_mapping.h"
#include "common/immutable_mapping.h"
#include "tests/policy_fixture.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static_assert(bolt::protocol::kProtocolVersion == 1);
static_assert(bolt::protocol::kPolicyEnvelopeLength == 44);
static_assert(bolt::protocol::kPolicyVersionOffset == 4);
static_assert(bolt::protocol::kPolicyHeaderLengthOffset == 6);
static_assert(bolt::protocol::kPolicyBodyLengthOffset == 8);
static_assert(bolt::protocol::kPolicyDigestOffset == 12);
static_assert(bolt::protocol::kPolicyMaximumBodyLength == 1'048'576);

bool RunPolicyPayloadTests();
bool RunProtocolMutationTests();
bool RunJobTests();
bool RunLauncherStartupTests();
bool RunStreamTests();
int RunDualStreamWriter(int argument_count, wchar_t** arguments);
int RunDescendantDualStreamWriter(int argument_count, wchar_t** arguments);
int RunBlockingStreamFixture(int argument_count);
int RunPtyEchoFixture(int argument_count);
int RunCorruptEventFixture(int argument_count);
int RunCliFixture(int argument_count);
int RunCompatibilityReadFixture(int argument_count, wchar_t** arguments);
int RunDroppedEventChannelFixture(int argument_count);
int RunRecoveryDeleteFixture(int argument_count, wchar_t** arguments) noexcept;
int RunRecoveryTruncateFixture(int argument_count, wchar_t** arguments) noexcept;
int RunRecoveryReplaceRenameFixture(int argument_count, wchar_t** arguments) noexcept;
int RunUnauthorizedRecoveryRequestFixture(int argument_count, wchar_t** arguments) noexcept;
int RunRecoveryDeleteTwoFixture(int argument_count, wchar_t** arguments) noexcept;
int RunRecoveryHandleAndChildFixture(int argument_count, wchar_t** arguments) noexcept;
int RunRecoveryNativeDispositionFixture(int argument_count, wchar_t** arguments) noexcept;
int RunRecoveryDelayedDeleteFixture(int argument_count, wchar_t** arguments) noexcept;
int RunRecoveryConcurrentChildrenFixture(int argument_count, wchar_t** arguments) noexcept;
int RunJobTreeParent(int argument_count, wchar_t** arguments);
int RunIgnoreGracefulChild(int argument_count, wchar_t** arguments);
bool RunNamedPipeTests();
bool RunProcessTests();
bool RunProcessStartupLatencyTests();
bool RunDetoursTests();
bool RunEventFrameTests();
bool RunPolicyMappingTests();
bool RunProjfsApiTests();
bool RunProjectedWorkspaceProviderTests();
bool RunProjectedWorkspaceProtocolTests();
bool RunWorkspaceSecurityTests();
bool RunWorkspaceSecurityProtocolTests();
bool RunWorkspaceSecurityLauncherTests(const std::filesystem::path& directory);
int RunWorkspaceAclMutationFixture(int argument_count, wchar_t** arguments) noexcept;
bool RunRuntimePayloadTests();
bool RunBuildXlTreeTests();
bool RunFilesystemPolicyTests();
bool RunHandleAccessCacheTests();
bool RunPolicyDecisionCacheTests();
bool RunFilesystemRaceTests();
bool RunShellFileOperationTests();
bool RunNetworkPolicyTests();
bool RunRegistryPolicyTests();
bool RunRegistryHookTests();
int RunRegistryHookChild(int argument_count, wchar_t** arguments);
bool RunHttpConnectPolicyTests();
bool RunNetworkHookTests();
bool RunNetworkUnrestrictedTests();
bool RunNetworkEventSaturationTests();
bool RunNetworkStartupHandleTests();
bool RunNetworkInitializationFailureTests();
int RunNetworkInitializationMarkerChild(int argument_count, wchar_t** arguments);
int RunNetworkStartupHandleChild(int argument_count, wchar_t** arguments);
int RunNetworkUnrestrictedChild(int argument_count, wchar_t** arguments);
bool RunDnsBindingTests();
bool RunDnsRecordParserTests();
bool RunDnsProxyProtocolTests();
bool RunBoundedDnsResolverTests();
bool RunTcpProxyProtocolTests();
bool RunTcpProxyServerTests();
bool RunSystemTcpConnectorTests();
bool RunTcpRelayTests();
bool RunTcpProxyConnectionTests();
bool RunTcpProxyClientTests();
bool RunSocketTargetTableTests();
bool RunDnsProxyServerTests();
bool RunDnsProxySessionTests();
bool RunDnsProxyHandleTransportTests();
bool RunDnsProxyStartupTests();
bool RunSystemDnsResolverTests();
bool RunDnsProxyClientTests();
bool RunDnsProxyClientChannelTests();
bool RunImmutableMappingTests();
bool RunDnsProxyProcessTests();
bool RunNetworkAllowListTests();
int RunNetworkAllowListChild(int argument_count, wchar_t** arguments);
int RunNetworkAllowListLeaf(int argument_count, wchar_t** arguments);
int RunNetworkHookChild(int argument_count, wchar_t** arguments);
int RunProcessChild(int argument_count, wchar_t** arguments);
int RunFilesystemRaceChild(int argument_count, wchar_t** arguments);
int RunShellFileOperationChild(int argument_count, wchar_t** arguments);
int RunInheritedProcessParent(int argument_count, wchar_t** arguments);
int RunInheritedProcessLeaf(int argument_count, wchar_t** arguments);
int RunArgumentObservationLeaf(int argument_count, wchar_t** arguments);
int RunEntryMarkerChild(int argument_count, wchar_t** arguments);
int RunCreationMitigationChild(int argument_count, wchar_t** arguments);
int RunFaultedDescendantParent(int argument_count, wchar_t** arguments);
int RunNestedProcess(int argument_count, wchar_t** arguments);
int RunParentExitFixture(int argument_count, wchar_t** arguments);
int RunCrashTreeParent(int argument_count, wchar_t** arguments);
int RunPersistentLeaf(int argument_count, wchar_t** arguments);
int RunCompatibilityParent(int argument_count, wchar_t** arguments);
int RunCrossArchitectureProcessParent(int argument_count, wchar_t** arguments);

namespace {

bool write_exact(HANDLE handle, const std::uint8_t* bytes, std::size_t length) {
    std::size_t offset = 0;
    while (offset < length) {
        DWORD written = 0;
        if (!WriteFile(handle, bytes + offset, static_cast<DWORD>(length - offset),
                       &written, nullptr) || written == 0) {
            return false;
        }
        offset += written;
    }
    return true;
}

bool read_exact(HANDLE handle, std::uint8_t* bytes, std::size_t length) {
    std::size_t offset = 0;
    while (offset < length) {
        DWORD read = 0;
        if (!ReadFile(handle, bytes + offset, static_cast<DWORD>(length - offset),
                      &read, nullptr) || read == 0) {
            return false;
        }
        offset += read;
    }
    return true;
}

std::filesystem::path executable_directory() {
    std::wstring path(32'768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (length == 0 || length == path.size()) {
        return {};
    }
    path.resize(length);
    return std::filesystem::path(path).parent_path();
}

bool launcher_rejects_missing_resources(const std::filesystem::path& directory) {
#if defined(_WIN64)
    const auto launcher = directory / L"bolt-sandbox-launcher.exe";
    std::wstring command_line = L"\"" + launcher.wstring() + L"\"";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(
            launcher.c_str(), command_line.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr,
            &startup, &process)) {
        return false;
    }
    WaitForSingleObject(process.hProcess, INFINITE);
    DWORD exit_code = 0;
    const bool read_exit = GetExitCodeProcess(process.hProcess, &exit_code) != FALSE;
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return read_exit && exit_code != 0;
#else
    static_cast<void>(directory);
    return true;
#endif
}

bool hook_exports_matching_protocol(const std::filesystem::path& directory) {
#if defined(_WIN64)
    constexpr auto hook_name = L"bolt-sandbox-x64.dll";
#else
    constexpr auto hook_name = L"bolt-sandbox-x86.dll";
#endif
    const auto hook_path = directory / hook_name;
    const HMODULE module = LoadLibraryExW(
        hook_path.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (module == nullptr) {
        return false;
    }
    const auto version = reinterpret_cast<std::uint16_t (*)()>(
        GetProcAddress(module, "BoltSandboxProtocolVersion"));
    const bool matches = version != nullptr && version() == bolt::protocol::kProtocolVersion;
    FreeLibrary(module);
    return matches;
}

bool dns_proxy_rejects_missing_startup(const std::filesystem::path& directory) {
#if defined(_WIN64)
    const auto proxy = directory / L"bolt-sandbox-dns-proxy.exe";
    std::wstring command_line = L"\"" + proxy.wstring() + L"\"";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(
            proxy.c_str(), command_line.data(), nullptr, nullptr, FALSE, 0,
            nullptr, nullptr, &startup, &process)) {
        return false;
    }
    WaitForSingleObject(process.hProcess, 5'000);
    DWORD exit_code = 0;
    const bool passed = GetExitCodeProcess(process.hProcess, &exit_code) && exit_code != 0;
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return passed;
#else
    static_cast<void>(directory);
    return true;
#endif
}

bool dns_proxy_accepts_valid_startup(const std::filesystem::path& directory) {
#if defined(_WIN64)
    const auto proxy = directory / L"bolt-sandbox-dns-proxy.exe";
    const bolt::tests::NetworkAllowListRules allow_list{
        {{false, "localhost"}}, {}, {{443, 443}}};
    const auto policy_bytes = bolt::tests::SealPolicy(
        {}, bolt::tests::ChildProcessPolicyKind::kInherit,
        bolt::tests::NetworkPolicyKind::kAllowList, allow_list);
    bolt::common::ImmutablePolicyMapping policy;
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    HANDLE request_read = nullptr;
    HANDLE request_write = nullptr;
    HANDLE response_read = nullptr;
    HANDLE response_write = nullptr;
    if (policy_bytes.empty() ||
        bolt::common::ImmutablePolicyMapping::Create(
            policy_bytes.data(), policy_bytes.size(), policy) !=
            bolt::common::PolicyMappingStatus::kSuccess ||
        !SetHandleInformation(policy.handle(), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) ||
        !CreatePipe(&request_read, &request_write, &inheritable, 0) ||
        !CreatePipe(&response_read, &response_write, &inheritable, 0) ||
        !SetHandleInformation(request_write, HANDLE_FLAG_INHERIT, 0) ||
        !SetHandleInformation(response_read, HANDLE_FLAG_INHERIT, 0)) {
        return false;
    }
    bolt::protocol::DnsProxyStartup startup_payload{};
    startup_payload.policy_length = static_cast<std::uint32_t>(policy.length());
    startup_payload.policy_handle = reinterpret_cast<std::uintptr_t>(policy.handle());
    startup_payload.read_handle = reinterpret_cast<std::uintptr_t>(request_read);
    startup_payload.write_handle = reinterpret_cast<std::uintptr_t>(response_write);
    startup_payload.maximum_frame_length = 1'024;
    startup_payload.maximum_requests = 8;
    startup_payload.session.nonce[0] = 1;
    startup_payload.session.authentication_key[0] = 2;
    auto encoded_startup = bolt::protocol::EncodeDnsProxyStartup(startup_payload);
    bolt::common::ImmutableMapping startup_mapping;
    if (bolt::common::ImmutableMapping::Create(
            encoded_startup.data(), encoded_startup.size(), startup_mapping) !=
        bolt::common::ImmutableMappingStatus::kSuccess) {
        return false;
    }
    std::wstring command_line = L"\"" + proxy.wstring() + L"\"";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = startup_mapping.handle();
    startup.hStdOutput = request_read;
    startup.hStdError = response_write;
    PROCESS_INFORMATION process{};
    const bool created = CreateProcessW(
        proxy.c_str(), command_line.data(), nullptr, nullptr, TRUE, 0, nullptr,
        nullptr, &startup, &process) != FALSE;
    CloseHandle(request_read);
    CloseHandle(response_write);
    std::vector<std::uint8_t> request;
    const bool request_encoded = bolt::protocol::EncodeDnsProxyRequest(
        startup_payload.session, 1, 1'234, "localhost", 443, request) ==
        bolt::protocol::DnsProxyStatus::kSuccess;
    const std::uint32_t request_length = static_cast<std::uint32_t>(request.size());
    const std::array<std::uint8_t, 4> request_prefix = {
        static_cast<std::uint8_t>(request_length),
        static_cast<std::uint8_t>(request_length >> 8U),
        static_cast<std::uint8_t>(request_length >> 16U),
        static_cast<std::uint8_t>(request_length >> 24U),
    };
    const bool request_written = created && request_encoded &&
        write_exact(request_write, request_prefix.data(), request_prefix.size()) &&
        write_exact(request_write, request.data(), request.size());
    CloseHandle(request_write);
    if (!created) {
        std::fprintf(stderr, "dns proxy valid startup create failed: %lu\n",
                     static_cast<unsigned long>(GetLastError()));
        CloseHandle(response_read);
        return false;
    }
    const DWORD wait = WaitForSingleObject(process.hProcess, 5'000);
    DWORD exit_code = 0;
    std::array<std::uint8_t, 4> response_prefix{};
    const bool response_prefix_read =
        read_exact(response_read, response_prefix.data(), response_prefix.size());
    const std::size_t response_length =
        static_cast<std::size_t>(response_prefix[0]) |
        (static_cast<std::size_t>(response_prefix[1]) << 8U) |
        (static_cast<std::size_t>(response_prefix[2]) << 16U) |
        (static_cast<std::size_t>(response_prefix[3]) << 24U);
    std::vector<std::uint8_t> response(response_length);
    const bool response_body_read = response_length != 0 &&
        read_exact(response_read, response.data(), response.size());
    bolt::protocol::DnsProxyResponse decoded_response{};
    const bool response_valid = response_body_read &&
        bolt::protocol::DecodeDnsProxyResponse(
            startup_payload.session, response.data(), response.size(), 1,
            decoded_response) == bolt::protocol::DnsProxyStatus::kSuccess &&
        decoded_response.result == bolt::protocol::DnsProxyResult::kSuccess &&
        !decoded_response.addresses.empty();
    const bool passed = request_written && response_prefix_read && response_valid &&
                        wait == WAIT_OBJECT_0 &&
                        GetExitCodeProcess(process.hProcess, &exit_code) &&
                        exit_code == 0;
    if (!passed) {
        std::fprintf(
            stderr, "dns proxy valid startup failed: wait=%lu exit=%lu\n",
            static_cast<unsigned long>(wait),
            static_cast<unsigned long>(exit_code));
    }
    CloseHandle(response_read);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return passed;
#else
    static_cast<void>(directory);
    return true;
#endif
}

}  // namespace

int wmain(const int argument_count, wchar_t** arguments) {
    if (argument_count == 2 &&
        std::wstring(arguments[1]) == L"--dns-proxy-entry-tests") {
        const auto directory = executable_directory();
        return dns_proxy_rejects_missing_startup(directory) &&
                       dns_proxy_accepts_valid_startup(directory)
                   ? 0
                   : 1;
    }
    if (argument_count == 2 &&
        std::wstring(arguments[1]) == L"--filesystem-race-tests") {
        return RunFilesystemRaceTests() ? 0 : 1;
    }
    if (argument_count == 2 &&
        std::wstring(arguments[1]) == L"--process-startup-latency-tests") {
        return RunProcessStartupLatencyTests() ? 0 : 1;
    }
    if (argument_count == 2 &&
        std::wstring(arguments[1]) == L"--process-injection-failure-tests") {
        return RunProcessTests() ? 0 : 1;
    }
    if (argument_count == 2 &&
        std::wstring(arguments[1]) == L"--shell-file-operation-tests") {
        return RunShellFileOperationTests() ? 0 : 1;
    }
    if (argument_count == 2 && std::wstring(arguments[1]) == L"--network-policy-tests") {
        return RunNetworkPolicyTests() ? 0 : 1;
    }
    if (argument_count == 2 &&
        std::wstring(arguments[1]) == L"--registry-policy-tests") {
        return RunRegistryPolicyTests() ? 0 : 1;
    }
    if (argument_count == 2 &&
        std::wstring(arguments[1]) == L"--registry-hook-tests") {
        return RunRegistryHookTests() ? 0 : 1;
    }
    if (argument_count >= 2 &&
        std::wstring(arguments[1]) == L"--registry-hook-child") {
        return RunRegistryHookChild(argument_count, arguments);
    }
    if (argument_count == 2 &&
        std::wstring(arguments[1]) == L"--http-connect-policy-tests") {
        return RunHttpConnectPolicyTests() ? 0 : 1;
    }
    if (argument_count == 2 && std::wstring(arguments[1]) == L"--event-frame-tests") {
        return RunEventFrameTests() ? 0 : 1;
    }
    if (argument_count == 2 &&
        std::wstring(arguments[1]) == L"--runtime-payload-tests") {
        return RunRuntimePayloadTests() ? 0 : 1;
    }
    if (argument_count >= 2 && std::wstring(arguments[1]) == L"--network-hook-child") {
        return RunNetworkHookChild(argument_count, arguments);
    }
    if (argument_count >= 2 &&
        std::wstring(arguments[1]) == L"--network-unrestricted-child") {
        return RunNetworkUnrestrictedChild(argument_count, arguments);
    }
    if (argument_count == 2 && std::wstring(arguments[1]) == L"--network-hook-tests") {
        return RunNetworkHookTests() ? 0 : 1;
    }
    if (argument_count == 2 &&
        std::wstring(arguments[1]) == L"--network-event-saturation-tests") {
        return RunNetworkEventSaturationTests() ? 0 : 1;
    }
    if (argument_count == 2 &&
        std::wstring(arguments[1]) == L"--network-startup-handle-tests") {
        return RunNetworkStartupHandleTests() ? 0 : 1;
    }
    if (argument_count >= 2 &&
        std::wstring(arguments[1]) == L"--network-startup-handle-child") {
        return RunNetworkStartupHandleChild(argument_count, arguments);
    }
    if (argument_count == 2 &&
        std::wstring(arguments[1]) == L"--network-initialization-failure-tests") {
        return RunNetworkInitializationFailureTests() ? 0 : 1;
    }
    if (argument_count >= 2 &&
        std::wstring(arguments[1]) == L"--network-init-marker") {
        return RunNetworkInitializationMarkerChild(argument_count, arguments);
    }
    if (argument_count == 2 &&
        std::wstring(arguments[1]) == L"--network-unrestricted-tests") {
        return RunNetworkUnrestrictedTests() ? 0 : 1;
    }
    if (argument_count == 2 && std::wstring(arguments[1]) == L"--dns-binding-tests") {
        return RunDnsBindingTests() ? 0 : 1;
    }
    if (argument_count == 2 &&
        std::wstring(arguments[1]) == L"--dns-record-parser-tests") {
        return RunDnsRecordParserTests() ? 0 : 1;
    }
    if (argument_count == 2 && std::wstring(arguments[1]) == L"--dns-proxy-protocol-tests") {
        return RunDnsProxyProtocolTests() ? 0 : 1;
    }
    if (argument_count == 2 &&
        std::wstring(arguments[1]) == L"--bounded-dns-resolver-tests") {
        return RunBoundedDnsResolverTests() ? 0 : 1;
    }
    if (argument_count == 2 &&
        std::wstring(arguments[1]) == L"--tcp-proxy-protocol-tests") {
        return RunTcpProxyProtocolTests() ? 0 : 1;
    }
    if (argument_count == 2 &&
        std::wstring(arguments[1]) == L"--tcp-proxy-server-tests") {
        return RunTcpProxyServerTests() ? 0 : 1;
    }
    if (argument_count == 2 &&
        std::wstring(arguments[1]) == L"--system-tcp-connector-tests") {
        return RunSystemTcpConnectorTests() ? 0 : 1;
    }
    if (argument_count == 2 &&
        std::wstring(arguments[1]) == L"--tcp-relay-tests") {
        return RunTcpRelayTests() ? 0 : 1;
    }
    if (argument_count == 2 &&
        std::wstring(arguments[1]) == L"--tcp-proxy-connection-tests") {
        return RunTcpProxyConnectionTests() ? 0 : 1;
    }
    if (argument_count == 2 &&
        std::wstring(arguments[1]) == L"--tcp-proxy-client-tests") {
        return RunTcpProxyClientTests() ? 0 : 1;
    }
    if (argument_count == 2 &&
        std::wstring(arguments[1]) == L"--socket-target-table-tests") {
        return RunSocketTargetTableTests() ? 0 : 1;
    }
    if (argument_count == 2 && std::wstring(arguments[1]) == L"--dns-proxy-server-tests") {
        return RunDnsProxyServerTests() ? 0 : 1;
    }
    if (argument_count == 2 && std::wstring(arguments[1]) == L"--dns-proxy-session-tests") {
        return RunDnsProxySessionTests() ? 0 : 1;
    }
    if (argument_count == 2 && std::wstring(arguments[1]) == L"--dns-proxy-handle-tests") {
        return RunDnsProxyHandleTransportTests() ? 0 : 1;
    }
    if (argument_count == 2 && std::wstring(arguments[1]) == L"--dns-proxy-startup-tests") {
        return RunDnsProxyStartupTests() ? 0 : 1;
    }
    if (argument_count == 2 && std::wstring(arguments[1]) == L"--system-dns-resolver-tests") {
        return RunSystemDnsResolverTests() ? 0 : 1;
    }
    if (argument_count == 2 && std::wstring(arguments[1]) == L"--dns-proxy-client-tests") {
        return RunDnsProxyClientTests() ? 0 : 1;
    }
    if (argument_count == 2 && std::wstring(arguments[1]) == L"--dns-proxy-channel-tests") {
        return RunDnsProxyClientChannelTests() ? 0 : 1;
    }
    if (argument_count == 2 && std::wstring(arguments[1]) == L"--immutable-mapping-tests") {
        return RunImmutableMappingTests() ? 0 : 1;
    }
    if (argument_count == 2 && std::wstring(arguments[1]) == L"--dns-proxy-process-tests") {
        return RunDnsProxyProcessTests() ? 0 : 1;
    }
    if (argument_count >= 2 &&
        std::wstring(arguments[1]) == L"--network-allow-list-child") {
        return RunNetworkAllowListChild(argument_count, arguments);
    }
    if (argument_count >= 2 &&
        std::wstring(arguments[1]) == L"--network-allow-list-leaf") {
        return RunNetworkAllowListLeaf(argument_count, arguments);
    }
    if (argument_count == 2 &&
        std::wstring(arguments[1]) == L"--network-allow-list-tests") {
        return RunNetworkAllowListTests() ? 0 : 1;
    }
    if (argument_count == 2 && std::wstring(arguments[1]) == L"--job-child") {
        Sleep(INFINITE);
        return 0;
    }
    if (argument_count == 2 && std::wstring(arguments[1]) == L"--job-tests") {
        return RunJobTests() ? 0 : 1;
    }
    if (argument_count >= 2 && std::wstring(arguments[1]) == L"--job-tree-parent") {
        return RunJobTreeParent(argument_count, arguments);
    }
    if (argument_count >= 2 && std::wstring(arguments[1]) == L"--ignore-graceful") {
        return RunIgnoreGracefulChild(argument_count, arguments);
    }
    if (argument_count >= 2 && std::wstring(arguments[1]) == L"--dual-stream-writer") {
        return RunDualStreamWriter(argument_count, arguments);
    }
    if (argument_count >= 2 &&
        std::wstring(arguments[1]) == L"--descendant-dual-stream-writer") {
        return RunDescendantDualStreamWriter(argument_count, arguments);
    }
    if (argument_count >= 2 &&
        std::wstring(arguments[1]) == L"--blocking-stream-fixture") {
        return RunBlockingStreamFixture(argument_count);
    }
    if (argument_count >= 2 &&
        std::wstring(arguments[1]) == L"--pty-echo-fixture") {
        return RunPtyEchoFixture(argument_count);
    }
    if (argument_count >= 2 &&
        std::wstring(arguments[1]) == L"--corrupt-event-fixture") {
        return RunCorruptEventFixture(argument_count);
    }
    if (argument_count >= 2 &&
        std::wstring(arguments[1]) == L"--cli-fixture") {
        return RunCliFixture(argument_count);
    }
    if (argument_count >= 2 &&
        std::wstring(arguments[1]) == L"--compatibility-read-fixture") {
        return RunCompatibilityReadFixture(argument_count, arguments);
    }
    if (argument_count >= 2 &&
        std::wstring(arguments[1]) == L"--drop-event-channel-fixture") {
        return RunDroppedEventChannelFixture(argument_count);
    }
    if (argument_count >= 2 &&
        std::wstring(arguments[1]) == L"--recovery-delete-fixture") {
        return RunRecoveryDeleteFixture(argument_count, arguments);
    }
    if (argument_count >= 2 &&
        std::wstring(arguments[1]) == L"--recovery-truncate-fixture") {
        return RunRecoveryTruncateFixture(argument_count, arguments);
    }
    if (argument_count >= 2 &&
        std::wstring(arguments[1]) == L"--recovery-replace-rename-fixture") {
        return RunRecoveryReplaceRenameFixture(argument_count, arguments);
    }
    if (argument_count >= 2 &&
        std::wstring(arguments[1]) == L"--unauthorized-recovery-request-fixture") {
        return RunUnauthorizedRecoveryRequestFixture(argument_count, arguments);
    }
    if (argument_count >= 2 &&
        std::wstring(arguments[1]) == L"--recovery-delete-two-fixture") {
        return RunRecoveryDeleteTwoFixture(argument_count, arguments);
    }
    if (argument_count >= 2 &&
        std::wstring(arguments[1]) == L"--recovery-handle-child-fixture") {
        return RunRecoveryHandleAndChildFixture(argument_count, arguments);
    }
    if (argument_count >= 2 &&
        std::wstring(arguments[1]) == L"--recovery-native-disposition-fixture") {
        return RunRecoveryNativeDispositionFixture(argument_count, arguments);
    }
    if (argument_count >= 2 &&
        std::wstring(arguments[1]) == L"--recovery-delayed-delete-fixture") {
        return RunRecoveryDelayedDeleteFixture(argument_count, arguments);
    }
    if (argument_count >= 2 &&
        std::wstring(arguments[1]) == L"--recovery-concurrent-children-fixture") {
        return RunRecoveryConcurrentChildrenFixture(argument_count, arguments);
    }
    if (argument_count == 2 && std::wstring(arguments[1]) == L"--stream-tests") {
        return RunStreamTests() ? 0 : 1;
    }
    if (argument_count >= 2 && std::wstring(arguments[1]) == L"--process-child") {
        return RunProcessChild(argument_count, arguments);
    }
    if (argument_count >= 2 &&
        std::wstring(arguments[1]) == L"--filesystem-race-child") {
        return RunFilesystemRaceChild(argument_count, arguments);
    }
    if (argument_count >= 2 &&
        std::wstring(arguments[1]) == L"--shell-file-operation-child") {
        return RunShellFileOperationChild(argument_count, arguments);
    }
    if (argument_count >= 2 && std::wstring(arguments[1]) == L"--inherit-parent") {
        return RunInheritedProcessParent(argument_count, arguments);
    }
    if (argument_count >= 2 && std::wstring(arguments[1]) == L"--inherit-leaf") {
        return RunInheritedProcessLeaf(argument_count, arguments);
    }
    if (argument_count >= 2 &&
        std::wstring(arguments[1]) == L"--argument-observation") {
        return RunArgumentObservationLeaf(argument_count, arguments);
    }
    if (argument_count >= 2 &&
        std::wstring(arguments[1]) == L"--entry-marker") {
        return RunEntryMarkerChild(argument_count, arguments);
    }
    if (argument_count >= 2 &&
        std::wstring(arguments[1]) == L"--creation-mitigation-child") {
        return RunCreationMitigationChild(argument_count, arguments);
    }
    if (argument_count >= 2 &&
        std::wstring(arguments[1]) == L"--faulted-descendant-parent") {
        return RunFaultedDescendantParent(argument_count, arguments);
    }
    if (argument_count >= 2 && std::wstring(arguments[1]) == L"--nested-process") {
        return RunNestedProcess(argument_count, arguments);
    }
    if (argument_count >= 2 && std::wstring(arguments[1]) == L"--parent-exit-fixture") {
        return RunParentExitFixture(argument_count, arguments);
    }
    if (argument_count >= 2 && std::wstring(arguments[1]) == L"--crash-tree-parent") {
        return RunCrashTreeParent(argument_count, arguments);
    }
    if (argument_count >= 2 && std::wstring(arguments[1]) == L"--persistent-leaf") {
        return RunPersistentLeaf(argument_count, arguments);
    }
    if (argument_count >= 2 && std::wstring(arguments[1]) == L"--compatibility-parent") {
        return RunCompatibilityParent(argument_count, arguments);
    }
    if (argument_count >= 2 &&
        std::wstring(arguments[1]) == L"--cross-architecture-parent") {
        return RunCrossArchitectureProcessParent(argument_count, arguments);
    }
    if (argument_count >= 2 &&
        std::wstring(arguments[1]) == L"--workspace-acl-mutation-fixture") {
        return RunWorkspaceAclMutationFixture(argument_count, arguments);
    }
    constexpr std::uint8_t expected_magic[] = {'B', 'L', 'P', '1'};
    for (std::size_t index = 0; index < sizeof(expected_magic); ++index) {
        if (bolt::protocol::kPolicyMagic[index] != expected_magic[index]) {
            return 1;
        }
    }
    const auto directory = executable_directory();
    if (directory.empty() || !launcher_rejects_missing_resources(directory)) {
        return 2;
    }
    if (!hook_exports_matching_protocol(directory)) {
        return 3;
    }
    if (!RunPolicyPayloadTests()) {
        return 4;
    }
    if (!RunProtocolMutationTests()) {
        return 53;
    }
    if (!RunJobTests()) {
        return 5;
    }
    if (!RunLauncherStartupTests()) {
        return 18;
    }
    if (!RunStreamTests()) {
        return 16;
    }
    if (!RunNamedPipeTests()) {
        return 6;
    }
    if (!RunProcessTests()) {
        return 7;
    }
    if (!RunDetoursTests()) {
        return 8;
    }
    if (!RunEventFrameTests()) {
        return 9;
    }
    if (!RunPolicyMappingTests()) {
        return 10;
    }
    if (!RunProjfsApiTests()) {
        return 52;
    }
    if (!RunProjectedWorkspaceProviderTests()) {
        return 57;
    }
    if (!RunProjectedWorkspaceProtocolTests()) {
        return 58;
    }
    if (!RunWorkspaceSecurityTests()) {
        return 54;
    }
    if (!RunWorkspaceSecurityProtocolTests()) {
        return 55;
    }
    if (!RunWorkspaceSecurityLauncherTests(directory)) {
        return 56;
    }
    if (!RunRuntimePayloadTests()) {
        return 11;
    }
    if (!RunBuildXlTreeTests()) {
        return 12;
    }
    if (!RunFilesystemPolicyTests()) {
        return 13;
    }
    if (!RunHandleAccessCacheTests()) {
        return 50;
    }
    if (!RunPolicyDecisionCacheTests()) {
        return 51;
    }
    if (!RunShellFileOperationTests()) {
        return 14;
    }
    if (!RunFilesystemRaceTests()) {
        return 15;
    }
    if (!RunNetworkPolicyTests()) {
        return 16;
    }
    if (!RunRegistryPolicyTests()) {
        return 48;
    }
    if (!RunRegistryHookTests()) {
        return 49;
    }
    if (!RunHttpConnectPolicyTests()) {
        return 43;
    }
    if (!RunNetworkHookTests()) {
        return 17;
    }
    if (!RunNetworkUnrestrictedTests()) {
        return 41;
    }
    if (!RunDnsBindingTests()) {
        return 18;
    }
    if (!RunDnsRecordParserTests()) {
        return 44;
    }
    if (!RunDnsProxyProtocolTests()) {
        return 19;
    }
    if (!RunBoundedDnsResolverTests()) {
        return 45;
    }
    if (!RunDnsProxyServerTests()) {
        return 20;
    }
    if (!RunDnsProxySessionTests()) {
        return 21;
    }
    if (!RunDnsProxyHandleTransportTests()) {
        return 22;
    }
    if (!RunDnsProxyStartupTests()) {
        return 23;
    }
    if (!RunSystemDnsResolverTests()) {
        return 24;
    }
    if (!RunDnsProxyClientTests()) {
        return 25;
    }
    if (!RunDnsProxyClientChannelTests()) {
        return 26;
    }
    if (!RunImmutableMappingTests()) {
        return 27;
    }
    if (!RunDnsProxyProcessTests()) {
        return 28;
    }
    if (!RunNetworkAllowListTests()) {
        return 29;
    }
    if (!RunTcpProxyProtocolTests()) {
        return 30;
    }
    if (!RunTcpProxyServerTests()) {
        return 31;
    }
    if (!RunSystemTcpConnectorTests()) {
        return 32;
    }
    if (!RunTcpRelayTests()) {
        return 33;
    }
    if (!RunTcpProxyConnectionTests()) {
        return 34;
    }
    if (!RunTcpProxyClientTests()) {
        return 35;
    }
    if (!RunSocketTargetTableTests()) {
        return 36;
    }
    if (!RunNetworkEventSaturationTests()) {
        return 42;
    }
    if (!RunNetworkStartupHandleTests()) {
        return 46;
    }
    if (!RunNetworkInitializationFailureTests()) {
        return 47;
    }
    return 0;
}
