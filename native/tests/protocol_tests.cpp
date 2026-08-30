#include "protocol/version.h"

#include <cstddef>
#include <cstdint>
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
bool RunJobTests();
bool RunStreamTests();
int RunDualStreamWriter(int argument_count, wchar_t** arguments);
int RunJobTreeParent(int argument_count, wchar_t** arguments);
int RunIgnoreGracefulChild(int argument_count, wchar_t** arguments);
bool RunNamedPipeTests();
bool RunProcessTests();
bool RunDetoursTests();
bool RunEventFrameTests();
bool RunPolicyMappingTests();
bool RunRuntimePayloadTests();
bool RunBuildXlTreeTests();
bool RunFilesystemPolicyTests();
bool RunFilesystemRaceTests();
bool RunShellFileOperationTests();
int RunProcessChild(int argument_count, wchar_t** arguments);
int RunFilesystemRaceChild(int argument_count, wchar_t** arguments);
int RunShellFileOperationChild(int argument_count, wchar_t** arguments);
int RunInheritedProcessParent(int argument_count, wchar_t** arguments);
int RunInheritedProcessLeaf(int argument_count, wchar_t** arguments);
int RunNestedProcess(int argument_count, wchar_t** arguments);
int RunParentExitFixture(int argument_count, wchar_t** arguments);
int RunPersistentLeaf(int argument_count, wchar_t** arguments);
int RunCompatibilityParent(int argument_count, wchar_t** arguments);
int RunCrossArchitectureProcessParent(int argument_count, wchar_t** arguments);

namespace {

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

}  // namespace

int wmain(const int argument_count, wchar_t** arguments) {
    if (argument_count == 2 &&
        std::wstring(arguments[1]) == L"--filesystem-race-tests") {
        return RunFilesystemRaceTests() ? 0 : 1;
    }
    if (argument_count == 2 &&
        std::wstring(arguments[1]) == L"--shell-file-operation-tests") {
        return RunShellFileOperationTests() ? 0 : 1;
    }
    if (argument_count == 2 && std::wstring(arguments[1]) == L"--job-child") {
        Sleep(INFINITE);
        return 0;
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
    if (argument_count >= 2 && std::wstring(arguments[1]) == L"--nested-process") {
        return RunNestedProcess(argument_count, arguments);
    }
    if (argument_count >= 2 && std::wstring(arguments[1]) == L"--parent-exit-fixture") {
        return RunParentExitFixture(argument_count, arguments);
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
    if (!RunJobTests()) {
        return 5;
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
    if (!RunRuntimePayloadTests()) {
        return 11;
    }
    if (!RunBuildXlTreeTests()) {
        return 12;
    }
    if (!RunFilesystemPolicyTests()) {
        return 13;
    }
    if (!RunShellFileOperationTests()) {
        return 14;
    }
    if (!RunFilesystemRaceTests()) {
        return 15;
    }
    return 0;
}
