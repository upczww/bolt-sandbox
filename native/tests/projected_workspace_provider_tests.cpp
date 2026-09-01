#include "common/projected_workspace_provider.h"

#include <filesystem>
#include <cstring>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace {

const PRJ_CALLBACKS* g_callbacks = nullptr;
void* g_instance_context = nullptr;
std::vector<std::wstring> g_names;
std::vector<std::uint8_t> g_data;
std::uint64_t g_placeholder_size = 0;
bool g_stopped = false;
bool g_fail_placeholder = false;

HRESULT WINAPI FakeMark(
    PCWSTR,
    PCWSTR,
    const PRJ_PLACEHOLDER_VERSION_INFO*,
    const GUID*) noexcept {
    return S_OK;
}

HRESULT WINAPI FakeStart(
    PCWSTR,
    const PRJ_CALLBACKS* callbacks,
    const void* instance_context,
    const PRJ_STARTVIRTUALIZING_OPTIONS*,
    PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT* context) noexcept {
    g_callbacks = callbacks;
    g_instance_context = const_cast<void*>(instance_context);
    *context = reinterpret_cast<PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT>(1);
    return S_OK;
}

void WINAPI FakeStop(PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT) noexcept {
    g_stopped = true;
}

HRESULT WINAPI FakeWritePlaceholder(
    PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT,
    PCWSTR,
    const PRJ_PLACEHOLDER_INFO* information,
    UINT32) noexcept {
    g_placeholder_size = static_cast<std::uint64_t>(
        information->FileBasicInfo.FileSize);
    return g_fail_placeholder ? E_FAIL : S_OK;
}

HRESULT WINAPI FakeWriteData(
    PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT,
    const GUID*,
    void* buffer,
    UINT64,
    UINT32 length) noexcept {
    const auto* bytes = static_cast<const std::uint8_t*>(buffer);
    g_data.assign(bytes, bytes + length);
    return S_OK;
}

HRESULT WINAPI FakeFill(
    PCWSTR name,
    PRJ_FILE_BASIC_INFO*,
    PRJ_DIR_ENTRY_BUFFER_HANDLE) noexcept {
    g_names.emplace_back(name);
    return S_OK;
}

BOOLEAN WINAPI FakeMatch(PCWSTR, PCWSTR pattern) noexcept {
    return std::wcscmp(pattern, L"*") == 0 ? TRUE : FALSE;
}

int WINAPI FakeCompare(PCWSTR left, PCWSTR right) noexcept {
    return CompareStringOrdinal(left, -1, right, -1, TRUE) - CSTR_EQUAL;
}

void* WINAPI FakeAllocate(
    PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT,
    const size_t size) noexcept {
    return HeapAlloc(GetProcessHeap(), 0, size);
}

void WINAPI FakeFree(void* buffer) noexcept {
    HeapFree(GetProcessHeap(), 0, buffer);
}

HRESULT WINAPI FakeInstanceInfo(
    PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT,
    PRJ_VIRTUALIZATION_INSTANCE_INFO* information) noexcept {
    *information = PRJ_VIRTUALIZATION_INSTANCE_INFO{};
    information->WriteAlignment = 1;
    return S_OK;
}

}  // namespace

bool RunProjectedWorkspaceProviderTests() {
    wchar_t temporary[MAX_PATH]{};
    const DWORD length = GetTempPathW(MAX_PATH, temporary);
    if (length == 0 || length >= MAX_PATH) {
        return false;
    }
    const auto fixture = std::filesystem::path(temporary) /
                         (L"bolt-projected-source-" +
                          std::to_wstring(GetCurrentProcessId()) + L"-" +
                          std::to_wstring(GetTickCount64()));
    const auto source = fixture / L"source";
    std::error_code error;
    std::filesystem::remove_all(fixture, error);
    if (!std::filesystem::create_directories(source / L"目录") ||
        !std::filesystem::create_directories(source / L"alpha")) {
        return false;
    }
    const std::string contents = "0123456789";
    {
        HANDLE file = CreateFileW(
            (source / L"目录" / L"数据.txt").c_str(), GENERIC_WRITE, 0,
            nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        DWORD written = 0;
        const bool seeded = file != INVALID_HANDLE_VALUE &&
                            WriteFile(
                                file, contents.data(),
                                static_cast<DWORD>(contents.size()), &written,
                                nullptr) &&
                            written == contents.size();
        if (file != INVALID_HANDLE_VALUE) {
            CloseHandle(file);
        }
        if (!seeded) {
            std::filesystem::remove_all(fixture, error);
            return false;
        }
    }
    bolt::common::ProjectedWorkspaceSource projected;
    const auto opened = bolt::common::ProjectedWorkspaceSource::Open(
        source, bolt::common::ProjectedWorkspaceLimits{16, 1'024}, projected);
    std::vector<bolt::common::ProjectedWorkspaceEntry> entries;
    const auto enumerated = projected.Enumerate(L"", entries);
    bolt::common::ProjectedWorkspaceEntry unicode_entry{};
    const auto found = projected.Lookup(L"目录\\数据.txt", unicode_entry);
    std::vector<std::uint8_t> range;
    const auto read = projected.Read(L"目录\\数据.txt", 3, 4, range);

    const auto projection = fixture / L"projection";
    const bool projection_created =
        std::filesystem::create_directory(projection);
    bolt::common::ProjectedWorkspaceProvider provider;
    const bolt::common::ProjfsFunctionTable functions{
        FakeMark, FakeStart, FakeStop, FakeWritePlaceholder, FakeWriteData,
        FakeFill, FakeMatch, FakeCompare, FakeAllocate, FakeFree,
        FakeInstanceInfo};
    const auto provider_started =
        bolt::common::ProjectedWorkspaceProvider::StartWithFunctions(
            projected, projection, functions, provider);
    PRJ_CALLBACK_DATA callback_data{};
    callback_data.Size = sizeof(callback_data);
    callback_data.NamespaceVirtualizationContext =
        reinterpret_cast<PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT>(1);
    callback_data.InstanceContext = g_instance_context;
    callback_data.FilePathName = L"目录\\数据.txt";
    callback_data.DataStreamId.Data1 = 1;
    const HRESULT placeholder =
        g_callbacks == nullptr
            ? E_UNEXPECTED
            : g_callbacks->GetPlaceholderInfoCallback(&callback_data);
    g_fail_placeholder = true;
    const HRESULT failed_placeholder =
        g_callbacks == nullptr
            ? E_UNEXPECTED
            : g_callbacks->GetPlaceholderInfoCallback(&callback_data);
    g_fail_placeholder = false;
    PRJ_CALLBACK_DATA malformed_callback = callback_data;
    malformed_callback.InstanceContext = nullptr;
    const HRESULT malformed_placeholder =
        g_callbacks == nullptr
            ? E_UNEXPECTED
            : g_callbacks->GetPlaceholderInfoCallback(&malformed_callback);
    const HRESULT file_data =
        g_callbacks == nullptr
            ? E_UNEXPECTED
            : g_callbacks->GetFileDataCallback(&callback_data, 2, 3);
    GUID enumeration{};
    callback_data.FilePathName = L"";
    const HRESULT enumeration_started =
        g_callbacks == nullptr
            ? E_UNEXPECTED
            : g_callbacks->StartDirectoryEnumerationCallback(
                  &callback_data, &enumeration);
    const HRESULT enumeration_read =
        g_callbacks == nullptr
            ? E_UNEXPECTED
            : g_callbacks->GetDirectoryEnumerationCallback(
                  &callback_data, &enumeration, L"*",
                  reinterpret_cast<PRJ_DIR_ENTRY_BUFFER_HANDLE>(1));
    const HRESULT enumeration_ended =
        g_callbacks == nullptr
            ? E_UNEXPECTED
            : g_callbacks->EndDirectoryEnumerationCallback(
                  &callback_data, &enumeration);
    provider.Stop();

    const auto view = fixture / L"view";
    const auto materialized = fixture / L"materialized";
    const bool view_created =
        std::filesystem::create_directories(view / L"nested") &&
        CopyFileW(
            (source / L"目录" / L"数据.txt").c_str(),
            (view / L"nested" / L"copy.txt").c_str(), TRUE);
    const auto materialized_status =
        bolt::common::MaterializeProjectedWorkspace(
            view, materialized,
            bolt::common::ProjectedWorkspaceLimits{16, 1'024});
    std::string materialized_contents(10, '\0');
    {
        HANDLE file = CreateFileW(
            (materialized / L"nested" / L"copy.txt").c_str(), GENERIC_READ,
            FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        DWORD read_length = 0;
        const bool read_materialized = file != INVALID_HANDLE_VALUE &&
                                       ReadFile(
                                           file, materialized_contents.data(),
                                           static_cast<DWORD>(
                                               materialized_contents.size()),
                                           &read_length, nullptr) &&
                                       read_length ==
                                           materialized_contents.size();
        if (file != INVALID_HANDLE_VALUE) {
            CloseHandle(file);
        }
        if (!read_materialized) {
            materialized_contents.clear();
        }
    }
    const auto materialized_hardlink = fixture / L"materialized-hardlink";
    const bool view_hardlink = CreateHardLinkW(
                                   (view / L"hardlink.txt").c_str(),
                                   (view / L"nested" / L"copy.txt").c_str(),
                                   nullptr) != FALSE;
    const auto materialized_hardlink_status =
        bolt::common::MaterializeProjectedWorkspace(
            view, materialized_hardlink,
            bolt::common::ProjectedWorkspaceLimits{16, 1'024});
    DeleteFileW((view / L"hardlink.txt").c_str());
    const auto stream_path =
        (view / L"nested" / L"copy.txt").native() + L":secret";
    const HANDLE stream = CreateFileW(
        stream_path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    const bool stream_created = stream != INVALID_HANDLE_VALUE;
    if (stream != INVALID_HANDLE_VALUE) {
        CloseHandle(stream);
    }
    const auto materialized_stream = fixture / L"materialized-stream";
    const auto materialized_stream_status =
        bolt::common::MaterializeProjectedWorkspace(
            view, materialized_stream,
            bolt::common::ProjectedWorkspaceLimits{16, 1'024});
    DeleteFileW(stream_path.c_str());

    const auto outside = fixture / L"outside.bin";
    {
        HANDLE file = CreateFileW(
            outside.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file != INVALID_HANDLE_VALUE) {
            CloseHandle(file);
        }
    }
    const bool linked = CreateHardLinkW(
                            (source / L"hardlink.bin").c_str(),
                            outside.c_str(), nullptr) != FALSE;
    bolt::common::ProjectedWorkspaceSource rejected;
    const auto hardlink_status = bolt::common::ProjectedWorkspaceSource::Open(
        source, bolt::common::ProjectedWorkspaceLimits{32, 1'024}, rejected);
    std::filesystem::remove_all(fixture, error);

    return opened == bolt::common::ProjectedWorkspaceStatus::kSuccess &&
           enumerated == bolt::common::ProjectedWorkspaceStatus::kSuccess &&
           entries.size() == 2 && entries[0].name == L"alpha" &&
           entries[1].name == L"目录" && entries[0].is_directory &&
           entries[1].is_directory &&
           found == bolt::common::ProjectedWorkspaceStatus::kSuccess &&
           !unicode_entry.is_directory && unicode_entry.size == contents.size() &&
           read == bolt::common::ProjectedWorkspaceStatus::kSuccess &&
           range == std::vector<std::uint8_t>({'3', '4', '5', '6'}) &&
           projection_created &&
           provider_started ==
               bolt::common::ProjectedWorkspaceStatus::kSuccess &&
           placeholder == S_OK && g_placeholder_size == contents.size() &&
           failed_placeholder == E_FAIL &&
           malformed_placeholder == E_INVALIDARG &&
           file_data == S_OK &&
           g_data == std::vector<std::uint8_t>({'2', '3', '4'}) &&
           enumeration_started == S_OK && enumeration_read == S_OK &&
           enumeration_ended == S_OK && g_names.size() == 2 &&
           g_names[0] == L"alpha" && g_names[1] == L"目录" && g_stopped &&
           view_created &&
           materialized_status ==
               bolt::common::ProjectedWorkspaceStatus::kSuccess &&
           materialized_contents == contents &&
           view_hardlink &&
           materialized_hardlink_status ==
               bolt::common::ProjectedWorkspaceStatus::kUnsupportedObject &&
           stream_created &&
           materialized_stream_status ==
               bolt::common::ProjectedWorkspaceStatus::kUnsupportedObject &&
           linked &&
           hardlink_status ==
               bolt::common::ProjectedWorkspaceStatus::kUnsupportedObject &&
           !error;
}
