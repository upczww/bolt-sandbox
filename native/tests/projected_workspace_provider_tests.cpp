#include "common/projected_workspace_provider.h"

#include <filesystem>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

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
           linked &&
           hardlink_status ==
               bolt::common::ProjectedWorkspaceStatus::kUnsupportedObject &&
           !error;
}
