#pragma once

#include "common/projfs_api.h"

#include <array>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace bolt::common {

enum class ProjectedWorkspaceStatus : std::uint8_t {
    kSuccess,
    kInvalidRoot,
    kInvalidPath,
    kNotFound,
    kUnsupportedObject,
    kQuotaExceeded,
    kInvalidRange,
    kIo,
    kUnavailable,
};

struct ProjectedWorkspaceLimits {
    std::uint32_t maximum_items = 0;
    std::uint64_t maximum_bytes = 0;
};

struct ProjectedWorkspaceEntry {
    std::wstring name;
    bool is_directory = false;
    std::uint64_t size = 0;
    std::uint32_t attributes = 0;
    std::int64_t creation_time = 0;
    std::int64_t last_access_time = 0;
    std::int64_t last_write_time = 0;
    std::int64_t change_time = 0;
};

class ProjectedWorkspaceSource final {
  public:
    static ProjectedWorkspaceStatus Open(
        const std::filesystem::path& root,
        ProjectedWorkspaceLimits limits,
        ProjectedWorkspaceSource& output) noexcept;

    ProjectedWorkspaceStatus Lookup(
        std::wstring_view relative_path,
        ProjectedWorkspaceEntry& output) const noexcept;
    ProjectedWorkspaceStatus Enumerate(
        std::wstring_view relative_directory,
        std::vector<ProjectedWorkspaceEntry>& output) const noexcept;
    ProjectedWorkspaceStatus Read(
        std::wstring_view relative_path,
        std::uint64_t offset,
        std::uint32_t length,
        std::vector<std::uint8_t>& output) const noexcept;

    [[nodiscard]] const std::filesystem::path& root() const noexcept {
        return root_;
    }

  private:
    std::filesystem::path root_;
    ProjectedWorkspaceLimits limits_{};
};

struct ProjfsFunctionTable {
    ProjfsApi::MarkDirectoryAsPlaceholderFunction mark_directory = nullptr;
    ProjfsApi::StartVirtualizingFunction start = nullptr;
    ProjfsApi::StopVirtualizingFunction stop = nullptr;
    ProjfsApi::WritePlaceholderInfoFunction write_placeholder = nullptr;
    ProjfsApi::WriteFileDataFunction write_data = nullptr;
    ProjfsApi::FillDirEntryBufferFunction fill_entry = nullptr;
    ProjfsApi::FileNameMatchFunction file_name_match = nullptr;
    ProjfsApi::AllocateAlignedBufferFunction allocate_buffer = nullptr;
    ProjfsApi::FreeAlignedBufferFunction free_buffer = nullptr;
    ProjfsApi::GetVirtualizationInstanceInfoFunction instance_info = nullptr;

    [[nodiscard]] bool complete() const noexcept;
};

class ProjectedWorkspaceProvider final {
  public:
    ProjectedWorkspaceProvider() noexcept = default;
    ~ProjectedWorkspaceProvider() noexcept;
    ProjectedWorkspaceProvider(const ProjectedWorkspaceProvider&) = delete;
    ProjectedWorkspaceProvider& operator=(const ProjectedWorkspaceProvider&) = delete;
    ProjectedWorkspaceProvider(ProjectedWorkspaceProvider&&) = delete;
    ProjectedWorkspaceProvider& operator=(ProjectedWorkspaceProvider&&) = delete;

    static ProjectedWorkspaceStatus Start(
        const ProjectedWorkspaceSource& source,
        const std::filesystem::path& projection_root,
        ProjectedWorkspaceProvider& output) noexcept;
    static ProjectedWorkspaceStatus StartWithFunctions(
        const ProjectedWorkspaceSource& source,
        const std::filesystem::path& projection_root,
        const ProjfsFunctionTable& functions,
        ProjectedWorkspaceProvider& output) noexcept;

    void Stop() noexcept;

  private:
    struct EnumerationSession {
        std::wstring directory;
        std::wstring search_expression;
        std::vector<ProjectedWorkspaceEntry> entries;
        std::size_t next = 0;
        bool initialized = false;
    };

    static HRESULT CALLBACK StartEnumerationCallback(
        const PRJ_CALLBACK_DATA* callback_data,
        const GUID* enumeration_id) noexcept;
    static HRESULT CALLBACK EndEnumerationCallback(
        const PRJ_CALLBACK_DATA* callback_data,
        const GUID* enumeration_id) noexcept;
    static HRESULT CALLBACK GetEnumerationCallback(
        const PRJ_CALLBACK_DATA* callback_data,
        const GUID* enumeration_id,
        PCWSTR search_expression,
        PRJ_DIR_ENTRY_BUFFER_HANDLE buffer) noexcept;
    static HRESULT CALLBACK GetPlaceholderCallback(
        const PRJ_CALLBACK_DATA* callback_data) noexcept;
    static HRESULT CALLBACK GetFileDataCallback(
        const PRJ_CALLBACK_DATA* callback_data,
        UINT64 offset,
        UINT32 length) noexcept;
    static HRESULT CALLBACK QueryFileNameCallback(
        const PRJ_CALLBACK_DATA* callback_data) noexcept;

    HRESULT StartEnumeration(
        const PRJ_CALLBACK_DATA& callback_data,
        const GUID& enumeration_id) noexcept;
    HRESULT EndEnumeration(const GUID& enumeration_id) noexcept;
    HRESULT GetEnumeration(
        const PRJ_CALLBACK_DATA& callback_data,
        const GUID& enumeration_id,
        PCWSTR search_expression,
        PRJ_DIR_ENTRY_BUFFER_HANDLE buffer) noexcept;
    HRESULT GetPlaceholder(const PRJ_CALLBACK_DATA& callback_data) noexcept;
    HRESULT GetFileData(
        const PRJ_CALLBACK_DATA& callback_data,
        UINT64 offset,
        UINT32 length) noexcept;
    HRESULT QueryFileName(const PRJ_CALLBACK_DATA& callback_data) noexcept;

    static std::array<std::uint8_t, 16> EnumerationKey(
        const GUID& value) noexcept;
    static ProjectedWorkspaceProvider* FromCallback(
        const PRJ_CALLBACK_DATA* callback_data) noexcept;

    ProjectedWorkspaceSource source_;
    ProjfsFunctionTable functions_{};
    PRJ_CALLBACKS callbacks_{};
    PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT context_ = nullptr;
    std::unique_ptr<ProjfsApi> system_api_;
    std::mutex enumerations_mutex_;
    std::map<std::array<std::uint8_t, 16>, EnumerationSession> enumerations_;
};

ProjectedWorkspaceStatus MaterializeProjectedWorkspace(
    const std::filesystem::path& projection_root,
    const std::filesystem::path& destination_root,
    ProjectedWorkspaceLimits limits) noexcept;

}  // namespace bolt::common
