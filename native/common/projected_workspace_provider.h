#pragma once

#include <cstdint>
#include <filesystem>
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

}  // namespace bolt::common
