#include "common/projected_workspace_provider.h"

#include <algorithm>
#include <array>
#include <cwctype>
#include <limits>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace bolt::common {
namespace {

constexpr DWORD kShareAll =
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

class UniqueHandle final {
  public:
    UniqueHandle() noexcept = default;
    explicit UniqueHandle(const HANDLE value) noexcept : value_(value) {}
    ~UniqueHandle() noexcept {
        if (value_ != INVALID_HANDLE_VALUE) {
            CloseHandle(value_);
        }
    }
    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;
    UniqueHandle(UniqueHandle&& other) noexcept : value_(other.release()) {}
    UniqueHandle& operator=(UniqueHandle&& other) noexcept {
        if (this != &other) {
            UniqueHandle replacement{other.release()};
            std::swap(value_, replacement.value_);
        }
        return *this;
    }

    [[nodiscard]] HANDLE get() const noexcept { return value_; }
    [[nodiscard]] bool valid() const noexcept {
        return value_ != INVALID_HANDLE_VALUE;
    }

  private:
    HANDLE release() noexcept {
        const HANDLE value = value_;
        value_ = INVALID_HANDLE_VALUE;
        return value;
    }

    HANDLE value_ = INVALID_HANDLE_VALUE;
};

std::wstring PathKey(const std::filesystem::path& path) {
    std::wstring key = path.native();
    if (key.compare(0, 8, L"\\\\?\\UNC\\") == 0) {
        key = L"\\\\" + key.substr(8);
    } else if (key.compare(0, 4, L"\\\\?\\") == 0) {
        key.erase(0, 4);
    }
    std::replace(key.begin(), key.end(), L'/', L'\\');
    while (key.size() > 3 && key.back() == L'\\') {
        key.pop_back();
    }
    std::transform(
        key.begin(), key.end(), key.begin(),
        [](const wchar_t value) { return std::towlower(value); });
    return key;
}

bool IsSameOrDescendant(
    const std::wstring& root,
    const std::wstring& candidate) noexcept {
    return candidate == root ||
           (candidate.size() > root.size() &&
            candidate.compare(0, root.size(), root) == 0 &&
            candidate[root.size()] == L'\\');
}

bool FinalPathKey(const HANDLE handle, std::wstring& output) {
    std::wstring path(32'768, L'\0');
    const DWORD length = GetFinalPathNameByHandleW(
        handle, path.data(), static_cast<DWORD>(path.size()),
        FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (length == 0 || length >= path.size()) {
        return false;
    }
    path.resize(length);
    output = PathKey(path);
    return true;
}

ProjectedWorkspaceStatus OpenEntry(
    const std::filesystem::path& root,
    const std::filesystem::path& path,
    ProjectedWorkspaceEntry& output,
    UniqueHandle& handle) noexcept {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        return GetLastError() == ERROR_FILE_NOT_FOUND ||
                       GetLastError() == ERROR_PATH_NOT_FOUND
                   ? ProjectedWorkspaceStatus::kNotFound
                   : ProjectedWorkspaceStatus::kIo;
    }
    if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        return ProjectedWorkspaceStatus::kUnsupportedObject;
    }
    const bool is_directory = (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    handle = UniqueHandle{CreateFileW(
        path.c_str(), GENERIC_READ, kShareAll, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT |
            (is_directory ? FILE_FLAG_BACKUP_SEMANTICS : 0),
        nullptr)};
    if (!handle.valid()) {
        return ProjectedWorkspaceStatus::kIo;
    }
    BY_HANDLE_FILE_INFORMATION information{};
    std::wstring final_path;
    if (!GetFileInformationByHandle(handle.get(), &information) ||
        !FinalPathKey(handle.get(), final_path) ||
        !IsSameOrDescendant(PathKey(root), final_path) ||
        (information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        (!is_directory && information.nNumberOfLinks != 1)) {
        return ProjectedWorkspaceStatus::kUnsupportedObject;
    }
    output.name = path.filename().native();
    output.is_directory = is_directory;
    output.size =
        (static_cast<std::uint64_t>(information.nFileSizeHigh) << 32) |
        information.nFileSizeLow;
    output.attributes = information.dwFileAttributes;
    const auto ticks = [](const FILETIME value) {
        return static_cast<std::int64_t>(
            (static_cast<std::uint64_t>(value.dwHighDateTime) << 32) |
            value.dwLowDateTime);
    };
    output.creation_time = ticks(information.ftCreationTime);
    output.last_access_time = ticks(information.ftLastAccessTime);
    output.last_write_time = ticks(information.ftLastWriteTime);
    output.change_time = output.last_write_time;
    return ProjectedWorkspaceStatus::kSuccess;
}

bool SafeRelativePath(const std::wstring_view relative) noexcept {
    if (relative.find(L':') != std::wstring_view::npos ||
        relative.find(L'\0') != std::wstring_view::npos) {
        return false;
    }
    const std::filesystem::path path(relative);
    if (path.is_absolute() || path.has_root_name() || path.has_root_directory()) {
        return false;
    }
    return std::all_of(
        path.begin(), path.end(), [](const auto& component) {
            return component != L"." && component != L".." &&
                   !component.empty();
        });
}

ProjectedWorkspaceStatus Resolve(
    const std::filesystem::path& root,
    const std::wstring_view relative,
    std::filesystem::path& output) noexcept {
    if (!SafeRelativePath(relative)) {
        return ProjectedWorkspaceStatus::kInvalidPath;
    }
    try {
        output = relative.empty() ? root : root / std::filesystem::path(relative);
    } catch (...) {
        return ProjectedWorkspaceStatus::kInvalidPath;
    }
    return ProjectedWorkspaceStatus::kSuccess;
}

ProjectedWorkspaceStatus ValidateTree(
    const std::filesystem::path& root,
    const ProjectedWorkspaceLimits limits) noexcept {
    std::uint32_t item_count = 0;
    std::uint64_t byte_count = 0;
    std::vector<std::filesystem::path> pending{root};
    try {
        while (!pending.empty()) {
            const auto directory = std::move(pending.back());
            pending.pop_back();
            for (const auto& child :
                 std::filesystem::directory_iterator(directory)) {
                if (item_count == limits.maximum_items) {
                    return ProjectedWorkspaceStatus::kQuotaExceeded;
                }
                ++item_count;
                ProjectedWorkspaceEntry entry{};
                UniqueHandle handle;
                const auto status = OpenEntry(root, child.path(), entry, handle);
                if (status != ProjectedWorkspaceStatus::kSuccess) {
                    return status;
                }
                if (entry.is_directory) {
                    pending.push_back(child.path());
                } else if (entry.size >
                           limits.maximum_bytes - byte_count) {
                    return ProjectedWorkspaceStatus::kQuotaExceeded;
                } else {
                    byte_count += entry.size;
                }
            }
        }
    } catch (...) {
        return ProjectedWorkspaceStatus::kIo;
    }
    return ProjectedWorkspaceStatus::kSuccess;
}

}  // namespace

ProjectedWorkspaceStatus ProjectedWorkspaceSource::Open(
    const std::filesystem::path& root,
    const ProjectedWorkspaceLimits limits,
    ProjectedWorkspaceSource& output) noexcept {
    if (!root.is_absolute() || limits.maximum_items == 0 ||
        limits.maximum_bytes == 0) {
        return ProjectedWorkspaceStatus::kInvalidRoot;
    }
    std::filesystem::path canonical;
    try {
        canonical = std::filesystem::canonical(root);
    } catch (...) {
        return ProjectedWorkspaceStatus::kInvalidRoot;
    }
    ProjectedWorkspaceEntry root_entry{};
    UniqueHandle root_handle;
    const auto root_status = OpenEntry(canonical, canonical, root_entry, root_handle);
    if (root_status != ProjectedWorkspaceStatus::kSuccess ||
        !root_entry.is_directory) {
        return root_status == ProjectedWorkspaceStatus::kSuccess
                   ? ProjectedWorkspaceStatus::kInvalidRoot
                   : root_status;
    }
    const auto validated = ValidateTree(canonical, limits);
    if (validated != ProjectedWorkspaceStatus::kSuccess) {
        return validated;
    }
    output.root_ = std::move(canonical);
    output.limits_ = limits;
    return ProjectedWorkspaceStatus::kSuccess;
}

ProjectedWorkspaceStatus ProjectedWorkspaceSource::Lookup(
    const std::wstring_view relative_path,
    ProjectedWorkspaceEntry& output) const noexcept {
    std::filesystem::path path;
    const auto resolved = Resolve(root_, relative_path, path);
    if (resolved != ProjectedWorkspaceStatus::kSuccess) {
        return resolved;
    }
    UniqueHandle handle;
    return OpenEntry(root_, path, output, handle);
}

ProjectedWorkspaceStatus ProjectedWorkspaceSource::Enumerate(
    const std::wstring_view relative_directory,
    std::vector<ProjectedWorkspaceEntry>& output) const noexcept {
    output.clear();
    std::filesystem::path directory;
    const auto resolved = Resolve(root_, relative_directory, directory);
    if (resolved != ProjectedWorkspaceStatus::kSuccess) {
        return resolved;
    }
    ProjectedWorkspaceEntry directory_entry{};
    UniqueHandle directory_handle;
    const auto opened =
        OpenEntry(root_, directory, directory_entry, directory_handle);
    if (opened != ProjectedWorkspaceStatus::kSuccess) {
        return opened;
    }
    if (!directory_entry.is_directory) {
        return ProjectedWorkspaceStatus::kInvalidPath;
    }
    try {
        for (const auto& child :
             std::filesystem::directory_iterator(directory)) {
            if (output.size() == limits_.maximum_items) {
                return ProjectedWorkspaceStatus::kQuotaExceeded;
            }
            ProjectedWorkspaceEntry entry{};
            UniqueHandle handle;
            const auto status = OpenEntry(root_, child.path(), entry, handle);
            if (status != ProjectedWorkspaceStatus::kSuccess) {
                return status;
            }
            output.push_back(std::move(entry));
        }
        std::sort(
            output.begin(), output.end(),
            [](const auto& left, const auto& right) {
                const int insensitive = CompareStringOrdinal(
                    left.name.c_str(), static_cast<int>(left.name.size()),
                    right.name.c_str(), static_cast<int>(right.name.size()),
                    TRUE);
                if (insensitive != CSTR_EQUAL) {
                    return insensitive == CSTR_LESS_THAN;
                }
                return left.name < right.name;
            });
    } catch (...) {
        output.clear();
        return ProjectedWorkspaceStatus::kIo;
    }
    return ProjectedWorkspaceStatus::kSuccess;
}

ProjectedWorkspaceStatus ProjectedWorkspaceSource::Read(
    const std::wstring_view relative_path,
    const std::uint64_t offset,
    const std::uint32_t length,
    std::vector<std::uint8_t>& output) const noexcept {
    output.clear();
    std::filesystem::path path;
    const auto resolved = Resolve(root_, relative_path, path);
    if (resolved != ProjectedWorkspaceStatus::kSuccess) {
        return resolved;
    }
    ProjectedWorkspaceEntry entry{};
    UniqueHandle handle;
    const auto opened = OpenEntry(root_, path, entry, handle);
    if (opened != ProjectedWorkspaceStatus::kSuccess) {
        return opened;
    }
    if (entry.is_directory || offset > entry.size ||
        length > entry.size - offset) {
        return ProjectedWorkspaceStatus::kInvalidRange;
    }
    try {
        output.resize(length);
    } catch (...) {
        return ProjectedWorkspaceStatus::kIo;
    }
    LARGE_INTEGER position{};
    position.QuadPart = static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(handle.get(), position, nullptr, FILE_BEGIN)) {
        output.clear();
        return ProjectedWorkspaceStatus::kIo;
    }
    std::size_t total = 0;
    while (total < output.size()) {
        DWORD read = 0;
        if (!ReadFile(
                handle.get(), output.data() + total,
                static_cast<DWORD>(output.size() - total), &read, nullptr) ||
            read == 0) {
            output.clear();
            return ProjectedWorkspaceStatus::kIo;
        }
        total += read;
    }
    return ProjectedWorkspaceStatus::kSuccess;
}

}  // namespace bolt::common
