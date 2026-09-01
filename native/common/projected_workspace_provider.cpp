#include "common/projected_workspace_provider.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <cwctype>
#include <limits>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>

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
    try {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        const DWORD error = GetLastError();
        return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND
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
    if (output.size >
        static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)())) {
        return ProjectedWorkspaceStatus::kUnsupportedObject;
    }
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
    } catch (...) {
        return ProjectedWorkspaceStatus::kIo;
    }
}

bool SafeRelativePath(const std::wstring_view relative) noexcept {
    if (relative.find(L':') != std::wstring_view::npos ||
        relative.find(L'\0') != std::wstring_view::npos) {
        return false;
    }
    try {
        const std::filesystem::path path(relative);
        if (path.is_absolute() || path.has_root_name() ||
            path.has_root_directory()) {
            return false;
        }
        return std::all_of(
            path.begin(), path.end(), [](const auto& component) {
                return component != L"." && component != L".." &&
                       !component.empty();
            });
    } catch (...) {
        return false;
    }
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
        length > entry.size - offset ||
        offset > static_cast<std::uint64_t>(
                     (std::numeric_limits<LONGLONG>::max)())) {
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

namespace {

HRESULT StatusToHresult(const ProjectedWorkspaceStatus status) noexcept {
    switch (status) {
        case ProjectedWorkspaceStatus::kSuccess:
            return S_OK;
        case ProjectedWorkspaceStatus::kNotFound:
            return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
        case ProjectedWorkspaceStatus::kInvalidRoot:
        case ProjectedWorkspaceStatus::kInvalidPath:
        case ProjectedWorkspaceStatus::kUnsupportedObject:
            return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
        case ProjectedWorkspaceStatus::kQuotaExceeded:
            return HRESULT_FROM_WIN32(ERROR_DISK_FULL);
        case ProjectedWorkspaceStatus::kInvalidRange:
            return HRESULT_FROM_WIN32(ERROR_HANDLE_EOF);
        case ProjectedWorkspaceStatus::kIo:
        case ProjectedWorkspaceStatus::kUnavailable:
            return E_FAIL;
    }
    return E_UNEXPECTED;
}

PRJ_FILE_BASIC_INFO ToBasicInfo(
    const ProjectedWorkspaceEntry& entry) noexcept {
    PRJ_FILE_BASIC_INFO information{};
    information.IsDirectory = entry.is_directory ? TRUE : FALSE;
    information.FileSize = static_cast<INT64>(entry.size);
    information.CreationTime.QuadPart = entry.creation_time;
    information.LastAccessTime.QuadPart = entry.last_access_time;
    information.LastWriteTime.QuadPart = entry.last_write_time;
    information.ChangeTime.QuadPart = entry.change_time;
    information.FileAttributes = entry.attributes;
    return information;
}

}  // namespace

bool ProjfsFunctionTable::complete() const noexcept {
    return mark_directory != nullptr && start != nullptr && stop != nullptr &&
           write_placeholder != nullptr && write_data != nullptr &&
           fill_entry != nullptr && file_name_match != nullptr &&
           file_name_compare != nullptr &&
           allocate_buffer != nullptr && free_buffer != nullptr &&
           instance_info != nullptr;
}

ProjectedWorkspaceProvider::~ProjectedWorkspaceProvider() noexcept {
    Stop();
}

ProjectedWorkspaceStatus ProjectedWorkspaceProvider::Start(
    const ProjectedWorkspaceSource& source,
    const std::filesystem::path& projection_root,
    ProjectedWorkspaceProvider& output) noexcept {
    std::unique_ptr<ProjfsApi> api;
    try {
        api = std::make_unique<ProjfsApi>();
    } catch (...) {
        return ProjectedWorkspaceStatus::kIo;
    }
    if (ProjfsApi::Load(*api) != ProjfsStatus::kSuccess) {
        return ProjectedWorkspaceStatus::kUnavailable;
    }
    const ProjfsFunctionTable functions{
        api->mark_directory_as_placeholder(),
        api->start_virtualizing(),
        api->stop_virtualizing(),
        api->write_placeholder_info(),
        api->write_file_data(),
        api->fill_dir_entry_buffer(),
        api->file_name_match(),
        api->file_name_compare(),
        api->allocate_aligned_buffer(),
        api->free_aligned_buffer(),
        api->get_virtualization_instance_info()};
    const auto started =
        StartWithFunctions(source, projection_root, functions, output);
    if (started == ProjectedWorkspaceStatus::kSuccess) {
        output.system_api_ = std::move(api);
    }
    return started;
}

ProjectedWorkspaceStatus ProjectedWorkspaceProvider::StartWithFunctions(
    const ProjectedWorkspaceSource& source,
    const std::filesystem::path& projection_root,
    const ProjfsFunctionTable& functions,
    ProjectedWorkspaceProvider& output) noexcept {
    output.Stop();
    if (!functions.complete() || source.root().empty() ||
        !projection_root.is_absolute()) {
        return ProjectedWorkspaceStatus::kInvalidRoot;
    }
    try {
        if (!std::filesystem::is_directory(projection_root) ||
            !std::filesystem::is_empty(projection_root)) {
            return ProjectedWorkspaceStatus::kInvalidRoot;
        }
    } catch (...) {
        return ProjectedWorkspaceStatus::kInvalidRoot;
    }
    const DWORD attributes = GetFileAttributesW(projection_root.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        return ProjectedWorkspaceStatus::kUnsupportedObject;
    }
    try {
        const auto source_key = PathKey(source.root());
        const auto projection_key = PathKey(projection_root);
        if (IsSameOrDescendant(source_key, projection_key) ||
            IsSameOrDescendant(projection_key, source_key)) {
            return ProjectedWorkspaceStatus::kInvalidRoot;
        }
    } catch (...) {
        return ProjectedWorkspaceStatus::kInvalidRoot;
    }
    GUID instance_id{};
    if (FAILED(CoCreateGuid(&instance_id)) ||
        FAILED(functions.mark_directory(
            projection_root.c_str(), nullptr, nullptr, &instance_id))) {
        return ProjectedWorkspaceStatus::kIo;
    }
    output.source_ = source;
    output.functions_ = functions;
    output.callbacks_ = PRJ_CALLBACKS{};
    output.callbacks_.StartDirectoryEnumerationCallback =
        StartEnumerationCallback;
    output.callbacks_.EndDirectoryEnumerationCallback = EndEnumerationCallback;
    output.callbacks_.GetDirectoryEnumerationCallback = GetEnumerationCallback;
    output.callbacks_.GetPlaceholderInfoCallback = GetPlaceholderCallback;
    output.callbacks_.GetFileDataCallback = GetFileDataCallback;
    output.callbacks_.QueryFileNameCallback = QueryFileNameCallback;
    PRJ_STARTVIRTUALIZING_OPTIONS options{};
    options.Flags = PRJ_FLAG_NONE;
    options.ConcurrentThreadCount = 2;
    options.PoolThreadCount = 4;
    if (FAILED(functions.start(
            projection_root.c_str(), &output.callbacks_, &output, &options,
            &output.context_)) ||
        output.context_ == nullptr) {
        output.context_ = nullptr;
        output.functions_ = ProjfsFunctionTable{};
        return ProjectedWorkspaceStatus::kIo;
    }
    return ProjectedWorkspaceStatus::kSuccess;
}

void ProjectedWorkspaceProvider::Stop() noexcept {
    if (context_ != nullptr && functions_.stop != nullptr) {
        functions_.stop(context_);
    }
    context_ = nullptr;
    {
        std::lock_guard<std::mutex> lock(enumerations_mutex_);
        enumerations_.clear();
    }
    callbacks_ = PRJ_CALLBACKS{};
    functions_ = ProjfsFunctionTable{};
    system_api_.reset();
}

std::array<std::uint8_t, 16> ProjectedWorkspaceProvider::EnumerationKey(
    const GUID& value) noexcept {
    std::array<std::uint8_t, 16> key{};
    static_assert(sizeof(value) == key.size());
    std::memcpy(key.data(), &value, key.size());
    return key;
}

ProjectedWorkspaceProvider* ProjectedWorkspaceProvider::FromCallback(
    const PRJ_CALLBACK_DATA* const callback_data) noexcept {
    if (callback_data == nullptr ||
        callback_data->Size < sizeof(PRJ_CALLBACK_DATA) ||
        callback_data->InstanceContext == nullptr) {
        return nullptr;
    }
    return static_cast<ProjectedWorkspaceProvider*>(
        callback_data->InstanceContext);
}

HRESULT CALLBACK ProjectedWorkspaceProvider::StartEnumerationCallback(
    const PRJ_CALLBACK_DATA* const callback_data,
    const GUID* const enumeration_id) noexcept {
    auto* const provider = FromCallback(callback_data);
    return provider == nullptr || enumeration_id == nullptr
               ? E_INVALIDARG
               : provider->StartEnumeration(*callback_data, *enumeration_id);
}

HRESULT CALLBACK ProjectedWorkspaceProvider::EndEnumerationCallback(
    const PRJ_CALLBACK_DATA* const callback_data,
    const GUID* const enumeration_id) noexcept {
    auto* const provider = FromCallback(callback_data);
    return provider == nullptr || enumeration_id == nullptr
               ? E_INVALIDARG
               : provider->EndEnumeration(*enumeration_id);
}

HRESULT CALLBACK ProjectedWorkspaceProvider::GetEnumerationCallback(
    const PRJ_CALLBACK_DATA* const callback_data,
    const GUID* const enumeration_id,
    PCWSTR const search_expression,
    const PRJ_DIR_ENTRY_BUFFER_HANDLE buffer) noexcept {
    auto* const provider = FromCallback(callback_data);
    return provider == nullptr || enumeration_id == nullptr || buffer == nullptr
               ? E_INVALIDARG
               : provider->GetEnumeration(
                     *callback_data, *enumeration_id, search_expression,
                     buffer);
}

HRESULT CALLBACK ProjectedWorkspaceProvider::GetPlaceholderCallback(
    const PRJ_CALLBACK_DATA* const callback_data) noexcept {
    auto* const provider = FromCallback(callback_data);
    return provider == nullptr ? E_INVALIDARG
                               : provider->GetPlaceholder(*callback_data);
}

HRESULT CALLBACK ProjectedWorkspaceProvider::GetFileDataCallback(
    const PRJ_CALLBACK_DATA* const callback_data,
    const UINT64 offset,
    const UINT32 length) noexcept {
    auto* const provider = FromCallback(callback_data);
    return provider == nullptr
               ? E_INVALIDARG
               : provider->GetFileData(*callback_data, offset, length);
}

HRESULT CALLBACK ProjectedWorkspaceProvider::QueryFileNameCallback(
    const PRJ_CALLBACK_DATA* const callback_data) noexcept {
    auto* const provider = FromCallback(callback_data);
    return provider == nullptr ? E_INVALIDARG
                               : provider->QueryFileName(*callback_data);
}

HRESULT ProjectedWorkspaceProvider::StartEnumeration(
    const PRJ_CALLBACK_DATA& callback_data,
    const GUID& enumeration_id) noexcept {
    if (callback_data.FilePathName == nullptr) {
        return E_INVALIDARG;
    }
    try {
        std::lock_guard<std::mutex> lock(enumerations_mutex_);
        const auto [_, inserted] = enumerations_.emplace(
            EnumerationKey(enumeration_id),
            EnumerationSession{callback_data.FilePathName});
        return inserted ? S_OK : E_INVALIDARG;
    } catch (...) {
        return E_OUTOFMEMORY;
    }
}

HRESULT ProjectedWorkspaceProvider::EndEnumeration(
    const GUID& enumeration_id) noexcept {
    std::lock_guard<std::mutex> lock(enumerations_mutex_);
    return enumerations_.erase(EnumerationKey(enumeration_id)) == 1
               ? S_OK
               : E_INVALIDARG;
}

HRESULT ProjectedWorkspaceProvider::GetEnumeration(
    const PRJ_CALLBACK_DATA& callback_data,
    const GUID& enumeration_id,
    PCWSTR const search_expression,
    const PRJ_DIR_ENTRY_BUFFER_HANDLE buffer) noexcept {
    try {
        std::lock_guard<std::mutex> lock(enumerations_mutex_);
        const auto found = enumerations_.find(EnumerationKey(enumeration_id));
        if (found == enumerations_.end()) {
            return E_INVALIDARG;
        }
        auto& session = found->second;
        if ((callback_data.Flags & PRJ_CB_DATA_FLAG_ENUM_RESTART_SCAN) != 0) {
            session.initialized = false;
            session.next = 0;
        }
        if (!session.initialized) {
            session.entries.clear();
            session.search_expression =
                search_expression == nullptr ? L"*" : search_expression;
            const auto status =
                source_.Enumerate(session.directory, session.entries);
            if (status != ProjectedWorkspaceStatus::kSuccess) {
                return StatusToHresult(status);
            }
            session.entries.erase(
                std::remove_if(
                    session.entries.begin(), session.entries.end(),
                    [this, &session](const auto& entry) {
                        return functions_.file_name_match(
                                   entry.name.c_str(),
                                   session.search_expression.c_str()) == FALSE;
                    }),
                session.entries.end());
            std::sort(
                session.entries.begin(), session.entries.end(),
                [this](const auto& left, const auto& right) {
                    return functions_.file_name_compare(
                               left.name.c_str(), right.name.c_str()) < 0;
                });
            session.next = 0;
            session.initialized = true;
        }
        while (session.next < session.entries.size()) {
            auto information = ToBasicInfo(session.entries[session.next]);
            const HRESULT filled = functions_.fill_entry(
                session.entries[session.next].name.c_str(), &information,
                buffer);
            if (filled == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER)) {
                break;
            }
            if (FAILED(filled)) {
                return filled;
            }
            ++session.next;
            if ((callback_data.Flags &
                 PRJ_CB_DATA_FLAG_ENUM_RETURN_SINGLE_ENTRY) != 0) {
                break;
            }
        }
        return S_OK;
    } catch (...) {
        return E_OUTOFMEMORY;
    }
}

HRESULT ProjectedWorkspaceProvider::GetPlaceholder(
    const PRJ_CALLBACK_DATA& callback_data) noexcept {
    if (callback_data.FilePathName == nullptr) {
        return E_INVALIDARG;
    }
    ProjectedWorkspaceEntry entry{};
    const auto status = source_.Lookup(callback_data.FilePathName, entry);
    if (status != ProjectedWorkspaceStatus::kSuccess) {
        return StatusToHresult(status);
    }
    PRJ_PLACEHOLDER_INFO information{};
    information.FileBasicInfo = ToBasicInfo(entry);
    return functions_.write_placeholder(
        callback_data.NamespaceVirtualizationContext,
        callback_data.FilePathName, &information,
        FIELD_OFFSET(PRJ_PLACEHOLDER_INFO, VariableData));
}

HRESULT ProjectedWorkspaceProvider::GetFileData(
    const PRJ_CALLBACK_DATA& callback_data,
    const UINT64 offset,
    const UINT32 length) noexcept {
    if (callback_data.FilePathName == nullptr || length == 0) {
        return E_INVALIDARG;
    }
    std::vector<std::uint8_t> data;
    const auto status =
        source_.Read(callback_data.FilePathName, offset, length, data);
    if (status != ProjectedWorkspaceStatus::kSuccess) {
        return StatusToHresult(status);
    }
    void* const buffer = functions_.allocate_buffer(
        callback_data.NamespaceVirtualizationContext, data.size());
    if (buffer == nullptr) {
        return E_OUTOFMEMORY;
    }
    std::memcpy(buffer, data.data(), data.size());
    const HRESULT written = functions_.write_data(
        callback_data.NamespaceVirtualizationContext,
        &callback_data.DataStreamId, buffer, offset, length);
    functions_.free_buffer(buffer);
    return written;
}

HRESULT ProjectedWorkspaceProvider::QueryFileName(
    const PRJ_CALLBACK_DATA& callback_data) noexcept {
    if (callback_data.FilePathName == nullptr) {
        return E_INVALIDARG;
    }
    ProjectedWorkspaceEntry entry{};
    return StatusToHresult(
        source_.Lookup(callback_data.FilePathName, entry));
}

namespace {

ProjectedWorkspaceStatus ProjectionEntryData(
    const std::filesystem::path& path,
    WIN32_FIND_DATAW& output,
    bool& skip) noexcept {
    skip = false;
    const HANDLE find = FindFirstFileW(path.c_str(), &output);
    if (find == INVALID_HANDLE_VALUE) {
        return ProjectedWorkspaceStatus::kIo;
    }
    FindClose(find);
    if ((output.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0) {
        return ProjectedWorkspaceStatus::kSuccess;
    }
    if (output.dwReserved0 == IO_REPARSE_TAG_PROJFS_TOMBSTONE) {
        skip = true;
        return ProjectedWorkspaceStatus::kSuccess;
    }
    return output.dwReserved0 == IO_REPARSE_TAG_PROJFS
               ? ProjectedWorkspaceStatus::kSuccess
               : ProjectedWorkspaceStatus::kUnsupportedObject;
}

bool HasOnlyPrimaryDataStream(const std::filesystem::path& path) noexcept {
    WIN32_FIND_STREAM_DATA stream{};
    const HANDLE find = FindFirstStreamW(
        path.c_str(), FindStreamInfoStandard, &stream, 0);
    if (find == INVALID_HANDLE_VALUE) {
        return GetLastError() == ERROR_HANDLE_EOF;
    }
    const bool primary = std::wcscmp(stream.cStreamName, L"::$DATA") == 0;
    const bool has_another = FindNextStreamW(find, &stream) != FALSE;
    const DWORD final_error = GetLastError();
    FindClose(find);
    return primary && !has_another && final_error == ERROR_HANDLE_EOF;
}

ProjectedWorkspaceStatus CopyMaterializedFile(
    const std::filesystem::path& projection_root,
    const std::filesystem::path& source,
    const std::filesystem::path& destination,
    const WIN32_FIND_DATAW& find_data,
    const std::uint64_t maximum_bytes,
    std::uint64_t& copied_bytes) noexcept {
    UniqueHandle input{CreateFileW(
        source.c_str(), GENERIC_READ | FILE_READ_ATTRIBUTES, kShareAll,
        nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr)};
    if (!input.valid() || !HasOnlyPrimaryDataStream(source)) {
        return ProjectedWorkspaceStatus::kUnsupportedObject;
    }
    BY_HANDLE_FILE_INFORMATION information{};
    std::wstring final_path;
    const bool projected_placeholder =
        (find_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 &&
        find_data.dwReserved0 == IO_REPARSE_TAG_PROJFS;
    if (!GetFileInformationByHandle(input.get(), &information) ||
        information.nNumberOfLinks != 1 ||
        ((information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 &&
         !projected_placeholder) ||
        !FinalPathKey(input.get(), final_path) ||
        !IsSameOrDescendant(PathKey(projection_root), final_path)) {
        return ProjectedWorkspaceStatus::kUnsupportedObject;
    }
    const std::uint64_t size =
        (static_cast<std::uint64_t>(information.nFileSizeHigh) << 32) |
        information.nFileSizeLow;
    if (size > maximum_bytes - copied_bytes) {
        return ProjectedWorkspaceStatus::kQuotaExceeded;
    }
    UniqueHandle output{CreateFileW(
        destination.c_str(), GENERIC_WRITE | FILE_WRITE_ATTRIBUTES, 0,
        nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr)};
    if (!output.valid()) {
        return ProjectedWorkspaceStatus::kIo;
    }
    std::array<std::uint8_t, 64 * 1'024> buffer{};
    std::uint64_t total = 0;
    while (total < size) {
        const DWORD requested = static_cast<DWORD>((std::min)(
            static_cast<std::uint64_t>(buffer.size()), size - total));
        DWORD read = 0;
        DWORD written = 0;
        if (!ReadFile(input.get(), buffer.data(), requested, &read, nullptr) ||
            read == 0 ||
            !WriteFile(
                output.get(), buffer.data(), read, &written, nullptr) ||
            written != read) {
            return ProjectedWorkspaceStatus::kIo;
        }
        total += read;
    }
    if (!SetFileTime(
            output.get(), &find_data.ftCreationTime,
            &find_data.ftLastAccessTime, &find_data.ftLastWriteTime)) {
        return ProjectedWorkspaceStatus::kIo;
    }
    copied_bytes += size;
    return ProjectedWorkspaceStatus::kSuccess;
}

void RemoveMaterialization(const std::filesystem::path& root) noexcept {
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
}

DWORD MaterializedAttributes(const DWORD source) noexcept {
    const DWORD retained = source &
        (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN |
         FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ARCHIVE |
         FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
    return retained == 0 ? FILE_ATTRIBUTE_NORMAL : retained;
}

}  // namespace

ProjectedWorkspaceStatus MaterializeProjectedWorkspace(
    const std::filesystem::path& projection_root,
    const std::filesystem::path& destination_root,
    const ProjectedWorkspaceLimits limits) noexcept {
    std::error_code destination_error;
    const bool destination_exists =
        std::filesystem::exists(destination_root, destination_error);
    if (!projection_root.is_absolute() || !destination_root.is_absolute() ||
        limits.maximum_items == 0 || limits.maximum_bytes == 0 ||
        destination_root.empty() || destination_error || destination_exists) {
        return ProjectedWorkspaceStatus::kInvalidRoot;
    }
    try {
        const auto projection_key = PathKey(projection_root);
        const auto destination_key = PathKey(destination_root);
        if (IsSameOrDescendant(projection_key, destination_key) ||
            IsSameOrDescendant(destination_key, projection_key)) {
            return ProjectedWorkspaceStatus::kInvalidRoot;
        }
        if (!std::filesystem::is_directory(projection_root) ||
            !std::filesystem::create_directory(destination_root)) {
            return ProjectedWorkspaceStatus::kInvalidRoot;
        }
        struct PendingDirectory {
            std::filesystem::path source;
            std::filesystem::path destination;
        };
        std::vector<PendingDirectory> pending{
            {projection_root, destination_root}};
        std::vector<std::pair<std::filesystem::path, WIN32_FIND_DATAW>>
            directory_metadata;
        std::uint32_t item_count = 0;
        std::uint64_t copied_bytes = 0;
        while (!pending.empty()) {
            const auto current = std::move(pending.back());
            pending.pop_back();
            for (const auto& child :
                 std::filesystem::directory_iterator(current.source)) {
                if (item_count == limits.maximum_items) {
                    RemoveMaterialization(destination_root);
                    return ProjectedWorkspaceStatus::kQuotaExceeded;
                }
                ++item_count;
                WIN32_FIND_DATAW data{};
                bool skip = false;
                const auto inspected =
                    ProjectionEntryData(child.path(), data, skip);
                if (inspected != ProjectedWorkspaceStatus::kSuccess) {
                    RemoveMaterialization(destination_root);
                    return inspected;
                }
                if (skip) {
                    continue;
                }
                const auto destination =
                    current.destination / child.path().filename();
                if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
                    if (!CreateDirectoryW(destination.c_str(), nullptr)) {
                        RemoveMaterialization(destination_root);
                        return ProjectedWorkspaceStatus::kIo;
                    }
                    pending.push_back({child.path(), destination});
                    directory_metadata.emplace_back(destination, data);
                } else {
                    const auto copied = CopyMaterializedFile(
                        projection_root, child.path(), destination, data,
                        limits.maximum_bytes, copied_bytes);
                    if (copied != ProjectedWorkspaceStatus::kSuccess ||
                        !SetFileAttributesW(
                            destination.c_str(),
                            MaterializedAttributes(
                                data.dwFileAttributes))) {
                        RemoveMaterialization(destination_root);
                        return copied == ProjectedWorkspaceStatus::kSuccess
                                   ? ProjectedWorkspaceStatus::kIo
                                   : copied;
                    }
                }
            }
        }
        for (auto current = directory_metadata.rbegin();
             current != directory_metadata.rend(); ++current) {
            UniqueHandle directory{CreateFileW(
                current->first.c_str(), FILE_WRITE_ATTRIBUTES, 0, nullptr,
                OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr)};
            if (!directory.valid() ||
                !SetFileTime(
                    directory.get(), &current->second.ftCreationTime,
                    &current->second.ftLastAccessTime,
                    &current->second.ftLastWriteTime) ||
                !SetFileAttributesW(
                    current->first.c_str(),
                    MaterializedAttributes(
                        current->second.dwFileAttributes))) {
                RemoveMaterialization(destination_root);
                return ProjectedWorkspaceStatus::kIo;
            }
        }
        return ProjectedWorkspaceStatus::kSuccess;
    } catch (...) {
        RemoveMaterialization(destination_root);
        return ProjectedWorkspaceStatus::kIo;
    }
}

}  // namespace bolt::common
