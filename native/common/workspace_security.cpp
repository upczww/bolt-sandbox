#include "common/workspace_security.h"

#include <limits>
#include <memory>
#include <atomic>
#include <string>
#include <utility>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

namespace bolt::common {
namespace {

constexpr SECURITY_INFORMATION kAuthorizationInformation =
    OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
    DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
constexpr DWORD kReparsePoint = FILE_ATTRIBUTE_REPARSE_POINT;

struct LocalFreeDeleter final {
    void operator()(void* const value) const noexcept {
        if (value != nullptr) {
            LocalFree(value);
        }
    }
};

using LocalAllocation = std::unique_ptr<void, LocalFreeDeleter>;

struct SecurityDescriptorView final {
    LocalAllocation allocation;
    PSID owner = nullptr;
    PSID group = nullptr;
    PACL dacl = nullptr;
    PACL label = nullptr;
    SECURITY_DESCRIPTOR_CONTROL control = 0;
};

bool IsSupportedPath(const std::filesystem::path& path) noexcept {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES &&
           (attributes & kReparsePoint) == 0;
}

WorkspaceSecurityStatus ReadDescriptor(
    const std::filesystem::path& path,
    SecurityDescriptorView& output) noexcept {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    PSID owner = nullptr;
    PSID group = nullptr;
    PACL dacl = nullptr;
    PACL label = nullptr;
    const DWORD status = GetNamedSecurityInfoW(
        path.c_str(), SE_FILE_OBJECT, kAuthorizationInformation, &owner,
        &group, &dacl, &label, &descriptor);
    if (status != ERROR_SUCCESS || descriptor == nullptr) {
        return WorkspaceSecurityStatus::kSecurityQueryFailed;
    }
    LocalAllocation allocation{descriptor};
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    if (!GetSecurityDescriptorControl(descriptor, &control, &revision)) {
        return WorkspaceSecurityStatus::kSecurityQueryFailed;
    }
    output = SecurityDescriptorView{
        std::move(allocation), owner, group, dacl, label, control};
    return WorkspaceSecurityStatus::kSuccess;
}

WorkspaceSecurityStatus DescribeDescriptor(
    const std::filesystem::path& path,
    std::wstring& output) noexcept {
    SecurityDescriptorView descriptor;
    const auto read = ReadDescriptor(path, descriptor);
    if (read != WorkspaceSecurityStatus::kSuccess) {
        return read;
    }
    LPWSTR encoded = nullptr;
    ULONG encoded_length = 0;
    if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor.allocation.get(), SDDL_REVISION_1,
            kAuthorizationInformation, &encoded, &encoded_length) ||
        encoded == nullptr) {
        return WorkspaceSecurityStatus::kSecurityQueryFailed;
    }
    LocalAllocation encoded_owner{encoded};
    try {
        output.assign(encoded, encoded_length);
    } catch (...) {
        return WorkspaceSecurityStatus::kSecurityQueryFailed;
    }
    return WorkspaceSecurityStatus::kSuccess;
}

WorkspaceSecurityStatus ApplyDescriptor(
    const std::filesystem::path& source,
    const std::filesystem::path& destination) noexcept {
    SecurityDescriptorView descriptor;
    const auto read = ReadDescriptor(source, descriptor);
    if (read != WorkspaceSecurityStatus::kSuccess) {
        return read;
    }
    SecurityDescriptorView destination_descriptor;
    const auto destination_read =
        ReadDescriptor(destination, destination_descriptor);
    if (destination_read != WorkspaceSecurityStatus::kSuccess) {
        return destination_read;
    }
    const bool owners_match =
        descriptor.owner == nullptr
            ? destination_descriptor.owner == nullptr
            : destination_descriptor.owner != nullptr &&
                  EqualSid(descriptor.owner, destination_descriptor.owner);
    const bool groups_match =
        descriptor.group == nullptr
            ? destination_descriptor.group == nullptr
            : destination_descriptor.group != nullptr &&
                  EqualSid(descriptor.group, destination_descriptor.group);
    if (!owners_match || !groups_match) {
        return WorkspaceSecurityStatus::kSecurityApplyFailed;
    }
    SECURITY_INFORMATION information = DACL_SECURITY_INFORMATION |
        ((descriptor.control & SE_DACL_PROTECTED) != 0
             ? PROTECTED_DACL_SECURITY_INFORMATION
             : UNPROTECTED_DACL_SECURITY_INFORMATION);
    std::wstring mutable_destination = destination.native();
    if (SetNamedSecurityInfoW(
            mutable_destination.data(), SE_FILE_OBJECT, information, nullptr,
            nullptr, descriptor.dacl, nullptr) != ERROR_SUCCESS) {
        return WorkspaceSecurityStatus::kSecurityApplyFailed;
    }
    std::wstring source_description;
    std::wstring destination_description;
    auto described = DescribeDescriptor(source, source_description);
    if (described != WorkspaceSecurityStatus::kSuccess) {
        return described;
    }
    described = DescribeDescriptor(destination, destination_description);
    if (described != WorkspaceSecurityStatus::kSuccess) {
        return described;
    }
    if (source_description == destination_description) {
        return WorkspaceSecurityStatus::kSuccess;
    }
    information = LABEL_SECURITY_INFORMATION |
        ((descriptor.control & SE_SACL_PROTECTED) != 0
             ? PROTECTED_SACL_SECURITY_INFORMATION
             : UNPROTECTED_SACL_SECURITY_INFORMATION);
    if (SetNamedSecurityInfoW(
            mutable_destination.data(), SE_FILE_OBJECT, information, nullptr,
            nullptr, nullptr, descriptor.label) != ERROR_SUCCESS) {
        return WorkspaceSecurityStatus::kSecurityApplyFailed;
    }
    destination_description.clear();
    described = DescribeDescriptor(destination, destination_description);
    if (described != WorkspaceSecurityStatus::kSuccess) {
        return described;
    }
    return source_description == destination_description
               ? WorkspaceSecurityStatus::kSuccess
               : WorkspaceSecurityStatus::kSecurityApplyFailed;
}

WorkspaceSecurityStatus VerifyCreatedAuthorization(
    const std::filesystem::path& path,
    const bool is_directory) noexcept {
    const auto parent = path.parent_path();
    if (parent.empty()) {
        return WorkspaceSecurityStatus::kUnsupportedObject;
    }
    static std::atomic_uint64_t next_probe{1};
    std::filesystem::path probe;
    HANDLE probe_file = INVALID_HANDLE_VALUE;
    bool created = false;
    for (std::uint32_t attempt = 0; attempt < 16 && !created; ++attempt) {
        const auto identifier = next_probe.fetch_add(1, std::memory_order_relaxed);
        probe = parent /
                (L".bolt-acl-probe-" +
                 std::to_wstring(GetCurrentProcessId()) + L"-" +
                 std::to_wstring(identifier));
        if (is_directory) {
            created = CreateDirectoryW(probe.c_str(), nullptr) != FALSE;
        } else {
            probe_file = CreateFileW(
                probe.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
            created = probe_file != INVALID_HANDLE_VALUE;
        }
        if (!created && GetLastError() != ERROR_ALREADY_EXISTS &&
            GetLastError() != ERROR_FILE_EXISTS) {
            return WorkspaceSecurityStatus::kSecurityQueryFailed;
        }
    }
    if (!created) {
        return WorkspaceSecurityStatus::kSecurityQueryFailed;
    }
    if (probe_file != INVALID_HANDLE_VALUE) {
        CloseHandle(probe_file);
    }
    std::wstring expected;
    std::wstring actual;
    const auto expected_status = DescribeDescriptor(probe, expected);
    const auto actual_status = DescribeDescriptor(path, actual);
    const bool removed = is_directory
                             ? RemoveDirectoryW(probe.c_str()) != FALSE
                             : DeleteFileW(probe.c_str()) != FALSE;
    if (!removed) {
        return WorkspaceSecurityStatus::kSecurityQueryFailed;
    }
    if (expected_status != WorkspaceSecurityStatus::kSuccess) {
        return expected_status;
    }
    if (actual_status != WorkspaceSecurityStatus::kSuccess) {
        return actual_status;
    }
    return expected == actual ? WorkspaceSecurityStatus::kSuccess
                              : WorkspaceSecurityStatus::kMismatch;
}

template <typename Visitor>
WorkspaceSecurityStatus VisitPairs(
    const std::filesystem::path& source_root,
    const std::filesystem::path& destination_root,
    const std::uint32_t maximum_items,
    const bool allow_missing_destination,
    Visitor&& visitor) noexcept {
    if (maximum_items == 0 || !source_root.is_absolute() ||
        !destination_root.is_absolute() ||
        !std::filesystem::is_directory(source_root) ||
        !std::filesystem::is_directory(destination_root) ||
        !IsSupportedPath(source_root) || !IsSupportedPath(destination_root)) {
        return WorkspaceSecurityStatus::kInvalidRoot;
    }
    auto status = visitor(source_root, destination_root);
    if (status != WorkspaceSecurityStatus::kSuccess) {
        return status;
    }
    std::uint32_t item_count = 0;
    try {
        for (const auto& entry :
             std::filesystem::recursive_directory_iterator(source_root)) {
            if (item_count == maximum_items) {
                return WorkspaceSecurityStatus::kQuotaExceeded;
            }
            ++item_count;
            const auto relative =
                std::filesystem::relative(entry.path(), source_root);
            const auto destination = destination_root / relative;
            if (!IsSupportedPath(entry.path())) {
                return WorkspaceSecurityStatus::kUnsupportedObject;
            }
            if (!std::filesystem::exists(destination)) {
                if (allow_missing_destination) {
                    continue;
                }
                return WorkspaceSecurityStatus::kUnsupportedObject;
            }
            if (!IsSupportedPath(destination) ||
                entry.is_directory() !=
                    std::filesystem::is_directory(destination) ||
                entry.is_regular_file() !=
                    std::filesystem::is_regular_file(destination)) {
                return WorkspaceSecurityStatus::kUnsupportedObject;
            }
            status = visitor(entry.path(), destination);
            if (status != WorkspaceSecurityStatus::kSuccess) {
                return status;
            }
        }
    } catch (...) {
        return WorkspaceSecurityStatus::kUnsupportedObject;
    }
    return WorkspaceSecurityStatus::kSuccess;
}

WorkspaceSecurityStatus VerifyCreatedEntries(
    const std::filesystem::path& source_root,
    const std::filesystem::path& destination_root,
    const std::uint32_t maximum_items) noexcept {
    std::uint32_t item_count = 0;
    try {
        for (const auto& entry :
             std::filesystem::recursive_directory_iterator(destination_root)) {
            if (item_count == maximum_items) {
                return WorkspaceSecurityStatus::kQuotaExceeded;
            }
            ++item_count;
            if (!IsSupportedPath(entry.path())) {
                return WorkspaceSecurityStatus::kUnsupportedObject;
            }
            const auto relative =
                std::filesystem::relative(entry.path(), destination_root);
            const auto source = source_root / relative;
            if (std::filesystem::exists(source)) {
                continue;
            }
            const bool is_directory = entry.is_directory();
            if (!is_directory && !entry.is_regular_file()) {
                return WorkspaceSecurityStatus::kUnsupportedObject;
            }
            const auto status =
                VerifyCreatedAuthorization(entry.path(), is_directory);
            if (status != WorkspaceSecurityStatus::kSuccess) {
                return status;
            }
        }
    } catch (...) {
        return WorkspaceSecurityStatus::kUnsupportedObject;
    }
    return WorkspaceSecurityStatus::kSuccess;
}

}  // namespace

WorkspaceSecurityStatus CopyWorkspaceAuthorization(
    const std::filesystem::path& source_root,
    const std::filesystem::path& destination_root,
    const std::uint32_t maximum_items) noexcept {
    return VisitPairs(
        source_root, destination_root, maximum_items, false,
        [](const std::filesystem::path& source,
           const std::filesystem::path& destination) {
            return ApplyDescriptor(source, destination);
        });
}

WorkspaceSecurityStatus VerifyWorkspaceAuthorization(
    const std::filesystem::path& source_root,
    const std::filesystem::path& destination_root,
    const std::uint32_t maximum_items) noexcept {
    const auto existing = VisitPairs(
        source_root, destination_root, maximum_items, true,
        [](const std::filesystem::path& source,
           const std::filesystem::path& destination) {
            std::wstring source_descriptor;
            std::wstring destination_descriptor;
            const auto source_status =
                DescribeDescriptor(source, source_descriptor);
            if (source_status != WorkspaceSecurityStatus::kSuccess) {
                return source_status;
            }
            const auto destination_status =
                DescribeDescriptor(destination, destination_descriptor);
            if (destination_status != WorkspaceSecurityStatus::kSuccess) {
                return destination_status;
            }
            return source_descriptor == destination_descriptor
                       ? WorkspaceSecurityStatus::kSuccess
                       : WorkspaceSecurityStatus::kMismatch;
        });
    if (existing != WorkspaceSecurityStatus::kSuccess) {
        return existing;
    }
    return VerifyCreatedEntries(
        source_root, destination_root, maximum_items);
}

}  // namespace bolt::common
