#include "hook/filesystem/filesystem_policy.h"
#include "hook/filesystem/policy_decision_cache.h"

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN

#include "CanonicalizedPath.h"
#include "hook/filesystem/safe_device.h"
#include "protocol/policy_payload.h"
#include "protocol/version.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <filesystem>
#include <limits>
#include <new>
#include <string>
#include <utility>
#include <vector>

#include <windows.h>

namespace bolt::filesystem {
namespace {

enum class RuleKind : std::uint8_t {
    kReadWrite,
    kReadOnly,
    kDeny,
    kMetadataRead,
    kInheritUser,
    kDeviceReadOnly,
};

struct Rule {
    std::wstring root;
    RuleKind kind;
    std::size_t depth;
    bool case_sensitive = false;
};

struct PathAlias {
    std::wstring prefix;
    std::wstring replacement;
};

class Reader {
  public:
    Reader(const std::uint8_t* bytes, const std::size_t length) noexcept
        : bytes_(bytes), length_(length) {}

    bool ReadU8(std::uint8_t& value) noexcept {
        const std::uint8_t* bytes = nullptr;
        if (!ReadBytes(1, bytes)) {
            return false;
        }
        value = bytes[0];
        return true;
    }

    bool ReadU32(std::size_t& value) noexcept {
        const std::uint8_t* bytes = nullptr;
        if (!ReadBytes(4, bytes)) {
            return false;
        }
        value = static_cast<std::size_t>(bytes[0]) |
                (static_cast<std::size_t>(bytes[1]) << 8U) |
                (static_cast<std::size_t>(bytes[2]) << 16U) |
                (static_cast<std::size_t>(bytes[3]) << 24U);
        return true;
    }

    bool ReadBytes(const std::size_t count, const std::uint8_t*& bytes) noexcept {
        if (count > length_ - offset_) {
            return false;
        }
        bytes = bytes_ + offset_;
        offset_ += count;
        return true;
    }

    [[nodiscard]] bool Finished() const noexcept { return offset_ == length_; }

  private:
    const std::uint8_t* bytes_;
    std::size_t length_;
    std::size_t offset_ = 0;
};

bool ReadComponent(Reader& reader, std::uint8_t& kind, std::wstring& value) {
    std::size_t code_units = 0;
    const std::uint8_t* bytes = nullptr;
    if (!reader.ReadU8(kind) || !reader.ReadU32(code_units) ||
        code_units > std::numeric_limits<std::size_t>::max() / 2 ||
        !reader.ReadBytes(code_units * 2, bytes)) {
        return false;
    }
    value.clear();
    value.reserve(code_units);
    for (std::size_t index = 0; index < code_units; ++index) {
        const auto code_unit = static_cast<wchar_t>(
            static_cast<std::uint16_t>(bytes[index * 2]) |
            static_cast<std::uint16_t>(bytes[index * 2 + 1] << 8U));
        if (code_unit == L'\0') {
            return false;
        }
        value.push_back(code_unit);
    }
    return true;
}

bool HasSeparator(const std::wstring& value) noexcept {
    return value.find_first_of(L"\\/") != std::wstring::npos;
}

bool ValidExactDevicePath(const std::wstring& value) noexcept {
    constexpr wchar_t prefix[] = L"\\Device\\";
    constexpr std::size_t prefix_length = std::size(prefix) - 1;
    constexpr wchar_t win32_prefix[] = L"\\\\.\\";
    constexpr std::size_t win32_prefix_length =
        std::size(win32_prefix) - 1;
    if (value.empty() || value.size() > 1'024 || value.back() == L'\\' ||
        value.find_first_of(L"/:*?") != std::wstring::npos) {
        return false;
    }
    if (value.size() > win32_prefix_length &&
        CompareStringOrdinal(
            value.data(), static_cast<int>(win32_prefix_length),
            win32_prefix, static_cast<int>(win32_prefix_length), TRUE) ==
            CSTR_EQUAL) {
        return value.find(L'\\', win32_prefix_length) ==
               std::wstring::npos;
    }
    if (value.size() <= prefix_length ||
        CompareStringOrdinal(
            value.data(), static_cast<int>(prefix_length), prefix,
            static_cast<int>(prefix_length), TRUE) != CSTR_EQUAL) {
        return false;
    }
    std::size_t offset = prefix_length;
    while (offset < value.size()) {
        const std::size_t end = value.find(L'\\', offset);
        const std::wstring component = value.substr(
            offset, end == std::wstring::npos ? std::wstring::npos
                                               : end - offset);
        if (component.empty() || component == L"." || component == L"..") {
            return false;
        }
        offset = end == std::wstring::npos ? value.size() : end + 1;
    }
    return true;
}

bool ParseRule(const std::uint8_t* bytes, const std::size_t length, Rule& rule) {
    Reader reader(bytes, length);
    std::uint8_t kind = 0;
    std::size_t component_count = 0;
    if (!reader.ReadU8(kind) ||
        kind > static_cast<std::uint8_t>(RuleKind::kDeviceReadOnly) ||
        !reader.ReadU32(component_count)) {
        return false;
    }

    if (kind == static_cast<std::uint8_t>(RuleKind::kDeviceReadOnly)) {
        std::uint8_t component_kind = 0;
        std::wstring device;
        if (component_count != 1 ||
            !ReadComponent(reader, component_kind, device) ||
            component_kind != 3 || !ValidExactDevicePath(device) ||
            !reader.Finished()) {
            return false;
        }
        rule.root = std::move(device);
        rule.kind = RuleKind::kDeviceReadOnly;
        rule.depth = 1;
        return true;
    }
    if (component_count < 2) {
        return false;
    }

    std::uint8_t component_kind = 0;
    std::wstring component;
    if (!ReadComponent(reader, component_kind, component) || component_kind != 0 ||
        component.empty()) {
        return false;
    }
    rule.root = std::move(component);

    if (!ReadComponent(reader, component_kind, component) || component_kind != 1 ||
        !component.empty()) {
        return false;
    }
    if (!rule.root.empty() && !IsDirectorySeparator(rule.root.back())) {
        rule.root.push_back(L'\\');
    }

    for (std::size_t index = 2; index < component_count; ++index) {
        if (!ReadComponent(reader, component_kind, component) || component_kind != 2 ||
            component.empty() || HasSeparator(component) || component == L"." || component == L"..") {
            return false;
        }
        if (!IsDirectorySeparator(rule.root.back())) {
            rule.root.push_back(L'\\');
        }
        rule.root.append(component);
    }
    rule.kind = static_cast<RuleKind>(kind);
    rule.depth = component_count;
    return reader.Finished();
}

bool EqualIgnoreCase(const std::wstring& left, const std::wstring& right) noexcept {
    if (left.size() != right.size() || left.size() > static_cast<std::size_t>(INT_MAX)) {
        return false;
    }
    return CompareStringOrdinal(
               left.data(), static_cast<int>(left.size()), right.data(),
               static_cast<int>(right.size()), TRUE) == CSTR_EQUAL;
}

bool QueryCaseSensitiveIdentity(
    const std::wstring& root,
    FILE_ID_INFO& identity) noexcept {
    try {
        if (root.rfind(L"\\\\", 0) == 0) {
            return false;
        }
        const std::filesystem::path path(root);
        const auto parent = path.parent_path();
        if (parent.empty()) {
            return false;
        }
        const HANDLE parent_handle = CreateFileW(
            parent.c_str(), FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (parent_handle == INVALID_HANDLE_VALUE) {
            return false;
        }
        FILE_CASE_SENSITIVE_INFO case_information{};
        const bool case_sensitive =
            GetFileInformationByHandleEx(
                parent_handle, FileCaseSensitiveInfo, &case_information,
                sizeof(case_information)) != FALSE &&
            (case_information.Flags & FILE_CS_FLAG_CASE_SENSITIVE_DIR) != 0;
        CloseHandle(parent_handle);
        if (!case_sensitive) {
            return false;
        }

        const HANDLE target_handle = CreateFileW(
            root.c_str(), FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (target_handle == INVALID_HANDLE_VALUE) {
            return false;
        }
        const bool identified =
            GetFileInformationByHandleEx(
                target_handle, FileIdInfo, &identity, sizeof(identity)) != FALSE;
        CloseHandle(target_handle);
        return identified;
    } catch (...) {
        return false;
    }
}

bool EnableCaseSensitiveRules(Rule& left, Rule& right) noexcept {
    FILE_ID_INFO left_identity{};
    FILE_ID_INFO right_identity{};
    if (!QueryCaseSensitiveIdentity(left.root, left_identity) ||
        !QueryCaseSensitiveIdentity(right.root, right_identity)) {
        return false;
    }
    const bool distinct =
        left_identity.VolumeSerialNumber != right_identity.VolumeSerialNumber ||
        std::memcmp(
            left_identity.FileId.Identifier, right_identity.FileId.Identifier,
            sizeof(left_identity.FileId.Identifier)) != 0;
    if (!distinct) {
        return false;
    }
    left.case_sensitive = true;
    right.case_sensitive = true;
    return true;
}

bool RootContains(
    const std::wstring& root,
    const wchar_t* path,
    const bool case_sensitive = false) noexcept {
    const std::size_t path_length = std::wcslen(path);
    if (root.size() > path_length || root.size() > static_cast<std::size_t>(INT_MAX)) {
        return false;
    }
    if (CompareStringOrdinal(
            root.data(), static_cast<int>(root.size()), path,
            static_cast<int>(root.size()), case_sensitive ? FALSE : TRUE) !=
        CSTR_EQUAL) {
        return false;
    }
    return root.size() == path_length || IsDirectorySeparator(root.back()) ||
           IsDirectorySeparator(path[root.size()]);
}

bool HasPrefixIgnoreCase(
    const std::wstring& value,
    const std::wstring& prefix) noexcept {
    return value.size() >= prefix.size() &&
           prefix.size() <= static_cast<std::size_t>(INT_MAX) &&
           CompareStringOrdinal(
               value.data(), static_cast<int>(prefix.size()), prefix.data(),
               static_cast<int>(prefix.size()), TRUE) == CSTR_EQUAL;
}

bool ReplaceAlias(
    const std::wstring& path,
    const std::vector<PathAlias>& aliases,
    std::wstring& replaced) {
    for (const auto& alias : aliases) {
        if (!HasPrefixIgnoreCase(path, alias.prefix) ||
            (path.size() > alias.prefix.size() &&
             !IsDirectorySeparator(alias.prefix.back()) &&
             !IsDirectorySeparator(path[alias.prefix.size()]))) {
            continue;
        }
        replaced.assign(alias.replacement);
        replaced.append(path, alias.prefix.size(), std::wstring::npos);
        return true;
    }
    return false;
}

std::vector<PathAlias> LoadPathAliases() {
    std::vector<PathAlias> aliases;
    const DWORD required = GetLogicalDriveStringsW(0, nullptr);
    if (required == 0) {
        return aliases;
    }
    std::wstring drives(static_cast<std::size_t>(required) + 1, L'\0');
    if (GetLogicalDriveStringsW(required, drives.data()) == 0) {
        return {};
    }
    for (const wchar_t* drive = drives.c_str(); *drive != L'\0';
         drive += std::wcslen(drive) + 1) {
        if (std::wcslen(drive) < 3) {
            continue;
        }
        std::array<wchar_t, 64> volume_name{};
        if (GetVolumeNameForVolumeMountPointW(
                drive, volume_name.data(),
                static_cast<DWORD>(volume_name.size()))) {
            const std::wstring volume(volume_name.data());
            if (volume.rfind(L"\\\\?\\", 0) == 0 && volume.size() > 4) {
                aliases.push_back({volume.substr(4), drive});
            }
        }
        const wchar_t drive_name[] = {drive[0], L':', L'\0'};
        std::array<wchar_t, 32'768> device_name{};
        if (QueryDosDeviceW(
                drive_name, device_name.data(),
                static_cast<DWORD>(device_name.size())) != 0) {
            aliases.push_back({device_name.data(), drive_name});
        }
    }
    return aliases;
}

bool AssignPolicyPath(
    const wchar_t* path,
    const std::vector<PathAlias>& aliases,
    std::wstring& normalized_path) {
    if (path == nullptr) {
        return false;
    }
    const std::wstring raw_path(path);
    if (ReplaceAlias(raw_path, aliases, normalized_path)) {
        return true;
    }
    const auto canonical = CanonicalizedPath::Canonicalize(path);
    const wchar_t* normalized = canonical.GetPathStringWithoutTypePrefix();
    if (canonical.IsNull() || normalized == nullptr) {
        return false;
    }
    constexpr wchar_t unc_marker[] = L"UNC\\";
    if (canonical.Type == PathType::Win32Nt &&
        std::wcslen(normalized) >= std::size(unc_marker) - 1 &&
        CompareStringOrdinal(
            normalized, static_cast<int>(std::size(unc_marker) - 1),
            unc_marker, static_cast<int>(std::size(unc_marker) - 1), TRUE) ==
            CSTR_EQUAL) {
        normalized_path.assign(L"\\\\");
        normalized_path.append(normalized + std::size(unc_marker) - 1);
    } else {
        normalized_path.assign(normalized);
    }
    std::wstring replaced;
    if (ReplaceAlias(normalized_path, aliases, replaced)) {
        normalized_path = std::move(replaced);
    }
    return true;
}

Decision ApplyRule(const RuleKind kind, const Access access) noexcept {
    switch (kind) {
        case RuleKind::kReadWrite:
            return Decision::kAllow;
        case RuleKind::kReadOnly:
            return access == Access::kWrite ? Decision::kDeny : Decision::kAllow;
        case RuleKind::kDeny:
            return Decision::kDeny;
        case RuleKind::kMetadataRead:
            return access == Access::kMetadata ? Decision::kAllow : Decision::kDeny;
        case RuleKind::kInheritUser:
            return Decision::kInheritUser;
        case RuleKind::kDeviceReadOnly:
            return access == Access::kWrite ? Decision::kDeny
                                            : Decision::kAllow;
    }
    return Decision::kDeny;
}

}  // namespace

struct FilesystemPolicy::Impl {
    std::vector<Rule> rules;
    std::vector<PathAlias> aliases;
    mutable PolicyDecisionCache decision_cache;
};

FilesystemPolicy::FilesystemPolicy(std::unique_ptr<Impl> implementation) noexcept
    : implementation_(std::move(implementation)) {}

FilesystemPolicy::~FilesystemPolicy() = default;

PolicyLoadStatus FilesystemPolicy::Load(
    const std::uint8_t* payload,
    const std::size_t length,
    std::unique_ptr<FilesystemPolicy>& policy) noexcept {
    policy.reset();
    if (protocol::ValidatePolicyPayload(payload, length) != protocol::PolicyPayloadStatus::kValid) {
        return PolicyLoadStatus::kInvalidPayload;
    }

    try {
        Reader body(payload + protocol::kPolicyEnvelopeLength, length - protocol::kPolicyEnvelopeLength);
        std::uint8_t child_policy = 0;
        std::size_t rule_count = 0;
        if (!body.ReadU8(child_policy) || !body.ReadU32(rule_count)) {
            return PolicyLoadStatus::kInvalidFilesystemPolicy;
        }

        auto implementation = std::make_unique<Impl>();
        implementation->aliases = LoadPathAliases();
        implementation->rules.reserve(rule_count);
        for (std::size_t index = 0; index < rule_count; ++index) {
            std::size_t record_length = 0;
            const std::uint8_t* record_bytes = nullptr;
            Rule rule;
            if (!body.ReadU32(record_length) || !body.ReadBytes(record_length, record_bytes) ||
                !ParseRule(record_bytes, record_length, rule)) {
                return PolicyLoadStatus::kInvalidFilesystemPolicy;
            }
            for (auto& existing : implementation->rules) {
                if (!EqualIgnoreCase(existing.root, rule.root) ||
                    existing.kind == rule.kind) {
                    continue;
                }
                if (existing.root != rule.root) {
                    if (!EnableCaseSensitiveRules(existing, rule)) {
                        return PolicyLoadStatus::kInvalidFilesystemPolicy;
                    }
                } else if (
                    existing.kind != RuleKind::kDeny &&
                    rule.kind != RuleKind::kDeny) {
                    return PolicyLoadStatus::kInvalidFilesystemPolicy;
                }
            }
            implementation->rules.push_back(std::move(rule));
        }
        policy.reset(new FilesystemPolicy(std::move(implementation)));
        return PolicyLoadStatus::kValid;
    } catch (const std::bad_alloc&) {
        return PolicyLoadStatus::kOutOfMemory;
    } catch (...) {
        return PolicyLoadStatus::kInvalidFilesystemPolicy;
    }
}

PolicyEvaluation FilesystemPolicy::Evaluate(
    const wchar_t* path,
    const Access access) const noexcept {
    PolicyEvaluation evaluation;
    if (path == nullptr || implementation_ == nullptr) {
        return evaluation;
    }
    if (IsNullDevicePath(path)) {
        evaluation.decision = Decision::kAllow;
        evaluation.normalized_path = L"NUL";
        return evaluation;
    }
    for (const auto& rule : implementation_->rules) {
        if (rule.kind == RuleKind::kDeviceReadOnly &&
            EqualIgnoreCase(rule.root, path)) {
            evaluation.decision = ApplyRule(rule.kind, access);
            evaluation.normalized_path = rule.root;
            return evaluation;
        }
    }
    if (implementation_->decision_cache.Lookup(path, access, evaluation)) {
        return evaluation;
    }
    try {
        if (!AssignPolicyPath(
                path, implementation_->aliases, evaluation.normalized_path)) {
            return evaluation;
        }
        const wchar_t* normalized = evaluation.normalized_path.c_str();

        std::size_t maximum_depth = 0;
        for (const auto& rule : implementation_->rules) {
            const bool matches =
                rule.kind == RuleKind::kDeviceReadOnly
                    ? EqualIgnoreCase(rule.root, normalized)
                    : RootContains(
                          rule.root, normalized, rule.case_sensitive);
            if (!matches) {
                continue;
            }
            if (rule.kind == RuleKind::kDeny) {
                evaluation.decision = Decision::kDeny;
                return evaluation;
            }
            if (rule.depth > maximum_depth) {
                maximum_depth = rule.depth;
                evaluation.decision = ApplyRule(rule.kind, access);
            } else if (rule.depth == maximum_depth) {
                const auto candidate = ApplyRule(rule.kind, access);
                if (candidate == Decision::kDeny) {
                    evaluation.decision = Decision::kDeny;
                    return evaluation;
                }
                if (candidate == Decision::kInheritUser) {
                    evaluation.decision = candidate;
                }
            }
        }
        static_cast<void>(
            implementation_->decision_cache.Store(path, access, evaluation));
        return evaluation;
    } catch (...) {
        return PolicyEvaluation{};
    }
}

bool FilesystemPolicy::HasDeniedDescendant(const wchar_t* path) const noexcept {
    if (path == nullptr || implementation_ == nullptr) {
        return true;
    }
    try {
        std::wstring normalized_root;
        if (!AssignPolicyPath(
                path, implementation_->aliases, normalized_root)) {
            return true;
        }
        for (const auto& rule : implementation_->rules) {
            if (rule.kind == RuleKind::kDeny &&
                rule.root.size() > normalized_root.size() &&
                RootContains(
                    normalized_root, rule.root.c_str(), rule.case_sensitive)) {
                return true;
            }
        }
        return false;
    } catch (...) {
        return true;
    }
}

}  // namespace bolt::filesystem
