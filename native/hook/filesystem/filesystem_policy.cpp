#include "hook/filesystem/filesystem_policy.h"

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN

#include "CanonicalizedPath.h"
#include "protocol/policy_payload.h"
#include "protocol/version.h"

#include <algorithm>
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
};

struct Rule {
    std::wstring root;
    RuleKind kind;
    std::size_t depth;
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

bool ParseRule(const std::uint8_t* bytes, const std::size_t length, Rule& rule) {
    Reader reader(bytes, length);
    std::uint8_t kind = 0;
    std::size_t component_count = 0;
    if (!reader.ReadU8(kind) || kind > static_cast<std::uint8_t>(RuleKind::kInheritUser) ||
        !reader.ReadU32(component_count) || component_count < 2) {
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

bool RootContains(const std::wstring& root, const wchar_t* path) noexcept {
    const std::size_t path_length = std::wcslen(path);
    if (root.size() > path_length || root.size() > static_cast<std::size_t>(INT_MAX)) {
        return false;
    }
    if (CompareStringOrdinal(
            root.data(), static_cast<int>(root.size()), path,
            static_cast<int>(root.size()), TRUE) != CSTR_EQUAL) {
        return false;
    }
    return root.size() == path_length || IsDirectorySeparator(root.back()) ||
           IsDirectorySeparator(path[root.size()]);
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
    }
    return Decision::kDeny;
}

}  // namespace

struct FilesystemPolicy::Impl {
    std::vector<Rule> rules;
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
        implementation->rules.reserve(rule_count);
        for (std::size_t index = 0; index < rule_count; ++index) {
            std::size_t record_length = 0;
            const std::uint8_t* record_bytes = nullptr;
            Rule rule;
            if (!body.ReadU32(record_length) || !body.ReadBytes(record_length, record_bytes) ||
                !ParseRule(record_bytes, record_length, rule)) {
                return PolicyLoadStatus::kInvalidFilesystemPolicy;
            }
            for (const auto& existing : implementation->rules) {
                if (EqualIgnoreCase(existing.root, rule.root) && existing.kind != rule.kind &&
                    existing.kind != RuleKind::kDeny && rule.kind != RuleKind::kDeny) {
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

Decision FilesystemPolicy::Decide(const wchar_t* path, const Access access) const noexcept {
    if (path == nullptr || implementation_ == nullptr) {
        return Decision::kDeny;
    }
    try {
        const auto canonical = CanonicalizedPath::Canonicalize(path);
        const wchar_t* normalized = canonical.GetPathStringWithoutTypePrefix();
        if (canonical.IsNull() || normalized == nullptr) {
            return Decision::kDeny;
        }

        std::size_t maximum_depth = 0;
        Decision decision = Decision::kDeny;
        for (const auto& rule : implementation_->rules) {
            if (!RootContains(rule.root, normalized)) {
                continue;
            }
            if (rule.kind == RuleKind::kDeny) {
                return Decision::kDeny;
            }
            if (rule.depth > maximum_depth) {
                maximum_depth = rule.depth;
                decision = ApplyRule(rule.kind, access);
            } else if (rule.depth == maximum_depth) {
                const auto candidate = ApplyRule(rule.kind, access);
                if (candidate == Decision::kDeny) {
                    return Decision::kDeny;
                }
                if (candidate == Decision::kInheritUser) {
                    decision = candidate;
                }
            }
        }
        return decision;
    } catch (...) {
        return Decision::kDeny;
    }
}

}  // namespace bolt::filesystem
