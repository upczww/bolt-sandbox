#include "hook/registry/registry_policy.h"

#include "protocol/policy_payload.h"
#include "protocol/version.h"

#include <algorithm>
#include <limits>
#include <new>
#include <string>
#include <utility>
#include <vector>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace bolt::registry {
namespace {

constexpr std::size_t kMaximumRegistryRules = 2'048;
constexpr std::size_t kMaximumRegistryKeyCodeUnits = 255;

enum class RuleKind : std::uint8_t {
    kNoAccess = 0,
    kReadOnly = 1,
    kInheritUser = 2,
    kReadWrite = 3,
};

struct Rule {
    RegistryHive hive = RegistryHive::kCurrentUser;
    std::vector<std::wstring> components;
    RuleKind kind = RuleKind::kNoAccess;
};

class Reader final {
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
                static_cast<std::size_t>(bytes[1]) << 8U |
                static_cast<std::size_t>(bytes[2]) << 16U |
                static_cast<std::size_t>(bytes[3]) << 24U;
        return true;
    }

    bool ReadBytes(
        const std::size_t count,
        const std::uint8_t*& bytes) noexcept {
        if (offset_ > length_ || count > length_ - offset_) {
            return false;
        }
        bytes = bytes_ + offset_;
        offset_ += count;
        return true;
    }

    bool Skip(const std::size_t count) noexcept {
        const std::uint8_t* ignored = nullptr;
        return ReadBytes(count, ignored);
    }

    [[nodiscard]] bool Finished() const noexcept {
        return offset_ == length_;
    }

  private:
    const std::uint8_t* bytes_ = nullptr;
    std::size_t length_ = 0;
    std::size_t offset_ = 0;
};

bool SkipFilesystem(Reader& reader) noexcept {
    std::uint8_t child_policy = 0;
    std::size_t count = 0;
    if (!reader.ReadU8(child_policy) || !reader.ReadU32(count)) {
        return false;
    }
    for (std::size_t index = 0; index < count; ++index) {
        std::size_t length = 0;
        if (!reader.ReadU32(length) || !reader.Skip(length)) {
            return false;
        }
    }
    return true;
}

bool SkipNetwork(Reader& reader) noexcept {
    std::uint8_t mode = 0;
    if (!reader.ReadU8(mode) || mode > 2) {
        return false;
    }
    if (mode != 2) {
        return true;
    }
    std::size_t count = 0;
    if (!reader.ReadU32(count)) {
        return false;
    }
    for (std::size_t index = 0; index < count; ++index) {
        std::uint8_t wildcard = 0;
        std::size_t length = 0;
        if (!reader.ReadU8(wildcard) || !reader.ReadU32(length) ||
            !reader.Skip(length)) {
            return false;
        }
    }
    if (!reader.ReadU32(count)) {
        return false;
    }
    for (std::size_t index = 0; index < count; ++index) {
        std::uint8_t family = 0;
        std::uint8_t prefix = 0;
        if (!reader.ReadU8(family) || !reader.ReadU8(prefix) ||
            !reader.Skip(family == 4 ? 4 : family == 6 ? 16 : 0)) {
            return false;
        }
    }
    if (!reader.ReadU32(count) ||
        count > std::numeric_limits<std::size_t>::max() / 4) {
        return false;
    }
    return reader.Skip(count * 4);
}

bool Utf8ToWide(
    const std::uint8_t* bytes,
    const std::size_t length,
    std::wstring& value) {
    if (bytes == nullptr || length == 0 ||
        length > static_cast<std::size_t>(INT_MAX)) {
        return false;
    }
    const int required = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS,
        reinterpret_cast<const char*>(bytes), static_cast<int>(length),
        nullptr, 0);
    if (required <= 0) {
        return false;
    }
    value.resize(static_cast<std::size_t>(required));
    return MultiByteToWideChar(
               CP_UTF8, MB_ERR_INVALID_CHARS,
               reinterpret_cast<const char*>(bytes),
               static_cast<int>(length), value.data(), required) == required;
}

bool ValidComponent(const std::wstring& component) noexcept {
    return !component.empty() && component != L"." && component != L".." &&
           component.find_first_of(L"\\/:") == std::wstring::npos &&
           std::none_of(
               component.begin(), component.end(),
               [](const wchar_t value) {
                   return value == L'\0' || value < L' ' || value == 0x7f;
               });
}

bool EqualIgnoreCase(
    const std::wstring& left,
    const std::wstring& right) noexcept {
    return left.size() == right.size() &&
           left.size() <= static_cast<std::size_t>(INT_MAX) &&
           CompareStringOrdinal(
               left.data(), static_cast<int>(left.size()), right.data(),
               static_cast<int>(right.size()), TRUE) == CSTR_EQUAL;
}

bool SameRoot(const Rule& left, const Rule& right) noexcept {
    return left.hive == right.hive &&
           left.components.size() == right.components.size() &&
           std::equal(
               left.components.begin(), left.components.end(),
               right.components.begin(), EqualIgnoreCase);
}

bool Contains(
    const Rule& rule,
    const RegistryHive hive,
    const std::vector<std::wstring>& components) noexcept {
    return rule.hive == hive &&
           rule.components.size() <= components.size() &&
           std::equal(
               rule.components.begin(), rule.components.end(),
               components.begin(), EqualIgnoreCase);
}

bool ParseRelativeKey(
    const wchar_t* relative_key,
    std::vector<std::wstring>& components) {
    components.clear();
    if (relative_key == nullptr) {
        return false;
    }
    const std::wstring value(relative_key);
    if (value.size() > kMaximumRegistryKeyCodeUnits ||
        value.find_first_of(L"/:") != std::wstring::npos) {
        return false;
    }
    std::size_t offset = 0;
    while (offset < value.size()) {
        while (offset < value.size() && value[offset] == L'\\') {
            ++offset;
        }
        if (offset == value.size()) {
            break;
        }
        const std::size_t end = value.find(L'\\', offset);
        const std::size_t component_length = end == std::wstring::npos
                                                 ? value.size() - offset
                                                 : end - offset;
        std::wstring component = value.substr(offset, component_length);
        if (!ValidComponent(component)) {
            return false;
        }
        components.push_back(std::move(component));
        offset = end == std::wstring::npos ? value.size() : end + 1;
    }
    return true;
}

RegistryDecision DecisionFor(
    const RuleKind kind,
    const RegistryAccess access) noexcept {
    switch (kind) {
        case RuleKind::kNoAccess:
            return RegistryDecision::kDeny;
        case RuleKind::kReadOnly:
            return access == RegistryAccess::kWrite
                       ? RegistryDecision::kDeny
                       : RegistryDecision::kAllow;
        case RuleKind::kInheritUser:
            return RegistryDecision::kInheritUser;
        case RuleKind::kReadWrite:
            return RegistryDecision::kAllow;
    }
    return RegistryDecision::kDeny;
}

}  // namespace

struct RegistryPolicy::Impl {
    std::vector<Rule> rules;
};

RegistryPolicy::RegistryPolicy(
    std::unique_ptr<Impl> implementation) noexcept
    : implementation_(std::move(implementation)) {}

RegistryPolicy::~RegistryPolicy() = default;

RegistryPolicyLoadStatus RegistryPolicy::Load(
    const std::uint8_t* payload,
    const std::size_t length,
    std::unique_ptr<RegistryPolicy>& policy) noexcept {
    policy.reset();
    if (protocol::ValidatePolicyPayload(payload, length) !=
        protocol::PolicyPayloadStatus::kValid) {
        return RegistryPolicyLoadStatus::kInvalidPayload;
    }
    try {
        Reader reader(
            payload + protocol::kPolicyEnvelopeLength,
            length - protocol::kPolicyEnvelopeLength);
        if (!SkipFilesystem(reader) || !SkipNetwork(reader)) {
            return RegistryPolicyLoadStatus::kInvalidRegistryPolicy;
        }
        std::size_t rule_count = 0;
        if (!reader.ReadU32(rule_count) ||
            rule_count > kMaximumRegistryRules) {
            return RegistryPolicyLoadStatus::kInvalidRegistryPolicy;
        }
        auto implementation = std::make_unique<Impl>();
        implementation->rules.reserve(rule_count);
        for (std::size_t index = 0; index < rule_count; ++index) {
            std::uint8_t kind = 0;
            std::uint8_t hive = 0;
            std::size_t component_count = 0;
            if (!reader.ReadU8(kind) || kind > 3 || !reader.ReadU8(hive) ||
                hive > 4 || !reader.ReadU32(component_count) ||
                component_count > kMaximumRegistryKeyCodeUnits) {
                return RegistryPolicyLoadStatus::kInvalidRegistryPolicy;
            }
            Rule rule;
            rule.kind = static_cast<RuleKind>(kind);
            rule.hive = static_cast<RegistryHive>(hive);
            rule.components.reserve(component_count);
            std::size_t encoded_length = 0;
            for (std::size_t component = 0; component < component_count;
                 ++component) {
                std::size_t byte_length = 0;
                const std::uint8_t* bytes = nullptr;
                std::wstring value;
                if (!reader.ReadU32(byte_length) ||
                    !reader.ReadBytes(byte_length, bytes) ||
                    !Utf8ToWide(bytes, byte_length, value) ||
                    !ValidComponent(value) ||
                    value.size() > kMaximumRegistryKeyCodeUnits -
                                       encoded_length) {
                    return RegistryPolicyLoadStatus::kInvalidRegistryPolicy;
                }
                encoded_length += value.size() + 1;
                rule.components.push_back(std::move(value));
            }
            for (const auto& existing : implementation->rules) {
                if (!SameRoot(existing, rule)) {
                    continue;
                }
                if (existing.kind == rule.kind ||
                    (existing.kind != RuleKind::kNoAccess &&
                     rule.kind != RuleKind::kNoAccess)) {
                    return RegistryPolicyLoadStatus::kInvalidRegistryPolicy;
                }
            }
            implementation->rules.push_back(std::move(rule));
        }
        if (!reader.Finished()) {
            return RegistryPolicyLoadStatus::kInvalidRegistryPolicy;
        }
        policy = std::unique_ptr<RegistryPolicy>(
            new RegistryPolicy(std::move(implementation)));
        return RegistryPolicyLoadStatus::kValid;
    } catch (const std::bad_alloc&) {
        return RegistryPolicyLoadStatus::kOutOfMemory;
    } catch (...) {
        return RegistryPolicyLoadStatus::kInvalidRegistryPolicy;
    }
}

RegistryDecision RegistryPolicy::Decide(
    const RegistryHive hive,
    const wchar_t* relative_key,
    const RegistryAccess access) const noexcept {
    if (implementation_ == nullptr ||
        static_cast<std::uint8_t>(hive) >
            static_cast<std::uint8_t>(RegistryHive::kCurrentConfig) ||
        static_cast<std::uint8_t>(access) >
            static_cast<std::uint8_t>(RegistryAccess::kEnumerate)) {
        return RegistryDecision::kDeny;
    }
    try {
        std::vector<std::wstring> components;
        if (!ParseRelativeKey(relative_key, components)) {
            return RegistryDecision::kDeny;
        }
        const Rule* deepest = nullptr;
        for (const auto& rule : implementation_->rules) {
            if (!Contains(rule, hive, components)) {
                continue;
            }
            if (rule.kind == RuleKind::kNoAccess) {
                return RegistryDecision::kDeny;
            }
            if (deepest == nullptr ||
                rule.components.size() > deepest->components.size()) {
                deepest = &rule;
            }
        }
        return deepest == nullptr ? RegistryDecision::kDeny
                                  : DecisionFor(deepest->kind, access);
    } catch (...) {
        return RegistryDecision::kDeny;
    }
}

bool RegistryPolicy::MayTraverse(
    const RegistryHive hive,
    const wchar_t* relative_key) const noexcept {
    if (implementation_ == nullptr ||
        static_cast<std::uint8_t>(hive) >
            static_cast<std::uint8_t>(RegistryHive::kCurrentConfig)) {
        return false;
    }
    try {
        std::vector<std::wstring> components;
        if (!ParseRelativeKey(relative_key, components)) {
            return false;
        }
        return std::any_of(
            implementation_->rules.begin(), implementation_->rules.end(),
            [hive, &components](const Rule& rule) {
                return rule.hive == hive &&
                    components.size() < rule.components.size() &&
                    std::equal(
                        components.begin(), components.end(),
                        rule.components.begin(), EqualIgnoreCase);
            });
    } catch (...) {
        return false;
    }
}

}  // namespace bolt::registry
