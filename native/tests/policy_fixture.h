#pragma once

#include <cstdint>
#include <filesystem>
#include <vector>

namespace bolt::tests {

enum class FilesystemRuleKind : std::uint8_t {
    kReadWrite,
    kReadOnly,
    kDeny,
    kMetadataRead,
    kInheritUser,
};

struct FilesystemRule {
    FilesystemRuleKind kind;
    std::filesystem::path root;
};

enum class ChildProcessPolicyKind : std::uint8_t {
    kInherit = 0,
    kDeny = 1,
};

std::vector<std::uint8_t> SealPolicy(
    const std::vector<FilesystemRule>& filesystem_rules,
    ChildProcessPolicyKind child_process_policy =
        ChildProcessPolicyKind::kInherit);

}  // namespace bolt::tests
