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

std::vector<std::uint8_t> SealPolicy(
    const std::vector<FilesystemRule>& filesystem_rules);

}  // namespace bolt::tests
