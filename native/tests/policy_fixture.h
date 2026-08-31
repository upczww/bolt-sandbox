#pragma once

#include <cstdint>
#include <array>
#include <filesystem>
#include <string>
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

enum class NetworkPolicyKind : std::uint8_t {
    kUnrestricted = 0,
    kDenied = 1,
    kAllowList = 2,
};

struct NetworkDomainRule {
    bool wildcard = false;
    std::string ascii_domain;
};

struct NetworkAddressRule {
    std::uint8_t family = 4;
    std::uint8_t prefix_length = 0;
    std::array<std::uint8_t, 16> address{};
};

struct NetworkPortRule {
    std::uint16_t start = 0;
    std::uint16_t end = 0;
};

struct NetworkAllowListRules {
    std::vector<NetworkDomainRule> domains;
    std::vector<NetworkAddressRule> addresses;
    std::vector<NetworkPortRule> ports;
};

enum class RegistryRuleKind : std::uint8_t {
    kNoAccess = 0,
    kReadOnly = 1,
    kInheritUser = 2,
    kReadWrite = 3,
    kReadOnlyKey = 4,
    kHideKey = 5,
};

enum class RegistryHive : std::uint8_t {
    kClassesRoot = 0,
    kCurrentUser = 1,
    kLocalMachine = 2,
    kUsers = 3,
    kCurrentConfig = 4,
};

struct RegistryRule {
    RegistryRuleKind kind = RegistryRuleKind::kNoAccess;
    RegistryHive hive = RegistryHive::kCurrentUser;
    std::vector<std::string> components;
};

std::vector<std::uint8_t> SealPolicy(
    const std::vector<FilesystemRule>& filesystem_rules,
    ChildProcessPolicyKind child_process_policy =
        ChildProcessPolicyKind::kInherit,
    NetworkPolicyKind network_policy = NetworkPolicyKind::kUnrestricted,
    const NetworkAllowListRules& network_allow_list = {},
    const std::vector<RegistryRule>& registry_rules = {});

}  // namespace bolt::tests
