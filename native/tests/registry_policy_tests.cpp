#include "hook/registry/registry_policy.h"

#include "tests/policy_fixture.h"

#include <memory>
#include <vector>

bool RunRegistryPolicyTests() {
    const std::vector<bolt::tests::RegistryRule> rules = {
        {bolt::tests::RegistryRuleKind::kReadWrite,
         bolt::tests::RegistryHive::kCurrentUser,
         {"Software"}},
        {bolt::tests::RegistryRuleKind::kReadOnly,
         bolt::tests::RegistryHive::kCurrentUser,
         {"Software", "ReadOnly"}},
        {bolt::tests::RegistryRuleKind::kNoAccess,
         bolt::tests::RegistryHive::kCurrentUser,
         {"Software", "ReadOnly", "Credentials"}},
        {bolt::tests::RegistryRuleKind::kInheritUser,
         bolt::tests::RegistryHive::kLocalMachine,
         {"Software", "Compatibility"}},
        {bolt::tests::RegistryRuleKind::kReadOnly,
         bolt::tests::RegistryHive::kLocalMachine,
         {"Software", "Vendor"}},
        {bolt::tests::RegistryRuleKind::kReadOnlyKey,
         bolt::tests::RegistryHive::kLocalMachine,
         {"Software", "VersionMetadata"}},
        {bolt::tests::RegistryRuleKind::kHideKey,
         bolt::tests::RegistryHive::kCurrentUser,
         {"HiddenMetadata"}},
    };
    const auto payload = bolt::tests::SealPolicy(
        {}, bolt::tests::ChildProcessPolicyKind::kInherit,
        bolt::tests::NetworkPolicyKind::kUnrestricted, {}, rules);
    std::unique_ptr<bolt::registry::RegistryPolicy> policy;
    if (payload.empty() ||
        bolt::registry::RegistryPolicy::Load(
            payload.data(), payload.size(), policy) !=
            bolt::registry::RegistryPolicyLoadStatus::kValid ||
        policy == nullptr) {
        return false;
    }

    using Access = bolt::registry::RegistryAccess;
    using Decision = bolt::registry::RegistryDecision;
    using Hive = bolt::registry::RegistryHive;
    if (policy->Decide(Hive::kCurrentUser, L"Software\\Ordinary", Access::kRead) !=
            Decision::kAllow ||
        policy->Decide(Hive::kCurrentUser, L"Software\\Ordinary", Access::kWrite) !=
            Decision::kAllow ||
        policy->Decide(
            Hive::kCurrentUser, L"SOFTWARE\\\\readonly\\Value",
            Access::kRead) != Decision::kAllow ||
        policy->Decide(
            Hive::kCurrentUser, L"Software\\ReadOnly\\Value",
            Access::kEnumerate) != Decision::kAllow ||
        policy->Decide(
            Hive::kCurrentUser, L"Software\\ReadOnly\\Value",
            Access::kWrite) != Decision::kDeny ||
        policy->Decide(
            Hive::kCurrentUser,
            L"Software\\ReadOnly\\Credentials\\Token", Access::kRead) !=
            Decision::kDeny ||
        policy->Decide(
            Hive::kCurrentUser,
            L"Software\\ReadOnly\\Credentials\\Token", Access::kWrite) !=
            Decision::kDeny ||
        policy->Decide(
            Hive::kLocalMachine, L"Software\\Compatibility\\Legacy",
            Access::kWrite) != Decision::kInheritUser ||
        policy->Decide(
            Hive::kLocalMachine,
            L"Software\\Wow6432Node\\Vendor\\Product",
            Access::kRead) != Decision::kAllow ||
        policy->Decide(
            Hive::kLocalMachine,
            L"Software\\Wow6432Node\\Vendor\\Product",
            Access::kWrite) != Decision::kDeny ||
        policy->Decide(
            Hive::kLocalMachine, L"Software\\VersionMetadata",
            Access::kRead) != Decision::kAllow ||
        policy->Decide(
            Hive::kLocalMachine, L"Software\\VersionMetadata",
            Access::kWrite) != Decision::kDeny ||
        policy->Decide(
            Hive::kLocalMachine,
            L"Software\\VersionMetadata\\Sensitive",
            Access::kRead) != Decision::kDeny ||
        policy->Decide(
            Hive::kCurrentUser, L"HiddenMetadata",
            Access::kRead) != Decision::kNotFound ||
        policy->Decide(
            Hive::kCurrentUser, L"HiddenMetadata",
            Access::kWrite) != Decision::kDeny ||
        policy->Decide(
            Hive::kCurrentUser, L"HiddenMetadata\\Sensitive",
            Access::kRead) != Decision::kDeny ||
        policy->Decide(Hive::kCurrentUser, L"Outside", Access::kRead) !=
            Decision::kDeny ||
        policy->Decide(
            static_cast<Hive>(0xff), L"Software", Access::kRead) !=
            Decision::kDeny ||
        policy->Decide(Hive::kCurrentUser, L"..\\Software", Access::kRead) !=
            Decision::kDeny ||
        !policy->MayTraverse(Hive::kCurrentUser, L"") ||
        !policy->MayTraverse(Hive::kCurrentUser, L"Software") ||
        policy->MayTraverse(Hive::kCurrentUser, L"Outside")) {
        return false;
    }

    auto corrupted = payload;
    corrupted.back() ^= 0xff;
    return bolt::registry::RegistryPolicy::Load(
               corrupted.data(), corrupted.size(), policy) ==
               bolt::registry::RegistryPolicyLoadStatus::kInvalidPayload &&
           policy == nullptr;
}
