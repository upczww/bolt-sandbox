#include "TreeNode.h"
#include "PathTree.h"
#include "CanonicalizedPath.h"
#include "FilesCheckedForAccess.h"
#include "ResolvedPathCache.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

bool RunBuildXlTreeTests() {
    TreeNodeChildren children;
    auto original = std::make_unique<TreeNode>();
    TreeNode* original_pointer = original.get();
    children.emplace(L"MixedCase", original_pointer);

    std::pair<std::wstring, TreeNode*> found;
    if (!children.find(L"mixedcase", found) || found.first != L"MixedCase" ||
        found.second != original_pointer) {
        return false;
    }

    std::vector<std::unique_ptr<TreeNode>> owned_nodes;
    owned_nodes.reserve(TREE_NODE_CHILDREN_THRESHOLD + 2U);
    for (std::size_t index = 0; index < TREE_NODE_CHILDREN_THRESHOLD + 2U; ++index) {
        owned_nodes.push_back(std::make_unique<TreeNode>());
        TreeNode* node = owned_nodes.back().get();
        children.emplace(L"child-" + std::to_wstring(index), node);
    }

    if (children.size() != TREE_NODE_CHILDREN_THRESHOLD + 3U) {
        return false;
    }
    if (!children.find(L"CHILD-101", found) || found.second != owned_nodes[101].get()) {
        return false;
    }

    children.erase(L"MIXEDCASE");
    if (children.find(L"mixedcase", found)) {
        return false;
    }

    PathTree paths;
    if (!paths.TryInsert(L"C:\\Root\\first.txt") ||
        !paths.TryInsert(L"c:\\root\\nested\\second.txt") ||
        !paths.TryInsert(L"D:\\outside.txt")) {
        return false;
    }

    std::vector<std::wstring> descendants;
    paths.RetrieveAndRemoveAllDescendants(L"C:\\ROOT", descendants);
    if (descendants.size() != 2U) {
        return false;
    }

    descendants.clear();
    paths.RetrieveAndRemoveAllDescendants(L"c:\\root", descendants);
    if (!descendants.empty()) {
        return false;
    }
    paths.RetrieveAndRemoveAllDescendants(L"D:\\", descendants);
    if (descendants.size() != 1U || descendants[0] != L"D:\\outside.txt") {
        return false;
    }

    const auto canonical = CanonicalizedPath::Canonicalize(L"C:\\root\\.\\child\\..\\file.txt");
    if (canonical.IsNull() || canonical.Type != PathType::Win32 ||
        std::wstring(canonical.GetPathString()) != L"C:\\root\\file.txt" ||
        std::wstring(canonical.GetLastComponent()) != L"file.txt") {
        return false;
    }

    const auto device = CanonicalizedPath::Canonicalize(L"\\\\.\\C:\\root\\..\\file.txt");
    if (device.IsNull() || device.Type != PathType::LocalDevice ||
        std::wstring(device.GetPathStringWithoutTypePrefix()) != L"C:\\file.txt") {
        return false;
    }

    std::size_t extension_start = 0;
    const auto extended = canonical.RemoveLastComponent().Extend(L"\\nested\\result.bin", &extension_start);
    if (std::wstring(extended.GetPathString()) != L"C:\\root\\nested\\result.bin" ||
        extension_start != 8U) {
        return false;
    }

    const auto first_access = CanonicalizedPath::Canonicalize(L"C:\\bolt-tests\\checked.txt");
    const auto same_access = CanonicalizedPath::Canonicalize(L"c:\\BOLT-TESTS\\CHECKED.txt");
    auto* checked = FilesCheckedForAccess::GetInstance();
    if (!checked->TryRegisterPath(first_access) || checked->TryRegisterPath(same_access) ||
        !checked->IsRegistered(same_access)) {
        return false;
    }

    const std::wstring mixed_case_path = L"C:\\Root\\File.txt";
    const std::wstring upper_case_path = L"C:\\ROOT\\FILE.TXT";
    if (HashPath(mixed_case_path.c_str(), mixed_case_path.size()) !=
            HashPath(upper_case_path.c_str(), upper_case_path.size()) ||
        !IsPathWithinTree(L"C:\\Root", L"c:\\root\\nested\\file.txt") ||
        IsPathWithinTree(L"C:\\Root", L"C:\\Rooted\\file.txt")) {
        return false;
    }

    const std::wstring named_stream = L"C:\\Root\\file.txt:metadata";
    const std::wstring default_stream = L"C:\\Root\\file.txt::$DATA";
    if (!IsPathToNamedStream(named_stream.c_str(), named_stream.size()) ||
        IsPathToNamedStream(default_stream.c_str(), default_stream.size())) {
        return false;
    }

    ResolvedPathCache cache;
    if (!cache.InsertResolvingCheckResult(L"C:\\Root\\Link\\", true)) {
        return false;
    }
    const auto resolving = cache.GetResolvingCheckResult(L"c:\\root\\link");
    if (!resolving.Found || !resolving.Value) {
        return false;
    }

    std::wstring target = L"C:\\Resolved\\Target";
    if (!cache.InsertResolvedPathWithType(L"\\\\?\\C:\\Root\\Link", target, 0xA000000CU)) {
        return false;
    }
    const auto target_lookup = cache.GetResolvedPathAndType(L"C:\\ROOT\\LINK");
    if (!target_lookup.Found || target_lookup.Value.first != target ||
        target_lookup.Value.second != 0xA000000CU) {
        return false;
    }

    auto insertion_order = std::make_shared<std::vector<std::wstring>>(
        std::initializer_list<std::wstring>{L"C:\\Root\\Middle"});
    auto resolved_paths =
        std::make_shared<std::map<std::wstring, ResolvedPathType, CaseInsensitiveStringLessThan>>();
    resolved_paths->emplace(L"C:\\Root\\Middle", ResolvedPathType::Intermediate);
    resolved_paths->emplace(L"C:\\Resolved\\Target", ResolvedPathType::FullyResolved);
    if (!cache.InsertResolvedPaths(
            L"C:\\Root\\Alias", false, insertion_order, resolved_paths) ||
        !cache.GetResolvedPaths(L"c:\\root\\alias", false).Found) {
        return false;
    }
    cache.Invalidate(L"C:\\ROOT\\MIDDLE", false);
    if (cache.GetResolvedPaths(L"C:\\Root\\Alias", false).Found) {
        return false;
    }

    cache.InsertResolvingCheckResult(L"C:\\Tree\\Child\\Leaf", true);
    cache.Invalidate(L"C:\\Tree", true);
    if (cache.GetResolvingCheckResult(L"C:\\Tree\\Child\\Leaf").Found) {
        return false;
    }

    return NormalizePath(L"C:\\Root\\.\\nested\\..\\file.txt") == L"C:\\Root\\file.txt" &&
           NormalizePath(L"relative\\.\\path") == L"relative\\.\\path" &&
           PathCombine(L"C:\\Root", L"nested\\file.txt") ==
               L"C:\\Root\\nested\\file.txt";
}
