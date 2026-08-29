#include "TreeNode.h"
#include "PathTree.h"
#include "CanonicalizedPath.h"

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
    return std::wstring(extended.GetPathString()) == L"C:\\root\\nested\\result.bin" &&
           extension_start == 8U;
}
