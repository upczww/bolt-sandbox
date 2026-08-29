#include "TreeNode.h"

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
    return !children.find(L"mixedcase", found);
}
