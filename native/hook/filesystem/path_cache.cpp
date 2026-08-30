#include "hook/filesystem/path_cache.h"

#include "CanonicalizedPath.h"
#include "ResolvedPathCache.h"

namespace bolt::filesystem {

bool TryGetResolvedPathForPolicy(
    const wchar_t* path,
    std::wstring& resolved_path) noexcept {
    if (path == nullptr) {
        return false;
    }
    try {
        const auto cached = ResolvedPathCache::Instance().GetResolvedPaths(path, false);
        if (!cached.Found || cached.Value.first == nullptr || cached.Value.second == nullptr) {
            return false;
        }
        for (auto iterator = cached.Value.first->rbegin();
             iterator != cached.Value.first->rend(); ++iterator) {
            const auto entry = cached.Value.second->find(*iterator);
            if (entry != cached.Value.second->end() &&
                entry->second == ResolvedPathType::FullyResolved) {
                resolved_path = entry->first;
                return true;
            }
        }
    } catch (...) {
        resolved_path.clear();
    }
    return false;
}

void CacheResolvedPathForPolicy(
    const wchar_t* path,
    const std::wstring& resolved_path) noexcept {
    if (path == nullptr || resolved_path.empty()) {
        return;
    }
    try {
        auto order = std::make_shared<std::vector<std::wstring>>();
        auto paths = std::make_shared<
            std::map<std::wstring, ResolvedPathType, CaseInsensitiveStringLessThan>>();
        order->push_back(resolved_path);
        paths->emplace(resolved_path, ResolvedPathType::FullyResolved);
        static_cast<void>(
            ResolvedPathCache::Instance().InsertResolvedPaths(path, false, order, paths));
    } catch (...) {
        // Resolution caching is best effort. The caller already has the final path.
    }
}

void InvalidateResolvedPathForMutation(
    const wchar_t* path,
    const bool is_directory) noexcept {
    if (path == nullptr) {
        return;
    }
    try {
        const auto canonical = CanonicalizedPath::Canonicalize(path);
        const wchar_t* normalized = canonical.GetPathStringWithoutTypePrefix();
        if (!canonical.IsNull() && normalized != nullptr) {
            ResolvedPathCache::Instance().Invalidate(normalized, is_directory);
        }
    } catch (...) {
        // Cache invalidation is best effort. Policy checks remain fail closed.
    }
}

}  // namespace bolt::filesystem
