#include "hook/filesystem/path_cache.h"

#include "CanonicalizedPath.h"
#include "ResolvedPathCache.h"

namespace bolt::filesystem {

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
