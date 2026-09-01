#include "hook/filesystem/bounded_resolved_path_cache.h"

#include <string>

namespace {

bool ExactLookupAndInvalidation() {
    bolt::filesystem::BoundedResolvedPathCache cache;
    std::wstring resolved;
    if (!cache.Store(
            L"C:\\work\\link\\file.cpp",
            L"C:\\real\\source\\file.cpp") ||
        !cache.Lookup(L"C:\\work\\link\\file.cpp", resolved) ||
        resolved != L"C:\\real\\source\\file.cpp" ||
        cache.Lookup(L"C:\\WORK\\link\\file.cpp", resolved)) {
        return false;
    }
    cache.Invalidate(L"C:\\real\\source\\file.cpp", false);
    return !cache.Lookup(L"C:\\work\\link\\file.cpp", resolved) &&
           cache.size() == 0;
}

bool DirectoryInvalidationRemovesDescendantsOnly() {
    bolt::filesystem::BoundedResolvedPathCache cache;
    std::wstring resolved;
    return cache.Store(L"C:\\work\\tree", L"C:\\real\\tree") &&
           cache.Store(
               L"C:\\work\\tree\\child", L"C:\\real\\tree\\child") &&
           cache.Store(L"C:\\work\\sibling", L"C:\\real\\sibling") &&
           (cache.Invalidate(L"C:\\real\\tree", true), true) &&
           !cache.Lookup(L"C:\\work\\tree", resolved) &&
           !cache.Lookup(L"C:\\work\\tree\\child", resolved) &&
           cache.Lookup(L"C:\\work\\sibling", resolved) &&
           resolved == L"C:\\real\\sibling";
}

bool RelativeAndOversizedPathsFallBack() {
    bolt::filesystem::BoundedResolvedPathCache cache;
    std::wstring oversized(
        bolt::filesystem::BoundedResolvedPathCache::kMaximumPathLength + 1,
        L'a');
    return !cache.Store(L"relative", L"C:\\real") &&
           !cache.Store(oversized.c_str(), L"C:\\real") &&
           !cache.Store(L"C:\\work", oversized.c_str()) &&
           cache.size() == 0;
}

}  // namespace

bool RunBoundedResolvedPathCacheTests() {
    return ExactLookupAndInvalidation() &&
           DirectoryInvalidationRemovesDescendantsOnly() &&
           RelativeAndOversizedPathsFallBack();
}
