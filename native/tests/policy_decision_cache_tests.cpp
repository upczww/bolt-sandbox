#include "hook/filesystem/policy_decision_cache.h"

#include <cstddef>
#include <string>

namespace {

bool AccessClassesRemainIndependent() {
    bolt::filesystem::PolicyDecisionCache cache;
    bolt::filesystem::PolicyEvaluation write{
        bolt::filesystem::Decision::kAllow, L"C:\\work\\source.cpp"};
    bolt::filesystem::PolicyEvaluation output;
    if (!cache.Store(
            L"C:\\work\\.\\source.cpp",
            bolt::filesystem::Access::kWrite, write) ||
        !cache.Lookup(
            L"C:\\work\\.\\source.cpp",
            bolt::filesystem::Access::kWrite, output) ||
        output.decision != bolt::filesystem::Decision::kAllow ||
        output.normalized_path != L"C:\\work\\source.cpp" ||
        cache.Lookup(
            L"C:\\work\\.\\source.cpp",
            bolt::filesystem::Access::kRead, output)) {
        return false;
    }
    return cache.size() == 1;
}

bool RelativeAndOversizedPathsAreNotCached() {
    bolt::filesystem::PolicyDecisionCache cache;
    bolt::filesystem::PolicyEvaluation evaluation{
        bolt::filesystem::Decision::kAllow, L"C:\\work\\relative.txt"};
    std::wstring oversized(
        bolt::filesystem::PolicyDecisionCache::kMaximumPathLength + 1, L'a');
    return !cache.Store(
               L"relative.txt", bolt::filesystem::Access::kRead,
               evaluation) &&
           !cache.Store(
               oversized.c_str(), bolt::filesystem::Access::kRead,
               evaluation) &&
           cache.size() == 0;
}

bool CapacityExhaustionFallsBackWithoutEvictingValidEntries() {
    bolt::filesystem::PolicyDecisionCache cache;
    for (std::size_t index = 0;
         index < bolt::filesystem::PolicyDecisionCache::kCapacity; ++index) {
        const std::wstring path =
            L"C:\\work\\entry-" + std::to_wstring(index);
        const bolt::filesystem::PolicyEvaluation evaluation{
            bolt::filesystem::Decision::kAllow, path};
        if (!cache.Store(
                path.c_str(), bolt::filesystem::Access::kRead,
                evaluation)) {
            return false;
        }
    }
    const bolt::filesystem::PolicyEvaluation overflow{
        bolt::filesystem::Decision::kAllow, L"C:\\work\\overflow"};
    bolt::filesystem::PolicyEvaluation first;
    return !cache.Store(
               L"C:\\work\\overflow", bolt::filesystem::Access::kRead,
               overflow) &&
           cache.Lookup(
               L"C:\\work\\entry-0", bolt::filesystem::Access::kRead,
               first) &&
           first.normalized_path == L"C:\\work\\entry-0";
}

}  // namespace

bool RunPolicyDecisionCacheTests() {
    return AccessClassesRemainIndependent() &&
           RelativeAndOversizedPathsAreNotCached() &&
           CapacityExhaustionFallsBackWithoutEvictingValidEntries();
}
