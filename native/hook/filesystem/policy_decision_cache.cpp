#include "hook/filesystem/policy_decision_cache.h"

#include <utility>

namespace bolt::filesystem {
namespace {

bool Separator(const wchar_t value) noexcept {
    return value == L'\\' || value == L'/';
}

}  // namespace

bool PolicyDecisionCache::Cacheable(const wchar_t* const path) noexcept {
    if (path == nullptr) {
        return false;
    }
    std::size_t length = 0;
    while (length <= kMaximumPathLength && path[length] != L'\0') {
        ++length;
    }
    if (length == 0 || length > kMaximumPathLength) {
        return false;
    }
    const bool drive_absolute =
        length >= 3 && path[1] == L':' && Separator(path[2]);
    const bool network_or_extended =
        length >= 2 && Separator(path[0]) && Separator(path[1]);
    const bool nt_absolute =
        length >= 4 && path[0] == L'\\' && path[1] == L'?' &&
        path[2] == L'?' && Separator(path[3]);
    return drive_absolute || network_or_extended || nt_absolute;
}

std::size_t PolicyDecisionCache::Hash(
    const wchar_t* const path,
    const Access access) noexcept {
    std::uint64_t hash = 14'695'981'039'346'656'037ULL ^
                         static_cast<std::uint8_t>(access);
    for (const wchar_t* current = path; *current != L'\0'; ++current) {
        hash ^= static_cast<std::uint16_t>(*current);
        hash *= 1'099'511'628'211ULL;
    }
    return static_cast<std::size_t>(hash & (kCapacity - 1));
}

bool PolicyDecisionCache::Store(
    const wchar_t* const path,
    const Access access,
    const PolicyEvaluation& evaluation) noexcept {
    if (!Cacheable(path) || evaluation.normalized_path.empty() ||
        evaluation.normalized_path.size() > kMaximumPathLength) {
        return false;
    }
    std::wstring stored_path;
    std::wstring stored_normalized;
    try {
        stored_path.assign(path);
        stored_normalized = evaluation.normalized_path;
    } catch (...) {
        return false;
    }

    AcquireSRWLockExclusive(&lock_);
    const std::size_t start = Hash(path, access);
    for (std::size_t probe = 0; probe < kCapacity; ++probe) {
        auto& entry = entries_[(start + probe) & (kCapacity - 1)];
        if (entry.occupied && entry.access == access &&
            entry.path == stored_path) {
            ReleaseSRWLockExclusive(&lock_);
            return true;
        }
        if (!entry.occupied) {
            entry.path = std::move(stored_path);
            entry.normalized_path = std::move(stored_normalized);
            entry.access = access;
            entry.decision = evaluation.decision;
            entry.occupied = true;
            ++size_;
            ReleaseSRWLockExclusive(&lock_);
            return true;
        }
    }
    ReleaseSRWLockExclusive(&lock_);
    return false;
}

bool PolicyDecisionCache::Lookup(
    const wchar_t* const path,
    const Access access,
    PolicyEvaluation& evaluation) const noexcept {
    if (!Cacheable(path)) {
        return false;
    }
    AcquireSRWLockShared(&lock_);
    const std::size_t start = Hash(path, access);
    for (std::size_t probe = 0; probe < kCapacity; ++probe) {
        const auto& entry = entries_[(start + probe) & (kCapacity - 1)];
        if (!entry.occupied) {
            break;
        }
        if (entry.access == access && entry.path == path) {
            try {
                evaluation.decision = entry.decision;
                evaluation.normalized_path = entry.normalized_path;
                ReleaseSRWLockShared(&lock_);
                return true;
            } catch (...) {
                evaluation = {};
                ReleaseSRWLockShared(&lock_);
                return false;
            }
        }
    }
    ReleaseSRWLockShared(&lock_);
    return false;
}

std::size_t PolicyDecisionCache::size() const noexcept {
    AcquireSRWLockShared(&lock_);
    const std::size_t result = size_;
    ReleaseSRWLockShared(&lock_);
    return result;
}

}  // namespace bolt::filesystem
