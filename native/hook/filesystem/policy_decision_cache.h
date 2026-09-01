#pragma once

#include "hook/filesystem/filesystem_policy.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace bolt::filesystem {

class PolicyDecisionCache final {
  public:
    static constexpr std::size_t kCapacity = 2'048;
    static constexpr std::size_t kMaximumPathLength = 1'024;

    PolicyDecisionCache() noexcept = default;
    PolicyDecisionCache(const PolicyDecisionCache&) = delete;
    PolicyDecisionCache& operator=(const PolicyDecisionCache&) = delete;

    bool Store(
        const wchar_t* path,
        Access access,
        const PolicyEvaluation& evaluation) noexcept;
    [[nodiscard]] bool Lookup(
        const wchar_t* path,
        Access access,
        PolicyEvaluation& evaluation) const noexcept;
    [[nodiscard]] std::size_t size() const noexcept;

  private:
    struct Entry {
        std::wstring path;
        std::wstring normalized_path;
        Access access = Access::kMetadata;
        Decision decision = Decision::kDeny;
        bool occupied = false;
    };

    static bool Cacheable(const wchar_t* path) noexcept;
    static std::size_t Hash(const wchar_t* path, Access access) noexcept;

    mutable SRWLOCK lock_ = SRWLOCK_INIT;
    std::array<Entry, kCapacity> entries_{};
    std::size_t size_ = 0;
};

}  // namespace bolt::filesystem
