#include "hook/filesystem/handle_access_cache.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <thread>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace {

HANDLE FakeHandle(const std::size_t value) noexcept {
    return reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(value + 4));
}

bool ExactAccessAndRemoval() {
    bolt::filesystem::HandleAccessCache cache;
    const HANDLE handle = FakeHandle(1);
    const HANDLE duplicate = FakeHandle(2);
    if (!cache.Store(handle, bolt::filesystem::HandleAccess::kRead) ||
        !cache.Allows(handle, bolt::filesystem::HandleAccess::kRead) ||
        cache.Allows(handle, bolt::filesystem::HandleAccess::kWrite) ||
        cache.Allows(duplicate, bolt::filesystem::HandleAccess::kRead) ||
        !cache.Store(handle, bolt::filesystem::HandleAccess::kMetadata) ||
        !cache.Allows(handle, bolt::filesystem::HandleAccess::kMetadata)) {
        return false;
    }
    cache.Remove(handle);
    return !cache.Allows(handle, bolt::filesystem::HandleAccess::kRead) &&
           cache.size() == 0;
}

bool CapacityExhaustionFailsToCache() {
    bolt::filesystem::HandleAccessCache cache;
    for (std::size_t index = 0;
         index < bolt::filesystem::HandleAccessCache::kCapacity; ++index) {
        if (!cache.Store(
                FakeHandle(index), bolt::filesystem::HandleAccess::kRead)) {
            return false;
        }
    }
    return !cache.Store(
               FakeHandle(bolt::filesystem::HandleAccessCache::kCapacity),
               bolt::filesystem::HandleAccess::kRead) &&
           cache.Allows(FakeHandle(0), bolt::filesystem::HandleAccess::kRead) &&
           cache.Allows(
               FakeHandle(bolt::filesystem::HandleAccessCache::kCapacity - 1),
               bolt::filesystem::HandleAccess::kRead);
}

bool ConcurrentDisjointAccessIsStable() {
    bolt::filesystem::HandleAccessCache cache;
    std::array<bool, 4> passed{};
    std::array<std::thread, 4> workers;
    for (std::size_t worker = 0; worker < workers.size(); ++worker) {
        workers[worker] = std::thread([worker, &cache, &passed] {
            passed[worker] = true;
            for (std::size_t index = 0; index < 256; ++index) {
                const HANDLE handle = FakeHandle(worker * 256 + index);
                if (!cache.Store(
                        handle, bolt::filesystem::HandleAccess::kWrite) ||
                    !cache.Allows(
                        handle, bolt::filesystem::HandleAccess::kWrite)) {
                    passed[worker] = false;
                    return;
                }
            }
        });
    }
    for (auto& worker : workers) {
        worker.join();
    }
    for (const bool result : passed) {
        if (!result) {
            return false;
        }
    }
    return cache.size() == 1'024;
}

}  // namespace

bool RunHandleAccessCacheTests() {
    return ExactAccessAndRemoval() && CapacityExhaustionFailsToCache() &&
           ConcurrentDisjointAccessIsStable();
}
