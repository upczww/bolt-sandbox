#include "hook/filesystem/handle_access_cache.h"

#include <limits>

namespace bolt::filesystem {
namespace {

bool ValidHandle(const HANDLE handle) noexcept {
    return handle != nullptr && handle != INVALID_HANDLE_VALUE;
}

std::uint8_t AccessMask(const HandleAccess access) noexcept {
    return static_cast<std::uint8_t>(access);
}

}  // namespace

std::size_t HandleAccessCache::Hash(const HANDLE handle) noexcept {
    constexpr std::uintptr_t multiplier =
        sizeof(std::uintptr_t) == 8 ? 11'400'714'819'323'198'485ULL
                                    : 2'654'435'761ULL;
    const auto value = reinterpret_cast<std::uintptr_t>(handle) >> 2U;
    return static_cast<std::size_t>((value * multiplier) & (kCapacity - 1));
}

bool HandleAccessCache::Store(
    const HANDLE handle,
    const HandleAccess access) noexcept {
    const std::uint8_t mask = AccessMask(access);
    if (!ValidHandle(handle) || mask == 0 || (mask & ~0x0fU) != 0) {
        return false;
    }

    AcquireSRWLockExclusive(&lock_);
    const std::size_t start = Hash(handle);
    std::size_t available = kCapacity;
    for (std::size_t probe = 0; probe < kCapacity; ++probe) {
        const std::size_t index = (start + probe) & (kCapacity - 1);
        auto& entry = entries_[index];
        if (entry.state == EntryState::kOccupied && entry.handle == handle) {
            entry.access |= mask;
            ReleaseSRWLockExclusive(&lock_);
            return true;
        }
        if (entry.state == EntryState::kTombstone && available == kCapacity) {
            available = index;
        }
        if (entry.state == EntryState::kEmpty) {
            if (available == kCapacity) {
                available = index;
            }
            break;
        }
    }
    if (available == kCapacity) {
        ReleaseSRWLockExclusive(&lock_);
        return false;
    }
    entries_[available] = {handle, mask, EntryState::kOccupied};
    ++size_;
    ReleaseSRWLockExclusive(&lock_);
    return true;
}

bool HandleAccessCache::Allows(
    const HANDLE handle,
    const HandleAccess access) noexcept {
    const std::uint8_t mask = AccessMask(access);
    if (!ValidHandle(handle) || mask == 0 || (mask & ~0x0fU) != 0) {
        return false;
    }

    AcquireSRWLockShared(&lock_);
    const std::size_t start = Hash(handle);
    for (std::size_t probe = 0; probe < kCapacity; ++probe) {
        const auto& entry = entries_[(start + probe) & (kCapacity - 1)];
        if (entry.state == EntryState::kEmpty) {
            break;
        }
        if (entry.state == EntryState::kOccupied && entry.handle == handle) {
            const bool allowed = (entry.access & mask) == mask;
            ReleaseSRWLockShared(&lock_);
            return allowed;
        }
    }
    ReleaseSRWLockShared(&lock_);
    return false;
}

void HandleAccessCache::Remove(const HANDLE handle) noexcept {
    if (!ValidHandle(handle)) {
        return;
    }
    AcquireSRWLockExclusive(&lock_);
    const std::size_t start = Hash(handle);
    for (std::size_t probe = 0; probe < kCapacity; ++probe) {
        auto& entry = entries_[(start + probe) & (kCapacity - 1)];
        if (entry.state == EntryState::kEmpty) {
            break;
        }
        if (entry.state == EntryState::kOccupied && entry.handle == handle) {
            entry = {nullptr, 0, EntryState::kTombstone};
            --size_;
            break;
        }
    }
    ReleaseSRWLockExclusive(&lock_);
}

std::size_t HandleAccessCache::size() noexcept {
    AcquireSRWLockShared(&lock_);
    const std::size_t result = size_;
    ReleaseSRWLockShared(&lock_);
    return result;
}

}  // namespace bolt::filesystem
