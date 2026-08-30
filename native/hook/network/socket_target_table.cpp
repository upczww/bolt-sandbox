#include "hook/network/socket_target_table.h"

#include <algorithm>
#include <limits>
#include <new>
#include <utility>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace bolt::network {
namespace {

constexpr std::size_t kMaximumCapacity = 4'096;

struct Entry {
    bool occupied = false;
    std::uintptr_t socket = 0;
    protocol::NetworkEndpoint endpoint{};
};

class SharedLock final {
  public:
    explicit SharedLock(SRWLOCK& lock) noexcept : lock_(lock) {
        AcquireSRWLockShared(&lock_);
    }
    ~SharedLock() noexcept { ReleaseSRWLockShared(&lock_); }
    SharedLock(const SharedLock&) = delete;
    SharedLock& operator=(const SharedLock&) = delete;

  private:
    SRWLOCK& lock_;
};

class ExclusiveLock final {
  public:
    explicit ExclusiveLock(SRWLOCK& lock) noexcept : lock_(lock) {
        AcquireSRWLockExclusive(&lock_);
    }
    ~ExclusiveLock() noexcept { ReleaseSRWLockExclusive(&lock_); }
    ExclusiveLock(const ExclusiveLock&) = delete;
    ExclusiveLock& operator=(const ExclusiveLock&) = delete;

  private:
    SRWLOCK& lock_;
};

bool ValidSocket(const std::uintptr_t socket) noexcept {
    return socket != 0 && socket != std::numeric_limits<std::uintptr_t>::max();
}

bool ValidEndpoint(const protocol::NetworkEndpoint& endpoint) noexcept {
    if (endpoint.port == 0) {
        return false;
    }
    if (endpoint.family == protocol::NetworkAddressFamily::kIpv6) {
        return true;
    }
    return endpoint.family == protocol::NetworkAddressFamily::kIpv4 &&
           std::all_of(
               endpoint.address.begin() + 4, endpoint.address.end(),
               [](const std::uint8_t byte) { return byte == 0; });
}

}  // namespace

struct SocketTargetTable::Impl {
    SRWLOCK lock = SRWLOCK_INIT;
    std::unique_ptr<Entry[]> entries;
    std::size_t capacity = 0;
};

SocketTargetTable::SocketTargetTable(
    std::unique_ptr<Impl> implementation) noexcept
    : implementation_(std::move(implementation)) {}

SocketTargetTable::~SocketTargetTable() = default;

SocketTargetStatus SocketTargetTable::Create(
    const std::size_t capacity,
    std::unique_ptr<SocketTargetTable>& table) noexcept {
    table.reset();
    if (capacity == 0 || capacity > kMaximumCapacity) {
        return SocketTargetStatus::kInvalidArgument;
    }
    try {
        auto implementation = std::make_unique<Impl>();
        implementation->entries = std::make_unique<Entry[]>(capacity);
        implementation->capacity = capacity;
        table = std::unique_ptr<SocketTargetTable>(
            new SocketTargetTable(std::move(implementation)));
        return SocketTargetStatus::kSuccess;
    } catch (...) {
        return SocketTargetStatus::kAllocationFailed;
    }
}

SocketTargetStatus SocketTargetTable::Upsert(
    const std::uintptr_t socket,
    const protocol::NetworkEndpoint& endpoint) noexcept {
    if (implementation_ == nullptr || !ValidSocket(socket) ||
        !ValidEndpoint(endpoint)) {
        return SocketTargetStatus::kInvalidArgument;
    }
    ExclusiveLock guard(implementation_->lock);
    Entry* available = nullptr;
    for (std::size_t index = 0; index < implementation_->capacity; ++index) {
        Entry& entry = implementation_->entries[index];
        if (entry.occupied && entry.socket == socket) {
            entry.endpoint = endpoint;
            return SocketTargetStatus::kSuccess;
        }
        if (!entry.occupied && available == nullptr) {
            available = &entry;
        }
    }
    if (available == nullptr) {
        return SocketTargetStatus::kFull;
    }
    available->occupied = true;
    available->socket = socket;
    available->endpoint = endpoint;
    return SocketTargetStatus::kSuccess;
}

bool SocketTargetTable::Lookup(
    const std::uintptr_t socket,
    protocol::NetworkEndpoint& endpoint) const noexcept {
    endpoint = {};
    if (implementation_ == nullptr || !ValidSocket(socket)) {
        return false;
    }
    SharedLock guard(implementation_->lock);
    for (std::size_t index = 0; index < implementation_->capacity; ++index) {
        const Entry& entry = implementation_->entries[index];
        if (entry.occupied && entry.socket == socket) {
            endpoint = entry.endpoint;
            return true;
        }
    }
    return false;
}

bool SocketTargetTable::Remove(const std::uintptr_t socket) noexcept {
    if (implementation_ == nullptr || !ValidSocket(socket)) {
        return false;
    }
    ExclusiveLock guard(implementation_->lock);
    for (std::size_t index = 0; index < implementation_->capacity; ++index) {
        Entry& entry = implementation_->entries[index];
        if (entry.occupied && entry.socket == socket) {
            entry = {};
            return true;
        }
    }
    return false;
}

}  // namespace bolt::network
