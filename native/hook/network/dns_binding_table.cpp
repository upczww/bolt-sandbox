#include "hook/network/dns_binding_table.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <new>
#include <utility>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace bolt::network {
namespace {

constexpr std::size_t kMaximumCapacity = 4'096;
constexpr std::size_t kMaximumDomainLength = 253;

struct Entry {
    bool occupied = false;
    std::array<std::uint8_t, 16> session_id{};
    std::uint32_t process_id = 0;
    char domain[kMaximumDomainLength + 1U]{};
    AddressFamily family = AddressFamily::kIpv4;
    std::array<std::uint8_t, 16> address{};
    std::uint16_t port = 0;
    std::uint64_t expires_at = 0;
};

class SharedLock final {
  public:
    explicit SharedLock(SRWLOCK& lock) noexcept : lock_(lock) {
        AcquireSRWLockShared(&lock_);
    }
    ~SharedLock() { ReleaseSRWLockShared(&lock_); }

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
    ~ExclusiveLock() { ReleaseSRWLockExclusive(&lock_); }

    ExclusiveLock(const ExclusiveLock&) = delete;
    ExclusiveLock& operator=(const ExclusiveLock&) = delete;

  private:
    SRWLOCK& lock_;
};

bool ReadDomainLength(const char* domain, std::size_t& length) noexcept {
    length = 0;
    if (domain == nullptr) {
        return false;
    }
    std::size_t label_length = 0;
    bool first_is_hyphen = false;
    bool last_is_hyphen = false;
    while (length <= kMaximumDomainLength && domain[length] != '\0') {
        const unsigned char byte = static_cast<unsigned char>(domain[length]);
        if (byte == '.') {
            if (label_length == 0 || label_length > 63 || first_is_hyphen ||
                last_is_hyphen) {
                return false;
            }
            label_length = 0;
            first_is_hyphen = false;
            last_is_hyphen = false;
            ++length;
            continue;
        }
        if (!((byte >= 'a' && byte <= 'z') || (byte >= '0' && byte <= '9') ||
              byte == '-')) {
            return false;
        }
        if (label_length == 0) {
            first_is_hyphen = byte == '-';
        }
        ++label_length;
        last_is_hyphen = byte == '-';
        ++length;
    }
    return length != 0 && length <= kMaximumDomainLength && label_length != 0 &&
           label_length <= 63 && !first_is_hyphen && !last_is_hyphen;
}

bool ValidateKey(const BindingKey& key, std::size_t& domain_length) noexcept {
    const bool session_is_zero = std::all_of(
        key.session_id.begin(), key.session_id.end(),
        [](const std::uint8_t byte) { return byte == 0; });
    const std::size_t expected_address_length =
        key.family == AddressFamily::kIpv4
            ? 4
            : key.family == AddressFamily::kIpv6 ? 16 : 0;
    return !session_is_zero && key.process_id != 0 &&
           expected_address_length != 0 && key.address != nullptr &&
           key.address_length == expected_address_length &&
           ReadDomainLength(key.ascii_domain, domain_length);
}

bool Matches(const Entry& entry, const BindingKey& key) noexcept {
    const std::size_t address_length =
        key.family == AddressFamily::kIpv4 ? 4 : 16;
    return entry.occupied && entry.session_id == key.session_id &&
           entry.process_id == key.process_id && entry.family == key.family &&
           entry.port == key.port &&
           std::strcmp(entry.domain, key.ascii_domain) == 0 &&
           std::equal(
               entry.address.begin(), entry.address.begin() + address_length,
               key.address);
}

}  // namespace

struct DnsBindingTable::Impl {
    SRWLOCK lock = SRWLOCK_INIT;
    std::unique_ptr<Entry[]> entries;
    std::size_t capacity = 0;
};

DnsBindingTable::DnsBindingTable(std::unique_ptr<Impl> implementation) noexcept
    : implementation_(std::move(implementation)) {}

DnsBindingTable::~DnsBindingTable() = default;

BindingStatus DnsBindingTable::Create(
    const std::size_t capacity,
    std::unique_ptr<DnsBindingTable>& table) noexcept {
    table.reset();
    if (capacity == 0 || capacity > kMaximumCapacity) {
        return BindingStatus::kInvalidArgument;
    }
    try {
        auto implementation = std::make_unique<Impl>();
        implementation->entries = std::make_unique<Entry[]>(capacity);
        implementation->capacity = capacity;
        table = std::unique_ptr<DnsBindingTable>(
            new DnsBindingTable(std::move(implementation)));
        return BindingStatus::kSuccess;
    } catch (const std::bad_alloc&) {
        return BindingStatus::kAllocationFailed;
    } catch (...) {
        return BindingStatus::kAllocationFailed;
    }
}

BindingStatus DnsBindingTable::Upsert(
    const BindingKey& key,
    const std::uint64_t now,
    const std::uint64_t ttl) noexcept {
    std::size_t domain_length = 0;
    if (implementation_ == nullptr || ttl == 0 ||
        ttl > std::numeric_limits<std::uint64_t>::max() - now ||
        !ValidateKey(key, domain_length)) {
        return BindingStatus::kInvalidArgument;
    }
    const std::uint64_t expires_at = now + ttl;
    ExclusiveLock guard(implementation_->lock);
    Entry* available = nullptr;
    for (std::size_t index = 0; index < implementation_->capacity; ++index) {
        Entry& entry = implementation_->entries[index];
        if (entry.occupied && entry.expires_at <= now) {
            entry.occupied = false;
        }
        if (Matches(entry, key)) {
            entry.expires_at = expires_at;
            return BindingStatus::kSuccess;
        }
        if (!entry.occupied && available == nullptr) {
            available = &entry;
        }
    }
    if (available == nullptr) {
        return BindingStatus::kFull;
    }
    available->occupied = true;
    available->session_id = key.session_id;
    available->process_id = key.process_id;
    std::copy_n(key.ascii_domain, domain_length + 1U, available->domain);
    available->family = key.family;
    available->address.fill(0);
    std::copy_n(key.address, key.address_length, available->address.begin());
    available->port = key.port;
    available->expires_at = expires_at;
    return BindingStatus::kSuccess;
}

bool DnsBindingTable::IsAuthorized(
    const BindingKey& key,
    const std::uint64_t now) const noexcept {
    std::size_t domain_length = 0;
    if (implementation_ == nullptr || !ValidateKey(key, domain_length)) {
        return false;
    }
    SharedLock guard(implementation_->lock);
    for (std::size_t index = 0; index < implementation_->capacity; ++index) {
        const Entry& entry = implementation_->entries[index];
        if (entry.expires_at > now && Matches(entry, key)) {
            return true;
        }
    }
    return false;
}

bool DnsBindingTable::IsEndpointAuthorized(
    const std::array<std::uint8_t, 16>& session_id,
    const std::uint32_t process_id,
    const AddressFamily family,
    const std::uint8_t* const address,
    const std::size_t address_length,
    const std::uint16_t port,
    const std::uint64_t now) const noexcept {
    const std::size_t expected_length = family == AddressFamily::kIpv4
                                            ? 4
                                            : family == AddressFamily::kIpv6 ? 16 : 0;
    if (implementation_ == nullptr || process_id == 0 || port == 0 ||
        address == nullptr || address_length != expected_length) {
        return false;
    }
    SharedLock guard(implementation_->lock);
    for (std::size_t index = 0; index < implementation_->capacity; ++index) {
        const Entry& entry = implementation_->entries[index];
        if (entry.occupied && entry.expires_at > now &&
            entry.session_id == session_id && entry.process_id == process_id &&
            entry.family == family && (entry.port == 0 || entry.port == port) &&
            std::equal(
                entry.address.begin(), entry.address.begin() + address_length,
                address)) {
            return true;
        }
    }
    return false;
}

bool ClearDomainOutput(char* const output) noexcept {
    __try {
        output[0] = '\0';
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool CopyDomainOutput(
    const char* const domain,
    const std::size_t length,
    char* const output) noexcept {
    __try {
        std::copy_n(domain, length, output);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool DnsBindingTable::FindAuthorizedDomain(
    const std::array<std::uint8_t, 16>& session_id,
    const std::uint32_t process_id,
    const AddressFamily family,
    const std::uint8_t* const address,
    const std::size_t address_length,
    const std::uint16_t port,
    const std::uint64_t now,
    char* const output,
    const std::size_t output_capacity) const noexcept {
    if (output == nullptr || output_capacity == 0) {
        return false;
    }
    if (!ClearDomainOutput(output)) {
        return false;
    }
    const std::size_t expected_length = family == AddressFamily::kIpv4
                                            ? 4
                                            : family == AddressFamily::kIpv6 ? 16 : 0;
    if (implementation_ == nullptr || process_id == 0 || port == 0 ||
        address == nullptr || address_length != expected_length) {
        return false;
    }
    SharedLock guard(implementation_->lock);
    for (std::size_t index = 0; index < implementation_->capacity; ++index) {
        const Entry& entry = implementation_->entries[index];
        if (!entry.occupied || entry.expires_at <= now ||
            entry.session_id != session_id || entry.process_id != process_id ||
            entry.family != family ||
            (entry.port != 0 && entry.port != port) ||
            !std::equal(
                entry.address.begin(), entry.address.begin() + address_length,
                address)) {
            continue;
        }
        const std::size_t domain_length = std::strlen(entry.domain);
        if (domain_length + 1U > output_capacity) {
            return false;
        }
        return CopyDomainOutput(entry.domain, domain_length + 1U, output);
    }
    return false;
}

bool DnsBindingTable::HasAuthorizedDomain(
    const std::array<std::uint8_t, 16>& session_id,
    const std::uint32_t process_id,
    const char* const ascii_domain,
    const std::uint64_t now) const noexcept {
    std::size_t domain_length = 0;
    const bool session_is_zero = std::all_of(
        session_id.begin(), session_id.end(),
        [](const std::uint8_t byte) { return byte == 0; });
    if (implementation_ == nullptr || session_is_zero || process_id == 0 ||
        !ReadDomainLength(ascii_domain, domain_length)) {
        return false;
    }
    SharedLock guard(implementation_->lock);
    for (std::size_t index = 0; index < implementation_->capacity; ++index) {
        const Entry& entry = implementation_->entries[index];
        if (entry.occupied && entry.expires_at > now &&
            entry.session_id == session_id && entry.process_id == process_id &&
            entry.port == 0 &&
            std::strcmp(entry.domain, ascii_domain) == 0) {
            return true;
        }
    }
    return false;
}

std::size_t DnsBindingTable::ActiveCount(const std::uint64_t now) const noexcept {
    if (implementation_ == nullptr) {
        return 0;
    }
    SharedLock guard(implementation_->lock);
    std::size_t count = 0;
    for (std::size_t index = 0; index < implementation_->capacity; ++index) {
        const Entry& entry = implementation_->entries[index];
        if (entry.occupied && entry.expires_at > now) {
            ++count;
        }
    }
    return count;
}

}  // namespace bolt::network
