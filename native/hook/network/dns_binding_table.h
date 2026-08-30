#pragma once

#include "hook/network/network_policy.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>

namespace bolt::network {

enum class BindingStatus : std::uint8_t {
    kSuccess,
    kInvalidArgument,
    kFull,
    kAllocationFailed,
};

struct BindingKey {
    std::array<std::uint8_t, 16> session_id{};
    std::uint32_t process_id = 0;
    const char* ascii_domain = nullptr;
    AddressFamily family = AddressFamily::kIpv4;
    const std::uint8_t* address = nullptr;
    std::size_t address_length = 0;
    std::uint16_t port = 0;
};

class DnsBindingTable final {
  public:
    ~DnsBindingTable();

    DnsBindingTable(const DnsBindingTable&) = delete;
    DnsBindingTable& operator=(const DnsBindingTable&) = delete;

    static BindingStatus Create(
        std::size_t capacity,
        std::unique_ptr<DnsBindingTable>& table) noexcept;

    BindingStatus Upsert(
        const BindingKey& key,
        std::uint64_t now,
        std::uint64_t ttl) noexcept;

    [[nodiscard]] bool IsAuthorized(
        const BindingKey& key,
        std::uint64_t now) const noexcept;

    [[nodiscard]] bool IsEndpointAuthorized(
        const std::array<std::uint8_t, 16>& session_id,
        std::uint32_t process_id,
        AddressFamily family,
        const std::uint8_t* address,
        std::size_t address_length,
        std::uint16_t port,
        std::uint64_t now) const noexcept;

    [[nodiscard]] std::size_t ActiveCount(std::uint64_t now) const noexcept;

  private:
    struct Impl;
    explicit DnsBindingTable(std::unique_ptr<Impl> implementation) noexcept;

    std::unique_ptr<Impl> implementation_;
};

}  // namespace bolt::network
