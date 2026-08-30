#pragma once

#include "protocol/event_frame.h"

#include <cstddef>
#include <cstdint>
#include <memory>

namespace bolt::network {

enum class SocketTargetStatus : std::uint8_t {
    kSuccess,
    kInvalidArgument,
    kFull,
    kAllocationFailed,
};

class SocketTargetTable final {
  public:
    ~SocketTargetTable();
    SocketTargetTable(const SocketTargetTable&) = delete;
    SocketTargetTable& operator=(const SocketTargetTable&) = delete;

    static SocketTargetStatus Create(
        std::size_t capacity,
        std::unique_ptr<SocketTargetTable>& table) noexcept;

    SocketTargetStatus Upsert(
        std::uintptr_t socket,
        const protocol::NetworkEndpoint& endpoint) noexcept;

    [[nodiscard]] bool Lookup(
        std::uintptr_t socket,
        protocol::NetworkEndpoint& endpoint) const noexcept;

    bool Remove(std::uintptr_t socket) noexcept;

  private:
    struct Impl;
    explicit SocketTargetTable(std::unique_ptr<Impl> implementation) noexcept;
    std::unique_ptr<Impl> implementation_;
};

}  // namespace bolt::network
