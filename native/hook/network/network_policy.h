#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>

namespace bolt::network {

enum class Mode : std::uint8_t {
    kUnrestricted,
    kDenied,
    kAllowList,
};

enum class AddressFamily : std::uint8_t {
    kIpv4 = 4,
    kIpv6 = 6,
};

enum class Decision : std::uint8_t {
    kAllow,
    kDeny,
};

enum class PolicyLoadStatus : std::uint8_t {
    kValid,
    kInvalidPayload,
    kInvalidNetworkPolicy,
    kOutOfMemory,
};

class NetworkPolicy final {
  public:
    ~NetworkPolicy();

    NetworkPolicy(const NetworkPolicy&) = delete;
    NetworkPolicy& operator=(const NetworkPolicy&) = delete;

    static PolicyLoadStatus Load(
        const std::uint8_t* payload,
        std::size_t length,
        std::unique_ptr<NetworkPolicy>& policy) noexcept;

    [[nodiscard]] Mode mode() const noexcept { return mode_; }

    [[nodiscard]] Decision DecideConnect() const noexcept {
        return mode_ == Mode::kUnrestricted ? Decision::kAllow : Decision::kDeny;
    }

    [[nodiscard]] Decision DecideDomain(const char* ascii_domain) const noexcept;

    [[nodiscard]] Decision DecideAddress(
        AddressFamily family,
        const std::uint8_t* address,
        std::size_t address_length) const noexcept;

    [[nodiscard]] Decision DecidePort(std::uint16_t port) const noexcept;

  private:
    struct Impl;
    NetworkPolicy(Mode mode, std::unique_ptr<Impl> implementation) noexcept;

    Mode mode_;
    std::unique_ptr<Impl> implementation_;
};

}  // namespace bolt::network
