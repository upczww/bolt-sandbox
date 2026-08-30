#pragma once

#include <cstddef>
#include <cstdint>

namespace bolt::protocol {
struct RuntimePayload;
}

namespace bolt::network {

enum class HookInstallStatus : std::uint8_t {
    kSuccess,
    kInvalidPolicy,
    kTransactionFailed,
};

HookInstallStatus InstallNetworkHooks(
    const std::uint8_t* policy_payload,
    std::size_t policy_length,
    const protocol::RuntimePayload& runtime) noexcept;

}  // namespace bolt::network
