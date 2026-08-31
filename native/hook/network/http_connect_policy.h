#pragma once

#include "hook/network/network_policy.h"

#include <cstddef>
#include <cstdint>

namespace bolt::network {

inline constexpr std::size_t kMaximumHttpConnectPrefaceLength = 4'096;

enum class HttpConnectInspection : std::uint8_t {
    kNeedMore,
    kNotConnect,
    kAllow,
    kDeny,
};

HttpConnectInspection InspectHttpConnectPreface(
    const char* bytes,
    std::size_t length,
    bool end_of_stream,
    const NetworkPolicy& policy) noexcept;

}  // namespace bolt::network
