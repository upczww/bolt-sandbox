#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace bolt::protocol {

inline constexpr std::uint16_t kProtocolVersion = 1;
inline constexpr std::array<std::uint8_t, 4> kPolicyMagic = {'B', 'L', 'P', '1'};
inline constexpr std::size_t kPolicyEnvelopeLength = 44;
inline constexpr std::size_t kPolicyVersionOffset = 4;
inline constexpr std::size_t kPolicyHeaderLengthOffset = 6;
inline constexpr std::size_t kPolicyBodyLengthOffset = 8;
inline constexpr std::size_t kPolicyDigestOffset = 12;
inline constexpr std::size_t kPolicyMaximumBodyLength = 1'048'576;

}  // namespace bolt::protocol
