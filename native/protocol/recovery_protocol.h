#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace bolt::protocol {

inline constexpr std::size_t kRecoveryRequestHeaderLength = 32;
inline constexpr std::size_t kRecoveryResponseLength = 40;
inline constexpr std::size_t kRecoveryMaximumRequestLength =
    kRecoveryRequestHeaderLength + 32'767 * sizeof(wchar_t);

enum class RecoveryOperation : std::uint8_t {
    kDelete = 1,
    kTruncate = 2,
    kReplace = 3,
    kRename = 4,
};

enum class RecoveryProtocolStatus : std::uint8_t {
    kSuccess,
    kInvalidArgument,
    kInvalidLength,
    kInvalidMagic,
    kUnsupportedVersion,
    kInvalidHeader,
    kInvalidField,
    kAllocationFailed,
};

struct RecoveryResponse {
    std::uint64_t request_id = 0;
    bool succeeded = false;
    std::uint64_t artifact_id = 0;
    std::uint64_t byte_count = 0;
};

RecoveryProtocolStatus EncodeRecoveryRequest(
    std::uint64_t request_id,
    std::uint32_t process_id,
    RecoveryOperation operation,
    const wchar_t* path,
    std::vector<std::uint8_t>& encoded) noexcept;

RecoveryProtocolStatus DecodeRecoveryResponse(
    const std::uint8_t* encoded,
    std::size_t length,
    RecoveryResponse& response) noexcept;

}  // namespace bolt::protocol
