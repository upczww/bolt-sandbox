#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace bolt::protocol {

inline constexpr std::size_t kEventHeaderLength = 24;
inline constexpr std::size_t kReadyNonceLength = 16;
inline constexpr std::size_t kReadyFrameLength = kEventHeaderLength + kReadyNonceLength;
inline constexpr std::size_t kProcessViolationFrameLength = kEventHeaderLength + 5;
inline constexpr std::size_t kChildInjectionFailureFrameLength =
    kEventHeaderLength + 9;
inline constexpr std::size_t kIpv4NetworkViolationFrameLength = kEventHeaderLength + 12;
inline constexpr std::size_t kIpv6NetworkViolationFrameLength = kEventHeaderLength + 24;
inline constexpr std::size_t kEventsDroppedFrameLength = kEventHeaderLength + 12;
inline constexpr std::size_t kMaximumEventDomainBytes = 253;
inline constexpr std::size_t kMaximumEventPathCodeUnits = 32'767;

enum class FilesystemOperation : std::uint8_t {
    kRead = 0,
    kWrite = 1,
    kMetadata = 2,
    kCreate = 3,
    kDelete = 4,
    kRename = 5,
    kEnumerate = 6,
};

enum class ProcessOperation : std::uint8_t {
    kCreateWithToken = 0,
    kCreateWithLogon = 1,
    kElevation = 2,
    kBreakaway = 3,
    kMitigationWeakening = 4,
    kExternalDelegation = 5,
};

enum class ChildInjectionFailureReason : std::uint8_t {
    kUnsupportedArchitecture = 0,
    kPolicyUnavailable = 1,
    kInjectionFailed = 2,
    kHandshakeFailed = 3,
    kMitigationFailed = 4,
};

enum class RegistryOperation : std::uint8_t {
    kOpen = 0,
    kQuery = 1,
    kEnumerate = 2,
    kCreate = 3,
    kSetValue = 4,
    kDelete = 5,
    kRename = 6,
    kUnsupportedRemote = 7,
    kUnsupportedTransactional = 8,
};

enum class NetworkOperation : std::uint8_t {
    kResolve = 0,
    kConnect = 1,
    kSend = 2,
};

enum class NetworkAddressFamily : std::uint8_t {
    kIpv4 = 4,
    kIpv6 = 6,
};

struct NetworkEndpoint {
    NetworkAddressFamily family = NetworkAddressFamily::kIpv4;
    std::array<std::uint8_t, 16> address{};
    std::uint16_t port = 0;
};

enum class FrameEncodeStatus : std::uint8_t {
    kSuccess,
    kInvalidArgument,
    kInvalidOperation,
    kInvalidPath,
    kInvalidAddress,
    kInvalidDomain,
    kInvalidRegistryKey,
    kInsufficientBuffer,
};

enum class ReadyFrameStatus : std::uint8_t {
    kSuccess,
    kInvalidArgument,
    kInvalidLength,
    kInvalidMagic,
    kUnsupportedVersion,
    kUnexpectedKind,
    kUnexpectedSequence,
    kChecksumMismatch,
    kNonceMismatch,
};

std::array<std::uint8_t, kReadyFrameLength> EncodeReadyFrame(
    const std::array<std::uint8_t, kReadyNonceLength>& nonce) noexcept;

ReadyFrameStatus ValidateReadyFrame(
    const std::uint8_t* encoded,
    std::size_t length,
    const std::array<std::uint8_t, kReadyNonceLength>& expected_nonce) noexcept;

std::size_t FilesystemViolationFrameLength(const wchar_t* path) noexcept;

FrameEncodeStatus EncodeFilesystemViolationFrame(
    std::uint32_t process_id,
    FilesystemOperation operation,
    const wchar_t* path,
    std::uint64_t sequence,
    std::uint8_t* output,
    std::size_t capacity,
    std::size_t& written) noexcept;

FrameEncodeStatus EncodeProcessViolationFrame(
    std::uint32_t process_id,
    ProcessOperation operation,
    std::uint64_t sequence,
    std::uint8_t* output,
    std::size_t capacity,
    std::size_t& written) noexcept;

FrameEncodeStatus EncodeNetworkViolationFrame(
    std::uint32_t process_id,
    NetworkOperation operation,
    const NetworkEndpoint& endpoint,
    std::uint64_t sequence,
    std::uint8_t* output,
    std::size_t capacity,
    std::size_t& written) noexcept;

std::size_t DomainNetworkViolationFrameLength(const char* ascii_domain) noexcept;

FrameEncodeStatus EncodeDomainNetworkViolationFrame(
    std::uint32_t process_id,
    NetworkOperation operation,
    const char* ascii_domain,
    std::uint64_t sequence,
    std::uint8_t* output,
    std::size_t capacity,
    std::size_t& written) noexcept;

FrameEncodeStatus EncodeChildInjectionFailureFrame(
    std::uint32_t parent_process_id,
    std::uint32_t child_process_id,
    ChildInjectionFailureReason reason,
    std::uint64_t sequence,
    std::uint8_t* output,
    std::size_t capacity,
    std::size_t& written) noexcept;

std::size_t RegistryViolationFrameLength(const char* key) noexcept;

FrameEncodeStatus EncodeRegistryViolationFrame(
    std::uint32_t process_id,
    RegistryOperation operation,
    const char* key,
    std::uint64_t sequence,
    std::uint8_t* output,
    std::size_t capacity,
    std::size_t& written) noexcept;

FrameEncodeStatus EncodeEventsDroppedFrame(
    std::uint32_t process_id,
    std::uint64_t dropped_count,
    std::uint64_t sequence,
    std::uint8_t* output,
    std::size_t capacity,
    std::size_t& written) noexcept;

void RewriteFrameChecksum(std::uint8_t* encoded, std::size_t length) noexcept;

}  // namespace bolt::protocol
