#include "protocol/dns_proxy_startup.h"

#include "protocol/version.h"

#include <algorithm>

namespace bolt::protocol {
namespace {

constexpr std::array<std::uint8_t, 4> kMagic = {'B', 'L', 'S', '1'};
constexpr std::size_t kPolicyLengthOffset = 8;
constexpr std::size_t kMaximumFrameOffset = 12;
constexpr std::size_t kMaximumRequestsOffset = 16;
constexpr std::size_t kPolicyHandleOffset = 24;
constexpr std::size_t kReadHandleOffset = 32;
constexpr std::size_t kWriteHandleOffset = 40;
constexpr std::size_t kNonceOffset = 48;
constexpr std::size_t kKeyOffset = 64;
constexpr std::size_t kTcpListenerHandleOffset = 96;
constexpr std::size_t kTcpListenerPortOffset = 104;
constexpr std::size_t kMaximumTcpConnectionsOffset = 108;

void WriteU16(std::uint8_t* bytes, std::size_t offset, std::uint16_t value) noexcept {
    bytes[offset] = static_cast<std::uint8_t>(value);
    bytes[offset + 1] = static_cast<std::uint8_t>(value >> 8U);
}
void WriteU32(std::uint8_t* bytes, std::size_t offset, std::uint32_t value) noexcept {
    for (std::size_t index = 0; index < 4; ++index) {
        bytes[offset + index] = static_cast<std::uint8_t>(value >> (index * 8U));
    }
}
void WriteU64(std::uint8_t* bytes, std::size_t offset, std::uint64_t value) noexcept {
    for (std::size_t index = 0; index < 8; ++index) {
        bytes[offset + index] = static_cast<std::uint8_t>(value >> (index * 8U));
    }
}
std::uint16_t ReadU16(const std::uint8_t* bytes, std::size_t offset) noexcept {
    return static_cast<std::uint16_t>(bytes[offset]) |
           static_cast<std::uint16_t>(bytes[offset + 1] << 8U);
}
std::uint32_t ReadU32(const std::uint8_t* bytes, std::size_t offset) noexcept {
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < 4; ++index) {
        value |= static_cast<std::uint32_t>(bytes[offset + index]) << (index * 8U);
    }
    return value;
}
std::uint64_t ReadU64(const std::uint8_t* bytes, std::size_t offset) noexcept {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < 8; ++index) {
        value |= static_cast<std::uint64_t>(bytes[offset + index]) << (index * 8U);
    }
    return value;
}

DnsProxyStartupStatus Validate(const DnsProxyStartup& startup) noexcept {
    if (startup.policy_length == 0 || startup.policy_length > 1'048'576) {
        return DnsProxyStartupStatus::kInvalidPolicy;
    }
    if (startup.policy_handle == 0 || startup.read_handle == 0 || startup.write_handle == 0) {
        return DnsProxyStartupStatus::kInvalidHandle;
    }
    if (startup.tcp_listener_handle == 0 || startup.tcp_listener_port == 0) {
        return DnsProxyStartupStatus::kInvalidHandle;
    }
    if (startup.maximum_frame_length < kDnsProxyHeaderLength ||
        startup.maximum_frame_length > 1'048'576 || startup.maximum_requests == 0 ||
        startup.maximum_requests > 4'096 ||
        startup.maximum_tcp_connections == 0 ||
        startup.maximum_tcp_connections > 4'096) {
        return DnsProxyStartupStatus::kInvalidLimits;
    }
    const bool nonce_zero = std::all_of(
        startup.session.nonce.begin(), startup.session.nonce.end(),
        [](std::uint8_t byte) { return byte == 0; });
    const bool key_zero = std::all_of(
        startup.session.authentication_key.begin(),
        startup.session.authentication_key.end(),
        [](std::uint8_t byte) { return byte == 0; });
    return nonce_zero || key_zero ? DnsProxyStartupStatus::kInvalidSession
                                  : DnsProxyStartupStatus::kSuccess;
}

}  // namespace

std::array<std::uint8_t, kDnsProxyStartupLength> EncodeDnsProxyStartup(
    const DnsProxyStartup& startup) noexcept {
    std::array<std::uint8_t, kDnsProxyStartupLength> encoded{};
    if (Validate(startup) != DnsProxyStartupStatus::kSuccess) {
        return encoded;
    }
    std::copy(kMagic.begin(), kMagic.end(), encoded.begin());
    WriteU16(encoded.data(), 4, kProtocolVersion);
    WriteU16(encoded.data(), 6, static_cast<std::uint16_t>(encoded.size()));
    WriteU32(encoded.data(), kPolicyLengthOffset, startup.policy_length);
    WriteU32(encoded.data(), kMaximumFrameOffset, startup.maximum_frame_length);
    WriteU32(encoded.data(), kMaximumRequestsOffset, startup.maximum_requests);
    WriteU64(encoded.data(), kPolicyHandleOffset, startup.policy_handle);
    WriteU64(encoded.data(), kReadHandleOffset, startup.read_handle);
    WriteU64(encoded.data(), kWriteHandleOffset, startup.write_handle);
    std::copy(startup.session.nonce.begin(), startup.session.nonce.end(), encoded.begin() + kNonceOffset);
    std::copy(startup.session.authentication_key.begin(), startup.session.authentication_key.end(), encoded.begin() + kKeyOffset);
    WriteU64(
        encoded.data(), kTcpListenerHandleOffset,
        startup.tcp_listener_handle);
    WriteU16(
        encoded.data(), kTcpListenerPortOffset, startup.tcp_listener_port);
    WriteU32(
        encoded.data(), kMaximumTcpConnectionsOffset,
        startup.maximum_tcp_connections);
    return encoded;
}

DnsProxyStartupStatus DecodeDnsProxyStartup(
    const std::uint8_t* encoded, const std::size_t length,
    DnsProxyStartup& startup) noexcept {
    startup = {};
    if (encoded == nullptr) {
        return DnsProxyStartupStatus::kInvalidArgument;
    }
    if (length != kDnsProxyStartupLength) {
        return DnsProxyStartupStatus::kInvalidLength;
    }
    if (!std::equal(kMagic.begin(), kMagic.end(), encoded)) {
        return DnsProxyStartupStatus::kInvalidMagic;
    }
    if (ReadU16(encoded, 4) != kProtocolVersion) {
        return DnsProxyStartupStatus::kUnsupportedVersion;
    }
    if (ReadU16(encoded, 6) != kDnsProxyStartupLength) {
        return DnsProxyStartupStatus::kInvalidHeaderLength;
    }
    startup.policy_length = ReadU32(encoded, kPolicyLengthOffset);
    startup.maximum_frame_length = ReadU32(encoded, kMaximumFrameOffset);
    startup.maximum_requests = ReadU32(encoded, kMaximumRequestsOffset);
    startup.policy_handle = ReadU64(encoded, kPolicyHandleOffset);
    startup.read_handle = ReadU64(encoded, kReadHandleOffset);
    startup.write_handle = ReadU64(encoded, kWriteHandleOffset);
    std::copy_n(encoded + kNonceOffset, startup.session.nonce.size(), startup.session.nonce.begin());
    std::copy_n(encoded + kKeyOffset, startup.session.authentication_key.size(), startup.session.authentication_key.begin());
    startup.tcp_listener_handle = ReadU64(encoded, kTcpListenerHandleOffset);
    startup.tcp_listener_port = ReadU16(encoded, kTcpListenerPortOffset);
    startup.maximum_tcp_connections =
        ReadU32(encoded, kMaximumTcpConnectionsOffset);
    return Validate(startup);
}

}  // namespace bolt::protocol
