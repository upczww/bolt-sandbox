#include "protocol/tcp_proxy_protocol.h"

#include "protocol/version.h"

#include <algorithm>
#include <new>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

namespace bolt::protocol {
namespace {

constexpr std::array<std::uint8_t, 4> kMagic = {'B', 'L', 'T', '1'};
constexpr std::uint16_t kRequestKind = 1;
constexpr std::uint16_t kResponseKind = 2;
constexpr std::size_t kHeaderLength = 68;
constexpr std::size_t kVersionOffset = 4;
constexpr std::size_t kKindOffset = 6;
constexpr std::size_t kPayloadLengthOffset = 8;
constexpr std::size_t kSequenceOffset = 12;
constexpr std::size_t kNonceOffset = 20;
constexpr std::size_t kMacOffset = 36;
constexpr std::size_t kRequestProcessOffset = kHeaderLength;
constexpr std::size_t kRequestPortOffset = kRequestProcessOffset + 4;
constexpr std::size_t kRequestFamilyOffset = kRequestPortOffset + 2;
constexpr std::size_t kRequestReservedOffset = kRequestFamilyOffset + 1;
constexpr std::size_t kRequestDomainLengthOffset = kRequestReservedOffset + 1;
constexpr std::size_t kRequestSecondReservedOffset =
    kRequestDomainLengthOffset + 2;
constexpr std::size_t kRequestAddressOffset =
    kRequestSecondReservedOffset + 2;
constexpr std::size_t kRequestDomainOffset = kRequestAddressOffset + 16;
constexpr std::size_t kResponseResultOffset = kHeaderLength;
constexpr std::size_t kResponseReservedOffset = kResponseResultOffset + 1;
constexpr std::size_t kResponseNetworkErrorOffset =
    kResponseReservedOffset + 3;
constexpr std::size_t kResponseLength = kResponseNetworkErrorOffset + 4;

void WriteU16(
    std::uint8_t* const output,
    const std::size_t offset,
    const std::uint16_t value) noexcept {
    output[offset] = static_cast<std::uint8_t>(value);
    output[offset + 1] = static_cast<std::uint8_t>(value >> 8U);
}

void WriteU32(
    std::uint8_t* const output,
    const std::size_t offset,
    const std::uint32_t value) noexcept {
    for (std::size_t index = 0; index < 4; ++index) {
        output[offset + index] =
            static_cast<std::uint8_t>(value >> (index * 8U));
    }
}

void WriteU64(
    std::uint8_t* const output,
    const std::size_t offset,
    const std::uint64_t value) noexcept {
    for (std::size_t index = 0; index < 8; ++index) {
        output[offset + index] =
            static_cast<std::uint8_t>(value >> (index * 8U));
    }
}

std::uint16_t ReadU16(
    const std::uint8_t* const input,
    const std::size_t offset) noexcept {
    return static_cast<std::uint16_t>(input[offset]) |
           static_cast<std::uint16_t>(input[offset + 1] << 8U);
}

std::uint32_t ReadU32(
    const std::uint8_t* const input,
    const std::size_t offset) noexcept {
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < 4; ++index) {
        value |= static_cast<std::uint32_t>(input[offset + index])
                 << (index * 8U);
    }
    return value;
}

std::uint64_t ReadU64(
    const std::uint8_t* const input,
    const std::size_t offset) noexcept {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < 8; ++index) {
        value |= static_cast<std::uint64_t>(input[offset + index])
                 << (index * 8U);
    }
    return value;
}

bool DomainLength(
    const char* const domain,
    std::size_t& length) noexcept {
    length = 0;
    if (domain == nullptr || domain[0] == '\0') {
        return true;
    }
    while (length <= kTcpProxyMaximumDomainLength && domain[length] != '\0') {
        const auto byte = static_cast<unsigned char>(domain[length]);
        if (byte < 0x21U || byte > 0x7EU) {
            return false;
        }
        ++length;
    }
    return length <= kTcpProxyMaximumDomainLength;
}

bool ValidSession(const DnsProxySession& session) noexcept {
    const bool nonce_is_zero = std::all_of(
        session.nonce.begin(), session.nonce.end(),
        [](const std::uint8_t byte) { return byte == 0; });
    const bool key_is_zero = std::all_of(
        session.authentication_key.begin(), session.authentication_key.end(),
        [](const std::uint8_t byte) { return byte == 0; });
    return !nonce_is_zero && !key_is_zero;
}

bool ValidAddress(
    const DnsProxyAddressFamily family,
    const std::array<std::uint8_t, 16>& address) noexcept {
    if (family == DnsProxyAddressFamily::kIpv6) {
        return true;
    }
    return family == DnsProxyAddressFamily::kIpv4 &&
           std::all_of(
               address.begin() + 4, address.end(),
               [](const std::uint8_t byte) { return byte == 0; });
}

bool ConstantTimeEqual(
    const std::uint8_t* const left,
    const std::uint8_t* const right,
    const std::size_t size) noexcept {
    std::uint8_t difference = 0;
    for (std::size_t index = 0; index < size; ++index) {
        difference |= left[index] ^ right[index];
    }
    return difference == 0;
}

bool ComputeMac(
    const DnsProxySession& session,
    const std::uint8_t* const frame,
    const std::size_t length,
    std::array<std::uint8_t, kDnsProxyMacLength>& mac) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD object_length = 0;
    DWORD written = 0;
    if (BCryptOpenAlgorithmProvider(
            &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr,
            BCRYPT_ALG_HANDLE_HMAC_FLAG) < 0 ||
        BCryptGetProperty(
            algorithm, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&object_length), sizeof(object_length),
            &written, 0) < 0) {
        if (algorithm != nullptr) {
            BCryptCloseAlgorithmProvider(algorithm, 0);
        }
        return false;
    }
    std::vector<std::uint8_t> object(object_length);
    bool success = BCryptCreateHash(
                       algorithm, &hash, object.data(), object_length,
                       const_cast<PUCHAR>(session.authentication_key.data()),
                       static_cast<ULONG>(
                           session.authentication_key.size()),
                       0) >= 0;
    if (success) {
        success = BCryptHashData(
                      hash, const_cast<PUCHAR>(frame), kMacOffset, 0) >= 0;
    }
    if (success) {
        success = BCryptHashData(
                      hash,
                      const_cast<PUCHAR>(frame + kHeaderLength),
                      static_cast<ULONG>(length - kHeaderLength), 0) >= 0;
    }
    if (success) {
        success = BCryptFinishHash(
                      hash, mac.data(), static_cast<ULONG>(mac.size()), 0) >= 0;
    }
    if (hash != nullptr) {
        BCryptDestroyHash(hash);
    }
    if (!object.empty()) {
        SecureZeroMemory(object.data(), object.size());
    }
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return success;
}

void WriteHeader(
    const DnsProxySession& session,
    const std::uint16_t kind,
    const std::uint64_t sequence,
    std::vector<std::uint8_t>& encoded) noexcept {
    std::copy(kMagic.begin(), kMagic.end(), encoded.begin());
    WriteU16(encoded.data(), kVersionOffset, kProtocolVersion);
    WriteU16(encoded.data(), kKindOffset, kind);
    WriteU32(
        encoded.data(), kPayloadLengthOffset,
        static_cast<std::uint32_t>(encoded.size() - kHeaderLength));
    WriteU64(encoded.data(), kSequenceOffset, sequence);
    std::copy(
        session.nonce.begin(), session.nonce.end(),
        encoded.begin() + kNonceOffset);
}

TcpProxyStatus ValidateHeader(
    const DnsProxySession& session,
    const std::uint8_t* const encoded,
    const std::size_t length,
    const std::uint16_t expected_kind,
    const std::uint64_t expected_sequence) {
    if (ReadU32(encoded, kPayloadLengthOffset) != length - kHeaderLength) {
        return TcpProxyStatus::kInvalidLength;
    }
    if (!std::equal(kMagic.begin(), kMagic.end(), encoded)) {
        return TcpProxyStatus::kInvalidMagic;
    }
    if (ReadU16(encoded, kVersionOffset) != kProtocolVersion) {
        return TcpProxyStatus::kUnsupportedVersion;
    }
    if (ReadU16(encoded, kKindOffset) != expected_kind) {
        return TcpProxyStatus::kUnexpectedKind;
    }
    if (!ConstantTimeEqual(
            encoded + kNonceOffset, session.nonce.data(),
            session.nonce.size())) {
        return TcpProxyStatus::kSessionMismatch;
    }
    std::array<std::uint8_t, kDnsProxyMacLength> expected_mac{};
    if (!ComputeMac(session, encoded, length, expected_mac)) {
        return TcpProxyStatus::kCryptoFailed;
    }
    if (!ConstantTimeEqual(
            encoded + kMacOffset, expected_mac.data(), expected_mac.size())) {
        return TcpProxyStatus::kAuthenticationFailed;
    }
    if (ReadU64(encoded, kSequenceOffset) != expected_sequence) {
        return TcpProxyStatus::kUnexpectedSequence;
    }
    return TcpProxyStatus::kSuccess;
}

bool ValidResponseFields(
    const TcpProxyResult result,
    const std::uint32_t network_error) noexcept {
    const auto value = static_cast<std::uint8_t>(result);
    return value <= static_cast<std::uint8_t>(TcpProxyResult::kFailure) &&
           ((result == TcpProxyResult::kConnectFailed) ==
            (network_error != 0));
}

}  // namespace

std::size_t TcpProxyRequestFrameLength(
    const char* const ascii_domain) noexcept {
    std::size_t domain_length = 0;
    return DomainLength(ascii_domain, domain_length)
               ? kRequestDomainOffset + domain_length
               : 0;
}

TcpProxyStatus EncodeTcpProxyRequest(
    const DnsProxySession& session,
    const std::uint64_t sequence,
    const std::uint32_t process_id,
    const DnsProxyAddressFamily family,
    const std::array<std::uint8_t, 16>& address,
    const std::uint16_t port,
    const char* const ascii_domain,
    std::vector<std::uint8_t>& encoded) noexcept {
    encoded.clear();
    if (!ValidSession(session) || sequence == 0) {
        return TcpProxyStatus::kInvalidArgument;
    }
    if (process_id == 0) {
        return TcpProxyStatus::kInvalidProcess;
    }
    if (!ValidAddress(family, address)) {
        return TcpProxyStatus::kInvalidAddress;
    }
    if (port == 0) {
        return TcpProxyStatus::kInvalidPort;
    }
    std::size_t domain_length = 0;
    if (!DomainLength(ascii_domain, domain_length)) {
        return TcpProxyStatus::kInvalidDomain;
    }
    try {
        encoded.assign(kRequestDomainOffset + domain_length, 0);
        WriteHeader(session, kRequestKind, sequence, encoded);
        WriteU32(encoded.data(), kRequestProcessOffset, process_id);
        WriteU16(encoded.data(), kRequestPortOffset, port);
        encoded[kRequestFamilyOffset] = static_cast<std::uint8_t>(family);
        WriteU16(
            encoded.data(), kRequestDomainLengthOffset,
            static_cast<std::uint16_t>(domain_length));
        std::copy(
            address.begin(), address.end(),
            encoded.begin() + kRequestAddressOffset);
        if (domain_length != 0) {
            std::copy_n(
                ascii_domain, domain_length,
                encoded.begin() + kRequestDomainOffset);
        }
        std::array<std::uint8_t, kDnsProxyMacLength> mac{};
        if (!ComputeMac(session, encoded.data(), encoded.size(), mac)) {
            encoded.clear();
            return TcpProxyStatus::kCryptoFailed;
        }
        std::copy(mac.begin(), mac.end(), encoded.begin() + kMacOffset);
        return TcpProxyStatus::kSuccess;
    } catch (const std::bad_alloc&) {
        encoded.clear();
        return TcpProxyStatus::kAllocationFailed;
    } catch (...) {
        encoded.clear();
        return TcpProxyStatus::kInvalidArgument;
    }
}

TcpProxyStatus DecodeTcpProxyRequest(
    const DnsProxySession& session,
    const std::uint8_t* const encoded,
    const std::size_t length,
    const std::uint64_t expected_sequence,
    TcpProxyRequest& request) noexcept {
    request = {};
    if (encoded == nullptr || !ValidSession(session) || expected_sequence == 0) {
        return TcpProxyStatus::kInvalidArgument;
    }
    if (length < kRequestDomainOffset ||
        length > kRequestDomainOffset + kTcpProxyMaximumDomainLength) {
        return TcpProxyStatus::kInvalidLength;
    }
    try {
        const auto header = ValidateHeader(
            session, encoded, length, kRequestKind, expected_sequence);
        if (header != TcpProxyStatus::kSuccess) {
            return header;
        }
        if (encoded[kRequestReservedOffset] != 0 ||
            ReadU16(encoded, kRequestSecondReservedOffset) != 0) {
            return TcpProxyStatus::kInvalidArgument;
        }
        const auto process_id = ReadU32(encoded, kRequestProcessOffset);
        if (process_id == 0) {
            return TcpProxyStatus::kInvalidProcess;
        }
        const auto port = ReadU16(encoded, kRequestPortOffset);
        if (port == 0) {
            return TcpProxyStatus::kInvalidPort;
        }
        const auto family = static_cast<DnsProxyAddressFamily>(
            encoded[kRequestFamilyOffset]);
        std::array<std::uint8_t, 16> address{};
        std::copy_n(
            encoded + kRequestAddressOffset, address.size(), address.begin());
        if (!ValidAddress(family, address)) {
            return TcpProxyStatus::kInvalidAddress;
        }
        const std::size_t domain_length =
            ReadU16(encoded, kRequestDomainLengthOffset);
        if (domain_length > kTcpProxyMaximumDomainLength ||
            kRequestDomainOffset + domain_length != length) {
            return TcpProxyStatus::kInvalidDomain;
        }
        request.sequence = expected_sequence;
        request.process_id = process_id;
        request.family = family;
        request.address = address;
        request.port = port;
        if (domain_length != 0) {
            request.ascii_domain.assign(
                reinterpret_cast<const char*>(
                    encoded + kRequestDomainOffset),
                domain_length);
            std::size_t checked_length = 0;
            if (!DomainLength(request.ascii_domain.c_str(), checked_length) ||
                checked_length != domain_length) {
                request = {};
                return TcpProxyStatus::kInvalidDomain;
            }
        }
        return TcpProxyStatus::kSuccess;
    } catch (const std::bad_alloc&) {
        request = {};
        return TcpProxyStatus::kAllocationFailed;
    } catch (...) {
        request = {};
        return TcpProxyStatus::kInvalidArgument;
    }
}

TcpProxyStatus EncodeTcpProxyResponse(
    const DnsProxySession& session,
    const std::uint64_t sequence,
    const TcpProxyResult result,
    const std::uint32_t network_error,
    std::vector<std::uint8_t>& encoded) noexcept {
    encoded.clear();
    if (!ValidSession(session) || sequence == 0 ||
        !ValidResponseFields(result, network_error)) {
        return TcpProxyStatus::kInvalidArgument;
    }
    try {
        encoded.assign(kResponseLength, 0);
        WriteHeader(session, kResponseKind, sequence, encoded);
        encoded[kResponseResultOffset] = static_cast<std::uint8_t>(result);
        WriteU32(encoded.data(), kResponseNetworkErrorOffset, network_error);
        std::array<std::uint8_t, kDnsProxyMacLength> mac{};
        if (!ComputeMac(session, encoded.data(), encoded.size(), mac)) {
            encoded.clear();
            return TcpProxyStatus::kCryptoFailed;
        }
        std::copy(mac.begin(), mac.end(), encoded.begin() + kMacOffset);
        return TcpProxyStatus::kSuccess;
    } catch (const std::bad_alloc&) {
        encoded.clear();
        return TcpProxyStatus::kAllocationFailed;
    } catch (...) {
        encoded.clear();
        return TcpProxyStatus::kInvalidArgument;
    }
}

TcpProxyStatus DecodeTcpProxyResponse(
    const DnsProxySession& session,
    const std::uint8_t* const encoded,
    const std::size_t length,
    const std::uint64_t expected_sequence,
    TcpProxyResponse& response) noexcept {
    response = {};
    if (encoded == nullptr || !ValidSession(session) || expected_sequence == 0) {
        return TcpProxyStatus::kInvalidArgument;
    }
    if (length != kResponseLength) {
        return TcpProxyStatus::kInvalidLength;
    }
    try {
        const auto header = ValidateHeader(
            session, encoded, length, kResponseKind, expected_sequence);
        if (header != TcpProxyStatus::kSuccess) {
            return header;
        }
        if (encoded[kResponseReservedOffset] != 0 ||
            encoded[kResponseReservedOffset + 1] != 0 ||
            encoded[kResponseReservedOffset + 2] != 0) {
            return TcpProxyStatus::kInvalidArgument;
        }
        const auto result =
            static_cast<TcpProxyResult>(encoded[kResponseResultOffset]);
        const auto network_error =
            ReadU32(encoded, kResponseNetworkErrorOffset);
        if (!ValidResponseFields(result, network_error)) {
            return TcpProxyStatus::kInvalidArgument;
        }
        response.sequence = expected_sequence;
        response.result = result;
        response.network_error = network_error;
        return TcpProxyStatus::kSuccess;
    } catch (...) {
        response = {};
        return TcpProxyStatus::kInvalidArgument;
    }
}

}  // namespace bolt::protocol
