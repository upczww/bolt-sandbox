#include "protocol/dns_proxy_protocol.h"

#include "protocol/version.h"

#include <algorithm>
#include <new>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

namespace bolt::protocol {
namespace {

constexpr std::array<std::uint8_t, 4> kMagic = {'B', 'L', 'D', '1'};
constexpr std::uint16_t kRequestKind = 1;
constexpr std::uint16_t kResponseKind = 2;
constexpr std::size_t kVersionOffset = 4;
constexpr std::size_t kKindOffset = 6;
constexpr std::size_t kPayloadLengthOffset = 8;
constexpr std::size_t kSequenceOffset = 12;
constexpr std::size_t kNonceOffset = 20;
constexpr std::size_t kMacOffset = 36;
constexpr std::size_t kRequestPortOffset = kDnsProxyHeaderLength;
constexpr std::size_t kRequestFamilyOffset = kRequestPortOffset + 2;
constexpr std::size_t kRequestDomainLengthOffset = kRequestFamilyOffset + 2;
constexpr std::size_t kRequestDomainOffset = kRequestDomainLengthOffset + 2;
constexpr std::size_t kResponseResultOffset = kDnsProxyHeaderLength;
constexpr std::size_t kResponseCountOffset = kResponseResultOffset + 1;
constexpr std::size_t kResponseRecordsOffset = kResponseCountOffset + 3;
constexpr std::size_t kResponseRecordLength = 21;

void WriteU16(std::uint8_t* output, const std::size_t offset, const std::uint16_t value) noexcept {
    output[offset] = static_cast<std::uint8_t>(value);
    output[offset + 1] = static_cast<std::uint8_t>(value >> 8U);
}

void WriteU32(std::uint8_t* output, const std::size_t offset, const std::uint32_t value) noexcept {
    for (std::size_t index = 0; index < 4; ++index) {
        output[offset + index] = static_cast<std::uint8_t>(value >> (index * 8U));
    }
}

void WriteU64(std::uint8_t* output, const std::size_t offset, const std::uint64_t value) noexcept {
    for (std::size_t index = 0; index < 8; ++index) {
        output[offset + index] = static_cast<std::uint8_t>(value >> (index * 8U));
    }
}

std::uint16_t ReadU16(const std::uint8_t* input, const std::size_t offset) noexcept {
    return static_cast<std::uint16_t>(input[offset]) |
           static_cast<std::uint16_t>(input[offset + 1] << 8U);
}

std::uint32_t ReadU32(const std::uint8_t* input, const std::size_t offset) noexcept {
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < 4; ++index) {
        value |= static_cast<std::uint32_t>(input[offset + index]) << (index * 8U);
    }
    return value;
}

std::uint64_t ReadU64(const std::uint8_t* input, const std::size_t offset) noexcept {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < 8; ++index) {
        value |= static_cast<std::uint64_t>(input[offset + index]) << (index * 8U);
    }
    return value;
}

std::size_t DomainLength(const char* domain) noexcept {
    if (domain == nullptr) {
        return 0;
    }
    std::size_t length = 0;
    while (length <= kDnsProxyMaximumDomainLength && domain[length] != '\0') {
        const unsigned char byte = static_cast<unsigned char>(domain[length]);
        if (byte < 0x21U || byte > 0x7eU) {
            return 0;
        }
        ++length;
    }
    return length <= kDnsProxyMaximumDomainLength ? length : 0;
}

bool ComputeMac(
    const DnsProxySession& session,
    const std::uint8_t* frame,
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
                       static_cast<ULONG>(session.authentication_key.size()), 0) >= 0;
    if (success) {
        success = BCryptHashData(hash, const_cast<PUCHAR>(frame), kMacOffset, 0) >= 0;
    }
    if (success) {
        success = BCryptHashData(
                      hash, const_cast<PUCHAR>(frame + kDnsProxyHeaderLength),
                      static_cast<ULONG>(length - kDnsProxyHeaderLength), 0) >= 0;
    }
    if (success) {
        success = BCryptFinishHash(hash, mac.data(), static_cast<ULONG>(mac.size()), 0) >= 0;
    }
    if (hash != nullptr) {
        BCryptDestroyHash(hash);
    }
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return success;
}

bool ConstantTimeEqual(const std::uint8_t* left, const std::uint8_t* right, const std::size_t size) noexcept {
    std::uint8_t difference = 0;
    for (std::size_t index = 0; index < size; ++index) {
        difference |= left[index] ^ right[index];
    }
    return difference == 0;
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

}  // namespace

std::size_t DnsProxyRequestFrameLength(const char* ascii_domain) noexcept {
    const std::size_t domain_length = DomainLength(ascii_domain);
    return domain_length == 0 ? 0 : kRequestDomainOffset + domain_length;
}

DnsProxyStatus EncodeDnsProxyRequest(
    const DnsProxySession& session,
    const std::uint64_t sequence,
    const char* const ascii_domain,
    const std::uint16_t port,
    std::vector<std::uint8_t>& encoded,
    const DnsProxyQueryFamily family) noexcept {
    encoded.clear();
    if (!ValidSession(session) || sequence == 0) {
        return DnsProxyStatus::kInvalidArgument;
    }
    const std::size_t frame_length = DnsProxyRequestFrameLength(ascii_domain);
    if (frame_length == 0) {
        return DnsProxyStatus::kInvalidDomain;
    }
    if (family != DnsProxyQueryFamily::kAny &&
        family != DnsProxyQueryFamily::kIpv4 &&
        family != DnsProxyQueryFamily::kIpv6) {
        return DnsProxyStatus::kInvalidArgument;
    }
    try {
        encoded.assign(frame_length, 0);
        std::copy(kMagic.begin(), kMagic.end(), encoded.begin());
        WriteU16(encoded.data(), kVersionOffset, kProtocolVersion);
        WriteU16(encoded.data(), kKindOffset, kRequestKind);
        WriteU32(
            encoded.data(), kPayloadLengthOffset,
            static_cast<std::uint32_t>(frame_length - kDnsProxyHeaderLength));
        WriteU64(encoded.data(), kSequenceOffset, sequence);
        std::copy(session.nonce.begin(), session.nonce.end(), encoded.begin() + kNonceOffset);
        WriteU16(encoded.data(), kRequestPortOffset, port);
        encoded[kRequestFamilyOffset] = static_cast<std::uint8_t>(family);
        const std::size_t domain_length = frame_length - kRequestDomainOffset;
        WriteU16(
            encoded.data(), kRequestDomainLengthOffset,
            static_cast<std::uint16_t>(domain_length));
        std::copy_n(ascii_domain, domain_length, encoded.begin() + kRequestDomainOffset);
        std::array<std::uint8_t, kDnsProxyMacLength> mac{};
        if (!ComputeMac(session, encoded.data(), encoded.size(), mac)) {
            encoded.clear();
            return DnsProxyStatus::kCryptoFailed;
        }
        std::copy(mac.begin(), mac.end(), encoded.begin() + kMacOffset);
        return DnsProxyStatus::kSuccess;
    } catch (const std::bad_alloc&) {
        encoded.clear();
        return DnsProxyStatus::kAllocationFailed;
    } catch (...) {
        encoded.clear();
        return DnsProxyStatus::kInvalidArgument;
    }
}

DnsProxyStatus DecodeDnsProxyRequest(
    const DnsProxySession& session,
    const std::uint8_t* const encoded,
    const std::size_t length,
    const std::uint64_t expected_sequence,
    DnsProxyRequest& request) noexcept {
    request = {};
    if (encoded == nullptr || !ValidSession(session) || expected_sequence == 0) {
        return DnsProxyStatus::kInvalidArgument;
    }
    if (length < kRequestDomainOffset ||
        ReadU32(encoded, kPayloadLengthOffset) != length - kDnsProxyHeaderLength) {
        return DnsProxyStatus::kInvalidLength;
    }
    if (!std::equal(kMagic.begin(), kMagic.end(), encoded)) {
        return DnsProxyStatus::kInvalidMagic;
    }
    if (ReadU16(encoded, kVersionOffset) != kProtocolVersion) {
        return DnsProxyStatus::kUnsupportedVersion;
    }
    if (ReadU16(encoded, kKindOffset) != kRequestKind) {
        return DnsProxyStatus::kUnexpectedKind;
    }
    if (!ConstantTimeEqual(encoded + kNonceOffset, session.nonce.data(), session.nonce.size())) {
        return DnsProxyStatus::kSessionMismatch;
    }
    std::array<std::uint8_t, kDnsProxyMacLength> expected_mac{};
    try {
        if (!ComputeMac(session, encoded, length, expected_mac)) {
            return DnsProxyStatus::kCryptoFailed;
        }
    } catch (...) {
        return DnsProxyStatus::kAllocationFailed;
    }
    if (!ConstantTimeEqual(encoded + kMacOffset, expected_mac.data(), expected_mac.size())) {
        return DnsProxyStatus::kAuthenticationFailed;
    }
    if (ReadU64(encoded, kSequenceOffset) != expected_sequence) {
        return DnsProxyStatus::kUnexpectedSequence;
    }
    const std::uint16_t port = ReadU16(encoded, kRequestPortOffset);
    const std::size_t domain_length = ReadU16(encoded, kRequestDomainLengthOffset);
    const std::uint8_t family = encoded[kRequestFamilyOffset];
    if (family != 0 && family != 4 && family != 6) {
        return DnsProxyStatus::kInvalidArgument;
    }
    if (domain_length == 0 || domain_length > kDnsProxyMaximumDomainLength ||
        kRequestDomainOffset + domain_length != length) {
        return DnsProxyStatus::kInvalidDomain;
    }
    try {
        request.sequence = expected_sequence;
        request.port = port;
        request.family = static_cast<DnsProxyQueryFamily>(family);
        request.ascii_domain.assign(
            reinterpret_cast<const char*>(encoded + kRequestDomainOffset), domain_length);
        if (DomainLength(request.ascii_domain.c_str()) != domain_length) {
            request = {};
            return DnsProxyStatus::kInvalidDomain;
        }
        return DnsProxyStatus::kSuccess;
    } catch (const std::bad_alloc&) {
        request = {};
        return DnsProxyStatus::kAllocationFailed;
    } catch (...) {
        request = {};
        return DnsProxyStatus::kInvalidArgument;
    }
}

DnsProxyStatus EncodeDnsProxyResponse(
    const DnsProxySession& session,
    const std::uint64_t sequence,
    const DnsProxyResult result,
    const std::vector<DnsProxyAddress>& addresses,
    std::vector<std::uint8_t>& encoded) noexcept {
    encoded.clear();
    const auto result_value = static_cast<std::uint8_t>(result);
    if (!ValidSession(session) || sequence == 0 || result_value > 3) {
        return DnsProxyStatus::kInvalidArgument;
    }
    if (addresses.size() > kDnsProxyMaximumAddressRecords ||
        (result == DnsProxyResult::kSuccess) != !addresses.empty()) {
        return DnsProxyStatus::kInvalidArgument;
    }
    for (const auto& address : addresses) {
        if ((address.family != DnsProxyAddressFamily::kIpv4 &&
             address.family != DnsProxyAddressFamily::kIpv6) ||
            address.ttl_seconds == 0) {
            return DnsProxyStatus::kInvalidArgument;
        }
        if (address.family == DnsProxyAddressFamily::kIpv4 &&
            !std::all_of(
                address.address.begin() + 4, address.address.end(),
                [](const std::uint8_t byte) { return byte == 0; })) {
            return DnsProxyStatus::kInvalidArgument;
        }
    }
    try {
        const std::size_t frame_length =
            kResponseRecordsOffset + addresses.size() * kResponseRecordLength;
        encoded.assign(frame_length, 0);
        std::copy(kMagic.begin(), kMagic.end(), encoded.begin());
        WriteU16(encoded.data(), kVersionOffset, kProtocolVersion);
        WriteU16(encoded.data(), kKindOffset, kResponseKind);
        WriteU32(encoded.data(), kPayloadLengthOffset,
                 static_cast<std::uint32_t>(frame_length - kDnsProxyHeaderLength));
        WriteU64(encoded.data(), kSequenceOffset, sequence);
        std::copy(session.nonce.begin(), session.nonce.end(), encoded.begin() + kNonceOffset);
        encoded[kResponseResultOffset] = result_value;
        encoded[kResponseCountOffset] = static_cast<std::uint8_t>(addresses.size());
        for (std::size_t index = 0; index < addresses.size(); ++index) {
            const auto& address = addresses[index];
            const std::size_t offset = kResponseRecordsOffset + index * kResponseRecordLength;
            encoded[offset] = static_cast<std::uint8_t>(address.family);
            WriteU32(encoded.data(), offset + 1, address.ttl_seconds);
            std::copy(address.address.begin(), address.address.end(), encoded.begin() + offset + 5);
        }
        std::array<std::uint8_t, kDnsProxyMacLength> mac{};
        if (!ComputeMac(session, encoded.data(), encoded.size(), mac)) {
            encoded.clear();
            return DnsProxyStatus::kCryptoFailed;
        }
        std::copy(mac.begin(), mac.end(), encoded.begin() + kMacOffset);
        return DnsProxyStatus::kSuccess;
    } catch (const std::bad_alloc&) {
        encoded.clear();
        return DnsProxyStatus::kAllocationFailed;
    } catch (...) {
        encoded.clear();
        return DnsProxyStatus::kInvalidArgument;
    }
}

DnsProxyStatus DecodeDnsProxyResponse(
    const DnsProxySession& session,
    const std::uint8_t* const encoded,
    const std::size_t length,
    const std::uint64_t expected_sequence,
    DnsProxyResponse& response) noexcept {
    response = {};
    if (encoded == nullptr || !ValidSession(session) || expected_sequence == 0) {
        return DnsProxyStatus::kInvalidArgument;
    }
    if (length < kResponseRecordsOffset ||
        ReadU32(encoded, kPayloadLengthOffset) != length - kDnsProxyHeaderLength) {
        return DnsProxyStatus::kInvalidLength;
    }
    if (!std::equal(kMagic.begin(), kMagic.end(), encoded)) {
        return DnsProxyStatus::kInvalidMagic;
    }
    if (ReadU16(encoded, kVersionOffset) != kProtocolVersion) {
        return DnsProxyStatus::kUnsupportedVersion;
    }
    if (ReadU16(encoded, kKindOffset) != kResponseKind) {
        return DnsProxyStatus::kUnexpectedKind;
    }
    if (!ConstantTimeEqual(encoded + kNonceOffset, session.nonce.data(), session.nonce.size())) {
        return DnsProxyStatus::kSessionMismatch;
    }
    std::array<std::uint8_t, kDnsProxyMacLength> expected_mac{};
    try {
        if (!ComputeMac(session, encoded, length, expected_mac)) {
            return DnsProxyStatus::kCryptoFailed;
        }
    } catch (...) {
        return DnsProxyStatus::kAllocationFailed;
    }
    if (!ConstantTimeEqual(encoded + kMacOffset, expected_mac.data(), expected_mac.size())) {
        return DnsProxyStatus::kAuthenticationFailed;
    }
    if (ReadU64(encoded, kSequenceOffset) != expected_sequence) {
        return DnsProxyStatus::kUnexpectedSequence;
    }
    const std::uint8_t result_value = encoded[kResponseResultOffset];
    const std::size_t count = encoded[kResponseCountOffset];
    if (result_value > 3 || count > kDnsProxyMaximumAddressRecords ||
        kResponseRecordsOffset + count * kResponseRecordLength != length ||
        ((result_value == 0) != (count != 0))) {
        return DnsProxyStatus::kInvalidArgument;
    }
    try {
        response.sequence = expected_sequence;
        response.result = static_cast<DnsProxyResult>(result_value);
        response.addresses.reserve(count);
        for (std::size_t index = 0; index < count; ++index) {
            const std::size_t offset = kResponseRecordsOffset + index * kResponseRecordLength;
            DnsProxyAddress address{};
            const std::uint8_t family = encoded[offset];
            if (family != 4 && family != 6) {
                response = {};
                return DnsProxyStatus::kInvalidArgument;
            }
            address.family = static_cast<DnsProxyAddressFamily>(family);
            address.ttl_seconds = ReadU32(encoded, offset + 1);
            if (address.ttl_seconds == 0) {
                response = {};
                return DnsProxyStatus::kInvalidArgument;
            }
            std::copy_n(encoded + offset + 5, 16, address.address.begin());
            if (address.family == DnsProxyAddressFamily::kIpv4 &&
                !std::all_of(
                    address.address.begin() + 4, address.address.end(),
                    [](const std::uint8_t byte) { return byte == 0; })) {
                response = {};
                return DnsProxyStatus::kInvalidArgument;
            }
            response.addresses.push_back(address);
        }
        return DnsProxyStatus::kSuccess;
    } catch (const std::bad_alloc&) {
        response = {};
        return DnsProxyStatus::kAllocationFailed;
    } catch (...) {
        response = {};
        return DnsProxyStatus::kInvalidArgument;
    }
}

}  // namespace bolt::protocol
