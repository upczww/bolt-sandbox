#include "protocol/policy_payload.h"

#include "protocol/version.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <vector>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

namespace bolt::protocol {
namespace {

constexpr std::size_t kNetworkCategoryLimit = 1'024;
constexpr std::size_t kNetworkTotalLimit = 2'048;
constexpr std::size_t kRegistryTotalLimit = 2'124;

class Reader {
  public:
    Reader(const std::uint8_t* bytes, const std::size_t length) noexcept
        : bytes_(bytes), length_(length) {}

    bool ReadU8(std::uint8_t& value) noexcept {
        const std::uint8_t* bytes = nullptr;
        if (!ReadBytes(1, bytes)) {
            return false;
        }
        value = bytes[0];
        return true;
    }

    bool ReadU16(std::uint16_t& value) noexcept {
        const std::uint8_t* bytes = nullptr;
        if (!ReadBytes(2, bytes)) {
            return false;
        }
        value = static_cast<std::uint16_t>(bytes[0]) |
                static_cast<std::uint16_t>(bytes[1] << 8U);
        return true;
    }

    bool ReadCount(std::size_t& value) noexcept {
        const std::uint8_t* bytes = nullptr;
        if (!ReadBytes(4, bytes)) {
            return false;
        }
        value = static_cast<std::size_t>(bytes[0]) |
                (static_cast<std::size_t>(bytes[1]) << 8U) |
                (static_cast<std::size_t>(bytes[2]) << 16U) |
                (static_cast<std::size_t>(bytes[3]) << 24U);
        return true;
    }

    bool ReadBytes(const std::size_t count, const std::uint8_t*& value) noexcept {
        if (count > length_ - offset_) {
            return false;
        }
        value = bytes_ + offset_;
        offset_ += count;
        return true;
    }

    bool ReadSizedBytes(const std::uint8_t*& value, std::size_t& length) noexcept {
        return ReadCount(length) && ReadBytes(length, value);
    }

    bool Finished() const noexcept { return offset_ == length_; }

  private:
    const std::uint8_t* bytes_;
    std::size_t length_;
    std::size_t offset_ = 0;
};

std::uint16_t ReadU16(const std::uint8_t* bytes) noexcept {
    return static_cast<std::uint16_t>(bytes[0]) |
           static_cast<std::uint16_t>(bytes[1] << 8U);
}

std::size_t ReadU32(const std::uint8_t* bytes) noexcept {
    return static_cast<std::size_t>(bytes[0]) |
           (static_cast<std::size_t>(bytes[1]) << 8U) |
           (static_cast<std::size_t>(bytes[2]) << 16U) |
           (static_cast<std::size_t>(bytes[3]) << 24U);
}

bool HashPayload(
    const std::uint8_t* payload,
    const std::size_t body_length,
    std::array<std::uint8_t, 32>& digest) noexcept {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD object_length = 0;
    DWORD result_length = 0;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
        BCryptGetProperty(
            algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_length),
            sizeof(object_length), &result_length, 0) < 0) {
        if (algorithm != nullptr) {
            BCryptCloseAlgorithmProvider(algorithm, 0);
        }
        return false;
    }

    std::vector<std::uint8_t> hash_object;
    try {
        hash_object.resize(object_length);
    } catch (...) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return false;
    }
    bool success = BCryptCreateHash(
                       algorithm, &hash, hash_object.data(), object_length, nullptr, 0, 0) >= 0;
    if (success) {
        success = BCryptHashData(
                      hash, const_cast<PUCHAR>(payload),
                      static_cast<ULONG>(kPolicyDigestOffset), 0) >= 0;
    }
    if (success) {
        success = BCryptHashData(
                      hash, const_cast<PUCHAR>(payload + kPolicyEnvelopeLength),
                      static_cast<ULONG>(body_length), 0) >= 0;
    }
    if (success) {
        success = BCryptFinishHash(
                      hash, digest.data(), static_cast<ULONG>(digest.size()), 0) >= 0;
    }
    if (hash != nullptr) {
        BCryptDestroyHash(hash);
    }
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return success;
}

bool ValidateFilesystem(Reader& reader) noexcept {
    std::size_t rule_count = 0;
    if (!reader.ReadCount(rule_count)) {
        return false;
    }
    for (std::size_t rule = 0; rule < rule_count; ++rule) {
        std::size_t record_length = 0;
        const std::uint8_t* record_bytes = nullptr;
        if (!reader.ReadCount(record_length) ||
            !reader.ReadBytes(record_length, record_bytes)) {
            return false;
        }
        Reader record(record_bytes, record_length);
        std::uint8_t kind = 0;
        std::size_t component_count = 0;
        if (!record.ReadU8(kind) || kind > 4 || !record.ReadCount(component_count)) {
            return false;
        }
        for (std::size_t component = 0; component < component_count; ++component) {
            std::uint8_t component_kind = 0;
            std::size_t code_units = 0;
            const std::uint8_t* ignored = nullptr;
            if (!record.ReadU8(component_kind) || component_kind > 2 ||
                !record.ReadCount(code_units) || (component_kind == 1 && code_units != 0) ||
                code_units > std::numeric_limits<std::size_t>::max() / 2 ||
                !record.ReadBytes(code_units * 2, ignored)) {
                return false;
            }
        }
        if (!record.Finished()) {
            return false;
        }
    }
    return true;
}

bool ValidateAllowList(Reader& reader) noexcept {
    std::size_t domains = 0;
    if (!reader.ReadCount(domains) || domains > kNetworkCategoryLimit) {
        return false;
    }
    for (std::size_t index = 0; index < domains; ++index) {
        std::uint8_t wildcard = 0;
        const std::uint8_t* domain = nullptr;
        std::size_t length = 0;
        if (!reader.ReadU8(wildcard) || wildcard > 1 ||
            !reader.ReadSizedBytes(domain, length) || length == 0 ||
            !std::all_of(domain, domain + length, [](const std::uint8_t value) {
                return value <= 0x7f;
            })) {
            return false;
        }
    }

    std::size_t addresses = 0;
    if (!reader.ReadCount(addresses) || addresses > kNetworkCategoryLimit) {
        return false;
    }
    for (std::size_t index = 0; index < addresses; ++index) {
        std::uint8_t family = 0;
        std::uint8_t prefix = 0;
        const std::uint8_t* ignored = nullptr;
        if (!reader.ReadU8(family) || !reader.ReadU8(prefix) ||
            !((family == 4 && prefix <= 32 && reader.ReadBytes(4, ignored)) ||
              (family == 6 && prefix <= 128 && reader.ReadBytes(16, ignored)))) {
            return false;
        }
    }

    std::size_t ports = 0;
    if (!reader.ReadCount(ports) || ports > kNetworkCategoryLimit ||
        domains > kNetworkTotalLimit - addresses ||
        domains + addresses > kNetworkTotalLimit - ports) {
        return false;
    }
    for (std::size_t index = 0; index < ports; ++index) {
        std::uint16_t start = 0;
        std::uint16_t end = 0;
        if (!reader.ReadU16(start) || !reader.ReadU16(end) || start == 0 || start > end) {
            return false;
        }
    }
    return true;
}

bool ValidateNetwork(Reader& reader) noexcept {
    std::uint8_t mode = 0;
    if (!reader.ReadU8(mode)) {
        return false;
    }
    return mode <= 1 || (mode == 2 && ValidateAllowList(reader));
}

bool IsUtf8(const std::uint8_t* bytes, const std::size_t length) noexcept {
    if (length == 0 || length > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        return false;
    }
    return MultiByteToWideChar(
               CP_UTF8, MB_ERR_INVALID_CHARS, reinterpret_cast<LPCCH>(bytes),
               static_cast<int>(length), nullptr, 0) > 0;
}

bool ValidateRegistry(Reader& reader) noexcept {
    std::size_t rules = 0;
    if (!reader.ReadCount(rules) || rules > kRegistryTotalLimit) {
        return false;
    }
    for (std::size_t rule = 0; rule < rules; ++rule) {
        std::uint8_t kind = 0;
        std::uint8_t hive = 0;
        std::size_t components = 0;
        if (!reader.ReadU8(kind) || kind > 5 || !reader.ReadU8(hive) || hive > 4 ||
            !reader.ReadCount(components)) {
            return false;
        }
        for (std::size_t component = 0; component < components; ++component) {
            const std::uint8_t* bytes = nullptr;
            std::size_t length = 0;
            if (!reader.ReadSizedBytes(bytes, length) || !IsUtf8(bytes, length)) {
                return false;
            }
        }
    }
    return true;
}

bool ValidateBody(const std::uint8_t* body, const std::size_t length) noexcept {
    Reader reader(body, length);
    std::uint8_t child_policy = 0;
    return reader.ReadU8(child_policy) && child_policy <= 3 && ValidateFilesystem(reader) &&
           ValidateNetwork(reader) && ValidateRegistry(reader) && reader.Finished();
}

}  // namespace

PolicyPayloadStatus ValidatePolicyPayload(
    const std::uint8_t* payload,
    const std::size_t length) noexcept {
    if (payload == nullptr || length < kPolicyEnvelopeLength) {
        return PolicyPayloadStatus::kTruncatedHeader;
    }
    if (!std::equal(kPolicyMagic.begin(), kPolicyMagic.end(), payload)) {
        return PolicyPayloadStatus::kInvalidMagic;
    }
    if (ReadU16(payload + kPolicyVersionOffset) != kProtocolVersion) {
        return PolicyPayloadStatus::kUnsupportedVersion;
    }
    if (ReadU16(payload + kPolicyHeaderLengthOffset) != kPolicyEnvelopeLength) {
        return PolicyPayloadStatus::kInvalidHeaderLength;
    }
    const std::size_t body_length = ReadU32(payload + kPolicyBodyLengthOffset);
    if (body_length > kPolicyMaximumBodyLength) {
        return PolicyPayloadStatus::kBodyTooLarge;
    }
    if (body_length != length - kPolicyEnvelopeLength) {
        return PolicyPayloadStatus::kLengthMismatch;
    }

    std::array<std::uint8_t, 32> digest{};
    if (!HashPayload(payload, body_length, digest)) {
        return PolicyPayloadStatus::kDigestFailure;
    }
    if (!std::equal(digest.begin(), digest.end(), payload + kPolicyDigestOffset)) {
        return PolicyPayloadStatus::kDigestMismatch;
    }
    if (!ValidateBody(payload + kPolicyEnvelopeLength, body_length)) {
        return PolicyPayloadStatus::kInvalidBody;
    }
    return PolicyPayloadStatus::kValid;
}

}  // namespace bolt::protocol
