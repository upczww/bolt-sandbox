#include "protocol/workspace_security_protocol.h"

#include "protocol/version.h"

#include <algorithm>
#include <cstring>
#include <limits>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

namespace bolt::protocol {
namespace {

constexpr std::array<std::uint8_t, 4> kRequestMagic = {'B', 'W', 'S', '1'};
constexpr std::array<std::uint8_t, 4> kResponseMagic = {'B', 'W', 'R', '1'};
constexpr std::size_t kDigestOffset = 32;
constexpr std::size_t kDigestLength = 32;
constexpr std::size_t kMaximumPathCodeUnits = 32'767;

void WriteU16(
    std::uint8_t* const output,
    const std::size_t offset,
    const std::uint16_t value) noexcept {
    std::memcpy(output + offset, &value, sizeof(value));
}

void WriteU32(
    std::uint8_t* const output,
    const std::size_t offset,
    const std::uint32_t value) noexcept {
    std::memcpy(output + offset, &value, sizeof(value));
}

std::uint16_t ReadU16(
    const std::uint8_t* const input,
    const std::size_t offset) noexcept {
    std::uint16_t value = 0;
    std::memcpy(&value, input + offset, sizeof(value));
    return value;
}

std::uint32_t ReadU32(
    const std::uint8_t* const input,
    const std::size_t offset) noexcept {
    std::uint32_t value = 0;
    std::memcpy(&value, input + offset, sizeof(value));
    return value;
}

bool IsKnown(const WorkspaceSecurityOperation operation) noexcept {
    return operation == WorkspaceSecurityOperation::kCopy ||
           operation == WorkspaceSecurityOperation::kVerify ||
           operation == WorkspaceSecurityOperation::kCopyRoot;
}

bool IsKnown(const WorkspaceSecurityResult result) noexcept {
    return result >= WorkspaceSecurityResult::kSuccess &&
           result <= WorkspaceSecurityResult::kProtocolError;
}

bool IsValid(const WorkspaceSecurityRequest& request) noexcept {
    return IsKnown(request.operation) && request.maximum_items != 0 &&
           !request.source_root.empty() &&
           request.source_root.size() <= kMaximumPathCodeUnits &&
           request.source_root.find(L'\0') == std::wstring::npos &&
           !request.destination_root.empty() &&
           request.destination_root.size() <= kMaximumPathCodeUnits &&
           request.destination_root.find(L'\0') == std::wstring::npos;
}

bool HashRequest(
    const std::uint8_t* const encoded,
    const std::size_t length,
    std::array<std::uint8_t, kDigestLength>& digest) noexcept {
    if (encoded == nullptr || length < kWorkspaceSecurityHeaderLength) {
        return false;
    }
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD object_length = 0;
    DWORD returned = 0;
    if (BCryptOpenAlgorithmProvider(
            &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
        BCryptGetProperty(
            algorithm, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&object_length), sizeof(object_length),
            &returned, 0) < 0) {
        if (algorithm != nullptr) {
            BCryptCloseAlgorithmProvider(algorithm, 0);
        }
        return false;
    }
    std::vector<std::uint8_t> object;
    try {
        object.resize(object_length);
    } catch (...) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return false;
    }
    bool succeeded =
        BCryptCreateHash(
            algorithm, &hash, object.data(), object_length, nullptr, 0, 0) >=
        0;
    if (succeeded) {
        succeeded = BCryptHashData(
                        hash, const_cast<PUCHAR>(encoded),
                        static_cast<ULONG>(kDigestOffset), 0) >= 0;
    }
    if (succeeded && length > kWorkspaceSecurityHeaderLength) {
        succeeded = BCryptHashData(
                        hash,
                        const_cast<PUCHAR>(
                            encoded + kWorkspaceSecurityHeaderLength),
                        static_cast<ULONG>(
                            length - kWorkspaceSecurityHeaderLength),
                        0) >= 0;
    }
    if (succeeded) {
        succeeded = BCryptFinishHash(
                        hash, digest.data(),
                        static_cast<ULONG>(digest.size()), 0) >= 0;
    }
    if (hash != nullptr) {
        BCryptDestroyHash(hash);
    }
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return succeeded;
}

void AppendUtf16(
    std::vector<std::uint8_t>& encoded,
    const std::wstring& value) {
    const auto* const bytes =
        reinterpret_cast<const std::uint8_t*>(value.data());
    encoded.insert(
        encoded.end(), bytes, bytes + value.size() * sizeof(wchar_t));
}

bool ReadUtf16(
    const std::uint8_t* const encoded,
    const std::size_t length,
    std::size_t& offset,
    const std::size_t code_units,
    std::wstring& output) {
    if (code_units > std::numeric_limits<std::size_t>::max() /
                         sizeof(wchar_t) ||
        code_units * sizeof(wchar_t) > length - offset) {
        return false;
    }
    output.resize(code_units);
    std::memcpy(
        output.data(), encoded + offset, code_units * sizeof(wchar_t));
    offset += code_units * sizeof(wchar_t);
    return true;
}

}  // namespace

bool WorkspaceSecurityRequest::operator==(
    const WorkspaceSecurityRequest& other) const noexcept {
    return operation == other.operation &&
           maximum_items == other.maximum_items &&
           source_root == other.source_root &&
           destination_root == other.destination_root;
}

WorkspaceSecurityProtocolStatus EncodeWorkspaceSecurityRequest(
    const WorkspaceSecurityRequest& request,
    std::vector<std::uint8_t>& encoded) noexcept {
    encoded.clear();
    if (!IsValid(request)) {
        return WorkspaceSecurityProtocolStatus::kInvalidField;
    }
    const std::size_t body_length =
        (request.source_root.size() + request.destination_root.size()) *
        sizeof(wchar_t);
    const std::size_t total_length =
        kWorkspaceSecurityHeaderLength + body_length;
    if (total_length > kWorkspaceSecurityMaximumRequestLength ||
        total_length > std::numeric_limits<std::uint32_t>::max()) {
        return WorkspaceSecurityProtocolStatus::kInvalidLength;
    }
    try {
        encoded.assign(kWorkspaceSecurityHeaderLength, 0);
        encoded.reserve(total_length);
        std::copy(kRequestMagic.begin(), kRequestMagic.end(), encoded.begin());
        WriteU16(encoded.data(), 4, kProtocolVersion);
        WriteU16(
            encoded.data(), 6,
            static_cast<std::uint16_t>(kWorkspaceSecurityHeaderLength));
        WriteU32(encoded.data(), 8, static_cast<std::uint32_t>(total_length));
        WriteU16(
            encoded.data(), 12,
            static_cast<std::uint16_t>(request.operation));
        WriteU32(encoded.data(), 16, request.maximum_items);
        WriteU32(
            encoded.data(), 20,
            static_cast<std::uint32_t>(request.source_root.size()));
        WriteU32(
            encoded.data(), 24,
            static_cast<std::uint32_t>(request.destination_root.size()));
        AppendUtf16(encoded, request.source_root);
        AppendUtf16(encoded, request.destination_root);
    } catch (...) {
        encoded.clear();
        return WorkspaceSecurityProtocolStatus::kAllocationFailed;
    }
    std::array<std::uint8_t, kDigestLength> digest{};
    if (!HashRequest(encoded.data(), encoded.size(), digest)) {
        encoded.clear();
        return WorkspaceSecurityProtocolStatus::kAllocationFailed;
    }
    std::copy(digest.begin(), digest.end(), encoded.begin() + kDigestOffset);
    return WorkspaceSecurityProtocolStatus::kSuccess;
}

WorkspaceSecurityProtocolStatus DecodeWorkspaceSecurityRequest(
    const std::uint8_t* const encoded,
    const std::size_t length,
    WorkspaceSecurityRequest& request) noexcept {
    if (encoded == nullptr) {
        return WorkspaceSecurityProtocolStatus::kInvalidArgument;
    }
    if (length < kWorkspaceSecurityHeaderLength ||
        length > kWorkspaceSecurityMaximumRequestLength ||
        ReadU32(encoded, 8) != length) {
        return WorkspaceSecurityProtocolStatus::kInvalidLength;
    }
    if (!std::equal(kRequestMagic.begin(), kRequestMagic.end(), encoded)) {
        return WorkspaceSecurityProtocolStatus::kInvalidMagic;
    }
    if (ReadU16(encoded, 4) != kProtocolVersion) {
        return WorkspaceSecurityProtocolStatus::kUnsupportedVersion;
    }
    if (ReadU16(encoded, 6) != kWorkspaceSecurityHeaderLength ||
        ReadU16(encoded, 14) != 0 || ReadU32(encoded, 28) != 0) {
        return WorkspaceSecurityProtocolStatus::kInvalidHeader;
    }
    std::array<std::uint8_t, kDigestLength> digest{};
    if (!HashRequest(encoded, length, digest) ||
        !std::equal(digest.begin(), digest.end(), encoded + kDigestOffset)) {
        return WorkspaceSecurityProtocolStatus::kDigestMismatch;
    }
    WorkspaceSecurityRequest decoded{};
    decoded.operation =
        static_cast<WorkspaceSecurityOperation>(ReadU16(encoded, 12));
    decoded.maximum_items = ReadU32(encoded, 16);
    const std::size_t source_length = ReadU32(encoded, 20);
    const std::size_t destination_length = ReadU32(encoded, 24);
    std::size_t offset = kWorkspaceSecurityHeaderLength;
    try {
        if (!ReadUtf16(
                encoded, length, offset, source_length,
                decoded.source_root) ||
            !ReadUtf16(
                encoded, length, offset, destination_length,
                decoded.destination_root) ||
            offset != length) {
            return WorkspaceSecurityProtocolStatus::kInvalidLength;
        }
    } catch (...) {
        return WorkspaceSecurityProtocolStatus::kAllocationFailed;
    }
    if (!IsValid(decoded)) {
        return WorkspaceSecurityProtocolStatus::kInvalidField;
    }
    request = std::move(decoded);
    return WorkspaceSecurityProtocolStatus::kSuccess;
}

std::array<std::uint8_t, kWorkspaceSecurityResponseLength>
EncodeWorkspaceSecurityResponse(const WorkspaceSecurityResult result) noexcept {
    std::array<std::uint8_t, kWorkspaceSecurityResponseLength> encoded{};
    if (!IsKnown(result)) {
        return encoded;
    }
    std::copy(kResponseMagic.begin(), kResponseMagic.end(), encoded.begin());
    WriteU16(encoded.data(), 4, kProtocolVersion);
    WriteU16(
        encoded.data(), 6,
        static_cast<std::uint16_t>(kWorkspaceSecurityResponseLength));
    WriteU32(encoded.data(), 8, static_cast<std::uint32_t>(result));
    return encoded;
}

WorkspaceSecurityProtocolStatus DecodeWorkspaceSecurityResponse(
    const std::uint8_t* const encoded,
    const std::size_t length,
    WorkspaceSecurityResult& result) noexcept {
    if (encoded == nullptr) {
        return WorkspaceSecurityProtocolStatus::kInvalidArgument;
    }
    if (length != kWorkspaceSecurityResponseLength) {
        return WorkspaceSecurityProtocolStatus::kInvalidLength;
    }
    if (!std::equal(kResponseMagic.begin(), kResponseMagic.end(), encoded)) {
        return WorkspaceSecurityProtocolStatus::kInvalidMagic;
    }
    if (ReadU16(encoded, 4) != kProtocolVersion) {
        return WorkspaceSecurityProtocolStatus::kUnsupportedVersion;
    }
    if (ReadU16(encoded, 6) != kWorkspaceSecurityResponseLength) {
        return WorkspaceSecurityProtocolStatus::kInvalidHeader;
    }
    const auto decoded =
        static_cast<WorkspaceSecurityResult>(ReadU32(encoded, 8));
    if (!IsKnown(decoded)) {
        return WorkspaceSecurityProtocolStatus::kInvalidField;
    }
    result = decoded;
    return WorkspaceSecurityProtocolStatus::kSuccess;
}

}  // namespace bolt::protocol
