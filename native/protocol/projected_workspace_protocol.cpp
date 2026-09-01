#include "protocol/projected_workspace_protocol.h"

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

constexpr std::array<std::uint8_t, 4> kRequestMagic = {'B', 'P', 'J', '1'};
constexpr std::array<std::uint8_t, 4> kReadyMagic = {'B', 'P', 'Y', '1'};
constexpr std::array<std::uint8_t, 4> kFinishedMagic = {'B', 'P', 'F', '1'};
constexpr std::array<std::uint8_t, 4> kControlMagic = {'B', 'P', 'C', '1'};
constexpr std::size_t kDigestOffset = 48;
constexpr std::size_t kDigestLength = 32;
constexpr std::size_t kMaximumPathCodeUnits = 32'767;

void WriteU16(std::uint8_t* output, std::size_t offset, std::uint16_t value) noexcept {
    std::memcpy(output + offset, &value, sizeof(value));
}
void WriteU32(std::uint8_t* output, std::size_t offset, std::uint32_t value) noexcept {
    std::memcpy(output + offset, &value, sizeof(value));
}
void WriteU64(std::uint8_t* output, std::size_t offset, std::uint64_t value) noexcept {
    std::memcpy(output + offset, &value, sizeof(value));
}
std::uint16_t ReadU16(const std::uint8_t* input, std::size_t offset) noexcept {
    std::uint16_t value = 0;
    std::memcpy(&value, input + offset, sizeof(value));
    return value;
}
std::uint32_t ReadU32(const std::uint8_t* input, std::size_t offset) noexcept {
    std::uint32_t value = 0;
    std::memcpy(&value, input + offset, sizeof(value));
    return value;
}
std::uint64_t ReadU64(const std::uint8_t* input, std::size_t offset) noexcept {
    std::uint64_t value = 0;
    std::memcpy(&value, input + offset, sizeof(value));
    return value;
}

bool ValidRequest(const ProjectedWorkspaceRequest& request) noexcept {
    return !request.source_root.empty() &&
           request.source_root.size() <= kMaximumPathCodeUnits &&
           request.source_root.find(L'\0') == std::wstring::npos &&
           !request.projection_root.empty() &&
           request.projection_root.size() <= kMaximumPathCodeUnits &&
           request.projection_root.find(L'\0') == std::wstring::npos &&
           request.maximum_items != 0 && request.maximum_bytes != 0;
}

bool KnownResult(ProjectedWorkspaceResult result) noexcept {
    return result >= ProjectedWorkspaceResult::kSuccess &&
           result <= ProjectedWorkspaceResult::kProtocolError;
}

bool KnownControl(ProjectedWorkspaceControl control) noexcept {
    return control == ProjectedWorkspaceControl::kMaterialize ||
           control == ProjectedWorkspaceControl::kDiscard;
}

bool HashRequest(
    const std::uint8_t* encoded,
    std::size_t length,
    std::array<std::uint8_t, kDigestLength>& digest) noexcept {
    if (encoded == nullptr || length < kProjectedWorkspaceHeaderLength) {
        return false;
    }
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD object_length = 0;
    DWORD returned = 0;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
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
    bool succeeded = BCryptCreateHash(
                         algorithm, &hash, object.data(), object_length,
                         nullptr, 0, 0) >= 0;
    if (succeeded) {
        succeeded = BCryptHashData(
                        hash, const_cast<PUCHAR>(encoded),
                        static_cast<ULONG>(kDigestOffset), 0) >= 0;
    }
    if (succeeded && length > kProjectedWorkspaceHeaderLength) {
        succeeded = BCryptHashData(
                        hash,
                        const_cast<PUCHAR>(encoded + kProjectedWorkspaceHeaderLength),
                        static_cast<ULONG>(length - kProjectedWorkspaceHeaderLength), 0) >= 0;
    }
    if (succeeded) {
        succeeded = BCryptFinishHash(
                        hash, digest.data(), static_cast<ULONG>(digest.size()), 0) >= 0;
    }
    if (hash != nullptr) {
        BCryptDestroyHash(hash);
    }
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return succeeded;
}

void AppendUtf16(std::vector<std::uint8_t>& output, const std::wstring& value) {
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(value.data());
    output.insert(output.end(), bytes, bytes + value.size() * sizeof(wchar_t));
}

bool ReadUtf16(
    const std::uint8_t* input,
    std::size_t length,
    std::size_t& offset,
    std::size_t code_units,
    std::wstring& output) {
    if (code_units > std::numeric_limits<std::size_t>::max() / sizeof(wchar_t) ||
        code_units * sizeof(wchar_t) > length - offset) {
        return false;
    }
    output.resize(code_units);
    std::memcpy(output.data(), input + offset, code_units * sizeof(wchar_t));
    offset += code_units * sizeof(wchar_t);
    return true;
}

const std::array<std::uint8_t, 4>& ResponseMagic(
    ProjectedWorkspaceResponseKind kind) noexcept {
    return kind == ProjectedWorkspaceResponseKind::kReady ? kReadyMagic
                                                           : kFinishedMagic;
}

}  // namespace

bool ProjectedWorkspaceRequest::operator==(
    const ProjectedWorkspaceRequest& other) const noexcept {
    return source_root == other.source_root &&
           projection_root == other.projection_root &&
           maximum_items == other.maximum_items &&
           maximum_bytes == other.maximum_bytes;
}

ProjectedWorkspaceProtocolStatus EncodeProjectedWorkspaceRequest(
    const ProjectedWorkspaceRequest& request,
    std::vector<std::uint8_t>& encoded) noexcept {
    encoded.clear();
    if (!ValidRequest(request)) {
        return ProjectedWorkspaceProtocolStatus::kInvalidField;
    }
    const std::size_t body_length =
        (request.source_root.size() + request.projection_root.size()) * sizeof(wchar_t);
    const std::size_t total_length = kProjectedWorkspaceHeaderLength + body_length;
    if (total_length > kProjectedWorkspaceMaximumRequestLength ||
        total_length > std::numeric_limits<std::uint32_t>::max()) {
        return ProjectedWorkspaceProtocolStatus::kInvalidLength;
    }
    try {
        encoded.assign(kProjectedWorkspaceHeaderLength, 0);
        encoded.reserve(total_length);
        std::copy(kRequestMagic.begin(), kRequestMagic.end(), encoded.begin());
        WriteU16(encoded.data(), 4, kProtocolVersion);
        WriteU16(encoded.data(), 6, static_cast<std::uint16_t>(kProjectedWorkspaceHeaderLength));
        WriteU32(encoded.data(), 8, static_cast<std::uint32_t>(total_length));
        WriteU32(encoded.data(), 12, static_cast<std::uint32_t>(request.source_root.size()));
        WriteU32(encoded.data(), 16, static_cast<std::uint32_t>(request.projection_root.size()));
        WriteU32(encoded.data(), 20, request.maximum_items);
        WriteU64(encoded.data(), 24, request.maximum_bytes);
        AppendUtf16(encoded, request.source_root);
        AppendUtf16(encoded, request.projection_root);
    } catch (...) {
        encoded.clear();
        return ProjectedWorkspaceProtocolStatus::kAllocationFailed;
    }
    std::array<std::uint8_t, kDigestLength> digest{};
    if (!HashRequest(encoded.data(), encoded.size(), digest)) {
        encoded.clear();
        return ProjectedWorkspaceProtocolStatus::kAllocationFailed;
    }
    std::copy(digest.begin(), digest.end(), encoded.begin() + kDigestOffset);
    return ProjectedWorkspaceProtocolStatus::kSuccess;
}

ProjectedWorkspaceProtocolStatus DecodeProjectedWorkspaceRequest(
    const std::uint8_t* encoded,
    std::size_t length,
    ProjectedWorkspaceRequest& request) noexcept {
    if (encoded == nullptr) {
        return ProjectedWorkspaceProtocolStatus::kInvalidArgument;
    }
    if (length < kProjectedWorkspaceHeaderLength ||
        length > kProjectedWorkspaceMaximumRequestLength || ReadU32(encoded, 8) != length) {
        return ProjectedWorkspaceProtocolStatus::kInvalidLength;
    }
    if (!std::equal(kRequestMagic.begin(), kRequestMagic.end(), encoded)) {
        return ProjectedWorkspaceProtocolStatus::kInvalidMagic;
    }
    if (ReadU16(encoded, 4) != kProtocolVersion) {
        return ProjectedWorkspaceProtocolStatus::kUnsupportedVersion;
    }
    if (ReadU16(encoded, 6) != kProjectedWorkspaceHeaderLength ||
        std::any_of(encoded + 32, encoded + 48, [](std::uint8_t value) { return value != 0; })) {
        return ProjectedWorkspaceProtocolStatus::kInvalidHeader;
    }
    std::array<std::uint8_t, kDigestLength> digest{};
    if (!HashRequest(encoded, length, digest) ||
        !std::equal(digest.begin(), digest.end(), encoded + kDigestOffset)) {
        return ProjectedWorkspaceProtocolStatus::kDigestMismatch;
    }
    ProjectedWorkspaceRequest decoded{};
    decoded.maximum_items = ReadU32(encoded, 20);
    decoded.maximum_bytes = ReadU64(encoded, 24);
    const std::size_t source_length = ReadU32(encoded, 12);
    const std::size_t projection_length = ReadU32(encoded, 16);
    std::size_t offset = kProjectedWorkspaceHeaderLength;
    try {
        if (!ReadUtf16(encoded, length, offset, source_length, decoded.source_root) ||
            !ReadUtf16(encoded, length, offset, projection_length, decoded.projection_root) ||
            offset != length) {
            return ProjectedWorkspaceProtocolStatus::kInvalidLength;
        }
    } catch (...) {
        return ProjectedWorkspaceProtocolStatus::kAllocationFailed;
    }
    if (!ValidRequest(decoded)) {
        return ProjectedWorkspaceProtocolStatus::kInvalidField;
    }
    request = std::move(decoded);
    return ProjectedWorkspaceProtocolStatus::kSuccess;
}

std::array<std::uint8_t, kProjectedWorkspaceResponseLength>
EncodeProjectedWorkspaceResponse(
    ProjectedWorkspaceResponseKind kind,
    ProjectedWorkspaceResult result) noexcept {
    std::array<std::uint8_t, kProjectedWorkspaceResponseLength> encoded{};
    if (!KnownResult(result)) {
        return encoded;
    }
    const auto& magic = ResponseMagic(kind);
    std::copy(magic.begin(), magic.end(), encoded.begin());
    WriteU16(encoded.data(), 4, kProtocolVersion);
    WriteU16(encoded.data(), 6, static_cast<std::uint16_t>(encoded.size()));
    WriteU32(encoded.data(), 8, static_cast<std::uint32_t>(result));
    return encoded;
}

ProjectedWorkspaceProtocolStatus DecodeProjectedWorkspaceResponse(
    const std::uint8_t* encoded,
    std::size_t length,
    ProjectedWorkspaceResponseKind expected_kind,
    ProjectedWorkspaceResult& result) noexcept {
    if (encoded == nullptr) {
        return ProjectedWorkspaceProtocolStatus::kInvalidArgument;
    }
    if (length != kProjectedWorkspaceResponseLength) {
        return ProjectedWorkspaceProtocolStatus::kInvalidLength;
    }
    const auto& magic = ResponseMagic(expected_kind);
    if (!std::equal(magic.begin(), magic.end(), encoded)) {
        return ProjectedWorkspaceProtocolStatus::kInvalidMagic;
    }
    if (ReadU16(encoded, 4) != kProtocolVersion) {
        return ProjectedWorkspaceProtocolStatus::kUnsupportedVersion;
    }
    if (ReadU16(encoded, 6) != length) {
        return ProjectedWorkspaceProtocolStatus::kInvalidHeader;
    }
    const auto decoded = static_cast<ProjectedWorkspaceResult>(ReadU32(encoded, 8));
    if (!KnownResult(decoded)) {
        return ProjectedWorkspaceProtocolStatus::kInvalidField;
    }
    result = decoded;
    return ProjectedWorkspaceProtocolStatus::kSuccess;
}

std::array<std::uint8_t, kProjectedWorkspaceControlLength>
EncodeProjectedWorkspaceControl(ProjectedWorkspaceControl control) noexcept {
    std::array<std::uint8_t, kProjectedWorkspaceControlLength> encoded{};
    if (!KnownControl(control)) {
        return encoded;
    }
    std::copy(kControlMagic.begin(), kControlMagic.end(), encoded.begin());
    WriteU16(encoded.data(), 4, kProtocolVersion);
    WriteU16(encoded.data(), 6, static_cast<std::uint16_t>(control));
    return encoded;
}

ProjectedWorkspaceProtocolStatus DecodeProjectedWorkspaceControl(
    const std::uint8_t* encoded,
    std::size_t length,
    ProjectedWorkspaceControl& control) noexcept {
    if (encoded == nullptr) {
        return ProjectedWorkspaceProtocolStatus::kInvalidArgument;
    }
    if (length != kProjectedWorkspaceControlLength) {
        return ProjectedWorkspaceProtocolStatus::kInvalidLength;
    }
    if (!std::equal(kControlMagic.begin(), kControlMagic.end(), encoded)) {
        return ProjectedWorkspaceProtocolStatus::kInvalidMagic;
    }
    if (ReadU16(encoded, 4) != kProtocolVersion) {
        return ProjectedWorkspaceProtocolStatus::kUnsupportedVersion;
    }
    const auto decoded = static_cast<ProjectedWorkspaceControl>(ReadU16(encoded, 6));
    if (!KnownControl(decoded)) {
        return ProjectedWorkspaceProtocolStatus::kInvalidField;
    }
    control = decoded;
    return ProjectedWorkspaceProtocolStatus::kSuccess;
}

}  // namespace bolt::protocol
