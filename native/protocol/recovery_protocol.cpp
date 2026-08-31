#include "protocol/recovery_protocol.h"

#include "protocol/version.h"

#include <algorithm>
#include <array>
#include <cstring>

namespace bolt::protocol {
namespace {

constexpr std::array<std::uint8_t, 4> kRequestMagic = {'B', 'R', 'Q', '1'};
constexpr std::array<std::uint8_t, 4> kResponseMagic = {'B', 'R', 'P', '1'};

template <typename T>
void Write(std::uint8_t* output, const std::size_t offset, const T value) noexcept {
    std::memcpy(output + offset, &value, sizeof(value));
}

template <typename T>
T Read(const std::uint8_t* input, const std::size_t offset) noexcept {
    T value{};
    std::memcpy(&value, input + offset, sizeof(value));
    return value;
}

bool ValidOperation(const RecoveryOperation operation) noexcept {
    return operation >= RecoveryOperation::kDelete &&
           operation <= RecoveryOperation::kRename;
}

}  // namespace

RecoveryProtocolStatus EncodeRecoveryRequest(
    const std::uint64_t request_id,
    const std::uint32_t process_id,
    const RecoveryOperation operation,
    const wchar_t* const path,
    std::vector<std::uint8_t>& encoded) noexcept {
    encoded.clear();
    if (request_id == 0 || process_id == 0 || !ValidOperation(operation) ||
        path == nullptr) {
        return RecoveryProtocolStatus::kInvalidArgument;
    }
    std::size_t path_length = 0;
    while (path_length <= 32'767 && path[path_length] != L'\0') {
        ++path_length;
    }
    if (path_length == 0 || path_length > 32'767) {
        return RecoveryProtocolStatus::kInvalidField;
    }
    const std::size_t total =
        kRecoveryRequestHeaderLength + path_length * sizeof(wchar_t);
    try {
        encoded.assign(total, 0);
    } catch (...) {
        return RecoveryProtocolStatus::kAllocationFailed;
    }
    std::copy(kRequestMagic.begin(), kRequestMagic.end(), encoded.begin());
    Write(encoded.data(), 4, kProtocolVersion);
    Write(
        encoded.data(), 6,
        static_cast<std::uint16_t>(kRecoveryRequestHeaderLength));
    Write(encoded.data(), 8, static_cast<std::uint32_t>(total));
    Write(encoded.data(), 12, static_cast<std::uint32_t>(path_length));
    Write(encoded.data(), 16, request_id);
    Write(encoded.data(), 24, process_id);
    encoded[28] = static_cast<std::uint8_t>(operation);
    std::memcpy(
        encoded.data() + kRecoveryRequestHeaderLength, path,
        path_length * sizeof(wchar_t));
    return RecoveryProtocolStatus::kSuccess;
}

RecoveryProtocolStatus DecodeRecoveryResponse(
    const std::uint8_t* const encoded,
    const std::size_t length,
    RecoveryResponse& response) noexcept {
    if (encoded == nullptr) {
        return RecoveryProtocolStatus::kInvalidArgument;
    }
    if (length != kRecoveryResponseLength ||
        Read<std::uint32_t>(encoded, 8) != kRecoveryResponseLength) {
        return RecoveryProtocolStatus::kInvalidLength;
    }
    if (!std::equal(kResponseMagic.begin(), kResponseMagic.end(), encoded)) {
        return RecoveryProtocolStatus::kInvalidMagic;
    }
    if (Read<std::uint16_t>(encoded, 4) != kProtocolVersion) {
        return RecoveryProtocolStatus::kUnsupportedVersion;
    }
    if (Read<std::uint16_t>(encoded, 6) != kRecoveryResponseLength) {
        return RecoveryProtocolStatus::kInvalidHeader;
    }
    const std::uint8_t status = encoded[20];
    if (status > 1 || encoded[21] != 0 || encoded[22] != 0 ||
        encoded[23] != 0) {
        return RecoveryProtocolStatus::kInvalidField;
    }
    RecoveryResponse decoded{};
    decoded.request_id = Read<std::uint64_t>(encoded, 12);
    decoded.succeeded = status == 0;
    decoded.artifact_id = Read<std::uint64_t>(encoded, 24);
    decoded.byte_count = Read<std::uint64_t>(encoded, 32);
    if (decoded.request_id == 0 ||
        (decoded.succeeded && decoded.artifact_id == 0) ||
        (!decoded.succeeded &&
         (decoded.artifact_id != 0 || decoded.byte_count != 0))) {
        return RecoveryProtocolStatus::kInvalidField;
    }
    response = decoded;
    return RecoveryProtocolStatus::kSuccess;
}

}  // namespace bolt::protocol
