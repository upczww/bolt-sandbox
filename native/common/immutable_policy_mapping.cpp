#include "common/immutable_policy_mapping.h"

#include "protocol/policy_payload.h"

#include <cstring>
#include <limits>

namespace bolt::common {

ImmutablePolicyMapping::~ImmutablePolicyMapping() noexcept {
    Close();
}

PolicyMappingStatus ImmutablePolicyMapping::Create(
    const std::uint8_t* payload,
    const std::size_t length,
    ImmutablePolicyMapping& output) noexcept {
    if (payload == nullptr || length == 0 ||
        length > std::numeric_limits<DWORD>::max()) {
        return PolicyMappingStatus::kInvalidArgument;
    }
    if (protocol::ValidatePolicyPayload(payload, length) !=
        protocol::PolicyPayloadStatus::kValid) {
        return PolicyMappingStatus::kInvalidPayload;
    }

    const HANDLE writable = CreateFileMappingW(
        INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, static_cast<DWORD>(length), nullptr);
    if (writable == nullptr) {
        return PolicyMappingStatus::kCreateFailed;
    }
    void* view = MapViewOfFile(writable, FILE_MAP_WRITE, 0, 0, length);
    if (view == nullptr) {
        CloseHandle(writable);
        return PolicyMappingStatus::kMapFailed;
    }
    std::memcpy(view, payload, length);
    UnmapViewOfFile(view);

    HANDLE read_only = nullptr;
    if (!DuplicateHandle(
            GetCurrentProcess(), writable, GetCurrentProcess(), &read_only, FILE_MAP_READ, TRUE,
            0)) {
        CloseHandle(writable);
        return PolicyMappingStatus::kDuplicateFailed;
    }
    CloseHandle(writable);

    output.Close();
    output.handle_ = read_only;
    output.length_ = length;
    return PolicyMappingStatus::kSuccess;
}

PolicyMappingStatus ImmutablePolicyMapping::Validate() const noexcept {
    if (handle_ == nullptr || length_ == 0) {
        return PolicyMappingStatus::kInvalidArgument;
    }
    const auto* view = static_cast<const std::uint8_t*>(
        MapViewOfFile(handle_, FILE_MAP_READ, 0, 0, length_));
    if (view == nullptr) {
        return PolicyMappingStatus::kMapFailed;
    }
    const auto status = protocol::ValidatePolicyPayload(view, length_);
    UnmapViewOfFile(view);
    return status == protocol::PolicyPayloadStatus::kValid
               ? PolicyMappingStatus::kSuccess
               : PolicyMappingStatus::kInvalidPayload;
}

void ImmutablePolicyMapping::Close() noexcept {
    const HANDLE handle = handle_;
    handle_ = nullptr;
    length_ = 0;
    if (handle != nullptr) {
        CloseHandle(handle);
    }
}

}  // namespace bolt::common
