#include "common/immutable_mapping.h"

#include <cstring>
#include <limits>

namespace bolt::common {

ImmutableMapping::~ImmutableMapping() noexcept { Close(); }

ImmutableMappingStatus ImmutableMapping::Create(
    const std::uint8_t* const bytes,
    const std::size_t length,
    ImmutableMapping& output) noexcept {
    if (bytes == nullptr || length == 0 ||
        length > std::numeric_limits<DWORD>::max()) {
        return ImmutableMappingStatus::kInvalidArgument;
    }
    const HANDLE writable = CreateFileMappingW(
        INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
        static_cast<DWORD>(length), nullptr);
    if (writable == nullptr) {
        return ImmutableMappingStatus::kCreateFailed;
    }
    void* view = MapViewOfFile(writable, FILE_MAP_WRITE, 0, 0, length);
    if (view == nullptr) {
        CloseHandle(writable);
        return ImmutableMappingStatus::kMapFailed;
    }
    std::memcpy(view, bytes, length);
    UnmapViewOfFile(view);
    HANDLE read_only = nullptr;
    if (!DuplicateHandle(
            GetCurrentProcess(), writable, GetCurrentProcess(), &read_only,
            FILE_MAP_READ, TRUE, 0)) {
        CloseHandle(writable);
        return ImmutableMappingStatus::kDuplicateFailed;
    }
    CloseHandle(writable);
    output.Close();
    output.handle_ = read_only;
    output.length_ = length;
    return ImmutableMappingStatus::kSuccess;
}

void ImmutableMapping::Close() noexcept {
    const HANDLE handle = handle_;
    handle_ = nullptr;
    length_ = 0;
    if (handle != nullptr) {
        CloseHandle(handle);
    }
}

}  // namespace bolt::common
