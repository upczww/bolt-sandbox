#pragma once

#include <cstddef>
#include <cstdint>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace bolt::common {

enum class ImmutableMappingStatus : std::uint8_t {
    kSuccess,
    kInvalidArgument,
    kCreateFailed,
    kMapFailed,
    kDuplicateFailed,
};

class ImmutableMapping final {
  public:
    ImmutableMapping() noexcept = default;
    ~ImmutableMapping() noexcept;
    ImmutableMapping(const ImmutableMapping&) = delete;
    ImmutableMapping& operator=(const ImmutableMapping&) = delete;

    static ImmutableMappingStatus Create(
        const std::uint8_t* bytes,
        std::size_t length,
        ImmutableMapping& output) noexcept;

    void Close() noexcept;
    HANDLE handle() const noexcept { return handle_; }
    std::size_t length() const noexcept { return length_; }

  private:
    HANDLE handle_ = nullptr;
    std::size_t length_ = 0;
};

}  // namespace bolt::common
