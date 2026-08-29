#pragma once

#include <cstddef>
#include <cstdint>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace bolt::common {

enum class PolicyMappingStatus : std::uint8_t {
    kSuccess,
    kInvalidArgument,
    kInvalidPayload,
    kCreateFailed,
    kMapFailed,
    kDuplicateFailed,
};

class ImmutablePolicyMapping final {
  public:
    ImmutablePolicyMapping() noexcept = default;
    ~ImmutablePolicyMapping() noexcept;

    ImmutablePolicyMapping(const ImmutablePolicyMapping&) = delete;
    ImmutablePolicyMapping& operator=(const ImmutablePolicyMapping&) = delete;
    ImmutablePolicyMapping(ImmutablePolicyMapping&&) = delete;
    ImmutablePolicyMapping& operator=(ImmutablePolicyMapping&&) = delete;

    static PolicyMappingStatus Create(
        const std::uint8_t* payload,
        std::size_t length,
        ImmutablePolicyMapping& output) noexcept;

    PolicyMappingStatus Validate() const noexcept;
    void Close() noexcept;

    HANDLE handle() const noexcept { return handle_; }
    std::size_t length() const noexcept { return length_; }

  private:
    HANDLE handle_ = nullptr;
    std::size_t length_ = 0;
};

}  // namespace bolt::common
