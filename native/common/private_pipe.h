#pragma once

#include <cstdint>
#include <string_view>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace bolt::common {

enum class PipeStatus : std::uint8_t {
    kSuccess,
    kInvalidName,
    kAllocationFailed,
    kSecurityFailed,
    kCreateFailed,
    kInvalidState,
    kConnectFailed,
};

class PrivatePipe final {
  public:
    PrivatePipe() noexcept = default;
    ~PrivatePipe() noexcept;

    PrivatePipe(const PrivatePipe&) = delete;
    PrivatePipe& operator=(const PrivatePipe&) = delete;
    PrivatePipe(PrivatePipe&&) = delete;
    PrivatePipe& operator=(PrivatePipe&&) = delete;

    static PipeStatus Create(std::wstring_view name, PrivatePipe& output) noexcept;

    PipeStatus Accept() noexcept;
    void Close() noexcept;

    HANDLE handle() const noexcept { return handle_; }

  private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    bool connected_ = false;
};

}  // namespace bolt::common
