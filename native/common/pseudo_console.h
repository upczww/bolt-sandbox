#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdint>

namespace bolt::common {

enum class PseudoConsoleStatus : std::uint8_t {
    kSuccess,
    kUnavailable,
    kInvalidSize,
    kPipeFailed,
    kCreateFailed,
    kResizeFailed,
};

class PseudoConsole final {
  public:
    PseudoConsole() noexcept = default;
    ~PseudoConsole() noexcept;
    PseudoConsole(const PseudoConsole&) = delete;
    PseudoConsole& operator=(const PseudoConsole&) = delete;

    PseudoConsoleStatus Create(std::uint16_t columns, std::uint16_t rows) noexcept;
    PseudoConsoleStatus Resize(std::uint16_t columns, std::uint16_t rows) noexcept;
    void Close() noexcept;

    [[nodiscard]] HPCON handle() const noexcept { return handle_; }
    [[nodiscard]] HANDLE input() const noexcept { return input_write_; }
    [[nodiscard]] HANDLE output() const noexcept { return output_read_; }
    [[nodiscard]] HANDLE TakeOutput() noexcept;
    void CloseClientCreationHandles() noexcept;

  private:
    using CreateFunction = HRESULT(WINAPI*)(COORD, HANDLE, HANDLE, DWORD, HPCON*);
    using ResizeFunction = HRESULT(WINAPI*)(HPCON, COORD);
    using CloseFunction = void(WINAPI*)(HPCON);

    CreateFunction create_ = nullptr;
    ResizeFunction resize_ = nullptr;
    CloseFunction close_ = nullptr;
    HPCON handle_ = nullptr;
    HANDLE input_write_ = nullptr;
    HANDLE output_read_ = nullptr;
    HANDLE input_read_ = nullptr;
    HANDLE output_write_ = nullptr;
};

}  // namespace bolt::common
