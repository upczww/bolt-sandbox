#include "common/pseudo_console.h"

#include <climits>

namespace bolt::common {
namespace {

template <typename Function>
Function Resolve(const HMODULE module, const char* const name) noexcept {
    return reinterpret_cast<Function>(GetProcAddress(module, name));
}

void CloseHandleIfValid(const HANDLE handle) noexcept {
    if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
        CloseHandle(handle);
    }
}

}  // namespace

PseudoConsole::~PseudoConsole() noexcept {
    Close();
}

PseudoConsoleStatus PseudoConsole::Create(
    const std::uint16_t columns,
    const std::uint16_t rows) noexcept {
    Close();
    if (columns == 0 || rows == 0 || columns > SHRT_MAX || rows > SHRT_MAX) {
        return PseudoConsoleStatus::kInvalidSize;
    }
    const HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    create_ = Resolve<CreateFunction>(kernel, "CreatePseudoConsole");
    resize_ = Resolve<ResizeFunction>(kernel, "ResizePseudoConsole");
    close_ = Resolve<CloseFunction>(kernel, "ClosePseudoConsole");
    if (create_ == nullptr || resize_ == nullptr || close_ == nullptr) {
        Close();
        return PseudoConsoleStatus::kUnavailable;
    }

    if (!CreatePipe(&input_read_, &input_write_, nullptr, 0) ||
        !CreatePipe(&output_read_, &output_write_, nullptr, 0)) {
        Close();
        return PseudoConsoleStatus::kPipeFailed;
    }
    const COORD size = {
        static_cast<SHORT>(columns), static_cast<SHORT>(rows)};
    const HRESULT result =
        create_(size, input_read_, output_write_, 0, &handle_);
    if (FAILED(result) || handle_ == nullptr) {
        Close();
        return PseudoConsoleStatus::kCreateFailed;
    }
    return PseudoConsoleStatus::kSuccess;
}

PseudoConsoleStatus PseudoConsole::Resize(
    const std::uint16_t columns,
    const std::uint16_t rows) noexcept {
    if (handle_ == nullptr || resize_ == nullptr || columns == 0 || rows == 0) {
        return PseudoConsoleStatus::kInvalidSize;
    }
    const COORD size = {
        static_cast<SHORT>(columns), static_cast<SHORT>(rows)};
    return SUCCEEDED(resize_(handle_, size))
               ? PseudoConsoleStatus::kSuccess
               : PseudoConsoleStatus::kResizeFailed;
}

HANDLE PseudoConsole::TakeOutput() noexcept {
    const HANDLE output = output_read_;
    output_read_ = nullptr;
    return output;
}

void PseudoConsole::CloseClientCreationHandles() noexcept {
    CloseHandleIfValid(input_read_);
    input_read_ = nullptr;
    CloseHandleIfValid(output_write_);
    output_write_ = nullptr;
}

void PseudoConsole::Close() noexcept {
    if (handle_ != nullptr && close_ != nullptr) {
        close_(handle_);
    }
    handle_ = nullptr;
    CloseHandleIfValid(input_write_);
    input_write_ = nullptr;
    CloseHandleIfValid(output_read_);
    output_read_ = nullptr;
    CloseClientCreationHandles();
    create_ = nullptr;
    resize_ = nullptr;
    close_ = nullptr;
}

}  // namespace bolt::common
