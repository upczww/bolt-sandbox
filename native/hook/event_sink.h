#pragma once

#include "protocol/event_frame.h"

#include <cstdint>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace bolt::hook {

enum class EventSinkStatus : std::uint8_t {
    kSuccess,
    kInvalidHandle,
    kAlreadyInitialized,
    kAllocationFailed,
    kSynchronizationFailed,
    kThreadFailed,
};

EventSinkStatus InitializeEventSink(HANDLE event_handle) noexcept;

bool IsEventSinkHandle(HANDLE handle) noexcept;

bool TryReportFilesystemViolation(
    protocol::FilesystemOperation operation,
    const wchar_t* path) noexcept;

bool TryReportProcessViolation(protocol::ProcessOperation operation) noexcept;

bool WaitForEventSinkIdle(DWORD timeout_milliseconds) noexcept;

}  // namespace bolt::hook
