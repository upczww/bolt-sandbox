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

bool RegisterRuntimeIoHandles(
    HANDLE dns_response_read_handle,
    HANDLE dns_request_write_handle) noexcept;

bool IsRuntimeIoHandle(HANDLE handle, bool write_access) noexcept;

bool TryReportFilesystemViolation(
    protocol::FilesystemOperation operation,
    const wchar_t* path) noexcept;

bool TryReportProcessViolation(protocol::ProcessOperation operation) noexcept;

bool TryReportChildInjectionFailure(
    std::uint32_t child_process_id,
    protocol::ChildInjectionFailureReason reason) noexcept;

bool TryReportRegistryViolation(
    protocol::RegistryOperation operation,
    const char* key) noexcept;

bool TryReportNetworkViolation(
    protocol::NetworkOperation operation,
    const protocol::NetworkEndpoint& endpoint) noexcept;

bool TryReportDomainNetworkViolation(
    protocol::NetworkOperation operation,
    const char* ascii_domain) noexcept;

bool WaitForEventSinkIdle(DWORD timeout_milliseconds) noexcept;

}  // namespace bolt::hook
