#include "hook/event_sink.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace bolt::hook {
namespace {

constexpr std::size_t kQueueCapacity = 64;
constexpr std::size_t kMaximumFrameLength =
    protocol::kEventHeaderLength + 9U + protocol::kMaximumEventPathCodeUnits * 2U;

enum class EventRecordKind : std::uint8_t {
    kFilesystem,
    kProcess,
    kRegistry,
    kNetwork,
    kNetworkDomain,
};

struct EventRecord {
    EventRecordKind kind = EventRecordKind::kFilesystem;
    std::uint32_t process_id = 0;
    protocol::FilesystemOperation operation = protocol::FilesystemOperation::kRead;
    protocol::ProcessOperation process_operation =
        protocol::ProcessOperation::kCreateWithToken;
    protocol::RegistryOperation registry_operation =
        protocol::RegistryOperation::kOpen;
    protocol::NetworkOperation network_operation =
        protocol::NetworkOperation::kConnect;
    protocol::NetworkEndpoint network_endpoint{};
    char domain[protocol::kMaximumEventDomainBytes + 1U]{};
    char registry_key[4'097]{};
    std::uint64_t sequence = 0;
    std::size_t path_length = 0;
    wchar_t path[protocol::kMaximumEventPathCodeUnits + 1U]{};
};

struct EventSinkState {
    volatile LONG initialization_state = 0;
    volatile LONG writer_failed = 0;
    CRITICAL_SECTION lock{};
    HANDLE event_handle = INVALID_HANDLE_VALUE;
    HANDLE wake_event = nullptr;
    HANDLE idle_event = nullptr;
    HANDLE worker_thread = nullptr;
    EventRecord* records = nullptr;
    std::uint8_t* frame_buffer = nullptr;
    std::size_t head = 0;
    std::size_t tail = 0;
    std::size_t count = 0;
    std::uint64_t next_sequence = 1;
    std::uint64_t dropped_events = 0;
};

EventSinkState g_state;
PVOID volatile g_dns_response_read_handle = nullptr;
PVOID volatile g_dns_request_write_handle = nullptr;

bool WriteExact(
    const HANDLE handle,
    const std::uint8_t* bytes,
    const std::size_t length) noexcept {
    std::size_t offset = 0;
    while (offset < length) {
        DWORD written = 0;
        if (!WriteFile(
                handle, bytes + offset, static_cast<DWORD>(length - offset), &written,
                nullptr) ||
            written == 0) {
            return false;
        }
        offset += written;
    }
    return true;
}

void FailWriter() noexcept {
    InterlockedExchange(&g_state.writer_failed, 1);
    EnterCriticalSection(&g_state.lock);
    g_state.head = 0;
    g_state.tail = 0;
    g_state.count = 0;
    g_state.dropped_events = 0;
    SetEvent(g_state.idle_event);
    LeaveCriticalSection(&g_state.lock);
}

DWORD WINAPI EventWriterThread(LPVOID parameter) noexcept {
    static_cast<void>(parameter);
    for (;;) {
        if (WaitForSingleObject(g_state.wake_event, INFINITE) != WAIT_OBJECT_0) {
            FailWriter();
            return 1;
        }
        for (;;) {
            bool write_dropped_summary = false;
            std::uint64_t dropped_count = 0;
            std::uint64_t dropped_sequence = 0;
            EnterCriticalSection(&g_state.lock);
            if (g_state.count == 0) {
                if (g_state.dropped_events == 0) {
                    SetEvent(g_state.idle_event);
                    LeaveCriticalSection(&g_state.lock);
                    break;
                }
                write_dropped_summary = true;
                dropped_count = g_state.dropped_events;
                g_state.dropped_events = 0;
                dropped_sequence = g_state.next_sequence++;
            }
            const EventRecord* queued = write_dropped_summary
                                            ? nullptr
                                            : &g_state.records[g_state.head];
            LeaveCriticalSection(&g_state.lock);

            std::size_t frame_length = 0;
            protocol::FrameEncodeStatus encode_status =
                protocol::FrameEncodeStatus::kInvalidArgument;
            if (write_dropped_summary) {
                encode_status = protocol::EncodeEventsDroppedFrame(
                    GetCurrentProcessId(), dropped_count, dropped_sequence,
                    g_state.frame_buffer, kMaximumFrameLength, frame_length);
            } else {
                switch (queued->kind) {
                    case EventRecordKind::kFilesystem:
                        encode_status = protocol::EncodeFilesystemViolationFrame(
                            queued->process_id, queued->operation, queued->path,
                            queued->sequence, g_state.frame_buffer,
                            kMaximumFrameLength, frame_length);
                        break;
                    case EventRecordKind::kProcess:
                        encode_status = protocol::EncodeProcessViolationFrame(
                            queued->process_id, queued->process_operation,
                            queued->sequence, g_state.frame_buffer,
                            kMaximumFrameLength, frame_length);
                        break;
                    case EventRecordKind::kRegistry:
                        encode_status = protocol::EncodeRegistryViolationFrame(
                            queued->process_id, queued->registry_operation,
                            queued->registry_key, queued->sequence,
                            g_state.frame_buffer, kMaximumFrameLength,
                            frame_length);
                        break;
                    case EventRecordKind::kNetwork:
                        encode_status = protocol::EncodeNetworkViolationFrame(
                            queued->process_id, queued->network_operation,
                            queued->network_endpoint, queued->sequence,
                            g_state.frame_buffer, kMaximumFrameLength,
                            frame_length);
                        break;
                    case EventRecordKind::kNetworkDomain:
                        encode_status =
                            protocol::EncodeDomainNetworkViolationFrame(
                                queued->process_id, queued->network_operation,
                                queued->domain, queued->sequence,
                                g_state.frame_buffer, kMaximumFrameLength,
                                frame_length);
                        break;
                }
            }
            if (encode_status != protocol::FrameEncodeStatus::kSuccess ||
                !WriteExact(g_state.event_handle, g_state.frame_buffer, frame_length)) {
                FailWriter();
                return 1;
            }
            if (write_dropped_summary) {
                continue;
            }
            EnterCriticalSection(&g_state.lock);
            g_state.head = (g_state.head + 1U) % kQueueCapacity;
            --g_state.count;
            LeaveCriticalSection(&g_state.lock);
        }
    }
}

void RecordDroppedEvent() noexcept {
    if (g_state.dropped_events != UINT64_MAX) {
        ++g_state.dropped_events;
    }
}

std::size_t BoundedPathLength(const wchar_t* path) noexcept {
    if (path == nullptr) {
        return 0;
    }
    std::size_t length = 0;
    while (length <= protocol::kMaximumEventPathCodeUnits && path[length] != L'\0') {
        ++length;
    }
    return length <= protocol::kMaximumEventPathCodeUnits ? length : 0;
}

}  // namespace

EventSinkStatus InitializeEventSink(const HANDLE event_handle) noexcept {
    DWORD handle_flags = 0;
    if (event_handle == nullptr || event_handle == INVALID_HANDLE_VALUE ||
        !GetHandleInformation(event_handle, &handle_flags)) {
        return EventSinkStatus::kInvalidHandle;
    }
    if (InterlockedCompareExchange(&g_state.initialization_state, -1, 0) != 0) {
        return EventSinkStatus::kAlreadyInitialized;
    }
    if (!InitializeCriticalSectionEx(&g_state.lock, 4'000, 0)) {
        InterlockedExchange(&g_state.initialization_state, 0);
        return EventSinkStatus::kSynchronizationFailed;
    }
    g_state.records = static_cast<EventRecord*>(VirtualAlloc(
        nullptr, sizeof(EventRecord) * kQueueCapacity, MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE));
    g_state.frame_buffer = static_cast<std::uint8_t*>(VirtualAlloc(
        nullptr, kMaximumFrameLength, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (g_state.records == nullptr || g_state.frame_buffer == nullptr) {
        InterlockedExchange(&g_state.initialization_state, 0);
        return EventSinkStatus::kAllocationFailed;
    }
    g_state.wake_event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    g_state.idle_event = CreateEventW(nullptr, TRUE, TRUE, nullptr);
    if (g_state.wake_event == nullptr || g_state.idle_event == nullptr) {
        InterlockedExchange(&g_state.initialization_state, 0);
        return EventSinkStatus::kSynchronizationFailed;
    }
    g_state.event_handle = event_handle;
    g_state.worker_thread = CreateThread(nullptr, 0, EventWriterThread, nullptr, 0, nullptr);
    if (g_state.worker_thread == nullptr) {
        InterlockedExchange(&g_state.initialization_state, 0);
        return EventSinkStatus::kThreadFailed;
    }
    InterlockedExchange(&g_state.initialization_state, 1);
    return EventSinkStatus::kSuccess;
}

bool IsEventSinkHandle(const HANDLE handle) noexcept {
    return InterlockedCompareExchange(&g_state.initialization_state, 1, 1) == 1 &&
           handle == g_state.event_handle;
}

bool RegisterRuntimeIoHandles(
    const HANDLE dns_response_read_handle,
    const HANDLE dns_request_write_handle) noexcept {
    DWORD flags = 0;
    if (dns_response_read_handle == nullptr ||
        dns_response_read_handle == INVALID_HANDLE_VALUE ||
        dns_request_write_handle == nullptr ||
        dns_request_write_handle == INVALID_HANDLE_VALUE ||
        dns_response_read_handle == dns_request_write_handle ||
        !GetHandleInformation(dns_response_read_handle, &flags) ||
        !GetHandleInformation(dns_request_write_handle, &flags)) {
        return false;
    }
    if (InterlockedCompareExchangePointer(
            &g_dns_response_read_handle, dns_response_read_handle, nullptr) !=
        nullptr) {
        return false;
    }
    if (InterlockedCompareExchangePointer(
            &g_dns_request_write_handle, dns_request_write_handle, nullptr) !=
        nullptr) {
        InterlockedExchangePointer(&g_dns_response_read_handle, nullptr);
        return false;
    }
    return true;
}

bool IsRuntimeIoHandle(
    const HANDLE handle,
    const bool write_access) noexcept {
    if (write_access) {
        return IsEventSinkHandle(handle) ||
               handle == InterlockedCompareExchangePointer(
                             &g_dns_request_write_handle, nullptr, nullptr);
    }
    return handle == InterlockedCompareExchangePointer(
                         &g_dns_response_read_handle, nullptr, nullptr);
}

bool TryReportFilesystemViolation(
    const protocol::FilesystemOperation operation,
    const wchar_t* path) noexcept {
    if (InterlockedCompareExchange(&g_state.initialization_state, 1, 1) != 1 ||
        InterlockedCompareExchange(&g_state.writer_failed, 0, 0) != 0) {
        return false;
    }
    const std::size_t path_length = BoundedPathLength(path);
    if (path_length == 0) {
        return false;
    }
    EnterCriticalSection(&g_state.lock);
    if (g_state.count == kQueueCapacity) {
        RecordDroppedEvent();
        LeaveCriticalSection(&g_state.lock);
        return false;
    }
    EventRecord& record = g_state.records[g_state.tail];
    record.kind = EventRecordKind::kFilesystem;
    record.process_id = GetCurrentProcessId();
    record.operation = operation;
    record.sequence = g_state.next_sequence++;
    record.path_length = path_length;
    std::copy_n(path, path_length + 1U, record.path);
    g_state.tail = (g_state.tail + 1U) % kQueueCapacity;
    ++g_state.count;
    ResetEvent(g_state.idle_event);
    LeaveCriticalSection(&g_state.lock);
    SetEvent(g_state.wake_event);
    return true;
}

bool TryReportProcessViolation(
    const protocol::ProcessOperation operation) noexcept {
    if (InterlockedCompareExchange(&g_state.initialization_state, 1, 1) != 1 ||
        InterlockedCompareExchange(&g_state.writer_failed, 0, 0) != 0) {
        return false;
    }
    EnterCriticalSection(&g_state.lock);
    if (g_state.count == kQueueCapacity) {
        RecordDroppedEvent();
        LeaveCriticalSection(&g_state.lock);
        return false;
    }
    EventRecord& record = g_state.records[g_state.tail];
    record.kind = EventRecordKind::kProcess;
    record.process_id = GetCurrentProcessId();
    record.process_operation = operation;
    record.sequence = g_state.next_sequence++;
    record.path_length = 0;
    record.path[0] = L'\0';
    g_state.tail = (g_state.tail + 1U) % kQueueCapacity;
    ++g_state.count;
    ResetEvent(g_state.idle_event);
    LeaveCriticalSection(&g_state.lock);
    SetEvent(g_state.wake_event);
    return true;
}

bool TryReportRegistryViolation(
    const protocol::RegistryOperation operation,
    const char* const key) noexcept {
    if (InterlockedCompareExchange(&g_state.initialization_state, 1, 1) != 1 ||
        InterlockedCompareExchange(&g_state.writer_failed, 0, 0) != 0 ||
        protocol::RegistryViolationFrameLength(key) == 0) {
        return false;
    }
    std::size_t key_length = 0;
    while (key[key_length] != '\0') {
        ++key_length;
    }
    EnterCriticalSection(&g_state.lock);
    if (g_state.count == kQueueCapacity) {
        RecordDroppedEvent();
        LeaveCriticalSection(&g_state.lock);
        return false;
    }
    EventRecord& record = g_state.records[g_state.tail];
    record.kind = EventRecordKind::kRegistry;
    record.process_id = GetCurrentProcessId();
    record.registry_operation = operation;
    record.sequence = g_state.next_sequence++;
    std::copy_n(key, key_length + 1U, record.registry_key);
    record.path_length = 0;
    record.path[0] = L'\0';
    g_state.tail = (g_state.tail + 1U) % kQueueCapacity;
    ++g_state.count;
    ResetEvent(g_state.idle_event);
    LeaveCriticalSection(&g_state.lock);
    SetEvent(g_state.wake_event);
    return true;
}

bool TryReportNetworkViolation(
    const protocol::NetworkOperation operation,
    const protocol::NetworkEndpoint& endpoint) noexcept {
    if (InterlockedCompareExchange(&g_state.initialization_state, 1, 1) != 1 ||
        InterlockedCompareExchange(&g_state.writer_failed, 0, 0) != 0) {
        return false;
    }
    EnterCriticalSection(&g_state.lock);
    if (g_state.count == kQueueCapacity) {
        RecordDroppedEvent();
        LeaveCriticalSection(&g_state.lock);
        return false;
    }
    EventRecord& record = g_state.records[g_state.tail];
    record.kind = EventRecordKind::kNetwork;
    record.process_id = GetCurrentProcessId();
    record.network_operation = operation;
    record.network_endpoint = endpoint;
    record.sequence = g_state.next_sequence++;
    record.path_length = 0;
    record.path[0] = L'\0';
    g_state.tail = (g_state.tail + 1U) % kQueueCapacity;
    ++g_state.count;
    ResetEvent(g_state.idle_event);
    LeaveCriticalSection(&g_state.lock);
    SetEvent(g_state.wake_event);
    return true;
}

bool TryReportDomainNetworkViolation(
    const protocol::NetworkOperation operation,
    const char* const ascii_domain) noexcept {
    if (InterlockedCompareExchange(&g_state.initialization_state, 1, 1) != 1 ||
        InterlockedCompareExchange(&g_state.writer_failed, 0, 0) != 0 ||
        protocol::DomainNetworkViolationFrameLength(ascii_domain) == 0) {
        return false;
    }
    std::size_t domain_length = 0;
    while (ascii_domain[domain_length] != '\0') {
        ++domain_length;
    }
    EnterCriticalSection(&g_state.lock);
    if (g_state.count == kQueueCapacity) {
        RecordDroppedEvent();
        LeaveCriticalSection(&g_state.lock);
        return false;
    }
    EventRecord& record = g_state.records[g_state.tail];
    record.kind = EventRecordKind::kNetworkDomain;
    record.process_id = GetCurrentProcessId();
    record.network_operation = operation;
    record.sequence = g_state.next_sequence++;
    std::copy_n(ascii_domain, domain_length + 1U, record.domain);
    record.path_length = 0;
    record.path[0] = L'\0';
    g_state.tail = (g_state.tail + 1U) % kQueueCapacity;
    ++g_state.count;
    ResetEvent(g_state.idle_event);
    LeaveCriticalSection(&g_state.lock);
    SetEvent(g_state.wake_event);
    return true;
}

bool WaitForEventSinkIdle(const DWORD timeout_milliseconds) noexcept {
    if (InterlockedCompareExchange(&g_state.initialization_state, 1, 1) != 1 ||
        WaitForSingleObject(g_state.idle_event, timeout_milliseconds) != WAIT_OBJECT_0) {
        return false;
    }
    return InterlockedCompareExchange(&g_state.writer_failed, 0, 0) == 0;
}

}  // namespace bolt::hook
