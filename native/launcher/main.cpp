#include "protocol/launcher_control.h"
#include "protocol/launcher_startup.h"
#include "protocol/launcher_transport.h"
#include "protocol/event_frame.h"
#include "protocol/policy_payload.h"
#include "protocol/recovery_protocol.h"

#include "common/execution_job.h"
#include "common/immutable_policy_mapping.h"
#include "common/private_pipe.h"
#include "common/suspended_process.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <limits>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace {

constexpr DWORD kStartupTimeoutMilliseconds = 5'000;
constexpr DWORD kEventClosureGraceMilliseconds = 100;
constexpr std::size_t kStreamChunkLength = 4'096;

void CloseIfValid(const HANDLE handle) noexcept {
    if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
        CloseHandle(handle);
    }
}

bool ParseHandle(const wchar_t* const text, HANDLE& output) noexcept {
    if (text == nullptr || *text == L'\0' || *text == L'-') {
        return false;
    }
    wchar_t* end = nullptr;
    errno = 0;
    const unsigned long long value = std::wcstoull(text, &end, 10);
    if (errno != 0 || end == text || *end != L'\0' || value == 0 ||
        value > (std::numeric_limits<std::uintptr_t>::max)()) {
        return false;
    }
    output = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(value));
    DWORD flags = 0;
    return GetHandleInformation(output, &flags) != FALSE;
}

bool HasKillOnClose(const HANDLE job) noexcept {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    return QueryInformationJobObject(
               job, JobObjectExtendedLimitInformation, &limits,
               sizeof(limits), nullptr) != FALSE &&
           (limits.BasicLimitInformation.LimitFlags &
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) != 0;
}

DWORD WaitForStartupSignal(
    const HANDLE expected,
    const HANDLE shutdown,
    const HANDLE owner) noexcept {
    const std::array<HANDLE, 3> handles = {expected, shutdown, owner};
    return WaitForMultipleObjects(
        static_cast<DWORD>(handles.size()), handles.data(), FALSE,
        kStartupTimeoutMilliseconds);
}

bool ReadExact(
    const HANDLE input,
    std::uint8_t* bytes,
    const std::size_t length) noexcept {
    std::size_t offset = 0;
    while (offset < length) {
        DWORD read = 0;
        const DWORD remaining = static_cast<DWORD>(length - offset);
        if (!ReadFile(input, bytes + offset, remaining, &read, nullptr) ||
            read == 0) {
            return false;
        }
        offset += read;
    }
    return true;
}

bool WriteExact(
    const HANDLE output,
    const std::uint8_t* bytes,
    const std::size_t length) noexcept {
    std::size_t offset = 0;
    while (offset < length) {
        DWORD written = 0;
        if (!WriteFile(
                output, bytes + offset, static_cast<DWORD>(length - offset),
                &written, nullptr) ||
            written == 0) {
            return false;
        }
        offset += written;
    }
    return true;
}

class TransportWriter final {
  public:
    explicit TransportWriter(const HANDLE output) noexcept : output_(output) {}

    bool Write(
        const bolt::protocol::LauncherTransportKind kind,
        const std::uint8_t* const payload,
        const std::uint32_t payload_length) noexcept {
        std::array<
            std::uint8_t, bolt::protocol::kLauncherTransportHeaderLength>
            header{};
        if (bolt::protocol::EncodeLauncherTransportHeader(
                kind, payload_length, header) !=
            bolt::protocol::LauncherTransportStatus::kSuccess) {
            failed_.store(true, std::memory_order_release);
            return false;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        const bool written =
            WriteExact(output_, header.data(), header.size()) &&
            (payload_length == 0 ||
             WriteExact(output_, payload, payload_length));
        if (!written) {
            failed_.store(true, std::memory_order_release);
        }
        return written;
    }

    bool failed() const noexcept {
        return failed_.load(std::memory_order_acquire);
    }

  private:
    HANDLE output_;
    std::mutex mutex_;
    std::atomic_bool failed_ = false;
};

bool CreateTargetPipe(HANDLE& read, HANDLE& write) noexcept {
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    return CreatePipe(&read, &write, &inheritable, kStreamChunkLength) &&
           SetHandleInformation(read, HANDLE_FLAG_INHERIT, 0);
}

struct RecoveryChannels {
    HANDLE request_read = nullptr;
    HANDLE request_write = nullptr;
    HANDLE response_read = nullptr;
    HANDLE response_write = nullptr;
    HANDLE mutex = nullptr;
    HANDLE counter = nullptr;

    ~RecoveryChannels() noexcept {
        CloseIfValid(request_read);
        CloseIfValid(request_write);
        CloseIfValid(response_read);
        CloseIfValid(response_write);
        CloseIfValid(mutex);
        CloseIfValid(counter);
    }

    bool Create(const bool enabled) noexcept {
        if (!enabled) {
            return true;
        }
        SECURITY_ATTRIBUTES inheritable{};
        inheritable.nLength = sizeof(inheritable);
        inheritable.bInheritHandle = TRUE;
        if (!CreatePipe(
                &request_read, &request_write, &inheritable, 4'096) ||
            !SetHandleInformation(request_read, HANDLE_FLAG_INHERIT, 0) ||
            !CreatePipe(
                &response_read, &response_write, &inheritable, 4'096) ||
            !SetHandleInformation(response_write, HANDLE_FLAG_INHERIT, 0)) {
            return false;
        }
        mutex = CreateMutexW(&inheritable, FALSE, nullptr);
        counter = CreateFileMappingW(
            INVALID_HANDLE_VALUE, &inheritable, PAGE_READWRITE, 0,
            sizeof(LONG64), nullptr);
        auto* value = counter == nullptr
                          ? nullptr
                          : static_cast<volatile LONG64*>(MapViewOfFile(
                                counter, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0,
                                sizeof(LONG64)));
        if (mutex == nullptr || counter == nullptr || value == nullptr) {
            if (value != nullptr) {
                UnmapViewOfFile(const_cast<LONG64*>(value));
            }
            return false;
        }
        InterlockedExchange64(value, 0);
        UnmapViewOfFile(const_cast<LONG64*>(value));
        return true;
    }

    void CloseTargetEnds() noexcept {
        CloseIfValid(request_write);
        request_write = nullptr;
        CloseIfValid(response_read);
        response_read = nullptr;
        CloseIfValid(mutex);
        mutex = nullptr;
        CloseIfValid(counter);
        counter = nullptr;
    }
};

void ForwardByteStream(
    const HANDLE input,
    const bolt::protocol::LauncherTransportKind data_kind,
    const bolt::protocol::LauncherTransportKind eof_kind,
    TransportWriter& writer) noexcept {
    std::array<std::uint8_t, kStreamChunkLength> chunk{};
    for (;;) {
        DWORD read = 0;
        if (!ReadFile(
                input, chunk.data(), static_cast<DWORD>(chunk.size()), &read,
                nullptr) ||
            read == 0) {
            break;
        }
        if (!writer.Write(data_kind, chunk.data(), read)) {
            break;
        }
    }
    CloseHandle(input);
    writer.Write(eof_kind, nullptr, 0);
}

enum class EventForwardFailure : std::uint8_t {
    kNone = 0,
    kProtocolIntegrity = 1,
    kChannelLost = 2,
};

void SignalEventFailure(
    const HANDLE target_process,
    const HANDLE signal,
    std::atomic<EventForwardFailure>& failure,
    const EventForwardFailure reason) noexcept {
    if (reason == EventForwardFailure::kChannelLost &&
        WaitForSingleObject(
            target_process, kEventClosureGraceMilliseconds) ==
            WAIT_OBJECT_0) {
        return;
    }
    EventForwardFailure expected = EventForwardFailure::kNone;
    if (failure.compare_exchange_strong(
            expected, reason, std::memory_order_acq_rel)) {
        SetEvent(signal);
    }
}

void ForwardEventStream(
    const HANDLE input,
    const HANDLE target_process,
    const HANDLE failure_signal,
    std::atomic<EventForwardFailure>& failure,
    TransportWriter& writer) noexcept {
    std::array<std::uint8_t, bolt::protocol::kEventHeaderLength> header{};
    std::uint64_t next_sequence = 1;
    for (;;) {
        if (!ReadExact(input, header.data(), header.size())) {
            SignalEventFailure(
                target_process, failure_signal, failure,
                EventForwardFailure::kChannelLost);
            break;
        }
        std::uint32_t payload_length = 0;
        std::memcpy(
            &payload_length, header.data() + 8, sizeof(payload_length));
        if (payload_length >
            bolt::protocol::kLauncherTransportMaximumPayload -
                header.size()) {
            SignalEventFailure(
                target_process, failure_signal, failure,
                EventForwardFailure::kProtocolIntegrity);
            break;
        }
        std::vector<std::uint8_t> frame;
        try {
            frame.resize(header.size() + payload_length);
        } catch (...) {
            SignalEventFailure(
                target_process, failure_signal, failure,
                EventForwardFailure::kProtocolIntegrity);
            break;
        }
        std::copy(header.begin(), header.end(), frame.begin());
        if (payload_length != 0 &&
            !ReadExact(
                input, frame.data() + header.size(), payload_length)) {
            SignalEventFailure(
                target_process, failure_signal, failure,
                EventForwardFailure::kProtocolIntegrity);
            break;
        }
        std::uint16_t kind = 0;
        std::memcpy(&kind, frame.data() + 6, sizeof(kind));
        if (kind == 1 || next_sequence ==
                             (std::numeric_limits<std::uint64_t>::max)() ||
            bolt::protocol::ValidateEventFrame(
                frame.data(), frame.size()) !=
                bolt::protocol::EventFrameStatus::kSuccess) {
            SignalEventFailure(
                target_process, failure_signal, failure,
                EventForwardFailure::kProtocolIntegrity);
            break;
        }
        std::memcpy(
            frame.data() + 12, &next_sequence, sizeof(next_sequence));
        bolt::protocol::RewriteFrameChecksum(frame.data(), frame.size());
        ++next_sequence;
        if (!writer.Write(
                bolt::protocol::LauncherTransportKind::kEvent, frame.data(),
                static_cast<std::uint32_t>(frame.size()))) {
            SignalEventFailure(
                target_process, failure_signal, failure,
                EventForwardFailure::kProtocolIntegrity);
            break;
        }
    }
}

void ForwardRecoveryRequests(
    const HANDLE input,
    TransportWriter& writer) noexcept {
    for (;;) {
        std::array<
            std::uint8_t, bolt::protocol::kRecoveryRequestHeaderLength>
            header{};
        if (!ReadExact(input, header.data(), header.size())) {
            return;
        }
        std::uint16_t version = 0;
        std::uint16_t header_length = 0;
        std::uint32_t total_length = 0;
        std::uint32_t path_length = 0;
        std::memcpy(&version, header.data() + 4, sizeof(version));
        std::memcpy(
            &header_length, header.data() + 6, sizeof(header_length));
        std::memcpy(&total_length, header.data() + 8, sizeof(total_length));
        std::memcpy(&path_length, header.data() + 12, sizeof(path_length));
        const bool valid_header =
            std::equal(
                header.begin(), header.begin() + 4,
                std::array<std::uint8_t, 4>{'B', 'R', 'Q', '1'}.begin()) &&
            version == 1 &&
            header_length == bolt::protocol::kRecoveryRequestHeaderLength &&
            total_length >= bolt::protocol::kRecoveryRequestHeaderLength &&
            total_length <= bolt::protocol::kRecoveryMaximumRequestLength &&
            path_length != 0 && path_length <= 32'767 &&
            total_length == bolt::protocol::kRecoveryRequestHeaderLength +
                                path_length * sizeof(wchar_t);
        if (!valid_header) {
            return;
        }
        std::vector<std::uint8_t> request;
        try {
            request.resize(total_length);
        } catch (...) {
            return;
        }
        std::copy(header.begin(), header.end(), request.begin());
        if (!ReadExact(
                input, request.data() + header.size(),
                request.size() - header.size()) ||
            !writer.Write(
                bolt::protocol::LauncherTransportKind::kRecoveryRequest,
                request.data(), total_length)) {
            return;
        }
    }
}

bool WriteProcessExit(
    TransportWriter& writer,
    const DWORD process_id,
    const DWORD exit_code,
    const std::uint8_t reason,
    const bool has_exit_code) noexcept {
    std::array<std::uint8_t, 10> payload{};
    std::memcpy(payload.data(), &process_id, sizeof(process_id));
    payload[4] = reason;
    payload[5] = has_exit_code ? 1 : 0;
    if (has_exit_code) {
        std::memcpy(payload.data() + 6, &exit_code, sizeof(exit_code));
    }
    return writer.Write(
        bolt::protocol::LauncherTransportKind::kProcessExit, payload.data(),
        static_cast<std::uint32_t>(payload.size()));
}

struct ControlReaderContext {
    HANDLE input = nullptr;
    HANDLE signaled = nullptr;
    HANDLE recovery_response = nullptr;
    std::atomic<std::uint16_t> kind{0};
};

DWORD WINAPI ReadControlFrame(LPVOID parameter) noexcept {
    auto* context = static_cast<ControlReaderContext*>(parameter);
    if (context == nullptr) {
        return ERROR_INVALID_PARAMETER;
    }
    for (;;) {
        std::array<std::uint8_t, 4> magic{};
        if (!ReadExact(context->input, magic.data(), magic.size())) {
            break;
        }
        if (magic == std::array<std::uint8_t, 4>{'B', 'L', 'C', '1'}) {
            std::array<std::uint8_t, bolt::protocol::kLauncherControlLength>
                encoded{};
            std::copy(magic.begin(), magic.end(), encoded.begin());
            bolt::protocol::LauncherControlKind kind{};
            if (!ReadExact(
                    context->input, encoded.data() + magic.size(),
                    encoded.size() - magic.size()) ||
                bolt::protocol::DecodeLauncherControl(
                    encoded.data(), encoded.size(), kind) !=
                    bolt::protocol::LauncherControlStatus::kSuccess) {
                break;
            }
            context->kind.store(
                static_cast<std::uint16_t>(kind),
                std::memory_order_release);
            SetEvent(context->signaled);
            return ERROR_SUCCESS;
        }
        if (magic == std::array<std::uint8_t, 4>{'B', 'R', 'P', '1'} &&
            context->recovery_response != nullptr) {
            std::array<
                std::uint8_t, bolt::protocol::kRecoveryResponseLength>
                response{};
            std::copy(magic.begin(), magic.end(), response.begin());
            bolt::protocol::RecoveryResponse decoded{};
            if (!ReadExact(
                    context->input, response.data() + magic.size(),
                    response.size() - magic.size()) ||
                bolt::protocol::DecodeRecoveryResponse(
                    response.data(), response.size(), decoded) !=
                    bolt::protocol::RecoveryProtocolStatus::kSuccess ||
                !WriteExact(
                    context->recovery_response, response.data(),
                    response.size())) {
                break;
            }
            continue;
        }
        break;
    }
    context->kind.store(
        static_cast<std::uint16_t>(
            bolt::protocol::LauncherControlKind::kCancel),
        std::memory_order_release);
    SetEvent(context->signaled);
    return ERROR_BROKEN_PIPE;
}

void StopControlReader(const HANDLE thread) noexcept {
    if (thread == nullptr) {
        return;
    }
    CancelSynchronousIo(thread);
    WaitForSingleObject(thread, 5'000);
    CloseHandle(thread);
}

std::wstring EventPipeName(
    const std::array<std::uint8_t, 16>& nonce) {
    constexpr wchar_t digits[] = L"0123456789abcdef";
    std::wstring name = L"\\\\.\\pipe\\bolt-sandbox-";
    name.reserve(name.size() + nonce.size() * 2);
    for (const std::uint8_t byte : nonce) {
        name.push_back(digits[byte >> 4]);
        name.push_back(digits[byte & 0x0f]);
    }
    return name;
}

bool ToAnsiPath(const std::wstring& path, std::string& encoded) {
    const int required = WideCharToMultiByte(
        CP_ACP, WC_NO_BEST_FIT_CHARS, path.c_str(), -1, nullptr, 0, nullptr,
        nullptr);
    if (required <= 1) {
        return false;
    }
    encoded.resize(static_cast<std::size_t>(required));
    BOOL used_default = FALSE;
    if (WideCharToMultiByte(
            CP_ACP, WC_NO_BEST_FIT_CHARS, path.c_str(), -1, encoded.data(),
            required, nullptr, &used_default) != required ||
        used_default) {
        encoded.clear();
        return false;
    }
    encoded.pop_back();
    return true;
}

int RunDecodedSession(
    const bolt::protocol::LauncherStartRequest& request) noexcept {
    bolt::common::ImmutablePolicyMapping policy;
    bolt::common::PrivatePipe event_pipe;
    bolt::common::ExecutionJob job;
    const HANDLE release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    const std::wstring pipe_name =
        EventPipeName(request.endpoint_identifier);
    if (release == nullptr ||
        bolt::common::ImmutablePolicyMapping::Create(
            request.policy.data(), request.policy.size(), policy) !=
            bolt::common::PolicyMappingStatus::kSuccess ||
        bolt::common::PrivatePipe::Create(pipe_name, event_pipe) !=
            bolt::common::PipeStatus::kSuccess ||
        bolt::common::ExecutionJob::Create(job) !=
            bolt::common::JobStatus::kSuccess) {
        if (release != nullptr) {
            CloseHandle(release);
        }
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    HANDLE stdout_read = nullptr;
    HANDLE stdout_write = nullptr;
    HANDLE stderr_read = nullptr;
    HANDLE stderr_write = nullptr;
    RecoveryChannels recovery_channels;
    const HANDLE stdin_read = CreateFileW(
        L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        &inheritable, OPEN_EXISTING, 0, nullptr);
    if (stdin_read == INVALID_HANDLE_VALUE ||
        !CreateTargetPipe(stdout_read, stdout_write) ||
        !CreateTargetPipe(stderr_read, stderr_write) ||
        !recovery_channels.Create(request.recovery_enabled)) {
        CloseIfValid(stdin_read);
        CloseIfValid(stdout_read);
        CloseIfValid(stdout_write);
        CloseIfValid(stderr_read);
        CloseIfValid(stderr_write);
        CloseHandle(release);
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    const HANDLE event_client = CreateFileW(
        pipe_name.c_str(), FILE_WRITE_DATA, 0, &inheritable, OPEN_EXISTING, 0,
        nullptr);
    if (event_client == INVALID_HANDLE_VALUE ||
        event_pipe.Accept() != bolt::common::PipeStatus::kSuccess) {
        CloseIfValid(event_client);
        CloseHandle(stdin_read);
        CloseHandle(stdout_read);
        CloseHandle(stdout_write);
        CloseHandle(stderr_read);
        CloseHandle(stderr_write);
        CloseHandle(release);
        return ERROR_PIPE_NOT_CONNECTED;
    }
    std::wstring command(
        request.command_line.begin(), request.command_line.end() - 1);
    std::array<HANDLE, 9> inherited = {
        policy.handle(), event_client, stdin_read, stdout_write, stderr_write};
    std::size_t inherited_count = 5;
    if (request.recovery_enabled) {
        inherited[inherited_count++] = recovery_channels.request_write;
        inherited[inherited_count++] = recovery_channels.response_read;
        inherited[inherited_count++] = recovery_channels.mutex;
        inherited[inherited_count++] = recovery_channels.counter;
    }
    bolt::common::ProcessLaunchOptions options{
        request.program,
        command,
        request.cwd,
        const_cast<wchar_t*>(request.environment_block.data()),
        inherited.data(),
        inherited_count,
        0,
        stdin_read,
        stdout_write,
        stderr_write,
        recovery_channels.request_write,
        recovery_channels.response_read,
        recovery_channels.mutex,
        recovery_channels.counter};
    bolt::common::SuspendedProcess process;
    std::string hook_path;
    const bool prepared = ToAnsiPath(request.hook_path, hook_path) &&
        bolt::common::SuspendedProcess::Create(options, process) ==
            bolt::common::ProcessStatus::kSuccess &&
        process.AssignTo(job) == bolt::common::ProcessStatus::kSuccess &&
        process.InstallRuntimePayload(
            policy.handle(), policy.length(), event_client, release,
            request.nonce) == bolt::common::ProcessStatus::kSuccess &&
        process.Inject(hook_path) == bolt::common::ProcessStatus::kSuccess &&
        process.BeginHookInitialization() ==
            bolt::common::ProcessStatus::kSuccess;
    CloseHandle(event_client);
    CloseHandle(stdin_read);
    CloseHandle(stdout_write);
    CloseHandle(stderr_write);
    recovery_channels.CloseTargetEnds();
    std::array<std::uint8_t, bolt::protocol::kReadyFrameLength> ready{};
    const bool ready_ok = prepared &&
        ReadExact(event_pipe.handle(), ready.data(), ready.size()) &&
        bolt::protocol::ValidateReadyFrame(
            ready.data(), ready.size(), request.nonce) ==
            bolt::protocol::ReadyFrameStatus::kSuccess;
    if (!ready_ok) {
        job.Terminate(ERROR_DLL_INIT_FAILED);
        process.Wait(5'000);
        CloseHandle(stdout_read);
        CloseHandle(stderr_read);
        CloseHandle(release);
        return ERROR_DLL_INIT_FAILED;
    }
    std::array<std::uint8_t, 12> acknowledgment{
        'B', 'L', 'A', '1', 1, 0, 12, 0, 0, 0, 0, 0};
    const DWORD process_id = GetProcessId(process.process_handle());
    ControlReaderContext control{};
    control.input = GetStdHandle(STD_INPUT_HANDLE);
    control.recovery_response = recovery_channels.response_write;
    control.signaled = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    const HANDLE event_failure_signal =
        CreateEventW(nullptr, TRUE, FALSE, nullptr);
    std::atomic<EventForwardFailure> event_failure{
        EventForwardFailure::kNone};
    const HANDLE control_thread =
        control.signaled == nullptr
            ? nullptr
            : CreateThread(
                  nullptr, 0, ReadControlFrame, &control, 0, nullptr);
    std::memcpy(acknowledgment.data() + 8, &process_id, sizeof(process_id));
    if (process_id == 0 || control_thread == nullptr ||
        event_failure_signal == nullptr ||
        !WriteExact(
            GetStdHandle(STD_OUTPUT_HANDLE), acknowledgment.data(),
            acknowledgment.size())) {
        job.Terminate(ERROR_BROKEN_PIPE);
        process.Wait(5'000);
        StopControlReader(control_thread);
        CloseIfValid(control.signaled);
        CloseIfValid(event_failure_signal);
        CloseHandle(stdout_read);
        CloseHandle(stderr_read);
        CloseHandle(release);
        return ERROR_BROKEN_PIPE;
    }
    TransportWriter writer(GetStdHandle(STD_OUTPUT_HANDLE));
    if (!writer.Write(
            bolt::protocol::LauncherTransportKind::kEvent, ready.data(),
            static_cast<std::uint32_t>(ready.size()))) {
        job.Terminate(ERROR_BROKEN_PIPE);
        process.Wait(5'000);
        StopControlReader(control_thread);
        CloseHandle(control.signaled);
        CloseHandle(event_failure_signal);
        CloseHandle(stdout_read);
        CloseHandle(stderr_read);
        CloseHandle(release);
        return ERROR_BROKEN_PIPE;
    }
    std::thread stdout_thread;
    std::thread stderr_thread;
    std::thread event_thread;
    std::thread recovery_thread;
    try {
        stdout_thread = std::thread(
            ForwardByteStream, stdout_read,
            bolt::protocol::LauncherTransportKind::kStdout,
            bolt::protocol::LauncherTransportKind::kStdoutEof,
            std::ref(writer));
        stderr_thread = std::thread(
            ForwardByteStream, stderr_read,
            bolt::protocol::LauncherTransportKind::kStderr,
            bolt::protocol::LauncherTransportKind::kStderrEof,
            std::ref(writer));
        event_thread = std::thread(
            ForwardEventStream, event_pipe.handle(), process.process_handle(),
            event_failure_signal, std::ref(event_failure),
            std::ref(writer));
        if (request.recovery_enabled) {
            recovery_thread = std::thread(
                ForwardRecoveryRequests, recovery_channels.request_read,
                std::ref(writer));
        }
    } catch (...) {
        job.Terminate(ERROR_NOT_ENOUGH_MEMORY);
        process.Wait(5'000);
        if (stdout_thread.joinable()) {
            stdout_thread.join();
        } else {
            CloseIfValid(stdout_read);
        }
        if (stderr_thread.joinable()) {
            stderr_thread.join();
        } else {
            CloseIfValid(stderr_read);
        }
        if (event_thread.joinable()) {
            event_thread.join();
        }
        if (recovery_thread.joinable()) {
            recovery_thread.join();
        }
        StopControlReader(control_thread);
        CloseHandle(control.signaled);
        CloseHandle(event_failure_signal);
        CloseHandle(release);
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    if (process.ReleaseAfterReady() !=
        bolt::common::ProcessStatus::kSuccess) {
        job.Terminate(ERROR_DLL_INIT_FAILED);
    }
    const DWORD wait_milliseconds =
        request.has_timeout
            ? static_cast<DWORD>((std::min)(
                  request.timeout_milliseconds,
                  static_cast<std::uint64_t>(INFINITE - 1)))
            : INFINITE;
    const std::array<HANDLE, 3> wait_handles = {
        process.process_handle(), control.signaled, event_failure_signal};
    const DWORD wait_status = WaitForMultipleObjects(
        static_cast<DWORD>(wait_handles.size()), wait_handles.data(), FALSE,
        wait_milliseconds);
    std::uint8_t exit_reason = 0;
    bool has_exit_code = false;
    bool infrastructure_failure = false;
    EventForwardFailure infrastructure_reason = EventForwardFailure::kNone;
    DWORD exit_code = ERROR_PROCESS_ABORTED;
    if (wait_status == WAIT_TIMEOUT) {
        exit_reason = 2;
        job.Terminate(408);
        process.Wait(5'000);
    } else if (wait_status == WAIT_OBJECT_0 + 1) {
        const auto control_kind = static_cast<
            bolt::protocol::LauncherControlKind>(
            control.kind.load(std::memory_order_acquire));
        if (control_kind ==
            bolt::protocol::LauncherControlKind::kProtocolIntegrity) {
            infrastructure_failure = true;
            infrastructure_reason = EventForwardFailure::kProtocolIntegrity;
        } else {
            exit_reason =
                control_kind == bolt::protocol::LauncherControlKind::kTimeout
                    ? 2
                    : 1;
        }
        job.Terminate(
            exit_reason == 2 ? 408 : ERROR_PROCESS_ABORTED);
        process.Wait(5'000);
    } else if (wait_status == WAIT_OBJECT_0 + 2) {
        infrastructure_failure = true;
        infrastructure_reason =
            event_failure.load(std::memory_order_acquire);
        job.Terminate(ERROR_BROKEN_PIPE);
        process.Wait(5'000);
    } else if (
        wait_status == WAIT_OBJECT_0 &&
        process.ExitCode(exit_code) == bolt::common::ProcessStatus::kSuccess) {
        has_exit_code = true;
        exit_reason =
            (exit_code & 0xC000'0000U) == 0xC000'0000U ? 3 : 0;
        job.Terminate(exit_code);
    } else {
        exit_reason = 1;
        job.Terminate(ERROR_PROCESS_ABORTED);
        process.Wait(5'000);
    }
    StopControlReader(control_thread);
    CloseHandle(control.signaled);
    CloseHandle(event_failure_signal);
    stdout_thread.join();
    stderr_thread.join();
    event_thread.join();
    if (recovery_thread.joinable()) {
        recovery_thread.join();
    }
    if (infrastructure_failure) {
        const auto reason = static_cast<std::uint8_t>(infrastructure_reason);
        writer.Write(
            bolt::protocol::LauncherTransportKind::kInfrastructureFailure,
            &reason, 1);
    } else {
        WriteProcessExit(
            writer, process_id, exit_code, exit_reason, has_exit_code);
    }
    writer.Write(
        bolt::protocol::LauncherTransportKind::kEventEof, nullptr, 0);
    CloseHandle(release);
    if (writer.failed()) {
        return ERROR_BROKEN_PIPE;
    }
    if (infrastructure_failure) {
        return ERROR_INVALID_DATA;
    }
    if (exit_reason == 2) {
        return 408;
    }
    return has_exit_code ? static_cast<int>(exit_code)
                         : ERROR_PROCESS_ABORTED;
}

int RunStdioSession() noexcept {
    const HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    if (input == nullptr || input == INVALID_HANDLE_VALUE) {
        return ERROR_INVALID_HANDLE;
    }
    std::vector<std::uint8_t> encoded;
    try {
        encoded.resize(bolt::protocol::kLauncherStartHeaderLength);
    } catch (...) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    if (!ReadExact(input, encoded.data(), encoded.size())) {
        return ERROR_INVALID_DATA;
    }
    std::uint32_t total_length = 0;
    std::memcpy(&total_length, encoded.data() + 8, sizeof(total_length));
    if (total_length < bolt::protocol::kLauncherStartHeaderLength ||
        total_length > bolt::protocol::kLauncherStartMaximumLength) {
        return ERROR_INVALID_DATA;
    }
    try {
        encoded.resize(total_length);
    } catch (...) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    if (!ReadExact(
            input, encoded.data() + bolt::protocol::kLauncherStartHeaderLength,
            encoded.size() - bolt::protocol::kLauncherStartHeaderLength)) {
        return ERROR_INVALID_DATA;
    }
    bolt::protocol::LauncherStartRequest request{};
    if (bolt::protocol::DecodeLauncherStartRequest(
            encoded.data(), encoded.size(), request) !=
            bolt::protocol::LauncherStartStatus::kSuccess ||
        bolt::protocol::ValidatePolicyPayload(
            request.policy.data(), request.policy.size()) !=
            bolt::protocol::PolicyPayloadStatus::kValid) {
        return ERROR_INVALID_DATA;
    }
    const DWORD program_attributes = GetFileAttributesW(request.program.c_str());
    const DWORD cwd_attributes = GetFileAttributesW(request.cwd.c_str());
    const DWORD hook_attributes = GetFileAttributesW(request.hook_path.c_str());
    if (program_attributes == INVALID_FILE_ATTRIBUTES ||
        (program_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
        cwd_attributes == INVALID_FILE_ATTRIBUTES ||
        (cwd_attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
        hook_attributes == INVALID_FILE_ATTRIBUTES ||
        (hook_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        return ERROR_FILE_NOT_FOUND;
    }
    return RunDecodedSession(request);
}

}  // namespace

int wmain(const int argument_count, wchar_t** arguments) noexcept {
    if (argument_count == 2 &&
        std::wcscmp(arguments[1], L"--stdio-session") == 0) {
        return RunStdioSession();
    }
    if (argument_count != 8 ||
        std::wcscmp(arguments[1], L"--supervise-job") != 0) {
        return ERROR_INVALID_HANDLE;
    }
    HANDLE job = nullptr;
    HANDLE target_ready = nullptr;
    HANDLE host_ready = nullptr;
    HANDLE release = nullptr;
    HANDLE shutdown = nullptr;
    HANDLE owner = nullptr;
    if (!ParseHandle(arguments[2], job) ||
        !ParseHandle(arguments[3], target_ready) ||
        !ParseHandle(arguments[4], host_ready) ||
        !ParseHandle(arguments[5], release) ||
        !ParseHandle(arguments[6], shutdown) ||
        !ParseHandle(arguments[7], owner) || !HasKillOnClose(job)) {
        return ERROR_INVALID_HANDLE;
    }

    const DWORD target_status =
        WaitForStartupSignal(target_ready, shutdown, owner);
    if (target_status != WAIT_OBJECT_0) {
        return target_status == WAIT_TIMEOUT ? WAIT_TIMEOUT
                                             : ERROR_PROCESS_ABORTED;
    }
    if (!SetEvent(host_ready)) {
        return GetLastError();
    }
    const DWORD release_status = WaitForStartupSignal(release, shutdown, owner);
    if (release_status != WAIT_OBJECT_0) {
        return release_status == WAIT_TIMEOUT ? WAIT_TIMEOUT
                                              : ERROR_PROCESS_ABORTED;
    }

    const std::array<HANDLE, 2> terminal_handles = {shutdown, owner};
    const DWORD terminal_status = WaitForMultipleObjects(
        static_cast<DWORD>(terminal_handles.size()), terminal_handles.data(),
        FALSE, INFINITE);
    return terminal_status == WAIT_OBJECT_0 ? ERROR_SUCCESS
                                           : ERROR_PROCESS_ABORTED;
}
