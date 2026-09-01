#include "common/suspended_process.h"
#include "common/required_mitigations.h"

#include "protocol/policy_payload.h"
#include "protocol/runtime_payload.h"

#include <algorithm>
#include <limits>
#include <string>
#include <vector>

#include <detours.h>

namespace bolt::common {
namespace {

class AttributeList final {
  public:
    bool Initialize(
        const HANDLE* handles,
        const std::size_t count,
        const HPCON pseudo_console) noexcept {
        const DWORD attribute_count = 1 + (count == 0 ? 0 : 1) +
                                      (pseudo_console == nullptr ? 0 : 1);
        SIZE_T bytes = 0;
        InitializeProcThreadAttributeList(
            nullptr, attribute_count, 0, &bytes);
        try {
            storage_.resize(bytes);
        } catch (...) {
            return false;
        }
        list_ = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage_.data());
        if (!InitializeProcThreadAttributeList(
                list_, attribute_count, 0, &bytes)) {
            list_ = nullptr;
            return false;
        }
        mitigation_policy_ = kRequiredCreationMitigationPolicy;
        if (!UpdateProcThreadAttribute(
                list_, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                &mitigation_policy_, sizeof(mitigation_policy_), nullptr,
                nullptr) ||
            (count != 0 &&
             !UpdateProcThreadAttribute(
                 list_, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                 const_cast<HANDLE*>(handles), count * sizeof(HANDLE), nullptr,
                 nullptr)) ||
            (pseudo_console != nullptr &&
             !UpdateProcThreadAttribute(
                 list_, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                 pseudo_console, sizeof(HPCON), nullptr, nullptr))) {
            DeleteProcThreadAttributeList(list_);
            list_ = nullptr;
            return false;
        }
        return true;
    }

    ~AttributeList() noexcept {
        if (list_ != nullptr) {
            DeleteProcThreadAttributeList(list_);
        }
    }

    LPPROC_THREAD_ATTRIBUTE_LIST get() const noexcept { return list_; }

  private:
    std::vector<std::uint8_t> storage_;
    LPPROC_THREAD_ATTRIBUTE_LIST list_ = nullptr;
    std::uint64_t mitigation_policy_ = 0;
};

bool ValidateInheritedHandles(const ProcessLaunchOptions& options) noexcept {
    if (options.inherited_handle_count == 0) {
        return true;
    }
    if (options.inherited_handles == nullptr ||
        options.inherited_handle_count >
            std::numeric_limits<std::size_t>::max() / sizeof(HANDLE)) {
        return false;
    }
    for (std::size_t index = 0; index < options.inherited_handle_count; ++index) {
        const HANDLE handle = options.inherited_handles[index];
        DWORD flags = 0;
        if (handle == nullptr || handle == INVALID_HANDLE_VALUE ||
            !GetHandleInformation(handle, &flags) || (flags & HANDLE_FLAG_INHERIT) == 0) {
            return false;
        }
    }
    return true;
}

bool IncludesHandle(
    const ProcessLaunchOptions& options,
    const HANDLE expected) noexcept {
    for (std::size_t index = 0; index < options.inherited_handle_count; ++index) {
        if (options.inherited_handles[index] == expected) {
            return true;
        }
    }
    return false;
}

bool ValidateStandardHandles(const ProcessLaunchOptions& options) noexcept {
    const bool any = options.standard_input != nullptr ||
                     options.standard_output != nullptr ||
                     options.standard_error != nullptr;
    if (!any) {
        return true;
    }
    if (options.pseudo_console != nullptr) {
        return false;
    }
    return options.standard_input != nullptr &&
           options.standard_output != nullptr &&
           options.standard_error != nullptr &&
           IncludesHandle(options, options.standard_input) &&
           IncludesHandle(options, options.standard_output) &&
           IncludesHandle(options, options.standard_error);
}

bool ValidateRecoveryHandles(const ProcessLaunchOptions& options) noexcept {
    const std::array<HANDLE, 4> handles = {
        options.recovery_request, options.recovery_response,
        options.recovery_mutex, options.recovery_counter};
    const bool absent = std::all_of(
        handles.begin(), handles.end(),
        [](const HANDLE handle) { return handle == nullptr; });
    if (absent) {
        return true;
    }
    return std::all_of(
        handles.begin(), handles.end(),
        [&options](const HANDLE handle) {
            return handle != nullptr && handle != INVALID_HANDLE_VALUE &&
                   IncludesHandle(options, handle);
        });
}

void CloseRemoteHandle(
    const HANDLE process,
    const HANDLE remote_handle) noexcept {
    if (process == nullptr || remote_handle == nullptr) {
        return;
    }
    HANDLE local_copy = nullptr;
    if (DuplicateHandle(
            process, remote_handle, GetCurrentProcess(), &local_copy, 0, FALSE,
            DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE) &&
        local_copy != nullptr) {
        CloseHandle(local_copy);
    }
}

}  // namespace

SuspendedProcess::~SuspendedProcess() noexcept {
    Close();
}

ProcessStatus SuspendedProcess::Create(
    const ProcessLaunchOptions& options,
    SuspendedProcess& output) noexcept {
    if (options.application.empty() || options.command_line.empty()) {
        return ProcessStatus::kInvalidArgument;
    }
    if ((options.creation_flags &
         (CREATE_BREAKAWAY_FROM_JOB | EXTENDED_STARTUPINFO_PRESENT)) != 0) {
        return ProcessStatus::kUnsupportedFlags;
    }
    if (!ValidateInheritedHandles(options) ||
        !ValidateStandardHandles(options) ||
        !ValidateRecoveryHandles(options)) {
        return ProcessStatus::kInvalidInheritedHandle;
    }

    std::wstring application;
    std::wstring current_directory;
    std::vector<wchar_t> command_line;
    try {
        application.assign(options.application);
        current_directory.assign(options.current_directory);
        command_line.assign(options.command_line.begin(), options.command_line.end());
        command_line.push_back(L'\0');
    } catch (...) {
        return ProcessStatus::kAllocationFailed;
    }

    AttributeList attributes;
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    if (options.standard_input != nullptr) {
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = options.standard_input;
        startup.StartupInfo.hStdOutput = options.standard_output;
        startup.StartupInfo.hStdError = options.standard_error;
    } else if (options.pseudo_console != nullptr) {
        // Windows otherwise copies redirected parent standard handles even
        // when ordinary handle inheritance is disabled, bypassing ConPTY.
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    }
    const bool pseudo_console = options.pseudo_console != nullptr;
    if (!attributes.Initialize(
            pseudo_console ? nullptr : options.inherited_handles,
            pseudo_console ? 0 : options.inherited_handle_count,
            options.pseudo_console)) {
        return ProcessStatus::kAttributeListFailed;
    }
    startup.lpAttributeList = attributes.get();

    DWORD flags = options.creation_flags | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT;
    if (options.environment != nullptr) {
        flags |= CREATE_UNICODE_ENVIRONMENT;
    }
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(
            application.c_str(), command_line.data(), nullptr, nullptr,
            !pseudo_console && options.inherited_handle_count != 0, flags,
            options.environment,
            current_directory.empty() ? nullptr : current_directory.c_str(), &startup.StartupInfo,
            &process)) {
        return ProcessStatus::kCreateFailed;
    }

    output.Close();
    output.process_ = process.hProcess;
    output.thread_ = process.hThread;
    output.assigned_ = false;
    output.payload_installed_ = false;
    output.injected_ = false;
    output.initialization_started_ = false;
    output.resumed_ = false;
    output.isolated_console_ = pseudo_console;
    output.duplicated_handles_.clear();
    if (pseudo_console) {
        try {
            output.duplicated_handles_.reserve(options.inherited_handle_count);
        } catch (...) {
            output.Close();
            return ProcessStatus::kAllocationFailed;
        }
        for (std::size_t index = 0; index < options.inherited_handle_count;
             ++index) {
            HANDLE remote = nullptr;
            if (!DuplicateHandle(
                    GetCurrentProcess(), options.inherited_handles[index],
                    output.process_, &remote, 0, FALSE,
                    DUPLICATE_SAME_ACCESS)) {
                output.Close();
                return ProcessStatus::kInvalidInheritedHandle;
            }
            output.duplicated_handles_.emplace_back(
                options.inherited_handles[index], remote);
        }
    }
    output.release_event_ = nullptr;
    output.standard_output_ = options.standard_output;
    output.standard_error_ = options.standard_error;
    output.recovery_request_ = output.RemoteHandle(options.recovery_request);
    output.recovery_response_ = output.RemoteHandle(options.recovery_response);
    output.recovery_mutex_ = output.RemoteHandle(options.recovery_mutex);
    output.recovery_counter_ = output.RemoteHandle(options.recovery_counter);
    return ProcessStatus::kSuccess;
}

ProcessStatus SuspendedProcess::AssignTo(ExecutionJob& job) noexcept {
    if (process_ == nullptr || assigned_ || resumed_) {
        return ProcessStatus::kInvalidState;
    }
    if (job.Assign(process_) != JobStatus::kSuccess) {
        return ProcessStatus::kAssignFailed;
    }
    assigned_ = true;
    return ProcessStatus::kSuccess;
}

ProcessStatus SuspendedProcess::InstallRuntimePayload(
    const HANDLE policy_handle,
    const std::size_t policy_length,
    const HANDLE event_handle,
    const HANDLE release_handle,
    const std::array<std::uint8_t, 16>& nonce,
    const HANDLE dns_request_handle,
    const HANDLE dns_response_handle,
    const std::array<std::uint8_t, 32>* const dns_authentication_key,
    const std::uint32_t dns_maximum_frame_length,
    const std::uint16_t tcp_proxy_port,
    const std::uint16_t tcp_proxy_ipv6_port,
    const protocol::RuntimeStartupFault descendant_startup_fault) noexcept {
    if (process_ == nullptr || !assigned_ || payload_installed_ || injected_ ||
        initialization_started_) {
        return ProcessStatus::kInvalidState;
    }
    const HANDLE handles[] = {policy_handle, event_handle};
    for (const HANDLE handle : handles) {
        DWORD flags = 0;
        if (handle == nullptr || handle == INVALID_HANDLE_VALUE ||
            !GetHandleInformation(handle, &flags) || (flags & HANDLE_FLAG_INHERIT) == 0) {
            return ProcessStatus::kInvalidRuntimePayload;
        }
    }
    DWORD release_flags = 0;
    if (release_handle == nullptr || release_handle == INVALID_HANDLE_VALUE ||
        !GetHandleInformation(release_handle, &release_flags)) {
        return ProcessStatus::kInvalidRuntimePayload;
    }
    static_cast<void>(release_flags);
    const bool dns_absent = dns_request_handle == nullptr &&
                            dns_response_handle == nullptr &&
                            dns_authentication_key == nullptr &&
                            dns_maximum_frame_length == 0 &&
                            tcp_proxy_port == 0 && tcp_proxy_ipv6_port == 0;
    if (!dns_absent) {
        if (dns_request_handle == nullptr || dns_response_handle == nullptr ||
            dns_authentication_key == nullptr || dns_maximum_frame_length < 68 ||
            tcp_proxy_port == 0 || tcp_proxy_ipv6_port == 0) {
            return ProcessStatus::kInvalidRuntimePayload;
        }
        for (const HANDLE handle : {dns_request_handle, dns_response_handle}) {
            DWORD flags = 0;
            if (handle == INVALID_HANDLE_VALUE ||
                !GetHandleInformation(handle, &flags) ||
                (flags & HANDLE_FLAG_INHERIT) == 0) {
                return ProcessStatus::kInvalidRuntimePayload;
            }
        }
    }
    if (policy_length > std::numeric_limits<std::uint32_t>::max()) {
        return ProcessStatus::kInvalidRuntimePayload;
    }
    const auto* policy = static_cast<const std::uint8_t*>(
        MapViewOfFile(policy_handle, FILE_MAP_READ, 0, 0, policy_length));
    if (policy == nullptr) {
        return ProcessStatus::kInvalidRuntimePayload;
    }
    const auto policy_status = protocol::ValidatePolicyPayload(policy, policy_length);
    UnmapViewOfFile(policy);
    if (policy_status != protocol::PolicyPayloadStatus::kValid) {
        return ProcessStatus::kInvalidRuntimePayload;
    }
    void* writable_policy =
        MapViewOfFile(policy_handle, FILE_MAP_WRITE, 0, 0, policy_length);
    if (writable_policy != nullptr) {
        UnmapViewOfFile(writable_policy);
        return ProcessStatus::kInvalidRuntimePayload;
    }
    const DWORD process_id = GetProcessId(process_);
    if (process_id == 0) {
        return ProcessStatus::kInvalidRuntimePayload;
    }
    HANDLE remote_release = nullptr;
    if (!DuplicateHandle(
            GetCurrentProcess(), release_handle, process_, &remote_release,
            SYNCHRONIZE, FALSE, 0)) {
        return ProcessStatus::kInvalidRuntimePayload;
    }
    const HANDLE sequence_mutex = CreateMutexW(nullptr, FALSE, nullptr);
    HANDLE remote_sequence_mutex = nullptr;
    const bool sequence_duplicated = sequence_mutex != nullptr &&
        DuplicateHandle(
            GetCurrentProcess(), sequence_mutex, process_,
            &remote_sequence_mutex, SYNCHRONIZE | MUTEX_MODIFY_STATE, FALSE,
            0);
    CloseHandle(sequence_mutex);
    if (!sequence_duplicated) {
        CloseRemoteHandle(process_, remote_release);
        CloseRemoteHandle(process_, remote_sequence_mutex);
        return ProcessStatus::kInvalidRuntimePayload;
    }
    protocol::RuntimePayload payload{};
    payload.target_process_id = process_id;
    payload.policy_length = static_cast<std::uint32_t>(policy_length);
    payload.policy_handle =
        reinterpret_cast<std::uintptr_t>(RemoteHandle(policy_handle));
    payload.event_handle =
        reinterpret_cast<std::uintptr_t>(RemoteHandle(event_handle));
    payload.release_handle = reinterpret_cast<std::uintptr_t>(remote_release);
    payload.handshake_nonce = nonce;
    payload.descendant_startup_fault = descendant_startup_fault;
    payload.standard_output_handle =
        reinterpret_cast<std::uintptr_t>(standard_output_);
    payload.standard_error_handle =
        reinterpret_cast<std::uintptr_t>(standard_error_);
    payload.event_write_mutex_handle =
        reinterpret_cast<std::uintptr_t>(remote_sequence_mutex);
    payload.recovery_request_handle =
        reinterpret_cast<std::uintptr_t>(recovery_request_);
    payload.recovery_response_handle =
        reinterpret_cast<std::uintptr_t>(recovery_response_);
    payload.recovery_mutex_handle =
        reinterpret_cast<std::uintptr_t>(recovery_mutex_);
    payload.recovery_counter_handle =
        reinterpret_cast<std::uintptr_t>(recovery_counter_);
    payload.isolated_console = isolated_console_;
    if (!dns_absent) {
        payload.dns_request_handle = reinterpret_cast<std::uintptr_t>(
            RemoteHandle(dns_request_handle));
        payload.dns_response_handle = reinterpret_cast<std::uintptr_t>(
            RemoteHandle(dns_response_handle));
        payload.dns_authentication_key = *dns_authentication_key;
        payload.dns_maximum_frame_length = dns_maximum_frame_length;
        payload.tcp_proxy_port = tcp_proxy_port;
        payload.tcp_proxy_ipv6_port = tcp_proxy_ipv6_port;
    }
    auto encoded = protocol::EncodeRuntimePayload(payload);
    protocol::RuntimePayload checked{};
    if (protocol::DecodeRuntimePayload(encoded.data(), encoded.size(), checked) !=
        protocol::RuntimePayloadStatus::kSuccess) {
        CloseRemoteHandle(process_, remote_release);
        CloseRemoteHandle(process_, remote_sequence_mutex);
        return ProcessStatus::kInvalidRuntimePayload;
    }
    if (!DetourCopyPayloadToProcess(
            process_, protocol::kRuntimePayloadGuid, encoded.data(),
            static_cast<DWORD>(encoded.size()))) {
        CloseRemoteHandle(process_, remote_release);
        CloseRemoteHandle(process_, remote_sequence_mutex);
        return ProcessStatus::kPayloadCopyFailed;
    }
    payload_installed_ = true;
    release_event_ = release_handle;
    return ProcessStatus::kSuccess;
}

ProcessStatus SuspendedProcess::Inject(const std::string_view dll_path) noexcept {
    if (process_ == nullptr || !assigned_ || !payload_installed_ || injected_ || resumed_) {
        return ProcessStatus::kInvalidState;
    }
    if (dll_path.empty() || dll_path.find('\0') != std::string_view::npos) {
        return ProcessStatus::kInvalidDllPath;
    }
    std::string path;
    try {
        path.assign(dll_path);
    } catch (...) {
        return ProcessStatus::kAllocationFailed;
    }
    const DWORD attributes = GetFileAttributesA(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        return ProcessStatus::kInvalidDllPath;
    }
    LPCSTR dlls[] = {path.c_str()};
    if (!DetourUpdateProcessWithDll(process_, dlls, 1)) {
        return ProcessStatus::kInjectFailed;
    }
    injected_ = true;
    return ProcessStatus::kSuccess;
}

ProcessStatus SuspendedProcess::Resume() noexcept {
    return ProcessStatus::kInvalidState;
}

ProcessStatus SuspendedProcess::BeginHookInitialization() noexcept {
    if (thread_ == nullptr || !assigned_ || !payload_installed_ || !injected_ ||
        initialization_started_ || resumed_) {
        return ProcessStatus::kInvalidState;
    }
    if (ResumeThread(thread_) == static_cast<DWORD>(-1)) {
        return ProcessStatus::kInitializationFailed;
    }
    initialization_started_ = true;
    return ProcessStatus::kSuccess;
}

ProcessStatus SuspendedProcess::ReleaseAfterReady() noexcept {
    if (!initialization_started_ || resumed_ || release_event_ == nullptr) {
        return ProcessStatus::kInvalidState;
    }
    if (!SetEvent(release_event_)) {
        return ProcessStatus::kReleaseFailed;
    }
    resumed_ = true;
    return ProcessStatus::kSuccess;
}

ProcessStatus SuspendedProcess::Wait(const DWORD milliseconds) noexcept {
    if (process_ == nullptr) {
        return ProcessStatus::kInvalidState;
    }
    const DWORD result = WaitForSingleObject(process_, milliseconds);
    if (result == WAIT_OBJECT_0) {
        return ProcessStatus::kSuccess;
    }
    if (result == WAIT_TIMEOUT) {
        return ProcessStatus::kWaitTimeout;
    }
    return ProcessStatus::kWaitFailed;
}

ProcessStatus SuspendedProcess::ExitCode(DWORD& exit_code) const noexcept {
    if (process_ == nullptr) {
        return ProcessStatus::kInvalidState;
    }
    if (!GetExitCodeProcess(process_, &exit_code)) {
        return ProcessStatus::kExitCodeFailed;
    }
    return ProcessStatus::kSuccess;
}

HANDLE SuspendedProcess::RemoteHandle(const HANDLE local) const noexcept {
    if (local == nullptr || duplicated_handles_.empty()) {
        return local;
    }
    const auto found = std::find_if(
        duplicated_handles_.begin(), duplicated_handles_.end(),
        [local](const auto& handles) { return handles.first == local; });
    return found == duplicated_handles_.end() ? nullptr : found->second;
}

void SuspendedProcess::Close() noexcept {
    const HANDLE process = process_;
    const HANDLE thread = thread_;
    const bool resumed = resumed_;
    process_ = nullptr;
    thread_ = nullptr;
    assigned_ = false;
    payload_installed_ = false;
    injected_ = false;
    initialization_started_ = false;
    resumed_ = false;
    isolated_console_ = false;
    release_event_ = nullptr;
    standard_output_ = nullptr;
    standard_error_ = nullptr;
    recovery_request_ = nullptr;
    recovery_response_ = nullptr;
    recovery_mutex_ = nullptr;
    recovery_counter_ = nullptr;
    duplicated_handles_.clear();
    if (process != nullptr && !resumed) {
        TerminateProcess(process, ERROR_PROCESS_ABORTED);
    }
    if (thread != nullptr) {
        CloseHandle(thread);
    }
    if (process != nullptr) {
        CloseHandle(process);
    }
}

}  // namespace bolt::common
