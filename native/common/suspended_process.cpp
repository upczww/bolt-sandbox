#include "common/suspended_process.h"
#include "common/required_mitigations.h"

#include "protocol/policy_payload.h"
#include "protocol/runtime_payload.h"

#include <limits>
#include <string>
#include <vector>

#include <detours.h>

namespace bolt::common {
namespace {

class AttributeList final {
  public:
    bool Initialize(const HANDLE* handles, const std::size_t count) noexcept {
        const DWORD attribute_count = count == 0 ? 1 : 2;
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
                 nullptr))) {
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
    if (!ValidateInheritedHandles(options)) {
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
    if (!attributes.Initialize(
            options.inherited_handles, options.inherited_handle_count)) {
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
            options.inherited_handle_count != 0, flags, options.environment,
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
    output.release_event_ = nullptr;
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
    const std::uint16_t tcp_proxy_ipv6_port) noexcept {
    if (process_ == nullptr || !assigned_ || payload_installed_ || injected_ ||
        initialization_started_) {
        return ProcessStatus::kInvalidState;
    }
    const HANDLE handles[] = {policy_handle, event_handle, release_handle};
    for (const HANDLE handle : handles) {
        DWORD flags = 0;
        if (handle == nullptr || handle == INVALID_HANDLE_VALUE ||
            !GetHandleInformation(handle, &flags) || (flags & HANDLE_FLAG_INHERIT) == 0) {
            return ProcessStatus::kInvalidRuntimePayload;
        }
    }
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
    protocol::RuntimePayload payload{};
    payload.target_process_id = process_id;
    payload.policy_length = static_cast<std::uint32_t>(policy_length);
    payload.policy_handle = reinterpret_cast<std::uintptr_t>(policy_handle);
    payload.event_handle = reinterpret_cast<std::uintptr_t>(event_handle);
    payload.release_handle = reinterpret_cast<std::uintptr_t>(release_handle);
    payload.handshake_nonce = nonce;
    if (!dns_absent) {
        payload.dns_request_handle =
            reinterpret_cast<std::uintptr_t>(dns_request_handle);
        payload.dns_response_handle =
            reinterpret_cast<std::uintptr_t>(dns_response_handle);
        payload.dns_authentication_key = *dns_authentication_key;
        payload.dns_maximum_frame_length = dns_maximum_frame_length;
        payload.tcp_proxy_port = tcp_proxy_port;
        payload.tcp_proxy_ipv6_port = tcp_proxy_ipv6_port;
    }
    auto encoded = protocol::EncodeRuntimePayload(payload);
    protocol::RuntimePayload checked{};
    if (protocol::DecodeRuntimePayload(encoded.data(), encoded.size(), checked) !=
        protocol::RuntimePayloadStatus::kSuccess) {
        return ProcessStatus::kInvalidRuntimePayload;
    }
    if (!DetourCopyPayloadToProcess(
            process_, protocol::kRuntimePayloadGuid, encoded.data(),
            static_cast<DWORD>(encoded.size()))) {
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
    release_event_ = nullptr;
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
