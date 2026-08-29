#include "common/suspended_process.h"

#include <limits>
#include <string>
#include <vector>

#include <detours.h>

namespace bolt::common {
namespace {

class AttributeList final {
  public:
    bool Initialize(const HANDLE* handles, const std::size_t count) noexcept {
        SIZE_T bytes = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
        try {
            storage_.resize(bytes);
        } catch (...) {
            return false;
        }
        list_ = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage_.data());
        if (!InitializeProcThreadAttributeList(list_, 1, 0, &bytes)) {
            list_ = nullptr;
            return false;
        }
        if (!UpdateProcThreadAttribute(
                list_, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                const_cast<HANDLE*>(handles), count * sizeof(HANDLE), nullptr, nullptr)) {
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
    if (options.inherited_handle_count != 0) {
        if (!attributes.Initialize(options.inherited_handles, options.inherited_handle_count)) {
            return ProcessStatus::kAttributeListFailed;
        }
        startup.lpAttributeList = attributes.get();
    }

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
    output.injected_ = false;
    output.resumed_ = false;
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

ProcessStatus SuspendedProcess::Inject(const std::string_view dll_path) noexcept {
    if (process_ == nullptr || !assigned_ || injected_ || resumed_) {
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
    if (thread_ == nullptr || !assigned_ || !injected_ || resumed_) {
        return ProcessStatus::kInvalidState;
    }
    if (ResumeThread(thread_) == static_cast<DWORD>(-1)) {
        return ProcessStatus::kResumeFailed;
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
    injected_ = false;
    resumed_ = false;
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
