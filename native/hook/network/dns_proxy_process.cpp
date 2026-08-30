#include "hook/network/dns_proxy_process.h"

#include "common/immutable_mapping.h"
#include "common/immutable_policy_mapping.h"
#include "protocol/dns_proxy_startup.h"

#include <array>
#include <limits>
#include <new>
#include <string>
#include <utility>
#include <vector>

namespace bolt::network {

DnsProxyProcess::~DnsProxyProcess() noexcept { Close(); }

DnsProxyProcessStatus DnsProxyProcess::Start(
    const std::filesystem::path& executable,
    const std::uint8_t* const policy_bytes,
    const std::size_t policy_length,
    const protocol::DnsProxySession& session,
    const std::uint32_t maximum_frame_length,
    const std::uint32_t maximum_requests,
    std::unique_ptr<DnsProxyProcess>& output) noexcept {
    output.reset();
    if (!executable.is_absolute() || policy_bytes == nullptr || policy_length == 0 ||
        policy_length > std::numeric_limits<std::uint32_t>::max()) {
        return DnsProxyProcessStatus::kInvalidArgument;
    }
    try {
        common::ImmutablePolicyMapping policy;
        if (common::ImmutablePolicyMapping::Create(
                policy_bytes, policy_length, policy) !=
            common::PolicyMappingStatus::kSuccess) {
            return DnsProxyProcessStatus::kResourceFailed;
        }
        SECURITY_ATTRIBUTES security{};
        security.nLength = sizeof(security);
        security.bInheritHandle = TRUE;
        HANDLE request_read = nullptr;
        HANDLE request_write = nullptr;
        HANDLE response_read = nullptr;
        HANDLE response_write = nullptr;
        if (!CreatePipe(&request_read, &request_write, &security, 0) ||
            !CreatePipe(&response_read, &response_write, &security, 0) ||
            !SetHandleInformation(request_write, HANDLE_FLAG_INHERIT, 0) ||
            !SetHandleInformation(response_read, HANDLE_FLAG_INHERIT, 0)) {
            return DnsProxyProcessStatus::kResourceFailed;
        }
        protocol::DnsProxyStartup startup{};
        startup.policy_length = static_cast<std::uint32_t>(policy_length);
        startup.policy_handle = reinterpret_cast<std::uintptr_t>(policy.handle());
        startup.read_handle = reinterpret_cast<std::uintptr_t>(request_read);
        startup.write_handle = reinterpret_cast<std::uintptr_t>(response_write);
        startup.maximum_frame_length = maximum_frame_length;
        startup.maximum_requests = maximum_requests;
        startup.session = session;
        const auto startup_bytes = protocol::EncodeDnsProxyStartup(startup);
        common::ImmutableMapping startup_mapping;
        if (common::ImmutableMapping::Create(
                startup_bytes.data(), startup_bytes.size(), startup_mapping) !=
            common::ImmutableMappingStatus::kSuccess) {
            return DnsProxyProcessStatus::kResourceFailed;
        }
        SIZE_T attribute_size = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &attribute_size);
        std::vector<std::uint8_t> storage(attribute_size);
        auto* attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
        const std::array<HANDLE, 4> inherited = {
            startup_mapping.handle(), policy.handle(), request_read, response_write};
        if (!InitializeProcThreadAttributeList(attributes, 1, 0, &attribute_size) ||
            !UpdateProcThreadAttribute(
                attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                const_cast<HANDLE*>(inherited.data()), sizeof(inherited), nullptr,
                nullptr)) {
            return DnsProxyProcessStatus::kResourceFailed;
        }
        STARTUPINFOEXW startup_info{};
        startup_info.StartupInfo.cb = sizeof(startup_info);
        startup_info.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup_info.StartupInfo.hStdInput = startup_mapping.handle();
        startup_info.StartupInfo.hStdOutput = request_read;
        startup_info.StartupInfo.hStdError = response_write;
        startup_info.lpAttributeList = attributes;
        std::wstring command_line = L"\"" + executable.wstring() + L"\"";
        PROCESS_INFORMATION created{};
        const BOOL created_ok = CreateProcessW(
            executable.c_str(), command_line.data(), nullptr, nullptr, TRUE,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, nullptr, nullptr,
            &startup_info.StartupInfo, &created);
        DeleteProcThreadAttributeList(attributes);
        CloseHandle(request_read);
        CloseHandle(response_write);
        if (!created_ok) {
            CloseHandle(request_write);
            CloseHandle(response_read);
            return DnsProxyProcessStatus::kCreateFailed;
        }
        CloseHandle(created.hThread);
        auto process = std::unique_ptr<DnsProxyProcess>(new DnsProxyProcess());
        process->process_ = created.hProcess;
        process->request_write_ = request_write;
        process->response_read_ = response_read;
        output = std::move(process);
        return DnsProxyProcessStatus::kSuccess;
    } catch (...) {
        return DnsProxyProcessStatus::kResourceFailed;
    }
}

void DnsProxyProcess::CloseClientHandles() noexcept {
    if (request_write_ != nullptr) {
        CloseHandle(request_write_);
        request_write_ = nullptr;
    }
    if (response_read_ != nullptr) {
        CloseHandle(response_read_);
        response_read_ = nullptr;
    }
}

DnsProxyProcessStatus DnsProxyProcess::Wait(const DWORD timeout) noexcept {
    if (process_ == nullptr) {
        return DnsProxyProcessStatus::kInvalidArgument;
    }
    const DWORD result = WaitForSingleObject(process_, timeout);
    if (result == WAIT_TIMEOUT) {
        return DnsProxyProcessStatus::kWaitTimeout;
    }
    if (result != WAIT_OBJECT_0) {
        return DnsProxyProcessStatus::kWaitFailed;
    }
    DWORD exit_code = 0;
    return GetExitCodeProcess(process_, &exit_code) && exit_code == 0
               ? DnsProxyProcessStatus::kSuccess
               : DnsProxyProcessStatus::kProcessFailed;
}

void DnsProxyProcess::Close() noexcept {
    CloseClientHandles();
    if (process_ != nullptr) {
        if (WaitForSingleObject(process_, 0) == WAIT_TIMEOUT) {
            TerminateProcess(process_, 1);
            WaitForSingleObject(process_, 5'000);
        }
        CloseHandle(process_);
        process_ = nullptr;
    }
}

}  // namespace bolt::network
