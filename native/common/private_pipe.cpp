#include "common/private_pipe.h"

#include <algorithm>
#include <array>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>

namespace bolt::common {
namespace {

constexpr std::wstring_view kPipePrefix = L"\\\\.\\pipe\\bolt-sandbox-";
constexpr DWORD kPipeBufferSize = 64 * 1'024;

bool IsValidName(const std::wstring_view name) noexcept {
    return name.size() == kPipePrefix.size() + 32 &&
           name.compare(0, kPipePrefix.size(), kPipePrefix) == 0 &&
           std::all_of(name.begin() + static_cast<std::ptrdiff_t>(kPipePrefix.size()), name.end(),
                       [](const wchar_t value) {
                           return (value >= L'0' && value <= L'9') ||
                                  (value >= L'a' && value <= L'f');
                       });
}

class PipeSecurity final {
  public:
    bool Initialize() noexcept {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
            return false;
        }
        DWORD token_length = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &token_length);
        try {
            token_user_.resize(token_length);
        } catch (...) {
            CloseHandle(token);
            return false;
        }
        const bool token_ok = GetTokenInformation(
                                  token, TokenUser, token_user_.data(), token_length,
                                  &token_length) != FALSE;
        CloseHandle(token);
        if (!token_ok) {
            return false;
        }

        DWORD system_sid_length = static_cast<DWORD>(system_sid_.size());
        if (!CreateWellKnownSid(
                WinLocalSystemSid, nullptr, system_sid_.data(), &system_sid_length)) {
            return false;
        }
        const auto* token_user = reinterpret_cast<const TOKEN_USER*>(token_user_.data());
        std::array<EXPLICIT_ACCESSW, 2> access{};
        access[0].grfAccessPermissions = FILE_GENERIC_READ | FILE_WRITE_DATA;
        access[0].grfAccessMode = SET_ACCESS;
        access[0].grfInheritance = NO_INHERITANCE;
        access[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        access[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
        access[0].Trustee.ptstrName = static_cast<LPWSTR>(token_user->User.Sid);
        access[1].grfAccessPermissions = GENERIC_ALL;
        access[1].grfAccessMode = SET_ACCESS;
        access[1].grfInheritance = NO_INHERITANCE;
        access[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        access[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        access[1].Trustee.ptstrName = reinterpret_cast<LPWSTR>(system_sid_.data());
        if (SetEntriesInAclW(
                static_cast<ULONG>(access.size()), access.data(), nullptr, &acl_) !=
            ERROR_SUCCESS) {
            return false;
        }
        if (!InitializeSecurityDescriptor(&descriptor_, SECURITY_DESCRIPTOR_REVISION) ||
            !SetSecurityDescriptorDacl(&descriptor_, TRUE, acl_, FALSE) ||
            !SetSecurityDescriptorControl(
                &descriptor_, SE_DACL_PROTECTED, SE_DACL_PROTECTED)) {
            return false;
        }
        attributes_.nLength = sizeof(attributes_);
        attributes_.lpSecurityDescriptor = &descriptor_;
        attributes_.bInheritHandle = FALSE;
        return true;
    }

    ~PipeSecurity() noexcept {
        if (acl_ != nullptr) {
            LocalFree(acl_);
        }
    }

    SECURITY_ATTRIBUTES* attributes() noexcept { return &attributes_; }

  private:
    std::vector<std::uint8_t> token_user_;
    std::array<std::uint8_t, SECURITY_MAX_SID_SIZE> system_sid_{};
    PACL acl_ = nullptr;
    SECURITY_DESCRIPTOR descriptor_{};
    SECURITY_ATTRIBUTES attributes_{};
};

}  // namespace

PrivatePipe::~PrivatePipe() noexcept {
    Close();
}

PipeStatus PrivatePipe::Create(
    const std::wstring_view name,
    PrivatePipe& output) noexcept {
    if (!IsValidName(name)) {
        return PipeStatus::kInvalidName;
    }
    PipeSecurity security;
    if (!security.Initialize()) {
        return PipeStatus::kSecurityFailed;
    }
    std::wstring terminated_name;
    try {
        terminated_name.assign(name);
    } catch (...) {
        return PipeStatus::kAllocationFailed;
    }
    const HANDLE pipe = CreateNamedPipeW(
        terminated_name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1,
        kPipeBufferSize, kPipeBufferSize, 0, security.attributes());
    if (pipe == INVALID_HANDLE_VALUE) {
        return PipeStatus::kCreateFailed;
    }
    output.Close();
    output.handle_ = pipe;
    output.connected_ = false;
    return PipeStatus::kSuccess;
}

PipeStatus PrivatePipe::Accept() noexcept {
    if (handle_ == INVALID_HANDLE_VALUE || connected_) {
        return PipeStatus::kInvalidState;
    }
    if (!ConnectNamedPipe(handle_, nullptr) && GetLastError() != ERROR_PIPE_CONNECTED) {
        return PipeStatus::kConnectFailed;
    }
    connected_ = true;
    return PipeStatus::kSuccess;
}

void PrivatePipe::Close() noexcept {
    const HANDLE pipe = handle_;
    const bool connected = connected_;
    handle_ = INVALID_HANDLE_VALUE;
    connected_ = false;
    if (pipe != INVALID_HANDLE_VALUE) {
        if (connected) {
            DisconnectNamedPipe(pipe);
        }
        CloseHandle(pipe);
    }
}

}  // namespace bolt::common
