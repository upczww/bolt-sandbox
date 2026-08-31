#include "protocol/launcher_startup.h"

#include "protocol/version.h"

#include <algorithm>
#include <cstring>
#include <limits>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

namespace bolt::protocol {
namespace {

constexpr std::array<std::uint8_t, 4> kMagic = {'B', 'L', 'S', '1'};
constexpr std::size_t kDigestOffset = 64;
constexpr std::size_t kDigestLength = 32;
constexpr std::uint32_t kHasTimeout = 1;
constexpr std::uint32_t kRecoveryEnabled = 2;
constexpr std::size_t kMaximumPathCodeUnits = 32'767;
constexpr std::size_t kMaximumCommandCodeUnits = 32'767;
constexpr std::size_t kMaximumEnvironmentCodeUnits = 524'288;
constexpr std::size_t kMaximumPolicyBytes = 1'048'620;

void WriteU16(
    std::uint8_t* const output,
    const std::size_t offset,
    const std::uint16_t value) noexcept {
    std::memcpy(output + offset, &value, sizeof(value));
}

void WriteU32(
    std::uint8_t* const output,
    const std::size_t offset,
    const std::uint32_t value) noexcept {
    std::memcpy(output + offset, &value, sizeof(value));
}

void WriteU64(
    std::uint8_t* const output,
    const std::size_t offset,
    const std::uint64_t value) noexcept {
    std::memcpy(output + offset, &value, sizeof(value));
}

std::uint16_t ReadU16(
    const std::uint8_t* const input,
    const std::size_t offset) noexcept {
    std::uint16_t value = 0;
    std::memcpy(&value, input + offset, sizeof(value));
    return value;
}

std::uint32_t ReadU32(
    const std::uint8_t* const input,
    const std::size_t offset) noexcept {
    std::uint32_t value = 0;
    std::memcpy(&value, input + offset, sizeof(value));
    return value;
}

std::uint64_t ReadU64(
    const std::uint8_t* const input,
    const std::size_t offset) noexcept {
    std::uint64_t value = 0;
    std::memcpy(&value, input + offset, sizeof(value));
    return value;
}

bool HashRequest(
    const std::uint8_t* const encoded,
    const std::size_t length,
    std::array<std::uint8_t, kDigestLength>& digest) noexcept {
    if (encoded == nullptr || length < kLauncherStartHeaderLength) {
        return false;
    }
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD object_length = 0;
    DWORD result_length = 0;
    if (BCryptOpenAlgorithmProvider(
            &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
        BCryptGetProperty(
            algorithm, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&object_length), sizeof(object_length),
            &result_length, 0) < 0) {
        if (algorithm != nullptr) {
            BCryptCloseAlgorithmProvider(algorithm, 0);
        }
        return false;
    }
    std::vector<std::uint8_t> object;
    try {
        object.resize(object_length);
    } catch (...) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return false;
    }
    bool succeeded =
        BCryptCreateHash(
            algorithm, &hash, object.data(), object_length, nullptr, 0, 0) >=
        0;
    if (succeeded) {
        succeeded = BCryptHashData(
                        hash, const_cast<PUCHAR>(encoded),
                        static_cast<ULONG>(kDigestOffset), 0) >= 0;
    }
    if (succeeded && length > kLauncherStartHeaderLength) {
        succeeded = BCryptHashData(
                        hash,
                        const_cast<PUCHAR>(
                            encoded + kLauncherStartHeaderLength),
                        static_cast<ULONG>(length - kLauncherStartHeaderLength),
                        0) >= 0;
    }
    if (succeeded) {
        succeeded = BCryptFinishHash(
                        hash, digest.data(),
                        static_cast<ULONG>(digest.size()), 0) >= 0;
    }
    if (hash != nullptr) {
        BCryptDestroyHash(hash);
    }
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return succeeded;
}

bool ContainsNull(const std::wstring& value) noexcept {
    return value.find(L'\0') != std::wstring::npos;
}

bool ValidRequest(const LauncherStartRequest& request) noexcept {
    return !request.program.empty() &&
           request.program.size() <= kMaximumPathCodeUnits &&
           !ContainsNull(request.program) && !request.cwd.empty() &&
           request.cwd.size() <= kMaximumPathCodeUnits &&
           !ContainsNull(request.cwd) && !request.hook_path.empty() &&
           request.hook_path.size() <= kMaximumPathCodeUnits &&
           !ContainsNull(request.hook_path) &&
           !request.command_line.empty() &&
           request.command_line.size() <= kMaximumCommandCodeUnits &&
           request.command_line.back() == L'\0' &&
           std::find(
               request.command_line.begin(), request.command_line.end() - 1,
               L'\0') == request.command_line.end() - 1 &&
           request.environment_block.size() >= 2 &&
           request.environment_block.size() <=
               kMaximumEnvironmentCodeUnits &&
           request.environment_block[request.environment_block.size() - 1] ==
               L'\0' &&
           request.environment_block[request.environment_block.size() - 2] ==
               L'\0' &&
           !request.policy.empty() &&
           request.policy.size() <= kMaximumPolicyBytes &&
           (!request.has_timeout || request.timeout_milliseconds != 0) &&
           (request.has_timeout || request.timeout_milliseconds == 0) &&
           std::any_of(
               request.nonce.begin(), request.nonce.end(),
               [](const std::uint8_t byte) { return byte != 0; });
}

bool CheckedAdd(
    std::size_t& total,
    const std::size_t count,
    const std::size_t width = 1) noexcept {
    if (count > std::numeric_limits<std::size_t>::max() / width ||
        count * width > std::numeric_limits<std::size_t>::max() - total) {
        return false;
    }
    total += count * width;
    return true;
}

void AppendUtf16(
    std::vector<std::uint8_t>& encoded,
    const wchar_t* const value,
    const std::size_t length) {
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(value);
    encoded.insert(encoded.end(), bytes, bytes + length * sizeof(wchar_t));
}

bool ReadUtf16(
    const std::uint8_t* const encoded,
    const std::size_t length,
    std::size_t& offset,
    const std::size_t code_units,
    std::vector<wchar_t>& output) {
    if (code_units > std::numeric_limits<std::size_t>::max() /
                         sizeof(wchar_t) ||
        code_units * sizeof(wchar_t) > length - offset) {
        return false;
    }
    output.resize(code_units);
    std::memcpy(
        output.data(), encoded + offset, code_units * sizeof(wchar_t));
    offset += code_units * sizeof(wchar_t);
    return true;
}

}  // namespace

bool LauncherStartRequest::operator==(
    const LauncherStartRequest& other) const noexcept {
    return program == other.program && cwd == other.cwd &&
           command_line == other.command_line &&
           environment_block == other.environment_block &&
           policy == other.policy && hook_path == other.hook_path &&
           has_timeout == other.has_timeout &&
           timeout_milliseconds == other.timeout_milliseconds &&
           nonce == other.nonce &&
           recovery_enabled == other.recovery_enabled;
}

LauncherStartStatus EncodeLauncherStartRequest(
    const LauncherStartRequest& request,
    std::vector<std::uint8_t>& encoded) noexcept {
    encoded.clear();
    if (!ValidRequest(request)) {
        return LauncherStartStatus::kInvalidField;
    }
    std::size_t total = kLauncherStartHeaderLength;
    if (!CheckedAdd(total, request.program.size(), sizeof(wchar_t)) ||
        !CheckedAdd(total, request.cwd.size(), sizeof(wchar_t)) ||
        !CheckedAdd(total, request.command_line.size(), sizeof(wchar_t)) ||
        !CheckedAdd(
            total, request.environment_block.size(), sizeof(wchar_t)) ||
        !CheckedAdd(total, request.policy.size()) ||
        !CheckedAdd(total, request.hook_path.size(), sizeof(wchar_t)) ||
        total > kLauncherStartMaximumLength ||
        total > std::numeric_limits<std::uint32_t>::max()) {
        return LauncherStartStatus::kInvalidLength;
    }
    try {
        encoded.assign(kLauncherStartHeaderLength, 0);
        encoded.reserve(total);
        std::copy(kMagic.begin(), kMagic.end(), encoded.begin());
        WriteU16(encoded.data(), 4, kProtocolVersion);
        WriteU16(
            encoded.data(), 6,
            static_cast<std::uint16_t>(kLauncherStartHeaderLength));
        WriteU32(encoded.data(), 8, static_cast<std::uint32_t>(total));
        const std::array<std::size_t, 6> lengths = {
            request.program.size(), request.cwd.size(),
            request.command_line.size(), request.environment_block.size(),
            request.policy.size(), request.hook_path.size()};
        for (std::size_t index = 0; index < lengths.size(); ++index) {
            WriteU32(
                encoded.data(), 12 + index * 4,
                static_cast<std::uint32_t>(lengths[index]));
        }
        WriteU64(
            encoded.data(), 36,
            request.has_timeout ? request.timeout_milliseconds : 0);
        std::copy(
            request.nonce.begin(), request.nonce.end(), encoded.begin() + 44);
        WriteU32(
            encoded.data(), 60,
            (request.has_timeout ? kHasTimeout : 0) |
                (request.recovery_enabled ? kRecoveryEnabled : 0));
        AppendUtf16(encoded, request.program.data(), request.program.size());
        AppendUtf16(encoded, request.cwd.data(), request.cwd.size());
        AppendUtf16(
            encoded, request.command_line.data(), request.command_line.size());
        AppendUtf16(
            encoded, request.environment_block.data(),
            request.environment_block.size());
        encoded.insert(
            encoded.end(), request.policy.begin(), request.policy.end());
        AppendUtf16(
            encoded, request.hook_path.data(), request.hook_path.size());
    } catch (...) {
        encoded.clear();
        return LauncherStartStatus::kAllocationFailed;
    }
    std::array<std::uint8_t, kDigestLength> digest{};
    if (!HashRequest(encoded.data(), encoded.size(), digest)) {
        encoded.clear();
        return LauncherStartStatus::kAllocationFailed;
    }
    std::copy(digest.begin(), digest.end(), encoded.begin() + kDigestOffset);
    return LauncherStartStatus::kSuccess;
}

LauncherStartStatus DecodeLauncherStartRequest(
    const std::uint8_t* const encoded,
    const std::size_t length,
    LauncherStartRequest& request) noexcept {
    if (encoded == nullptr) {
        return LauncherStartStatus::kInvalidArgument;
    }
    if (length < kLauncherStartHeaderLength ||
        length > kLauncherStartMaximumLength || ReadU32(encoded, 8) != length) {
        return LauncherStartStatus::kInvalidLength;
    }
    if (!std::equal(kMagic.begin(), kMagic.end(), encoded)) {
        return LauncherStartStatus::kInvalidMagic;
    }
    if (ReadU16(encoded, 4) != kProtocolVersion) {
        return LauncherStartStatus::kUnsupportedVersion;
    }
    if (ReadU16(encoded, 6) != kLauncherStartHeaderLength) {
        return LauncherStartStatus::kInvalidHeader;
    }
    const std::uint32_t flags = ReadU32(encoded, 60);
    const std::uint64_t timeout = ReadU64(encoded, 36);
    if ((flags & ~(kHasTimeout | kRecoveryEnabled)) != 0 ||
        ((flags & kHasTimeout) == 0) != (timeout == 0)) {
        return LauncherStartStatus::kInvalidFlags;
    }
    std::array<std::uint8_t, kDigestLength> digest{};
    if (!HashRequest(encoded, length, digest) ||
        !std::equal(
            digest.begin(), digest.end(), encoded + kDigestOffset)) {
        return LauncherStartStatus::kDigestMismatch;
    }
    LauncherStartRequest decoded{};
    decoded.has_timeout = (flags & kHasTimeout) != 0;
    decoded.recovery_enabled = (flags & kRecoveryEnabled) != 0;
    decoded.timeout_milliseconds = timeout;
    std::copy(encoded + 44, encoded + 60, decoded.nonce.begin());
    const std::array<std::size_t, 6> lengths = {
        ReadU32(encoded, 12), ReadU32(encoded, 16), ReadU32(encoded, 20),
        ReadU32(encoded, 24), ReadU32(encoded, 28), ReadU32(encoded, 32)};
    std::size_t offset = kLauncherStartHeaderLength;
    try {
        std::vector<wchar_t> program;
        std::vector<wchar_t> cwd;
        std::vector<wchar_t> hook;
        if (!ReadUtf16(encoded, length, offset, lengths[0], program) ||
            !ReadUtf16(encoded, length, offset, lengths[1], cwd) ||
            !ReadUtf16(
                encoded, length, offset, lengths[2], decoded.command_line) ||
            !ReadUtf16(
                encoded, length, offset, lengths[3],
                decoded.environment_block) ||
            lengths[4] > length - offset) {
            return LauncherStartStatus::kInvalidLength;
        }
        decoded.program.assign(program.begin(), program.end());
        decoded.cwd.assign(cwd.begin(), cwd.end());
        decoded.policy.assign(encoded + offset, encoded + offset + lengths[4]);
        offset += lengths[4];
        if (!ReadUtf16(encoded, length, offset, lengths[5], hook) ||
            offset != length) {
            return LauncherStartStatus::kInvalidLength;
        }
        decoded.hook_path.assign(hook.begin(), hook.end());
    } catch (...) {
        return LauncherStartStatus::kAllocationFailed;
    }
    if (!ValidRequest(decoded)) {
        return LauncherStartStatus::kInvalidField;
    }
    request = std::move(decoded);
    return LauncherStartStatus::kSuccess;
}

}  // namespace bolt::protocol
