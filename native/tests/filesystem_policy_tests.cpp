#include "hook/filesystem/filesystem_policy.h"
#include "hook/filesystem/access_classifier.h"
#include "hook/filesystem/safe_device.h"

#include "protocol/version.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

namespace {

void append_u32(std::vector<std::uint8_t>& bytes, const std::size_t value) {
    for (std::size_t shift = 0; shift < 32; shift += 8) {
        bytes.push_back(static_cast<std::uint8_t>(value >> shift));
    }
}

void append_component(std::vector<std::uint8_t>& record, const std::uint8_t kind, const std::wstring& value) {
    record.push_back(kind);
    append_u32(record, value.size());
    for (const wchar_t code_unit : value) {
        record.push_back(static_cast<std::uint8_t>(code_unit));
        record.push_back(static_cast<std::uint8_t>(code_unit >> 8));
    }
}

void append_rule(
    std::vector<std::uint8_t>& body,
    const std::uint8_t kind,
    const std::vector<std::wstring>& components) {
    std::vector<std::uint8_t> record{kind};
    append_u32(record, components.size() + 2U);
    append_component(record, 0, L"C:");
    append_component(record, 1, L"");
    for (const auto& component : components) {
        append_component(record, 2, component);
    }
    append_u32(body, record.size());
    body.insert(body.end(), record.begin(), record.end());
}

bool hash_payload(std::vector<std::uint8_t>& payload) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD object_length = 0;
    DWORD result_length = 0;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
        BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_length),
                          sizeof(object_length), &result_length, 0) < 0) {
        return false;
    }
    std::vector<std::uint8_t> object(object_length);
    bool success = BCryptCreateHash(algorithm, &hash, object.data(), object_length, nullptr, 0, 0) >= 0;
    if (success) {
        success = BCryptHashData(hash, payload.data(), bolt::protocol::kPolicyDigestOffset, 0) >= 0;
    }
    if (success) {
        success = BCryptHashData(
                      hash, payload.data() + bolt::protocol::kPolicyEnvelopeLength,
                      static_cast<ULONG>(payload.size() - bolt::protocol::kPolicyEnvelopeLength), 0) >= 0;
    }
    if (success) {
        success = BCryptFinishHash(
                      hash, payload.data() + bolt::protocol::kPolicyDigestOffset, 32, 0) >= 0;
    }
    if (hash != nullptr) {
        BCryptDestroyHash(hash);
    }
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return success;
}

std::vector<std::uint8_t> policy_payload() {
    std::vector<std::uint8_t> body{0};
    append_u32(body, 6);
    append_rule(body, 0, {L"work"});
    append_rule(body, 2, {L"work", L"secret"});
    append_rule(body, 1, {L"sdk"});
    append_rule(body, 0, {L"sdk", L"cache"});
    append_rule(body, 3, {L"metadata"});
    append_rule(body, 4, {L"user"});
    body.push_back(0);
    append_u32(body, 0);

    std::vector<std::uint8_t> payload(bolt::protocol::kPolicyEnvelopeLength, 0);
    payload[0] = 'B';
    payload[1] = 'L';
    payload[2] = 'P';
    payload[3] = '1';
    payload[4] = 1;
    payload[6] = static_cast<std::uint8_t>(bolt::protocol::kPolicyEnvelopeLength);
    const auto body_length = body.size();
    for (std::size_t shift = 0; shift < 32; shift += 8) {
        payload[8 + shift / 8] = static_cast<std::uint8_t>(body_length >> shift);
    }
    payload.insert(payload.end(), body.begin(), body.end());
    if (!hash_payload(payload)) {
        return {};
    }
    return payload;
}

}  // namespace

bool RunFilesystemPolicyTests() {
    if (!bolt::filesystem::IsNetworkDevicePath(L"\\Device\\Afd") ||
        !bolt::filesystem::IsNetworkDevicePath(
            L"\\Device\\Afd\\AsyncConnectHlp") ||
        bolt::filesystem::IsNetworkDevicePath(L"\\Device\\Af") ||
        bolt::filesystem::IsNetworkDevicePath(
            L"\\Device\\AfdLookalike\\AsyncConnectHlp") ||
        bolt::filesystem::IsNetworkDevicePath(L"C:\\Device\\Afd")) {
        return false;
    }
    const auto payload = policy_payload();
    std::unique_ptr<bolt::filesystem::FilesystemPolicy> policy;
    if (payload.empty() || bolt::filesystem::FilesystemPolicy::Load(payload.data(), payload.size(), policy) !=
                               bolt::filesystem::PolicyLoadStatus::kValid) {
        return false;
    }

    using bolt::filesystem::Access;
    using bolt::filesystem::Decision;
    using bolt::protocol::FilesystemOperation;
    const auto metadata = bolt::filesystem::ClassifyCreateFileRequest(
        FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL | SYNCHRONIZE, OPEN_EXISTING);
    const auto read = bolt::filesystem::ClassifyCreateFileRequest(
        GENERIC_READ | GENERIC_EXECUTE, OPEN_EXISTING);
    const auto write = bolt::filesystem::ClassifyCreateFileRequest(
        GENERIC_READ | FILE_APPEND_DATA, OPEN_EXISTING);
    const auto create =
        bolt::filesystem::ClassifyCreateFileRequest(0, OPEN_ALWAYS);
    const auto truncate =
        bolt::filesystem::ClassifyCreateFileRequest(GENERIC_READ, TRUNCATE_EXISTING);
    const auto maximum_allowed =
        bolt::filesystem::ClassifyCreateFileRequest(MAXIMUM_ALLOWED, OPEN_EXISTING);
    const auto delete_on_close =
        bolt::filesystem::ClassifyCreateFileRequestWithFlags(
            GENERIC_READ, OPEN_EXISTING, FILE_FLAG_DELETE_ON_CLOSE);
    if (metadata.access != Access::kMetadata ||
        metadata.operation != FilesystemOperation::kMetadata ||
        read.access != Access::kRead || read.operation != FilesystemOperation::kRead ||
        write.access != Access::kWrite || write.operation != FilesystemOperation::kWrite ||
        create.access != Access::kWrite ||
        create.operation != FilesystemOperation::kCreate ||
        truncate.access != Access::kWrite ||
        truncate.operation != FilesystemOperation::kWrite ||
        maximum_allowed.access != Access::kWrite ||
        maximum_allowed.operation != FilesystemOperation::kWrite ||
        delete_on_close.access != Access::kWrite ||
        delete_on_close.operation != FilesystemOperation::kDelete) {
        return false;
    }
    if (bolt::filesystem::RequiresPreOpenFinalResolution(read, 0) ||
        bolt::filesystem::RequiresPreOpenFinalResolution(metadata, 0) ||
        !bolt::filesystem::RequiresPreOpenFinalResolution(write, 0) ||
        !bolt::filesystem::RequiresPreOpenFinalResolution(
            read, FILE_FLAG_DELETE_ON_CLOSE) ||
        !bolt::filesystem::RequiresPreOpenFinalResolution(
            read, FILE_FLAG_OPEN_REPARSE_POINT)) {
        return false;
    }

    const bolt::filesystem::PolicyView& policy_view = *policy;
    const auto evaluated = policy_view.Evaluate(
        L"\\\\?\\C:\\work\\source.cpp", Access::kWrite);
    const auto dot_evaluated = policy_view.Evaluate(
        L"C:\\work\\.\\nested\\..\\source.cpp", Access::kWrite);
    const auto invalid = policy_view.Evaluate(nullptr, Access::kRead);
    if (evaluated.decision != Decision::kAllow ||
        evaluated.normalized_path != L"C:\\work\\source.cpp" ||
        dot_evaluated.decision != Decision::kAllow ||
        dot_evaluated.normalized_path != L"C:\\work\\source.cpp" ||
        invalid.decision != Decision::kDeny || !invalid.normalized_path.empty()) {
        return false;
    }

    return policy->Decide(L"C:\\WORK\\source.cpp", Access::kWrite) == Decision::kAllow &&
           policy->HasDeniedDescendant(L"C:\\work") &&
           policy->HasDeniedDescendant(L"c:\\WORK") &&
           !policy->HasDeniedDescendant(L"C:\\work\\secret") &&
           !policy->HasDeniedDescendant(L"C:\\worker") &&
           policy->HasDeniedDescendant(nullptr) &&
           policy->Decide(L"C:\\work\\secret\\key", Access::kRead) == Decision::kDeny &&
           policy->Decide(L"C:\\sdk\\tool.exe", Access::kRead) == Decision::kAllow &&
           policy->Decide(L"C:\\sdk\\tool.exe", Access::kWrite) == Decision::kDeny &&
           policy->Decide(L"C:\\sdk\\cache\\item", Access::kWrite) == Decision::kAllow &&
           policy->Decide(L"C:\\metadata\\item", Access::kMetadata) == Decision::kAllow &&
           policy->Decide(L"C:\\metadata\\item", Access::kRead) == Decision::kDeny &&
           policy->Decide(L"C:\\user\\item", Access::kRead) == Decision::kInheritUser &&
           policy->Decide(L"C:\\worker\\lookalike", Access::kRead) == Decision::kDeny &&
           policy->Decide(L"C:\\outside\\item", Access::kRead) == Decision::kDeny;
}
