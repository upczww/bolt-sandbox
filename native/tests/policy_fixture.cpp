#include "tests/policy_fixture.h"

#include "protocol/version.h"

#include <cstddef>
#include <limits>
#include <string>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

namespace bolt::tests {
namespace {

bool AppendU32(std::vector<std::uint8_t>& bytes, const std::size_t value) {
    if (value > std::numeric_limits<std::uint32_t>::max()) {
        return false;
    }
    for (std::size_t shift = 0; shift < 32; shift += 8) {
        bytes.push_back(static_cast<std::uint8_t>(value >> shift));
    }
    return true;
}

bool AppendComponent(
    std::vector<std::uint8_t>& record,
    const std::uint8_t kind,
    const std::wstring& value) {
    record.push_back(kind);
    if (!AppendU32(record, value.size())) {
        return false;
    }
    for (const wchar_t code_unit : value) {
        const auto value_u16 = static_cast<std::uint16_t>(code_unit);
        record.push_back(static_cast<std::uint8_t>(value_u16));
        record.push_back(static_cast<std::uint8_t>(value_u16 >> 8));
    }
    return true;
}

bool AppendRule(std::vector<std::uint8_t>& body, const FilesystemRule& rule) {
    const auto normalized = rule.root.lexically_normal();
    const std::wstring root_name = normalized.root_name().wstring();
    if (!normalized.is_absolute() || root_name.empty() ||
        normalized.root_directory().empty()) {
        return false;
    }

    std::vector<std::wstring> components;
    for (const auto& component : normalized.relative_path()) {
        const std::wstring value = component.wstring();
        if (value.empty() || value == L"." || value == L"..") {
            return false;
        }
        components.push_back(value);
    }

    std::vector<std::uint8_t> record{
        static_cast<std::uint8_t>(rule.kind),
    };
    if (!AppendU32(record, components.size() + 2) ||
        !AppendComponent(record, 0, root_name) ||
        !AppendComponent(record, 1, L"")) {
        return false;
    }
    for (const auto& component : components) {
        if (!AppendComponent(record, 2, component)) {
            return false;
        }
    }
    return AppendU32(body, record.size()) &&
           (body.insert(body.end(), record.begin(), record.end()), true);
}

bool HashPayload(std::vector<std::uint8_t>& payload) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD object_length = 0;
    DWORD result_length = 0;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
        BCryptGetProperty(
            algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_length),
            sizeof(object_length), &result_length, 0) < 0) {
        if (algorithm != nullptr) {
            BCryptCloseAlgorithmProvider(algorithm, 0);
        }
        return false;
    }
    std::vector<std::uint8_t> object(object_length);
    bool success =
        BCryptCreateHash(algorithm, &hash, object.data(), object_length, nullptr, 0, 0) >= 0;
    if (success) {
        success = BCryptHashData(
                      hash, payload.data(),
                      static_cast<ULONG>(protocol::kPolicyDigestOffset), 0) >= 0;
    }
    if (success) {
        success = BCryptHashData(
                      hash, payload.data() + protocol::kPolicyEnvelopeLength,
                      static_cast<ULONG>(payload.size() - protocol::kPolicyEnvelopeLength), 0) >=
                  0;
    }
    if (success) {
        success = BCryptFinishHash(
                      hash, payload.data() + protocol::kPolicyDigestOffset, 32, 0) >= 0;
    }
    if (hash != nullptr) {
        BCryptDestroyHash(hash);
    }
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return success;
}

}  // namespace

std::vector<std::uint8_t> SealPolicy(
    const std::vector<FilesystemRule>& filesystem_rules) {
    std::vector<std::uint8_t> body{0};
    if (!AppendU32(body, filesystem_rules.size())) {
        return {};
    }
    for (const auto& rule : filesystem_rules) {
        if (!AppendRule(body, rule)) {
            return {};
        }
    }
    body.push_back(0);
    if (!AppendU32(body, 0)) {
        return {};
    }

    std::vector<std::uint8_t> payload(protocol::kPolicyEnvelopeLength, 0);
    payload[0] = 'B';
    payload[1] = 'L';
    payload[2] = 'P';
    payload[3] = '1';
    payload[4] = static_cast<std::uint8_t>(protocol::kProtocolVersion);
    payload[6] = static_cast<std::uint8_t>(protocol::kPolicyEnvelopeLength);
    const std::size_t body_length = body.size();
    for (std::size_t shift = 0; shift < 32; shift += 8) {
        payload[8 + shift / 8] = static_cast<std::uint8_t>(body_length >> shift);
    }
    payload.insert(payload.end(), body.begin(), body.end());
    return HashPayload(payload) ? payload : std::vector<std::uint8_t>{};
}

}  // namespace bolt::tests
