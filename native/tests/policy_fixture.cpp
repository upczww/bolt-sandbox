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

void AppendU16(std::vector<std::uint8_t>& bytes, const std::uint16_t value) {
    bytes.push_back(static_cast<std::uint8_t>(value));
    bytes.push_back(static_cast<std::uint8_t>(value >> 8U));
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

std::vector<RegistryRule> RegistryRulesWithCompatibility(
    const std::vector<RegistryRule>& requested) {
    std::vector<RegistryRule> rules = requested;
    const std::vector<RegistryRule> compatibility = {
        {RegistryRuleKind::kReadOnly, RegistryHive::kCurrentUser,
         {"SOFTWARE", "CLASSES"}},
        {RegistryRuleKind::kReadOnly, RegistryHive::kLocalMachine,
         {"SOFTWARE", "CLASSES"}},
        {RegistryRuleKind::kReadOnly, RegistryHive::kLocalMachine,
         {"SOFTWARE", "DOTNET", "SETUP", "INSTALLEDVERSIONS"}},
        {RegistryRuleKind::kReadOnly, RegistryHive::kLocalMachine,
         {"SYSTEM", "CURRENTCONTROLSET", "CONTROL", "NLS"}},
        {RegistryRuleKind::kReadOnly, RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "AMSI"}},
        {RegistryRuleKind::kReadOnly, RegistryHive::kLocalMachine,
         {"SOFTWARE", "POLICIES", "MICROSOFT", "POWERSHELLCORE"}},
        {RegistryRuleKind::kReadOnly, RegistryHive::kCurrentUser,
         {"SOFTWARE", "POLICIES", "MICROSOFT", "POWERSHELLCORE"}},
        {RegistryRuleKind::kReadOnly, RegistryHive::kLocalMachine,
         {"SOFTWARE", "POLICIES", "MICROSOFT", "WINDOWS", "POWERSHELL"}},
        {RegistryRuleKind::kReadOnly, RegistryHive::kCurrentUser,
         {"SOFTWARE", "POLICIES", "MICROSOFT", "WINDOWS", "POWERSHELL"}},
        {RegistryRuleKind::kReadOnly, RegistryHive::kLocalMachine,
         {"SOFTWARE", "POLICIES", "MICROSOFT", "WINDOWS", "SAFER"}},
        {RegistryRuleKind::kReadOnly, RegistryHive::kLocalMachine,
         {"SYSTEM", "CURRENTCONTROLSET", "CONTROL", "SRP"}},
        {RegistryRuleKind::kReadOnly, RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "WINDOWS NT", "CURRENTVERSION", "SERVER"}},
        {RegistryRuleKind::kReadOnly, RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "WINDOWS NT", "CURRENTVERSION", "TIME ZONES"}},
        {RegistryRuleKind::kReadOnlyKey, RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "WINDOWS NT", "CURRENTVERSION"}},
        {RegistryRuleKind::kReadOnlyKey, RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "WINDOWS", "CURRENTVERSION"}},
        {RegistryRuleKind::kHideKey, RegistryHive::kCurrentUser,
         {"ENVIRONMENT"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SYSTEM", "CURRENTCONTROLSET", "CONTROL", "SESSION MANAGER"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SYSTEM", "CURRENTCONTROLSET", "SERVICES", "WINSOCK2"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SYSTEM", "CURRENTCONTROLSET", "SERVICES", "WINSOCK"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SYSTEM", "CURRENTCONTROLSET", "SERVICES", "TCPIP", "PARAMETERS"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SYSTEM", "CURRENTCONTROLSET", "SERVICES", "TCPIP6", "PARAMETERS", "WINSOCK"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "OLE"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "APPMODEL", "LOOKASIDE", "MACHINE"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "APPMODEL", "LOOKASIDE", "USER"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "WOW64", "X86", "XTAJIT"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SYSTEM", "CURRENTCONTROLSET", "CONTROL", "SAFEBOOT", "OPTION"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SYSTEM", "CURRENTCONTROLSET", "SERVICES", "DNSCACHE", "PARAMETERS"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "POLICIES", "MICROSOFT", "WINDOWS", "SAFER", "CODEIDENTIFIERS"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kCurrentUser,
         {"SOFTWARE", "POLICIES", "MICROSOFT", "WINDOWS", "SAFER", "CODEIDENTIFIERS"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kCurrentUser,
         {"SOFTWARE", "MICROSOFT", "WINDOWS NT", "CURRENTVERSION"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "WINDOWS NT", "CURRENTVERSION", "CONTAINERS"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "WINDOWS", "CURRENTVERSION", "SIDEBYSIDE"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "LANGUAGEOVERLAY", "OVERLAYPACKAGES"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "WINDOWS", "CURRENTVERSION", "INTERNET SETTINGS"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kCurrentUser,
         {"SOFTWARE", "MICROSOFT", "WINDOWS", "CURRENTVERSION", "INTERNET SETTINGS"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "POLICIES", "MICROSOFT", "INTERNET EXPLORER", "MAIN"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kCurrentUser,
         {"SOFTWARE", "POLICIES", "MICROSOFT", "INTERNET EXPLORER", "MAIN"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "POLICIES", "MICROSOFT", "WINDOWS", "CURRENTVERSION", "INTERNET SETTINGS"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kCurrentUser,
         {"SOFTWARE", "POLICIES", "MICROSOFT", "WINDOWS", "CURRENTVERSION", "INTERNET SETTINGS"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "POLICIES", "MICROSOFT", "WINDOWS", "MPEHTTPEXT", "PAYLOAD"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "POLICIES", "MICROSOFT", "WINDOWS", "TENANTRESTRICTIONS", "PAYLOAD"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "RPC"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SYSTEM", "CURRENTCONTROLSET", "SERVICES", "CCG"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SYSTEM", "CURRENTCONTROLSET", "CONTROL", "COMPUTERNAME", "ACTIVECOMPUTERNAME"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SYSTEM", "SETUP"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "POLICIES", "MICROSOFT", "WINDOWS NT", "RPC"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SYSTEM", "CURRENTCONTROLSET", "CONTROL", "NLS", "SORTING", "IDS"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "POLICIES", "MICROSOFT", "PEERDIST", "SERVICE"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "WINDOWS NT", "CURRENTVERSION", "PEERDIST", "SERVICE"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SYSTEM", "CURRENTCONTROLSET", "CONTROL", "HVSI"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SYSTEM", "CURRENTCONTROLSET", "CONTROL", "SECURITYPROVIDERS"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SYSTEM", "CURRENTCONTROLSET", "CONTROL", "LSA", "SSPICACHE"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "POLICIES", "MICROSOFT", "WINDOWS", "SYSTEM"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "WINDOWS", "CURRENTVERSION", "POLICIES", "EXPLORER"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kCurrentUser,
         {"SOFTWARE", "MICROSOFT", "WINDOWS", "CURRENTVERSION", "POLICIES", "EXPLORER"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kCurrentUser,
         {"SOFTWARE", "MICROSOFT", "WINDOWS", "CURRENTVERSION", "THEMES", "PERSONALIZE"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "POLICIES", "MICROSOFT", "WINDOWS", "EXPLORER"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kCurrentUser,
         {"SOFTWARE", "POLICIES", "MICROSOFT", "WINDOWS", "EXPLORER"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "OLEAUT"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "WINDOWS", "CURRENTVERSION", "SHELLCOMPATIBILITY", "APPLICATIONS"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kCurrentUser,
         {"SOFTWARE", "MICROSOFT", "WINDOWS", "CURRENTVERSION", "POLICIES", "NONENUM"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "WINDOWS", "CURRENTVERSION", "POLICIES", "NONENUM"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "COM3"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kCurrentUser,
         {"SOFTWARE", "MICROSOFT", "WINDOWS", "CURRENTVERSION", "EXPLORER"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "WINDOWSRUNTIME"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SYSTEM", "CURRENTCONTROLSET", "SERVICES", "LANMANWORKSTATION", "PARAMETERS"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"ZONEMAP", "RANGES"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kCurrentUser,
         {"ZONEMAP", "RANGES"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kCurrentUser,
         {"SOFTWARE", "MICROSOFT", "INTERNET EXPLORER", "MAIN"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "INTERNET EXPLORER", "MAIN"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kCurrentUser,
         {"SOFTWARE", "MICROSOFT", "INTERNET EXPLORER", "SECURITY"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "INTERNET EXPLORER", "SECURITY"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "WINDOWS NT", "CURRENTVERSION", "PROFILELIST"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kCurrentUser,
         {"SOFTWARE", "MICROSOFT", "WINDOWS", "CURRENTVERSION", "SHELL EXTENSIONS", "BLOCKED"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "WINDOWS", "CURRENTVERSION", "SHELL EXTENSIONS", "BLOCKED"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kCurrentUser,
         {"SOFTWARE", "MICROSOFT", "WINDOWS NT", "CURRENTVERSION", "APPCOMPATFLAGS"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "WINDOWS NT", "CURRENTVERSION", "APPCOMPATFLAGS"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"OSDATA", "SOFTWARE", "MICROSOFT", "WINDOWS NT", "CURRENTVERSION", "APPCOMPATFLAGS"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kCurrentUser,
         {"SOFTWARE", "MICROSOFT", "WINDOWS", "CURRENTVERSION", "SHELL EXTENSIONS", "CACHED"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "WINDOWS", "CURRENTVERSION", "SHELL EXTENSIONS", "CACHED"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "WINDOWS", "CURRENTVERSION", "SHELLCOMPATIBILITY", "OBJECTS"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kCurrentUser,
         {"SOFTWARE", "POLICIES", "MICROSOFT", "WINDOWS", "APPX"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "POLICIES", "MICROSOFT", "WINDOWS", "APPX"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kCurrentUser,
         {"SOFTWARE", "MICROSOFT", "WINDOWS", "CURRENTVERSION", "APPMODELUNLOCK"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "WINDOWS", "CURRENTVERSION", "APPMODELUNLOCK"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "WINDOWS", "CURRENTVERSION", "DIAGNOSTICS", "DIAGTRACK", "PARTNERS", "COM", "RUNDOWNIIDSOFINTEREST"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SYSTEM", "CURRENTCONTROLSET", "CONTROL", "MUI", "STRINGCACHESETTINGS"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "WINDOWS", "CURRENTVERSION", "EXPLORER"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "WINDOWS NT", "CURRENTVERSION", "TERMINAL SERVER"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kCurrentUser,
         {"SOFTWARE", "MICROSOFT", "WINDOWS", "CURRENTVERSION", "PROPERTYSYSTEM"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "WINDOWS", "CURRENTVERSION", "PROPERTYSYSTEM"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kCurrentUser,
         {"SOFTWARE", "MICROSOFT", "WINDOWS", "CURRENTVERSION", "APP PATHS"}},
        {RegistryRuleKind::kInheritUser, RegistryHive::kLocalMachine,
         {"SOFTWARE", "MICROSOFT", "WINDOWS", "CURRENTVERSION", "APP PATHS"}},
    };
    for (const auto& candidate : compatibility) {
        const bool covered_by_read_only = candidate.kind ==
                RegistryRuleKind::kInheritUser &&
            std::any_of(
                rules.begin(), rules.end(),
                [&candidate](const RegistryRule& rule) {
                    if (rule.kind != RegistryRuleKind::kReadOnly ||
                        rule.hive != candidate.hive ||
                        rule.components.size() >
                            candidate.components.size()) {
                        return false;
                    }
                    for (std::size_t index = 0;
                         index < rule.components.size(); ++index) {
                        if (_stricmp(
                                rule.components[index].c_str(),
                                candidate.components[index].c_str()) != 0) {
                            return false;
                        }
                    }
                    return true;
                });
        if (covered_by_read_only) {
            continue;
        }
        const bool present = std::any_of(
            rules.begin(), rules.end(), [&candidate](const RegistryRule& rule) {
                if (rule.hive != candidate.hive ||
                    rule.components.size() != candidate.components.size()) {
                    return false;
                }
                for (std::size_t index = 0; index < rule.components.size(); ++index) {
                    if (_stricmp(
                            rule.components[index].c_str(),
                            candidate.components[index].c_str()) != 0) {
                        return false;
                    }
                }
                return true;
            });
        if (!present) {
            rules.push_back(candidate);
        }
    }
    return rules;
}

}  // namespace

std::vector<std::uint8_t> SealPolicy(
    const std::vector<FilesystemRule>& filesystem_rules,
    const ChildProcessPolicyKind child_process_policy,
    const NetworkPolicyKind network_policy,
    const NetworkAllowListRules& network_allow_list,
    const std::vector<RegistryRule>& registry_rules) {
    std::vector<std::uint8_t> body{
        static_cast<std::uint8_t>(child_process_policy)};
    if (!AppendU32(body, filesystem_rules.size())) {
        return {};
    }
    for (const auto& rule : filesystem_rules) {
        if (!AppendRule(body, rule)) {
            return {};
        }
    }
    body.push_back(static_cast<std::uint8_t>(network_policy));
    if (network_policy == NetworkPolicyKind::kAllowList) {
        if (!AppendU32(body, network_allow_list.domains.size())) {
            return {};
        }
        for (const auto& domain : network_allow_list.domains) {
            body.push_back(domain.wildcard ? 1 : 0);
            if (!AppendU32(body, domain.ascii_domain.size())) {
                return {};
            }
            body.insert(
                body.end(), domain.ascii_domain.begin(), domain.ascii_domain.end());
        }
        if (!AppendU32(body, network_allow_list.addresses.size())) {
            return {};
        }
        for (const auto& address : network_allow_list.addresses) {
            const std::size_t address_length = address.family == 4 ? 4 : 16;
            body.push_back(address.family);
            body.push_back(address.prefix_length);
            body.insert(
                body.end(), address.address.begin(),
                address.address.begin() + address_length);
        }
        if (!AppendU32(body, network_allow_list.ports.size())) {
            return {};
        }
        for (const auto& port : network_allow_list.ports) {
            AppendU16(body, port.start);
            AppendU16(body, port.end);
        }
    }
    const auto encoded_registry_rules =
        RegistryRulesWithCompatibility(registry_rules);
    if (!AppendU32(body, encoded_registry_rules.size())) {
        return {};
    }
    for (const auto& rule : encoded_registry_rules) {
        body.push_back(static_cast<std::uint8_t>(rule.kind));
        body.push_back(static_cast<std::uint8_t>(rule.hive));
        if (!AppendU32(body, rule.components.size())) {
            return {};
        }
        for (const auto& component : rule.components) {
            if (component.empty() || !AppendU32(body, component.size())) {
                return {};
            }
            body.insert(body.end(), component.begin(), component.end());
        }
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
