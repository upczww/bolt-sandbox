#include "hook/network/network_policy.h"

#include "protocol/policy_payload.h"
#include "protocol/version.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <new>
#include <string>
#include <utility>
#include <vector>

namespace bolt::network {
namespace {

constexpr std::size_t kMaximumRulesPerCategory = 1'024;
constexpr std::size_t kMaximumTotalRules = 2'048;
constexpr std::size_t kMaximumDomainLength = 253;

struct DomainRule {
    std::string ascii_domain;
    bool wildcard = false;
};

struct AddressRule {
    AddressFamily family = AddressFamily::kIpv4;
    std::uint8_t prefix_length = 0;
    std::array<std::uint8_t, 16> address{};
};

struct PortRule {
    std::uint16_t start = 0;
    std::uint16_t end = 0;
};

class Reader final {
  public:
    Reader(const std::uint8_t* bytes, const std::size_t length) noexcept
        : bytes_(bytes), length_(length) {}

    bool ReadU8(std::uint8_t& value) noexcept {
        const std::uint8_t* bytes = nullptr;
        if (!ReadBytes(1, bytes)) {
            return false;
        }
        value = bytes[0];
        return true;
    }

    bool ReadU16(std::uint16_t& value) noexcept {
        const std::uint8_t* bytes = nullptr;
        if (!ReadBytes(2, bytes)) {
            return false;
        }
        value = static_cast<std::uint16_t>(bytes[0]) |
                static_cast<std::uint16_t>(bytes[1] << 8U);
        return true;
    }

    bool ReadU32(std::size_t& value) noexcept {
        const std::uint8_t* bytes = nullptr;
        if (!ReadBytes(4, bytes)) {
            return false;
        }
        value = static_cast<std::size_t>(bytes[0]) |
                (static_cast<std::size_t>(bytes[1]) << 8U) |
                (static_cast<std::size_t>(bytes[2]) << 16U) |
                (static_cast<std::size_t>(bytes[3]) << 24U);
        return true;
    }

    bool ReadBytes(const std::size_t count, const std::uint8_t*& bytes) noexcept {
        if (offset_ > length_ || count > length_ - offset_) {
            return false;
        }
        bytes = bytes_ + offset_;
        offset_ += count;
        return true;
    }

    bool Skip(const std::size_t count) noexcept {
        const std::uint8_t* ignored = nullptr;
        return ReadBytes(count, ignored);
    }

  private:
    const std::uint8_t* bytes_;
    std::size_t length_;
    std::size_t offset_ = 0;
};

bool ReadNetworkMode(Reader& body, std::uint8_t& network_mode) noexcept {
    std::uint8_t child_policy = 0;
    std::size_t filesystem_rule_count = 0;
    if (!body.ReadU8(child_policy) || !body.ReadU32(filesystem_rule_count)) {
        return false;
    }
    for (std::size_t index = 0; index < filesystem_rule_count; ++index) {
        std::size_t record_length = 0;
        if (!body.ReadU32(record_length) || !body.Skip(record_length)) {
            return false;
        }
    }
    return body.ReadU8(network_mode);
}

bool IsCanonicalDomain(const std::string& domain) noexcept {
    if (domain.empty() || domain.size() > kMaximumDomainLength ||
        domain.front() == '.' || domain.back() == '.') {
        return false;
    }
    std::size_t label_length = 0;
    std::size_t label_count = 1;
    bool all_labels_numeric = true;
    bool ipv4_candidate = true;
    unsigned int numeric_label = 0;
    bool first_is_hyphen = false;
    bool last_is_hyphen = false;
    for (const unsigned char byte : domain) {
        if (byte == '.') {
            if (label_length == 0 || label_length > 63 || first_is_hyphen ||
                last_is_hyphen) {
                return false;
            }
            ++label_count;
            label_length = 0;
            first_is_hyphen = false;
            last_is_hyphen = false;
            numeric_label = 0;
            continue;
        }
        if (!((byte >= 'a' && byte <= 'z') || (byte >= '0' && byte <= '9') ||
              byte == '-')) {
            return false;
        }
        if (label_length == 0) {
            first_is_hyphen = byte == '-';
        }
        ++label_length;
        last_is_hyphen = byte == '-';
        if (byte >= '0' && byte <= '9') {
            if (ipv4_candidate) {
                const unsigned int digit = static_cast<unsigned int>(byte - '0');
                if (numeric_label > 25U || numeric_label * 10U + digit > 255U) {
                    ipv4_candidate = false;
                } else {
                    numeric_label = numeric_label * 10U + digit;
                }
            }
        } else {
            all_labels_numeric = false;
        }
        if (label_length > 63) {
            return false;
        }
    }
    return label_length != 0 && !first_is_hyphen && !last_is_hyphen &&
           !(all_labels_numeric && ipv4_candidate && label_count == 4);
}

bool HostBitsAreZero(
    const std::array<std::uint8_t, 16>& address,
    const std::size_t address_length,
    const std::uint8_t prefix_length) noexcept {
    const std::size_t full_bytes = prefix_length / 8U;
    const std::uint8_t remaining_bits = prefix_length % 8U;
    if (remaining_bits != 0) {
        const std::uint8_t host_mask =
            static_cast<std::uint8_t>((1U << (8U - remaining_bits)) - 1U);
        if ((address[full_bytes] & host_mask) != 0) {
            return false;
        }
    }
    const std::size_t first_host_byte =
        full_bytes + (remaining_bits == 0 ? 0U : 1U);
    return std::all_of(
        address.begin() + first_host_byte,
        address.begin() + address_length,
        [](const std::uint8_t byte) { return byte == 0; });
}

bool AddressMatches(
    const AddressRule& rule,
    const AddressFamily family,
    const std::uint8_t* candidate,
    const std::size_t candidate_length) noexcept {
    const std::size_t expected_length = family == AddressFamily::kIpv4 ? 4 : 16;
    if (rule.family != family || candidate == nullptr ||
        candidate_length != expected_length) {
        return false;
    }
    const std::size_t full_bytes = rule.prefix_length / 8U;
    if (!std::equal(
            rule.address.begin(), rule.address.begin() + full_bytes, candidate)) {
        return false;
    }
    const std::uint8_t remaining_bits = rule.prefix_length % 8U;
    if (remaining_bits == 0) {
        return true;
    }
    const std::uint8_t mask =
        static_cast<std::uint8_t>(0xffU << (8U - remaining_bits));
    return (rule.address[full_bytes] & mask) ==
           (candidate[full_bytes] & mask);
}

bool DomainMatches(const DomainRule& rule, const std::string& candidate) noexcept {
    if (!rule.wildcard) {
        return candidate == rule.ascii_domain;
    }
    if (candidate.size() <= rule.ascii_domain.size() + 1U ||
        candidate.compare(
            candidate.size() - rule.ascii_domain.size(),
            rule.ascii_domain.size(), rule.ascii_domain) != 0) {
        return false;
    }
    return candidate[candidate.size() - rule.ascii_domain.size() - 1U] == '.';
}

}  // namespace

struct NetworkPolicy::Impl {
    std::vector<DomainRule> domains;
    std::vector<AddressRule> addresses;
    std::vector<PortRule> ports;
};

NetworkPolicy::NetworkPolicy(
    const Mode mode,
    std::unique_ptr<Impl> implementation) noexcept
    : mode_(mode), implementation_(std::move(implementation)) {}

NetworkPolicy::~NetworkPolicy() = default;

PolicyLoadStatus NetworkPolicy::Load(
    const std::uint8_t* payload,
    const std::size_t length,
    std::unique_ptr<NetworkPolicy>& policy) noexcept {
    policy.reset();
    if (protocol::ValidatePolicyPayload(payload, length) !=
        protocol::PolicyPayloadStatus::kValid) {
        return PolicyLoadStatus::kInvalidPayload;
    }

    try {
        Reader body(
            payload + protocol::kPolicyEnvelopeLength,
            length - protocol::kPolicyEnvelopeLength);
        std::uint8_t network_mode = 0;
        if (!ReadNetworkMode(body, network_mode) || network_mode > 2) {
            return PolicyLoadStatus::kInvalidNetworkPolicy;
        }
        auto implementation = std::make_unique<Impl>();
        if (network_mode == 2) {
            std::size_t domain_count = 0;
            if (!body.ReadU32(domain_count) ||
                domain_count > kMaximumRulesPerCategory) {
                return PolicyLoadStatus::kInvalidNetworkPolicy;
            }
            implementation->domains.reserve(domain_count);
            for (std::size_t index = 0; index < domain_count; ++index) {
                std::uint8_t wildcard = 0;
                std::size_t domain_length = 0;
                const std::uint8_t* domain_bytes = nullptr;
                if (!body.ReadU8(wildcard) || wildcard > 1 ||
                    !body.ReadU32(domain_length) || domain_length == 0 ||
                    domain_length > kMaximumDomainLength ||
                    !body.ReadBytes(domain_length, domain_bytes)) {
                    return PolicyLoadStatus::kInvalidNetworkPolicy;
                }
                DomainRule rule{
                    std::string(
                        reinterpret_cast<const char*>(domain_bytes), domain_length),
                    wildcard != 0};
                if (!IsCanonicalDomain(rule.ascii_domain)) {
                    return PolicyLoadStatus::kInvalidNetworkPolicy;
                }
                implementation->domains.push_back(std::move(rule));
            }

            std::size_t address_count = 0;
            if (!body.ReadU32(address_count) ||
                address_count > kMaximumRulesPerCategory ||
                domain_count > kMaximumTotalRules - address_count) {
                return PolicyLoadStatus::kInvalidNetworkPolicy;
            }
            implementation->addresses.reserve(address_count);
            for (std::size_t index = 0; index < address_count; ++index) {
                std::uint8_t family = 0;
                AddressRule rule;
                if (!body.ReadU8(family) || !body.ReadU8(rule.prefix_length)) {
                    return PolicyLoadStatus::kInvalidNetworkPolicy;
                }
                std::size_t address_length = 0;
                if (family == 4 && rule.prefix_length <= 32) {
                    rule.family = AddressFamily::kIpv4;
                    address_length = 4;
                } else if (family == 6 && rule.prefix_length <= 128) {
                    rule.family = AddressFamily::kIpv6;
                    address_length = 16;
                } else {
                    return PolicyLoadStatus::kInvalidNetworkPolicy;
                }
                const std::uint8_t* address_bytes = nullptr;
                if (!body.ReadBytes(address_length, address_bytes)) {
                    return PolicyLoadStatus::kInvalidNetworkPolicy;
                }
                std::copy_n(address_bytes, address_length, rule.address.begin());
                if (!HostBitsAreZero(
                        rule.address, address_length, rule.prefix_length)) {
                    return PolicyLoadStatus::kInvalidNetworkPolicy;
                }
                implementation->addresses.push_back(rule);
            }

            std::size_t port_count = 0;
            if (!body.ReadU32(port_count) ||
                port_count > kMaximumRulesPerCategory ||
                domain_count + address_count > kMaximumTotalRules - port_count) {
                return PolicyLoadStatus::kInvalidNetworkPolicy;
            }
            implementation->ports.reserve(port_count);
            std::uint16_t previous_end = 0;
            for (std::size_t index = 0; index < port_count; ++index) {
                PortRule rule;
                if (!body.ReadU16(rule.start) || !body.ReadU16(rule.end) ||
                    rule.start == 0 || rule.start > rule.end ||
                    (index != 0 && rule.start <= previous_end)) {
                    return PolicyLoadStatus::kInvalidNetworkPolicy;
                }
                previous_end = rule.end;
                implementation->ports.push_back(rule);
            }
        }

        const Mode mode = network_mode == 0
                              ? Mode::kUnrestricted
                              : network_mode == 1 ? Mode::kDenied : Mode::kAllowList;
        policy = std::unique_ptr<NetworkPolicy>(
            new NetworkPolicy(mode, std::move(implementation)));
        return PolicyLoadStatus::kValid;
    } catch (const std::bad_alloc&) {
        return PolicyLoadStatus::kOutOfMemory;
    } catch (...) {
        return PolicyLoadStatus::kInvalidNetworkPolicy;
    }
}

Decision NetworkPolicy::DecideDomain(const char* const ascii_domain) const noexcept {
    if (mode_ == Mode::kUnrestricted) {
        return Decision::kAllow;
    }
    if (mode_ != Mode::kAllowList || ascii_domain == nullptr ||
        implementation_ == nullptr) {
        return Decision::kDeny;
    }
    try {
        std::string candidate(ascii_domain);
        std::transform(
            candidate.begin(), candidate.end(), candidate.begin(),
            [](const unsigned char byte) {
                return static_cast<char>(std::tolower(byte));
            });
        if (!IsCanonicalDomain(candidate)) {
            return Decision::kDeny;
        }
        return std::any_of(
                   implementation_->domains.begin(), implementation_->domains.end(),
                   [&candidate](const DomainRule& rule) {
                       return DomainMatches(rule, candidate);
                   })
                   ? Decision::kAllow
                   : Decision::kDeny;
    } catch (...) {
        return Decision::kDeny;
    }
}

Decision NetworkPolicy::DecideAddress(
    const AddressFamily family,
    const std::uint8_t* const address,
    const std::size_t address_length) const noexcept {
    if (mode_ == Mode::kUnrestricted) {
        return Decision::kAllow;
    }
    if (mode_ != Mode::kAllowList || implementation_ == nullptr ||
        (family != AddressFamily::kIpv4 && family != AddressFamily::kIpv6)) {
        return Decision::kDeny;
    }
    return std::any_of(
               implementation_->addresses.begin(), implementation_->addresses.end(),
               [family, address, address_length](const AddressRule& rule) {
                   return AddressMatches(rule, family, address, address_length);
               })
               ? Decision::kAllow
               : Decision::kDeny;
}

Decision NetworkPolicy::DecidePort(const std::uint16_t port) const noexcept {
    if (mode_ == Mode::kUnrestricted) {
        return Decision::kAllow;
    }
    if (mode_ != Mode::kAllowList || implementation_ == nullptr) {
        return Decision::kDeny;
    }
    return std::any_of(
               implementation_->ports.begin(), implementation_->ports.end(),
               [port](const PortRule& rule) {
                   return port >= rule.start && port <= rule.end;
               })
               ? Decision::kAllow
               : Decision::kDeny;
}

}  // namespace bolt::network
