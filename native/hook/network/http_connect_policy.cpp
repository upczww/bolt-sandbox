#include "hook/network/http_connect_policy.h"

#include <algorithm>
#include <array>
#include <cstring>

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>

namespace bolt::network {
namespace {

constexpr std::array<char, 8> kConnectPrefix = {
    'C', 'O', 'N', 'N', 'E', 'C', 'T', ' '};
constexpr std::array<char, 7> kHttpVersionPrefix = {
    'H', 'T', 'T', 'P', '/', '1', '.'};

bool ParsePort(
    const char* const bytes,
    const std::size_t length,
    std::uint16_t& port) noexcept {
    if (bytes == nullptr || length == 0 || length > 5) {
        return false;
    }
    unsigned int value = 0;
    for (std::size_t index = 0; index < length; ++index) {
        const unsigned char byte = static_cast<unsigned char>(bytes[index]);
        if (byte < '0' || byte > '9') {
            return false;
        }
        value = value * 10U + static_cast<unsigned int>(byte - '0');
    }
    if (value == 0 || value > 65'535U) {
        return false;
    }
    port = static_cast<std::uint16_t>(value);
    return true;
}

bool AddressAllowed(
    const char* const host,
    const NetworkPolicy& policy) noexcept {
    IN_ADDR ipv4{};
    if (InetPtonA(AF_INET, host, &ipv4) == 1) {
        return policy.DecideAddress(
                   AddressFamily::kIpv4,
                   reinterpret_cast<const std::uint8_t*>(&ipv4),
                   sizeof(ipv4)) == Decision::kAllow;
    }
    IN6_ADDR ipv6{};
    return InetPtonA(AF_INET6, host, &ipv6) == 1 &&
           policy.DecideAddress(
               AddressFamily::kIpv6,
               reinterpret_cast<const std::uint8_t*>(&ipv6), sizeof(ipv6)) ==
               Decision::kAllow;
}

}  // namespace

HttpConnectInspection InspectHttpConnectPreface(
    const char* const bytes,
    const std::size_t length,
    const bool end_of_stream,
    const NetworkPolicy& policy) noexcept {
    if (bytes == nullptr || length > kMaximumHttpConnectPrefaceLength) {
        return HttpConnectInspection::kDeny;
    }
    const std::size_t prefix_length =
        length < kConnectPrefix.size() ? length : kConnectPrefix.size();
    if (!std::equal(
            bytes, bytes + prefix_length, kConnectPrefix.begin())) {
        return HttpConnectInspection::kNotConnect;
    }
    if (length < kConnectPrefix.size()) {
        return end_of_stream ? HttpConnectInspection::kNotConnect
                             : HttpConnectInspection::kNeedMore;
    }

    std::size_t line_end = kConnectPrefix.size();
    while (line_end + 1 < length &&
           (bytes[line_end] != '\r' || bytes[line_end + 1] != '\n')) {
        ++line_end;
    }
    if (line_end + 1 >= length) {
        return end_of_stream || length == kMaximumHttpConnectPrefaceLength
                   ? HttpConnectInspection::kDeny
                   : HttpConnectInspection::kNeedMore;
    }

    std::size_t authority_end = kConnectPrefix.size();
    while (authority_end < line_end && bytes[authority_end] != ' ') {
        ++authority_end;
    }
    const std::size_t version_offset = authority_end + 1;
    if (authority_end == kConnectPrefix.size() ||
        version_offset + kHttpVersionPrefix.size() > line_end ||
        !std::equal(
            kHttpVersionPrefix.begin(), kHttpVersionPrefix.end(),
            bytes + version_offset)) {
        return HttpConnectInspection::kDeny;
    }

    const std::size_t authority_offset = kConnectPrefix.size();
    std::size_t host_offset = authority_offset;
    std::size_t host_end = authority_end;
    std::size_t port_offset = authority_end;
    if (bytes[authority_offset] == '[') {
        host_offset = authority_offset + 1;
        host_end = host_offset;
        while (host_end < authority_end && bytes[host_end] != ']') {
            ++host_end;
        }
        if (host_end == host_offset || host_end + 1 >= authority_end ||
            bytes[host_end + 1] != ':') {
            return HttpConnectInspection::kDeny;
        }
        port_offset = host_end + 2;
    } else {
        std::size_t separator = authority_end;
        while (separator > authority_offset && bytes[separator - 1] != ':') {
            --separator;
        }
        if (separator == authority_offset || separator == authority_end) {
            return HttpConnectInspection::kDeny;
        }
        host_end = separator - 1;
        port_offset = separator;
        if (std::find(
                bytes + host_offset, bytes + host_end, ':') !=
            bytes + host_end) {
            return HttpConnectInspection::kDeny;
        }
    }

    const std::size_t host_length = host_end - host_offset;
    if (host_length == 0 || host_length > 253 || port_offset >= authority_end) {
        return HttpConnectInspection::kDeny;
    }
    std::uint16_t port = 0;
    if (!ParsePort(
            bytes + port_offset, authority_end - port_offset, port) ||
        policy.DecidePort(port) != Decision::kAllow) {
        return HttpConnectInspection::kDeny;
    }
    std::array<char, 254> host{};
    std::copy_n(bytes + host_offset, host_length, host.begin());
    const bool allowed =
        AddressAllowed(host.data(), policy) ||
        policy.DecideDomain(host.data()) == Decision::kAllow;
    return allowed ? HttpConnectInspection::kAllow
                   : HttpConnectInspection::kDeny;
}

}  // namespace bolt::network
