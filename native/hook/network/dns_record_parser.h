#pragma once

#include "protocol/dns_proxy_protocol.h"

#include <cstdint>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <windns.h>

namespace bolt::network {

enum class DnsRecordParseStatus : std::uint8_t {
    kSuccess,
    kNotFound,
    kInvalid,
};

DnsRecordParseStatus CollectValidatedDnsAddresses(
    const char* query_domain,
    WORD query_type,
    const DNS_RECORD* records,
    std::vector<protocol::DnsProxyAddress>& addresses) noexcept;

}  // namespace bolt::network
