#include "hook/network/dns_proxy_session.h"

#include <limits>

namespace bolt::network {

DnsProxySessionStatus RunDnsProxySession(
    const protocol::DnsProxySession& session,
    const NetworkPolicy& policy,
    DnsResolver& resolver,
    DnsProxyTransport& transport,
    const std::size_t maximum_requests) noexcept {
    if (maximum_requests == 0) {
        return DnsProxySessionStatus::kLimitReached;
    }
    std::uint64_t sequence = 1;
    for (std::size_t processed = 0; processed < maximum_requests; ++processed) {
        try {
            std::vector<std::uint8_t> request;
            const auto read_status = transport.ReadFrame(request);
            if (read_status == TransportReadStatus::kEof) {
                return DnsProxySessionStatus::kCompleted;
            }
            if (read_status != TransportReadStatus::kFrame || request.empty()) {
                return DnsProxySessionStatus::kTransportFailed;
            }
            std::vector<std::uint8_t> response;
            if (ProcessDnsProxyRequest(
                    session, policy, sequence, request.data(), request.size(),
                    resolver, response) != protocol::DnsProxyStatus::kSuccess) {
                return DnsProxySessionStatus::kProtocolFailed;
            }
            if (response.empty() || !transport.WriteFrame(response)) {
                return DnsProxySessionStatus::kTransportFailed;
            }
            if (sequence == std::numeric_limits<std::uint64_t>::max()) {
                return DnsProxySessionStatus::kLimitReached;
            }
            ++sequence;
        } catch (...) {
            return DnsProxySessionStatus::kTransportFailed;
        }
    }
    return DnsProxySessionStatus::kLimitReached;
}

}  // namespace bolt::network
