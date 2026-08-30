#include "hook/network/dns_proxy_client_channel.h"

#include <algorithm>
#include <limits>
#include <new>
#include <utility>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace bolt::network {
namespace {

class ExclusiveLock final {
  public:
    explicit ExclusiveLock(SRWLOCK& lock) noexcept : lock_(lock) {
        AcquireSRWLockExclusive(&lock_);
    }
    ~ExclusiveLock() { ReleaseSRWLockExclusive(&lock_); }
    ExclusiveLock(const ExclusiveLock&) = delete;
    ExclusiveLock& operator=(const ExclusiveLock&) = delete;
  private:
    SRWLOCK& lock_;
};

bool AllZero(const std::uint8_t* bytes, const std::size_t length) noexcept {
    return std::all_of(bytes, bytes + length,
                       [](const std::uint8_t byte) { return byte == 0; });
}

}  // namespace

struct DnsProxyClientChannel::Impl {
    SRWLOCK lock = SRWLOCK_INIT;
    protocol::DnsProxySession session{};
    std::array<std::uint8_t, 16> session_id{};
    std::uint32_t process_id = 0;
    std::uint64_t next_sequence = 1;
    bool closed = false;
    std::unique_ptr<DnsProxyTransport> transport;
    DnsBindingTable* bindings = nullptr;
};

DnsProxyClientChannel::DnsProxyClientChannel(
    std::unique_ptr<Impl> implementation) noexcept
    : implementation_(std::move(implementation)) {}

DnsProxyClientChannel::~DnsProxyClientChannel() = default;

DnsProxyChannelStatus DnsProxyClientChannel::Create(
    const protocol::DnsProxySession& session,
    const std::array<std::uint8_t, 16>& session_id,
    const std::uint32_t process_id,
    std::unique_ptr<DnsProxyTransport> transport,
    DnsBindingTable& bindings,
    std::unique_ptr<DnsProxyClientChannel>& channel) noexcept {
    channel.reset();
    if (process_id == 0 || transport == nullptr ||
        AllZero(session_id.data(), session_id.size()) ||
        AllZero(session.nonce.data(), session.nonce.size()) ||
        AllZero(
            session.authentication_key.data(),
            session.authentication_key.size())) {
        return DnsProxyChannelStatus::kInvalidArgument;
    }
    try {
        auto implementation = std::make_unique<Impl>();
        implementation->session = session;
        implementation->session_id = session_id;
        implementation->process_id = process_id;
        implementation->transport = std::move(transport);
        implementation->bindings = &bindings;
        channel = std::unique_ptr<DnsProxyClientChannel>(
            new DnsProxyClientChannel(std::move(implementation)));
        return DnsProxyChannelStatus::kSuccess;
    } catch (...) {
        return DnsProxyChannelStatus::kInvalidArgument;
    }
}

DnsProxyChannelStatus DnsProxyClientChannel::Resolve(
    const char* const ascii_domain,
    const std::uint16_t port,
    const std::uint64_t now,
    std::vector<protocol::DnsProxyAddress>* const resolved_addresses,
    const protocol::DnsProxyQueryFamily family) noexcept {
    if (resolved_addresses != nullptr) {
        resolved_addresses->clear();
    }
    if (implementation_ == nullptr || ascii_domain == nullptr) {
        return DnsProxyChannelStatus::kInvalidArgument;
    }
    ExclusiveLock guard(implementation_->lock);
    if (implementation_->closed) {
        return DnsProxyChannelStatus::kClosed;
    }
    try {
        std::vector<std::uint8_t> request;
        if (protocol::EncodeDnsProxyRequest(
                implementation_->session, implementation_->next_sequence,
                implementation_->process_id, ascii_domain, port, request,
                family) !=
            protocol::DnsProxyStatus::kSuccess) {
            return DnsProxyChannelStatus::kInvalidArgument;
        }
        if (!implementation_->transport->WriteFrame(request)) {
            implementation_->closed = true;
            return DnsProxyChannelStatus::kTransportFailed;
        }
        std::vector<std::uint8_t> response;
        if (implementation_->transport->ReadFrame(response) !=
            TransportReadStatus::kFrame) {
            implementation_->closed = true;
            return DnsProxyChannelStatus::kTransportFailed;
        }
        const auto consume = ConsumeDnsProxyResponse(
            implementation_->session, implementation_->next_sequence,
            response.data(), response.size(), implementation_->session_id,
            implementation_->process_id, ascii_domain, port, now,
            *implementation_->bindings, resolved_addresses);
        if (consume == DnsProxyClientStatus::kProtocolFailed) {
            implementation_->closed = true;
            return DnsProxyChannelStatus::kProtocolFailed;
        }
        if (consume == DnsProxyClientStatus::kBindingFailed) {
            implementation_->closed = true;
            return DnsProxyChannelStatus::kBindingFailed;
        }
        if (implementation_->next_sequence ==
            std::numeric_limits<std::uint64_t>::max()) {
            implementation_->closed = true;
        } else {
            ++implementation_->next_sequence;
        }
        if (consume == DnsProxyClientStatus::kDenied) {
            return DnsProxyChannelStatus::kDenied;
        }
        if (consume == DnsProxyClientStatus::kNotFound) {
            return DnsProxyChannelStatus::kNotFound;
        }
        if (consume == DnsProxyClientStatus::kResolverFailed) {
            return DnsProxyChannelStatus::kResolverFailed;
        }
        return DnsProxyChannelStatus::kSuccess;
    } catch (...) {
        implementation_->closed = true;
        return DnsProxyChannelStatus::kTransportFailed;
    }
}

}  // namespace bolt::network
