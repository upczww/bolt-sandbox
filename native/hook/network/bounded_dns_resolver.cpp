#include "hook/network/bounded_dns_resolver.h"

#include <chrono>
#include <condition_variable>
#include <string>
#include <thread>
#include <utility>

namespace bolt::network {
namespace {

struct ResolveState {
    std::mutex lock;
    std::condition_variable completed;
    bool done = false;
    protocol::DnsProxyResult result = protocol::DnsProxyResult::kFailure;
    std::vector<protocol::DnsProxyAddress> addresses;
};

}  // namespace

BoundedDnsResolver::BoundedDnsResolver(
    std::shared_ptr<DnsResolver> resolver,
    const std::uint32_t timeout_milliseconds) noexcept
    : resolver_(std::move(resolver)),
      timeout_milliseconds_(timeout_milliseconds) {}

protocol::DnsProxyResult BoundedDnsResolver::Resolve(
    const char* const ascii_domain,
    const protocol::DnsProxyQueryFamily family,
    std::vector<protocol::DnsProxyAddress>& addresses) noexcept {
    addresses.clear();
    if (resolver_ == nullptr || timeout_milliseconds_ == 0 ||
        ascii_domain == nullptr || poisoned_.load(std::memory_order_acquire)) {
        return protocol::DnsProxyResult::kFailure;
    }
    std::unique_lock<std::mutex> exclusive(resolve_lock_, std::try_to_lock);
    if (!exclusive.owns_lock() || poisoned_.load(std::memory_order_acquire)) {
        return protocol::DnsProxyResult::kFailure;
    }
    try {
        const std::string domain(ascii_domain);
        auto state = std::make_shared<ResolveState>();
        const auto resolver = resolver_;
        std::thread worker([resolver, state, domain, family] {
            std::vector<protocol::DnsProxyAddress> resolved;
            const auto result =
                resolver->Resolve(domain.c_str(), family, resolved);
            {
                std::lock_guard<std::mutex> guard(state->lock);
                state->result = result;
                state->addresses = std::move(resolved);
                state->done = true;
            }
            state->completed.notify_one();
        });
        bool completed = false;
        {
            std::unique_lock<std::mutex> guard(state->lock);
            completed = state->completed.wait_for(
                guard,
                std::chrono::milliseconds(timeout_milliseconds_),
                [&state] { return state->done; });
        }
        if (!completed) {
            poisoned_.store(true, std::memory_order_release);
            worker.detach();
            return protocol::DnsProxyResult::kFailure;
        }
        worker.join();
        addresses = std::move(state->addresses);
        return state->result;
    } catch (...) {
        poisoned_.store(true, std::memory_order_release);
        addresses.clear();
        return protocol::DnsProxyResult::kFailure;
    }
}

}  // namespace bolt::network
