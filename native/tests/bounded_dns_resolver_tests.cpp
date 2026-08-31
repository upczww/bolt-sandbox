#include "hook/network/bounded_dns_resolver.h"

#include <atomic>
#include <chrono>
#include <memory>
#include <thread>
#include <vector>

namespace {

class DelayedResolver final : public bolt::network::DnsResolver {
  public:
    explicit DelayedResolver(const std::uint32_t delay_milliseconds) noexcept
        : delay_milliseconds_(delay_milliseconds) {}

    bolt::protocol::DnsProxyResult Resolve(
        const char*,
        bolt::protocol::DnsProxyQueryFamily,
        std::vector<bolt::protocol::DnsProxyAddress>& addresses) noexcept override {
        calls.fetch_add(1, std::memory_order_relaxed);
        std::this_thread::sleep_for(
            std::chrono::milliseconds(delay_milliseconds_));
        bolt::protocol::DnsProxyAddress address{};
        address.address[0] = 127;
        address.address[3] = 1;
        address.ttl_seconds = 1;
        addresses.push_back(address);
        return bolt::protocol::DnsProxyResult::kSuccess;
    }

    std::atomic<int> calls = 0;

  private:
    std::uint32_t delay_milliseconds_ = 0;
};

}  // namespace

bool RunBoundedDnsResolverTests() {
    auto fast = std::make_shared<DelayedResolver>(0);
    bolt::network::BoundedDnsResolver fast_bounded(fast, 100);
    std::vector<bolt::protocol::DnsProxyAddress> addresses;
    if (fast_bounded.Resolve(
            "localhost", bolt::protocol::DnsProxyQueryFamily::kAny,
            addresses) != bolt::protocol::DnsProxyResult::kSuccess ||
        addresses.size() != 1 || fast->calls.load() != 1) {
        return false;
    }

    auto delayed = std::make_shared<DelayedResolver>(100);
    bolt::network::BoundedDnsResolver bounded(delayed, 10);
    addresses.assign(1, {});
    const auto started = std::chrono::steady_clock::now();
    const auto timed_out = bounded.Resolve(
        "delayed.example", bolt::protocol::DnsProxyQueryFamily::kAny,
        addresses);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);
    const auto second_started = std::chrono::steady_clock::now();
    const auto poisoned = bounded.Resolve(
        "second.example", bolt::protocol::DnsProxyQueryFamily::kAny,
        addresses);
    const auto second_elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - second_started);
    const bool passed =
        timed_out == bolt::protocol::DnsProxyResult::kFailure &&
        poisoned == bolt::protocol::DnsProxyResult::kFailure &&
        elapsed.count() < 80 && second_elapsed.count() < 20 &&
        addresses.empty() && delayed->calls.load() == 1;
    std::this_thread::sleep_for(std::chrono::milliseconds(110));
    return passed;
}
