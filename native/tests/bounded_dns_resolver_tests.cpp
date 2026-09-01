#include "hook/network/bounded_dns_resolver.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <memory>
#include <mutex>
#include <vector>

namespace {

class ControlledResolver final : public bolt::network::DnsResolver {
  public:
    explicit ControlledResolver(const bool blocked) noexcept
        : blocked_(blocked) {}

    bolt::protocol::DnsProxyResult Resolve(
        const char*,
        bolt::protocol::DnsProxyQueryFamily,
        std::vector<bolt::protocol::DnsProxyAddress>& addresses) noexcept override {
        calls.fetch_add(1, std::memory_order_relaxed);
        {
            std::unique_lock<std::mutex> guard(lock_);
            if (blocked_) {
                changed_.wait(guard, [this] { return released_; });
            }
        }
        bolt::protocol::DnsProxyAddress address{};
        address.address[0] = 127;
        address.address[3] = 1;
        address.ttl_seconds = 1;
        addresses.push_back(address);
        {
            std::lock_guard<std::mutex> guard(lock_);
            completed_ = true;
        }
        changed_.notify_all();
        return bolt::protocol::DnsProxyResult::kSuccess;
    }

    void Release() noexcept {
        {
            std::lock_guard<std::mutex> guard(lock_);
            released_ = true;
        }
        changed_.notify_all();
    }

    bool WaitForCompletion() noexcept {
        std::unique_lock<std::mutex> guard(lock_);
        return changed_.wait_for(
            guard, std::chrono::seconds(30),
            [this] { return completed_; });
    }

    std::atomic<int> calls = 0;

  private:
    bool blocked_ = false;
    bool released_ = false;
    bool completed_ = false;
    std::mutex lock_;
    std::condition_variable changed_;
};

}  // namespace

bool RunBoundedDnsResolverTests() {
    auto fast = std::make_shared<ControlledResolver>(false);
    bolt::network::BoundedDnsResolver fast_bounded(fast, 30'000);
    std::vector<bolt::protocol::DnsProxyAddress> addresses;
    const auto fast_result = fast_bounded.Resolve(
            "localhost", bolt::protocol::DnsProxyQueryFamily::kAny,
            addresses);
    if (fast_result != bolt::protocol::DnsProxyResult::kSuccess ||
        addresses.size() != 1 || fast->calls.load() != 1) {
        std::fprintf(
            stderr,
            "bounded resolver fast failure result=%u addresses=%zu calls=%d\n",
            static_cast<unsigned>(fast_result), addresses.size(),
            fast->calls.load());
        return false;
    }

    auto delayed = std::make_shared<ControlledResolver>(true);
    bolt::network::BoundedDnsResolver bounded(delayed, 10);
    addresses.assign(1, {});
    const auto timed_out = bounded.Resolve(
        "delayed.example", bolt::protocol::DnsProxyQueryFamily::kAny,
        addresses);
    const auto poisoned = bounded.Resolve(
        "second.example", bolt::protocol::DnsProxyQueryFamily::kAny,
        addresses);
    const bool passed =
        timed_out == bolt::protocol::DnsProxyResult::kFailure &&
        poisoned == bolt::protocol::DnsProxyResult::kFailure &&
        addresses.empty();
    delayed->Release();
    const bool completed = delayed->WaitForCompletion();
    const bool called_once = delayed->calls.load() == 1;
    if (!passed || !completed || !called_once) {
        std::fprintf(
            stderr,
            "bounded resolver timeout failure first=%u second=%u addresses=%zu calls=%d completed=%d\n",
            static_cast<unsigned>(timed_out),
            static_cast<unsigned>(poisoned), addresses.size(),
            delayed->calls.load(), completed ? 1 : 0);
    }
    return completed && called_once && passed;
}
