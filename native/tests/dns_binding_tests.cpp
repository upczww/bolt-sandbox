#include "hook/network/dns_binding_table.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include <thread>
#include <vector>

namespace {

bolt::network::BindingKey MakeKey(
    const std::array<std::uint8_t, 16>& session,
    const std::uint32_t process_id,
    const char* domain,
    const std::array<std::uint8_t, 4>& address,
    const std::uint16_t port) {
    return bolt::network::BindingKey{
        session, process_id, domain, bolt::network::AddressFamily::kIpv4,
        address.data(), address.size(), port};
}

}  // namespace

bool RunDnsBindingTests() {
    std::unique_ptr<bolt::network::DnsBindingTable> table;
    if (bolt::network::DnsBindingTable::Create(2, table) !=
            bolt::network::BindingStatus::kSuccess ||
        table == nullptr) {
        return false;
    }

    const std::array<std::uint8_t, 16> session_one = {1};
    const std::array<std::uint8_t, 16> session_two = {2};
    const std::array<std::uint8_t, 4> address_one = {192, 0, 2, 10};
    const std::array<std::uint8_t, 4> address_two = {192, 0, 2, 11};
    const std::array<std::uint8_t, 4> address_three = {192, 0, 2, 12};
    const auto first = MakeKey(session_one, 10, "api.example", address_one, 443);
    if (table->Upsert(first, 100, 50) != bolt::network::BindingStatus::kSuccess ||
        !table->IsAuthorized(first, 149) || table->IsAuthorized(first, 150)) {
        return false;
    }
    if (!table->IsEndpointAuthorized(
            session_one, 10, bolt::network::AddressFamily::kIpv4,
            address_one.data(), address_one.size(), 443, 149) ||
        table->IsEndpointAuthorized(
            session_two, 10, bolt::network::AddressFamily::kIpv4,
            address_one.data(), address_one.size(), 443, 149)) {
        return false;
    }
    std::unique_ptr<bolt::network::DnsBindingTable> wildcard_table;
    bolt::network::DnsBindingTable::Create(1, wildcard_table);
    const auto wildcard_port = MakeKey(
        session_one, 10, "api.example", address_one, 0);
    if (wildcard_table->Upsert(wildcard_port, 100, 50) !=
            bolt::network::BindingStatus::kSuccess ||
        !wildcard_table->IsEndpointAuthorized(
            session_one, 10, bolt::network::AddressFamily::kIpv4,
            address_one.data(), address_one.size(), 8'443, 120)) {
        return false;
    }

    if (table->IsAuthorized(
            MakeKey(session_two, 10, "api.example", address_one, 443), 120) ||
        table->IsAuthorized(
            MakeKey(session_one, 11, "api.example", address_one, 443), 120) ||
        table->IsAuthorized(
            MakeKey(session_one, 10, "other.example", address_one, 443), 120) ||
        table->IsAuthorized(
            MakeKey(session_one, 10, "api.example", address_one, 80), 120) ||
        table->IsAuthorized(
            MakeKey(session_one, 10, "api.example", address_two, 443), 120)) {
        return false;
    }

    const auto second = MakeKey(session_one, 10, "cdn.example", address_two, 443);
    const auto third = MakeKey(session_one, 10, "third.example", address_three, 443);
    if (table->Upsert(first, 120, 100) != bolt::network::BindingStatus::kSuccess ||
        table->ActiveCount(120) != 1 ||
        table->Upsert(second, 120, 50) != bolt::network::BindingStatus::kSuccess ||
        table->Upsert(third, 121, 50) != bolt::network::BindingStatus::kFull ||
        table->Upsert(third, 220, 50) != bolt::network::BindingStatus::kSuccess ||
        !table->IsAuthorized(third, 220) || table->ActiveCount(220) != 1) {
        return false;
    }

    std::unique_ptr<bolt::network::DnsBindingTable> concurrent_table;
    if (bolt::network::DnsBindingTable::Create(1, concurrent_table) !=
        bolt::network::BindingStatus::kSuccess) {
        return false;
    }
    const auto concurrent_key =
        MakeKey(session_one, 20, "parallel.example", address_one, 443);
    if (concurrent_table->Upsert(concurrent_key, 0, 10'000) !=
        bolt::network::BindingStatus::kSuccess) {
        return false;
    }
    std::atomic<bool> failed = false;
    std::vector<std::thread> threads;
    threads.emplace_back([&] {
        for (std::uint64_t tick = 1; tick <= 1'000; ++tick) {
            if (concurrent_table->Upsert(concurrent_key, tick, 10'000) !=
                bolt::network::BindingStatus::kSuccess) {
                failed.store(true);
            }
        }
    });
    for (int index = 0; index < 3; ++index) {
        threads.emplace_back([&] {
            for (int attempt = 0; attempt < 2'000; ++attempt) {
                if (!concurrent_table->IsAuthorized(concurrent_key, 1'000)) {
                    failed.store(true);
                }
            }
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }

    std::array<std::uint8_t, 16> ipv6_address{};
    ipv6_address[0] = 0x20;
    ipv6_address[1] = 0x01;
    ipv6_address[2] = 0x0d;
    ipv6_address[3] = 0xb8;
    ipv6_address[15] = 1;
    const bolt::network::BindingKey ipv6_key{
        session_one, 10, "ipv6.example", bolt::network::AddressFamily::kIpv6,
        ipv6_address.data(), ipv6_address.size(), 443};
    if (table->Upsert(ipv6_key, 220, 50) !=
            bolt::network::BindingStatus::kSuccess ||
        !table->IsAuthorized(ipv6_key, 269)) {
        return false;
    }

    std::unique_ptr<bolt::network::DnsBindingTable> invalid;
    auto invalid_session = first;
    invalid_session.session_id = {};
    auto invalid_domain = first;
    invalid_domain.ascii_domain = "Bad.Example";
    auto invalid_address = first;
    invalid_address.address_length = 3;
    return !failed.load() &&
           bolt::network::DnsBindingTable::Create(0, invalid) ==
               bolt::network::BindingStatus::kInvalidArgument &&
           bolt::network::DnsBindingTable::Create(4'097, invalid) ==
               bolt::network::BindingStatus::kInvalidArgument &&
           table->Upsert(first, 1, 0) ==
               bolt::network::BindingStatus::kInvalidArgument &&
           table->Upsert(invalid_session, 1, 1) ==
               bolt::network::BindingStatus::kInvalidArgument &&
           table->Upsert(invalid_domain, 1, 1) ==
               bolt::network::BindingStatus::kInvalidArgument &&
           table->Upsert(invalid_address, 1, 1) ==
               bolt::network::BindingStatus::kInvalidArgument &&
           table->Upsert(first, UINT64_MAX, 1) ==
               bolt::network::BindingStatus::kInvalidArgument;
}
