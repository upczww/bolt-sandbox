#include "hook/network/socket_target_table.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <thread>
#include <vector>

bool RunSocketTargetTableTests() {
    std::unique_ptr<bolt::network::SocketTargetTable> table;
    if (bolt::network::SocketTargetTable::Create(2, table) !=
            bolt::network::SocketTargetStatus::kSuccess ||
        table == nullptr) {
        return false;
    }
    bolt::protocol::NetworkEndpoint first{};
    first.family = bolt::protocol::NetworkAddressFamily::kIpv4;
    first.address[0] = 192;
    first.address[1] = 0;
    first.address[2] = 2;
    first.address[3] = 10;
    first.port = 443;
    bolt::protocol::NetworkEndpoint second{};
    second.family = bolt::protocol::NetworkAddressFamily::kIpv6;
    second.address[0] = 0x20;
    second.address[1] = 0x01;
    second.address[15] = 1;
    second.port = 8'443;
    if (table->Upsert(10, first) !=
            bolt::network::SocketTargetStatus::kSuccess ||
        table->Upsert(11, second) !=
            bolt::network::SocketTargetStatus::kSuccess) {
        return false;
    }
    bolt::protocol::NetworkEndpoint found{};
    if (!table->Lookup(10, found) || found.family != first.family ||
        found.address != first.address || found.port != first.port ||
        !table->Lookup(11, found) || found.family != second.family ||
        found.address != second.address || found.port != second.port) {
        return false;
    }
    first.port = 444;
    if (table->Upsert(10, first) !=
            bolt::network::SocketTargetStatus::kSuccess ||
        !table->Lookup(10, found) || found.port != 444 ||
        table->Upsert(12, first) != bolt::network::SocketTargetStatus::kFull ||
        !table->Remove(10) || table->Lookup(10, found) ||
        table->Remove(10) ||
        table->Upsert(12, first) !=
            bolt::network::SocketTargetStatus::kSuccess) {
        return false;
    }

    std::unique_ptr<bolt::network::SocketTargetTable> concurrent;
    if (bolt::network::SocketTargetTable::Create(1, concurrent) !=
        bolt::network::SocketTargetStatus::kSuccess) {
        return false;
    }
    std::atomic<bool> failed = false;
    std::vector<std::thread> threads;
    threads.emplace_back([&] {
        for (std::uint16_t port = 1; port < 2'000; ++port) {
            auto endpoint = first;
            endpoint.port = port;
            if (concurrent->Upsert(20, endpoint) !=
                bolt::network::SocketTargetStatus::kSuccess) {
                failed.store(true);
            }
        }
    });
    for (int index = 0; index < 3; ++index) {
        threads.emplace_back([&] {
            for (int attempt = 0; attempt < 2'000; ++attempt) {
                bolt::protocol::NetworkEndpoint endpoint{};
                if (concurrent->Lookup(20, endpoint) && endpoint.port == 0) {
                    failed.store(true);
                }
            }
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }
    std::unique_ptr<bolt::network::SocketTargetTable> invalid;
    return !failed.load() &&
        bolt::network::SocketTargetTable::Create(0, invalid) ==
            bolt::network::SocketTargetStatus::kInvalidArgument &&
        table->Upsert(0, first) ==
            bolt::network::SocketTargetStatus::kInvalidArgument;
}
