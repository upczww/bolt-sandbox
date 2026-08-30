#include "hook/network/dns_proxy_process.h"
#include "hook/network/dns_proxy_client_channel.h"
#include "hook/network/dns_proxy_handle_transport.h"
#include "tests/policy_fixture.h"

#include <filesystem>
#include <memory>

bool RunDnsProxyProcessTests() {
#if defined(_WIN64)
    std::wstring executable(32'768, L'\0');
    const DWORD length = GetModuleFileNameW(
        nullptr, executable.data(), static_cast<DWORD>(executable.size()));
    if (length == 0 || length == executable.size()) {
        return false;
    }
    executable.resize(length);
    const auto proxy = std::filesystem::path(executable).parent_path() /
                       L"bolt-sandbox-dns-proxy.exe";
    const bolt::tests::NetworkAllowListRules rules{
        {{false, "localhost"}}, {}, {{11'949, 11'949}}};
    const auto policy = bolt::tests::SealPolicy(
        {}, bolt::tests::ChildProcessPolicyKind::kInherit,
        bolt::tests::NetworkPolicyKind::kAllowList, rules);
    bolt::protocol::DnsProxySession session{};
    session.nonce[0] = 1;
    session.authentication_key[0] = 2;
    std::unique_ptr<bolt::network::DnsProxyProcess> process;
    if (bolt::network::DnsProxyProcess::Start(
            proxy, policy.data(), policy.size(), session, 1'024, 8, process) !=
            bolt::network::DnsProxyProcessStatus::kSuccess ||
        process == nullptr) {
        return false;
    }
    std::unique_ptr<bolt::network::DnsProxyHandleTransport> transport;
    if (bolt::network::DnsProxyHandleTransport::Create(
            process->response_read_handle(), process->request_write_handle(),
            1'024, transport) != bolt::network::HandleTransportStatus::kSuccess) {
        return false;
    }
    std::unique_ptr<bolt::network::DnsBindingTable> bindings;
    bolt::network::DnsBindingTable::Create(8, bindings);
    std::unique_ptr<bolt::network::DnsProxyClientChannel> channel;
    const std::array<std::uint8_t, 16> session_id = {3};
    if (bolt::network::DnsProxyClientChannel::Create(
            session, session_id, 99, std::move(transport), *bindings, channel) !=
            bolt::network::DnsProxyChannelStatus::kSuccess ||
        channel->Resolve("localhost", 11'949, 1'000) !=
            bolt::network::DnsProxyChannelStatus::kSuccess) {
        return false;
    }
    channel.reset();
    process->CloseClientHandles();
    return process->Wait(5'000) == bolt::network::DnsProxyProcessStatus::kSuccess;
#else
    return true;
#endif
}
