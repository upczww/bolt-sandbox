#include "hook/network/network_hooks.h"

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <windns.h>
#include <ws2tcpip.h>

#include "hook/event_sink.h"
#include "hook/network/network_policy.h"
#include "hook/network/dns_binding_table.h"
#include "hook/network/dns_proxy_client_channel.h"
#include "hook/network/dns_proxy_handle_transport.h"
#include "hook/network/high_level_hooks.h"
#include "hook/network/socket_target_table.h"
#include "hook/network/tcp_proxy_client.h"
#include "protocol/runtime_payload.h"
#include "DetouredScope.h"

#include <cstring>
#include <algorithm>
#include <array>
#include <limits>
#include <memory>
#include <utility>

#include <detours.h>

namespace bolt::network {
namespace {

using ConnectFunction = int(WSAAPI*)(SOCKET, const sockaddr*, int);
using WsaConnectFunction = int(WSAAPI*)(
    SOCKET, const sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
using WsaIoctlFunction = decltype(&WSAIoctl);
using GetAddrInfoAFunction = decltype(&getaddrinfo);
using GetAddrInfoWFunction = decltype(&GetAddrInfoW);
using FreeAddrInfoAFunction = decltype(&freeaddrinfo);
using FreeAddrInfoWFunction = decltype(&FreeAddrInfoW);
using GetAddrInfoExWFunction = decltype(&GetAddrInfoExW);
using FreeAddrInfoExWFunction = decltype(&FreeAddrInfoExW);
#pragma warning(push)
#pragma warning(disable : 4996)
using GetAddrInfoExAFunction = decltype(&GetAddrInfoExA);
using FreeAddrInfoExAFunction = decltype(&FreeAddrInfoExA);
#pragma warning(pop)
using DnsQueryAFunction = decltype(&DnsQuery_A);
using DnsQueryUtf8Function = decltype(&DnsQuery_UTF8);
using DnsQueryWFunction = decltype(&DnsQuery_W);
using DnsQueryExFunction = decltype(&DnsQueryEx);
using DnsFreeFunction = decltype(&DnsFree);
using SendToFunction = decltype(&sendto);
using WsaSendToFunction = decltype(&WSASendTo);
using WsaSendFunction = decltype(&WSASend);
using GetPeerNameFunction = decltype(&getpeername);
using CloseSocketFunction = decltype(&closesocket);

std::unique_ptr<NetworkPolicy> g_policy;
std::unique_ptr<DnsBindingTable> g_dns_bindings;
std::unique_ptr<DnsProxyClientChannel> g_dns_channel;
std::unique_ptr<SocketTargetTable> g_socket_targets;
decltype(&socket) g_socket = socket;
decltype(&WSASocketW) g_wsa_socket_w = WSASocketW;
using WsaSocketAFunction = SOCKET(WSAAPI*)(
    int, int, int, LPWSAPROTOCOL_INFOA, GROUP, DWORD);
WsaSocketAFunction g_wsa_socket_a = nullptr;
std::array<std::uint8_t, 16> g_dns_session_id{};
protocol::DnsProxySession g_tcp_proxy_session{};
std::uint16_t g_tcp_proxy_port = 0;
std::uint16_t g_tcp_proxy_ipv6_port = 0;
std::uint64_t g_tcp_proxy_next_sequence = 1;
std::uint64_t g_tcp_proxy_ipv6_next_sequence = 1;
bool g_tcp_proxy_closed = false;
bool g_tcp_proxy_ipv6_closed = false;
SRWLOCK g_tcp_proxy_lock = SRWLOCK_INIT;
SRWLOCK g_high_level_dns_lock = SRWLOCK_INIT;

struct HighLevelDnsEntry {
    bool occupied = false;
    char domain[protocol::kDnsProxyMaximumDomainLength + 1U]{};
    std::uint64_t expires_at = 0;
};

constexpr std::size_t kHighLevelDnsCapacity = 64;
std::array<HighLevelDnsEntry, kHighLevelDnsCapacity> g_high_level_dns{};

class TcpProxyLock final {
  public:
    TcpProxyLock() noexcept { AcquireSRWLockExclusive(&g_tcp_proxy_lock); }
    ~TcpProxyLock() noexcept { ReleaseSRWLockExclusive(&g_tcp_proxy_lock); }
    TcpProxyLock(const TcpProxyLock&) = delete;
    TcpProxyLock& operator=(const TcpProxyLock&) = delete;
};

SOCKET WSAAPI DetouredSocket(
    const int address_family,
    const int type,
    const int protocol) noexcept {
    DetouredScope scope;
    return g_socket(address_family, type, protocol);
}

SOCKET WSAAPI DetouredWsaSocketW(
    const int address_family,
    const int type,
    const int protocol,
    const LPWSAPROTOCOL_INFOW protocol_information,
    const GROUP group,
    const DWORD flags) noexcept {
    DetouredScope scope;
    return g_wsa_socket_w(
        address_family, type, protocol, protocol_information, group, flags);
}

SOCKET WSAAPI DetouredWsaSocketA(
    const int address_family,
    const int type,
    const int protocol,
    const LPWSAPROTOCOL_INFOA protocol_information,
    const GROUP group,
    const DWORD flags) noexcept {
    DetouredScope scope;
    return g_wsa_socket_a(
        address_family, type, protocol, protocol_information, group, flags);
}

bool AttachSocketCreationHooks() noexcept {
    return DetourAttach(
               reinterpret_cast<PVOID*>(&g_socket),
               reinterpret_cast<PVOID>(DetouredSocket)) == NO_ERROR &&
           DetourAttach(
               reinterpret_cast<PVOID*>(&g_wsa_socket_w),
               reinterpret_cast<PVOID>(DetouredWsaSocketW)) == NO_ERROR &&
           DetourAttach(
               reinterpret_cast<PVOID*>(&g_wsa_socket_a),
               reinterpret_cast<PVOID>(DetouredWsaSocketA)) == NO_ERROR;
}

class HighLevelDnsSharedLock final {
  public:
    HighLevelDnsSharedLock() noexcept {
        AcquireSRWLockShared(&g_high_level_dns_lock);
    }
    ~HighLevelDnsSharedLock() noexcept {
        ReleaseSRWLockShared(&g_high_level_dns_lock);
    }
    HighLevelDnsSharedLock(const HighLevelDnsSharedLock&) = delete;
    HighLevelDnsSharedLock& operator=(const HighLevelDnsSharedLock&) = delete;
};

class HighLevelDnsExclusiveLock final {
  public:
    HighLevelDnsExclusiveLock() noexcept {
        AcquireSRWLockExclusive(&g_high_level_dns_lock);
    }
    ~HighLevelDnsExclusiveLock() noexcept {
        ReleaseSRWLockExclusive(&g_high_level_dns_lock);
    }
    HighLevelDnsExclusiveLock(const HighLevelDnsExclusiveLock&) = delete;
    HighLevelDnsExclusiveLock& operator=(const HighLevelDnsExclusiveLock&) = delete;
};

HANDLE HandleFromWire(const std::uint64_t value) noexcept {
    return reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(value));
}
ConnectFunction g_connect = connect;
WsaConnectFunction g_wsa_connect = WSAConnect;
WsaIoctlFunction g_wsa_ioctl = WSAIoctl;
GetAddrInfoAFunction g_get_addr_info_a = getaddrinfo;
GetAddrInfoWFunction g_get_addr_info_w = GetAddrInfoW;
FreeAddrInfoAFunction g_free_addr_info_a = freeaddrinfo;
FreeAddrInfoWFunction g_free_addr_info_w = FreeAddrInfoW;
GetAddrInfoExWFunction g_get_addr_info_ex_w = GetAddrInfoExW;
FreeAddrInfoExWFunction g_free_addr_info_ex_w = FreeAddrInfoExW;
#pragma warning(push)
#pragma warning(disable : 4996)
GetAddrInfoExAFunction g_get_addr_info_ex_a = GetAddrInfoExA;
FreeAddrInfoExAFunction g_free_addr_info_ex_a = FreeAddrInfoExA;
#pragma warning(pop)
#if defined(_M_IX86)
decltype(&WSAStartup) g_wsa_startup = WSAStartup;
SRWLOCK g_winsock_entrypoint_lock = SRWLOCK_INIT;
bool g_winsock_entrypoint_attempted = false;
bool g_winsock_entrypoint_succeeded = false;
#endif
DnsQueryAFunction g_dns_query_a = DnsQuery_A;
DnsQueryUtf8Function g_dns_query_utf8 = DnsQuery_UTF8;
DnsQueryWFunction g_dns_query_w = DnsQuery_W;
DnsQueryExFunction g_dns_query_ex = DnsQueryEx;
DnsFreeFunction g_dns_free = DnsFree;
SendToFunction g_send_to = sendto;
WsaSendToFunction g_wsa_send_to = WSASendTo;
WsaSendFunction g_wsa_send = WSASend;
GetPeerNameFunction g_get_peer_name = getpeername;
CloseSocketFunction g_close_socket = closesocket;
constexpr GUID kConnectExGuid = WSAID_CONNECTEX;
constexpr GUID kWsaSendMsgGuid = WSAID_WSASENDMSG;
constexpr GUID kAcceptExGuid = WSAID_ACCEPTEX;
constexpr GUID kDisconnectExGuid = WSAID_DISCONNECTEX;
constexpr GUID kGetAcceptExSockaddrsGuid = WSAID_GETACCEPTEXSOCKADDRS;
constexpr GUID kTransmitFileGuid = WSAID_TRANSMITFILE;
constexpr std::uint64_t kSyntheticAddressInfoMagic = 0x424c544144445231ULL;

struct SyntheticAddressInfoHeader {
    std::uint64_t magic = kSyntheticAddressInfoMagic;
    std::uint32_t kind = 0;
    std::uint32_t count = 0;
};

BOOL PASCAL DetouredConnectEx(
    SOCKET socket,
    const sockaddr* address,
    int address_length,
    PVOID send_buffer,
    DWORD send_length,
    LPDWORD bytes_sent,
    LPOVERLAPPED overlapped) noexcept;

INT WSAAPI DetouredWsaSendMsg(
    SOCKET socket,
    LPWSAMSG message,
    DWORD flags,
    LPDWORD bytes_sent,
    LPWSAOVERLAPPED overlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE completion_routine) noexcept;

int WSAAPI DetouredSendTo(
    SOCKET socket,
    const char* buffer,
    int length,
    int flags,
    const sockaddr* destination,
    int destination_length) noexcept;

int WSAAPI DetouredWsaSendTo(
    SOCKET socket,
    LPWSABUF buffers,
    DWORD buffer_count,
    LPDWORD bytes_sent,
    DWORD flags,
    const sockaddr* destination,
    int destination_length,
    LPWSAOVERLAPPED overlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE completion_routine) noexcept;

int WSAAPI DetouredGetPeerName(
    SOCKET socket,
    sockaddr* address,
    int* address_length) noexcept;

int WSAAPI DetouredCloseSocket(SOCKET socket) noexcept;

bool NetworkIsDenied() noexcept {
    const auto* policy = g_policy.get();
    return policy == nullptr || policy->DecideConnect() == Decision::kDeny;
}


bool CopyAsciiDomain(
    const char* domain,
    std::array<char, protocol::kMaximumEventDomainBytes + 1U>& output) noexcept {
    if (domain == nullptr) {
        return false;
    }
    __try {
        std::size_t length = 0;
        while (length <= protocol::kMaximumEventDomainBytes &&
               domain[length] != '\0') {
            const auto byte = static_cast<unsigned char>(domain[length]);
            if (byte < 0x21U || byte > 0x7eU) {
                return false;
            }
            output[length] =
                byte >= 'A' && byte <= 'Z'
                    ? static_cast<char>(byte + ('a' - 'A'))
                    : static_cast<char>(byte);
            ++length;
        }
        if (length == 0 || length > protocol::kMaximumEventDomainBytes) {
            return false;
        }
        output[length] = '\0';
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool ParsePort(const char* service, std::uint16_t& port) noexcept {
    port = 0;
    if (service == nullptr) {
        return true;
    }
    __try {
        unsigned int value = 0;
        std::size_t length = 0;
        while (length < 6 && service[length] != '\0') {
            const unsigned char byte = static_cast<unsigned char>(service[length]);
            if (byte < '0' || byte > '9') {
                return false;
            }
            value = value * 10U + static_cast<unsigned int>(byte - '0');
            ++length;
        }
        if (length == 0 || length >= 6 || value == 0 || value > 65'535U) {
            return false;
        }
        port = static_cast<std::uint16_t>(value);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool ParsePort(const wchar_t* service, std::uint16_t& port) noexcept {
    port = 0;
    if (service == nullptr) {
        return true;
    }
    __try {
        unsigned int value = 0;
        std::size_t length = 0;
        while (length < 6 && service[length] != L'\0') {
            const wchar_t byte = service[length];
            if (byte < L'0' || byte > L'9') {
                return false;
            }
            value = value * 10U + static_cast<unsigned int>(byte - L'0');
            ++length;
        }
        if (length == 0 || length >= 6 || value == 0 || value > 65'535U) {
            return false;
        }
        port = static_cast<std::uint16_t>(value);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

#pragma warning(push)
#pragma warning(disable : 4996)
template <typename Info, typename Hints>
INT BuildAddressInfoResults(
    const std::vector<protocol::DnsProxyAddress>& addresses,
    const std::uint16_t port,
    const Hints* hints,
    Info** results,
    const std::uint32_t kind) noexcept {
    if (addresses.empty() || results == nullptr) {
        return WSAEFAULT;
    }
    int socket_type = 0;
    int protocol_value = 0;
    int flags = 0;
    __try {
        if (hints != nullptr) {
            socket_type = hints->ai_socktype;
            protocol_value = hints->ai_protocol;
            flags = hints->ai_flags;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return WSAEFAULT;
    }
    const std::size_t total = sizeof(SyntheticAddressInfoHeader) +
                              sizeof(Info) * addresses.size() +
                              sizeof(sockaddr_storage) * addresses.size();
    auto* allocation = static_cast<std::uint8_t*>(
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, total));
    if (allocation == nullptr) {
        return WSA_NOT_ENOUGH_MEMORY;
    }
    auto* header = reinterpret_cast<SyntheticAddressInfoHeader*>(allocation);
    header->magic = kSyntheticAddressInfoMagic;
    header->kind = kind;
    header->count = static_cast<std::uint32_t>(addresses.size());
    auto* nodes = reinterpret_cast<Info*>(allocation + sizeof(*header));
    auto* sockets = reinterpret_cast<sockaddr_storage*>(nodes + addresses.size());
    for (std::size_t index = 0; index < addresses.size(); ++index) {
        nodes[index].ai_flags = flags;
        nodes[index].ai_socktype = socket_type;
        nodes[index].ai_protocol = protocol_value;
        nodes[index].ai_next = index + 1 < addresses.size() ? &nodes[index + 1] : nullptr;
        nodes[index].ai_addr = reinterpret_cast<sockaddr*>(&sockets[index]);
        if (addresses[index].family == protocol::DnsProxyAddressFamily::kIpv4) {
            auto* ipv4 = reinterpret_cast<sockaddr_in*>(&sockets[index]);
            ipv4->sin_family = AF_INET;
            ipv4->sin_port = htons(port);
            std::memcpy(&ipv4->sin_addr, addresses[index].address.data(), 4);
            nodes[index].ai_family = AF_INET;
            nodes[index].ai_addrlen = sizeof(sockaddr_in);
        } else {
            auto* ipv6 = reinterpret_cast<sockaddr_in6*>(&sockets[index]);
            ipv6->sin6_family = AF_INET6;
            ipv6->sin6_port = htons(port);
            std::memcpy(&ipv6->sin6_addr, addresses[index].address.data(), 16);
            nodes[index].ai_family = AF_INET6;
            nodes[index].ai_addrlen = sizeof(sockaddr_in6);
        }
    }
    __try {
        *results = nodes;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        HeapFree(GetProcessHeap(), 0, allocation);
        return WSAEFAULT;
    }
    return 0;
}
#pragma warning(pop)

DNS_STATUS BuildDnsRecords(
    const std::vector<protocol::DnsProxyAddress>& addresses,
    const WORD query_type,
    PDNS_RECORD* results) noexcept {
    if (results == nullptr ||
        (query_type != DNS_TYPE_A && query_type != DNS_TYPE_AAAA)) {
        return ERROR_ACCESS_DENIED;
    }
    std::size_t count = 0;
    for (const auto& address : addresses) {
        if ((query_type == DNS_TYPE_A &&
             address.family == protocol::DnsProxyAddressFamily::kIpv4) ||
            (query_type == DNS_TYPE_AAAA &&
             address.family == protocol::DnsProxyAddressFamily::kIpv6)) {
            ++count;
        }
    }
    if (count == 0) {
        __try {
            *results = nullptr;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return ERROR_INVALID_ADDRESS;
        }
        return DNS_INFO_NO_RECORDS;
    }
    const std::size_t total =
        sizeof(SyntheticAddressInfoHeader) + sizeof(DNS_RECORD) * count;
    auto* allocation = static_cast<std::uint8_t*>(
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, total));
    if (allocation == nullptr) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    auto* header = reinterpret_cast<SyntheticAddressInfoHeader*>(allocation);
    header->magic = kSyntheticAddressInfoMagic;
    header->kind = 5;
    header->count = static_cast<std::uint32_t>(count);
    auto* records = reinterpret_cast<DNS_RECORD*>(allocation + sizeof(*header));
    std::size_t output_index = 0;
    for (const auto& address : addresses) {
        const bool matches =
            (query_type == DNS_TYPE_A &&
             address.family == protocol::DnsProxyAddressFamily::kIpv4) ||
            (query_type == DNS_TYPE_AAAA &&
             address.family == protocol::DnsProxyAddressFamily::kIpv6);
        if (!matches) {
            continue;
        }
        DNS_RECORD& record = records[output_index];
        record.pNext = output_index + 1 < count ? &records[output_index + 1] : nullptr;
        record.wType = query_type;
        record.dwTtl = address.ttl_seconds;
        if (query_type == DNS_TYPE_A) {
            record.wDataLength = sizeof(DNS_A_DATA);
            std::memcpy(&record.Data.A.IpAddress, address.address.data(), 4);
        } else {
            record.wDataLength = sizeof(DNS_AAAA_DATA);
            std::copy_n(
                address.address.begin(), 16,
                record.Data.AAAA.Ip6Address.IP6Byte);
        }
        ++output_index;
    }
    __try {
        *results = records;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        HeapFree(GetProcessHeap(), 0, allocation);
        return ERROR_INVALID_ADDRESS;
    }
    return ERROR_SUCCESS;
}

bool TryFreeSynthetic(void* value) noexcept {
    if (value == nullptr) {
        return true;
    }
    __try {
        auto* header = reinterpret_cast<SyntheticAddressInfoHeader*>(value) - 1;
        if (header->magic != kSyntheticAddressInfoMagic ||
            header->count == 0 || header->count > protocol::kDnsProxyMaximumAddressRecords) {
            return false;
        }
        return HeapFree(GetProcessHeap(), 0, header) != FALSE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

#pragma warning(push)
#pragma warning(disable : 4996)
template <typename Hints>
bool ReadQueryFamily(
    const Hints* hints,
    protocol::DnsProxyQueryFamily& family) noexcept {
    family = protocol::DnsProxyQueryFamily::kAny;
    if (hints == nullptr) {
        return true;
    }
    __try {
        if (hints->ai_family == AF_UNSPEC) {
            return true;
        }
        if (hints->ai_family == AF_INET) {
            family = protocol::DnsProxyQueryFamily::kIpv4;
            return true;
        }
        if (hints->ai_family == AF_INET6) {
            family = protocol::DnsProxyQueryFamily::kIpv6;
            return true;
        }
        return false;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}
#pragma warning(pop)

bool CopyAsciiDomain(
    const wchar_t* domain,
    std::array<char, protocol::kMaximumEventDomainBytes + 1U>& output) noexcept {
    if (domain == nullptr) {
        return false;
    }
    __try {
        std::size_t length = 0;
        while (length <= protocol::kMaximumEventDomainBytes &&
               domain[length] != L'\0') {
            const wchar_t code_unit = domain[length];
            if (code_unit < 0x21 || code_unit > 0x7e) {
                return false;
            }
            output[length] =
                code_unit >= L'A' && code_unit <= L'Z'
                    ? static_cast<char>(code_unit + (L'a' - L'A'))
                    : static_cast<char>(code_unit);
            ++length;
        }
        if (length == 0 || length > protocol::kMaximumEventDomainBytes) {
            return false;
        }
        output[length] = '\0';
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool TryParseNumericAddress(
    const char* const host,
    AddressFamily& family,
    std::array<std::uint8_t, 16>& address,
    std::size_t& address_length) noexcept {
    address.fill(0);
    address_length = 0;
    if (host == nullptr) {
        return false;
    }
    __try {
        IN_ADDR ipv4{};
        if (InetPtonA(AF_INET, host, &ipv4) == 1) {
            family = AddressFamily::kIpv4;
            address_length = 4;
            std::memcpy(address.data(), &ipv4, address_length);
            return true;
        }
        IN6_ADDR ipv6{};
        if (InetPtonA(AF_INET6, host, &ipv6) == 1) {
            family = AddressFamily::kIpv6;
            address_length = 16;
            std::memcpy(address.data(), &ipv6, address_length);
            return true;
        }
        return false;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool TryParseNumericAddress(
    const wchar_t* const host,
    AddressFamily& family,
    std::array<std::uint8_t, 16>& address,
    std::size_t& address_length) noexcept {
    address.fill(0);
    address_length = 0;
    if (host == nullptr) {
        return false;
    }
    __try {
        IN_ADDR ipv4{};
        if (InetPtonW(AF_INET, host, &ipv4) == 1) {
            family = AddressFamily::kIpv4;
            address_length = 4;
            std::memcpy(address.data(), &ipv4, address_length);
            return true;
        }
        IN6_ADDR ipv6{};
        if (InetPtonW(AF_INET6, host, &ipv6) == 1) {
            family = AddressFamily::kIpv6;
            address_length = 16;
            std::memcpy(address.data(), &ipv6, address_length);
            return true;
        }
        return false;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

template <typename Result>
void ClearAddressResults(Result** results) noexcept {
    if (results == nullptr) {
        return;
    }
    __try {
        *results = nullptr;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

void ClearLookupHandle(const LPHANDLE handle) noexcept {
    if (handle == nullptr) {
        return;
    }
    __try {
        *handle = nullptr;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

PCWSTR ReadDnsQueryName(const PDNS_QUERY_REQUEST request) noexcept {
    if (request == nullptr) {
        return nullptr;
    }
    __try {
        return request->QueryName;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

void ClearDnsQueryOutputs(
    const PDNS_QUERY_RESULT results,
    const PDNS_QUERY_CANCEL cancel) noexcept {
    __try {
        if (results != nullptr) {
            results->QueryStatus = ERROR_ACCESS_DENIED;
            results->QueryOptions = 0;
            results->pQueryRecords = nullptr;
            results->Reserved = nullptr;
        }
        if (cancel != nullptr) {
            SecureZeroMemory(cancel, sizeof(*cancel));
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

template <typename Character>
void ReportDeniedResolution(const Character* domain) noexcept {
    std::array<char, protocol::kMaximumEventDomainBytes + 1U> ascii_domain{};
    if (CopyAsciiDomain(domain, ascii_domain)) {
        hook::TryReportDomainNetworkViolation(
            protocol::NetworkOperation::kResolve, ascii_domain.data());
    }
}


bool IsExtensionFunctionRequest(
    const DWORD control_code,
    const LPVOID input,
    const DWORD input_length,
    const GUID& expected) noexcept {
    if (control_code != SIO_GET_EXTENSION_FUNCTION_POINTER || input == nullptr ||
        input_length < sizeof(GUID)) {
        return false;
    }
    __try {
        return std::memcmp(input, &expected, sizeof(GUID)) == 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool IsConnectExRequest(
    const DWORD control_code,
    const LPVOID input,
    const DWORD input_length) noexcept {
    return IsExtensionFunctionRequest(
        control_code, input, input_length, kConnectExGuid);
}

bool IsWsaSendMsgRequest(
    const DWORD control_code,
    const LPVOID input,
    const DWORD input_length) noexcept {
    return IsExtensionFunctionRequest(
        control_code, input, input_length, kWsaSendMsgGuid);
}

bool IsSafeNonEgressExtensionRequest(
    const DWORD control_code,
    const LPVOID input,
    const DWORD input_length) noexcept {
    return IsExtensionFunctionRequest(
               control_code, input, input_length, kAcceptExGuid) ||
           IsExtensionFunctionRequest(
               control_code, input, input_length, kDisconnectExGuid) ||
           IsExtensionFunctionRequest(
               control_code, input, input_length,
               kGetAcceptExSockaddrsGuid) ||
           IsExtensionFunctionRequest(
               control_code, input, input_length, kTransmitFileGuid);
}

bool IsExtensionFunctionControl(const DWORD control_code) noexcept {
    return control_code == SIO_GET_EXTENSION_FUNCTION_POINTER ||
           control_code == SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER;
}

bool ClearBytesReturned(const LPDWORD bytes_returned) noexcept {
    if (bytes_returned == nullptr) {
        return false;
    }
    __try {
        *bytes_returned = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool WriteConnectExResult(
    const LPVOID output,
    const DWORD output_length,
    const LPDWORD bytes_returned) noexcept {
    if (output == nullptr || output_length < sizeof(LPFN_CONNECTEX) ||
        bytes_returned == nullptr) {
        return false;
    }
    __try {
        *static_cast<LPFN_CONNECTEX*>(output) = DetouredConnectEx;
        *bytes_returned = sizeof(LPFN_CONNECTEX);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool WriteWsaSendMsgResult(
    const LPVOID output,
    const DWORD output_length,
    const LPDWORD bytes_returned) noexcept {
    if (output == nullptr || output_length < sizeof(LPFN_WSASENDMSG) ||
        bytes_returned == nullptr) {
        return false;
    }
    __try {
        *static_cast<LPFN_WSASENDMSG*>(output) = DetouredWsaSendMsg;
        *bytes_returned = sizeof(LPFN_WSASENDMSG);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool ReadEndpoint(
    const sockaddr* address,
    const int address_length,
    protocol::NetworkEndpoint& endpoint) noexcept {
    if (address == nullptr ||
        address_length < static_cast<int>(sizeof(address->sa_family))) {
        return false;
    }
    __try {
        if (address->sa_family == AF_INET &&
            address_length >= static_cast<int>(sizeof(sockaddr_in))) {
            const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(address);
            endpoint.family = protocol::NetworkAddressFamily::kIpv4;
            std::memcpy(endpoint.address.data(), &ipv4->sin_addr, 4);
            endpoint.port = ntohs(ipv4->sin_port);
            return true;
        }
        if (address->sa_family == AF_INET6 &&
            address_length >= static_cast<int>(sizeof(sockaddr_in6))) {
            const auto* ipv6 = reinterpret_cast<const sockaddr_in6*>(address);
            if (ipv6->sin6_scope_id != 0) {
                return false;
            }
            endpoint.family = protocol::NetworkAddressFamily::kIpv6;
            std::memcpy(endpoint.address.data(), &ipv6->sin6_addr, 16);
            endpoint.port = ntohs(ipv6->sin6_port);
            return true;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return false;
}

bool RegisterHighLevelDnsDomain(
    const char* const domain,
    const std::vector<protocol::DnsProxyAddress>& addresses,
    const std::uint64_t now) noexcept {
    if (domain == nullptr || addresses.empty()) {
        return false;
    }
    std::uint32_t minimum_ttl = addresses.front().ttl_seconds;
    for (const auto& address : addresses) {
        minimum_ttl = std::min(minimum_ttl, address.ttl_seconds);
    }
    const std::size_t domain_length = std::strlen(domain);
    if (minimum_ttl == 0 || domain_length == 0 ||
        domain_length > protocol::kDnsProxyMaximumDomainLength) {
        return false;
    }
    const std::uint64_t expires_at =
        now + static_cast<std::uint64_t>(minimum_ttl) * 1'000U;
    HighLevelDnsExclusiveLock guard;
    HighLevelDnsEntry* available = nullptr;
    for (auto& entry : g_high_level_dns) {
        if (entry.occupied && entry.expires_at <= now) {
            entry = {};
        }
        if (entry.occupied && std::strcmp(entry.domain, domain) == 0) {
            entry.expires_at = expires_at;
            return true;
        }
        if (!entry.occupied && available == nullptr) {
            available = &entry;
        }
    }
    if (available == nullptr) {
        return false;
    }
    available->occupied = true;
    std::copy_n(domain, domain_length + 1U, available->domain);
    available->expires_at = expires_at;
    return true;
}

template <typename Character>
bool HasHighLevelDnsDomain(const Character* domain) noexcept {
    std::array<char, protocol::kMaximumEventDomainBytes + 1U> ascii_domain{};
    if (!CopyAsciiDomain(domain, ascii_domain)) {
        return false;
    }
    const std::uint64_t now = GetTickCount64();
    HighLevelDnsSharedLock guard;
    for (const auto& entry : g_high_level_dns) {
        if (entry.occupied && entry.expires_at > now &&
            std::strcmp(entry.domain, ascii_domain.data()) == 0) {
            return true;
        }
    }
    return false;
}

bool WriteTransferredBytes(
    const LPDWORD output,
    const DWORD value) noexcept {
    if (output == nullptr) {
        return true;
    }
    __try {
        *output = value;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool WriteEndpoint(
    const protocol::NetworkEndpoint& endpoint,
    sockaddr* const address,
    int* const address_length) noexcept {
    if (address == nullptr || address_length == nullptr) {
        WSASetLastError(WSAEFAULT);
        return false;
    }
    __try {
        const int required =
            endpoint.family == protocol::NetworkAddressFamily::kIpv4
                ? static_cast<int>(sizeof(sockaddr_in))
                : static_cast<int>(sizeof(sockaddr_in6));
        if (*address_length < required) {
            *address_length = required;
            WSASetLastError(WSAEFAULT);
            return false;
        }
        if (endpoint.family == protocol::NetworkAddressFamily::kIpv4) {
            sockaddr_in value{};
            value.sin_family = AF_INET;
            value.sin_port = htons(endpoint.port);
            std::memcpy(&value.sin_addr, endpoint.address.data(), 4);
            std::memcpy(address, &value, sizeof(value));
        } else {
            sockaddr_in6 value{};
            value.sin6_family = AF_INET6;
            value.sin6_port = htons(endpoint.port);
            std::memcpy(&value.sin6_addr, endpoint.address.data(), 16);
            std::memcpy(address, &value, sizeof(value));
        }
        *address_length = required;
        WSASetLastError(0);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        WSASetLastError(WSAEFAULT);
        return false;
    }
}


bool DenyConnect(
    const sockaddr* address,
    const int address_length) noexcept {
    const auto* policy = g_policy.get();
    if (policy != nullptr && policy->mode() == Mode::kUnrestricted) {
        return false;
    }
    protocol::NetworkEndpoint endpoint{};
    const bool endpoint_valid = ReadEndpoint(address, address_length, endpoint);
    if (endpoint_valid) {
        hook::TryReportNetworkViolation(
            protocol::NetworkOperation::kConnect, endpoint);
    }
    WSASetLastError(WSAEACCES);
    return true;
}

bool TryProxyConnect(
    const SOCKET socket,
    const sockaddr* const address,
    const int address_length,
    int& result) noexcept {
    result = SOCKET_ERROR;
    const auto* policy = g_policy.get();
    if (policy == nullptr || policy->mode() != Mode::kAllowList) {
        return false;
    }
    protocol::NetworkEndpoint endpoint{};
    if (!ReadEndpoint(address, address_length, endpoint) ||
        policy->DecidePort(endpoint.port) != Decision::kAllow) {
        return false;
    }
    const AddressFamily family =
        endpoint.family == protocol::NetworkAddressFamily::kIpv4
            ? AddressFamily::kIpv4
            : AddressFamily::kIpv6;
    const std::size_t endpoint_length =
        family == AddressFamily::kIpv4 ? 4 : 16;
    const std::uint16_t proxy_port = family == AddressFamily::kIpv4
                                         ? g_tcp_proxy_port
                                         : g_tcp_proxy_ipv6_port;
    if (proxy_port == 0) {
        return false;
    }
    std::array<char, protocol::kMaximumEventDomainBytes + 1U> domain{};
    const bool explicit_address =
        policy->DecideAddress(
            family, endpoint.address.data(), endpoint_length) ==
        Decision::kAllow;
    const bool bound_domain = !explicit_address && g_dns_bindings != nullptr &&
        g_dns_bindings->FindAuthorizedDomain(
            g_dns_session_id, GetCurrentProcessId(), family,
            endpoint.address.data(), endpoint_length, endpoint.port,
            GetTickCount64(), domain.data(), domain.size());
    if (!explicit_address && !bound_domain) {
        return false;
    }

    TcpProxyLock guard;
    bool& proxy_closed = family == AddressFamily::kIpv4
                             ? g_tcp_proxy_closed
                             : g_tcp_proxy_ipv6_closed;
    std::uint64_t& next_sequence =
        family == AddressFamily::kIpv4 ? g_tcp_proxy_next_sequence
                                       : g_tcp_proxy_ipv6_next_sequence;
    if (proxy_closed) {
        WSASetLastError(WSAENETDOWN);
        return true;
    }
    std::uint32_t network_error = 0;
    const auto status = ConnectTcpSocketThroughProxy(
        socket, g_connect, proxy_port, g_tcp_proxy_session,
        next_sequence, GetCurrentProcessId(), family,
        endpoint.address.data(), endpoint_length, endpoint.port,
        bound_domain ? domain.data() : nullptr, network_error);
    const bool authenticated_response =
        status == TcpProxyClientStatus::kConnected ||
        status == TcpProxyClientStatus::kDenied ||
        status == TcpProxyClientStatus::kConnectFailed ||
        status == TcpProxyClientStatus::kProxyFailure;
    if (authenticated_response) {
        if (next_sequence ==
            std::numeric_limits<std::uint64_t>::max()) {
            proxy_closed = true;
        } else {
            ++next_sequence;
        }
    } else if (status != TcpProxyClientStatus::kProxyConnectFailed &&
               status != TcpProxyClientStatus::kInvalidArgument) {
        proxy_closed = true;
    }
    if (status == TcpProxyClientStatus::kConnected) {
        if (g_socket_targets == nullptr ||
            g_socket_targets->Upsert(
                static_cast<std::uintptr_t>(socket), endpoint) !=
                SocketTargetStatus::kSuccess) {
            shutdown(socket, SD_BOTH);
            WSASetLastError(WSAENOBUFS);
            return true;
        }
        result = 0;
        WSASetLastError(0);
        return true;
    }
    WSASetLastError(
        network_error == 0 ? WSAENETDOWN : static_cast<int>(network_error));
    return true;
}

bool DenySend(
    const sockaddr* address,
    const int address_length) noexcept {
    const auto* policy = g_policy.get();
    if (policy != nullptr && policy->mode() == Mode::kUnrestricted) {
        return false;
    }
    protocol::NetworkEndpoint endpoint{};
    const bool endpoint_valid = ReadEndpoint(address, address_length, endpoint);
    if (endpoint_valid) {
        hook::TryReportNetworkViolation(
            protocol::NetworkOperation::kSend, endpoint);
    }
    WSASetLastError(WSAEACCES);
    return true;
}

int WSAAPI DetouredConnect(
    const SOCKET socket,
    const sockaddr* address,
    const int address_length) noexcept {
    int proxy_result = SOCKET_ERROR;
    if (TryProxyConnect(socket, address, address_length, proxy_result)) {
        return proxy_result;
    }
    if (DenyConnect(address, address_length)) {
        return SOCKET_ERROR;
    }
    return g_connect(socket, address, address_length);
}

int WSAAPI DetouredWsaConnect(
    const SOCKET socket,
    const sockaddr* address,
    const int address_length,
    LPWSABUF caller_data,
    LPWSABUF callee_data,
    LPQOS socket_qos,
    LPQOS group_qos) noexcept {
    int proxy_result = SOCKET_ERROR;
    if (caller_data == nullptr && callee_data == nullptr && socket_qos == nullptr &&
        group_qos == nullptr &&
        TryProxyConnect(socket, address, address_length, proxy_result)) {
        return proxy_result;
    }
    if (DenyConnect(address, address_length)) {
        return SOCKET_ERROR;
    }
    return g_wsa_connect(
        socket, address, address_length, caller_data, callee_data, socket_qos,
        group_qos);
}

BOOL PASCAL DetouredConnectEx(
    const SOCKET socket,
    const sockaddr* address,
    const int address_length,
    PVOID send_buffer,
    const DWORD send_length,
    LPDWORD bytes_sent,
    LPOVERLAPPED overlapped) noexcept {
    if (overlapped == nullptr || (send_length != 0 && send_buffer == nullptr)) {
        WSASetLastError(overlapped == nullptr ? WSAEINVAL : WSAEFAULT);
        return FALSE;
    }

    int proxy_result = SOCKET_ERROR;
    if (TryProxyConnect(socket, address, address_length, proxy_result)) {
        if (proxy_result == SOCKET_ERROR) {
            return FALSE;
        }
        WSABUF buffer{};
        buffer.buf = static_cast<char*>(send_buffer);
        buffer.len = send_length;
        DWORD transferred = 0;
        const int send_status = g_wsa_send(
            socket, &buffer, 1, &transferred, 0, overlapped, nullptr);
        if (send_status == 0) {
            if (!WriteTransferredBytes(bytes_sent, transferred)) {
                shutdown(socket, SD_BOTH);
                if (g_socket_targets != nullptr) {
                    g_socket_targets->Remove(
                        static_cast<std::uintptr_t>(socket));
                }
                WSASetLastError(WSAEFAULT);
                return FALSE;
            }
            WSASetLastError(0);
            return TRUE;
        }
        const int send_error = WSAGetLastError();
        if (send_error == WSA_IO_PENDING) {
            if (!WriteTransferredBytes(bytes_sent, 0)) {
                shutdown(socket, SD_BOTH);
                if (g_socket_targets != nullptr) {
                    g_socket_targets->Remove(
                        static_cast<std::uintptr_t>(socket));
                }
                WSASetLastError(WSAEFAULT);
                return FALSE;
            }
            WSASetLastError(WSA_IO_PENDING);
            return FALSE;
        }
        shutdown(socket, SD_BOTH);
        if (g_socket_targets != nullptr) {
            g_socket_targets->Remove(static_cast<std::uintptr_t>(socket));
        }
        WSASetLastError(send_error);
        return FALSE;
    }

    if (DenyConnect(address, address_length)) {
        return FALSE;
    }

    GUID connect_ex_guid = kConnectExGuid;
    LPFN_CONNECTEX provider_connect_ex = nullptr;
    DWORD bytes_returned = 0;
    if (g_wsa_ioctl(
            socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &connect_ex_guid,
            sizeof(connect_ex_guid), &provider_connect_ex,
            sizeof(provider_connect_ex), &bytes_returned, nullptr, nullptr) ==
            SOCKET_ERROR ||
        provider_connect_ex == nullptr ||
        bytes_returned != sizeof(provider_connect_ex)) {
        return FALSE;
    }
    return provider_connect_ex(
        socket, address, address_length, send_buffer, send_length, bytes_sent,
        overlapped);
}

int WSAAPI DetouredWsaIoctl(
    const SOCKET socket,
    const DWORD control_code,
    LPVOID input,
    const DWORD input_length,
    LPVOID output,
    const DWORD output_length,
    LPDWORD bytes_returned,
    LPWSAOVERLAPPED overlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE completion_routine) noexcept {
    const bool connect_ex_request =
        IsConnectExRequest(control_code, input, input_length);
    const bool send_msg_request =
        IsWsaSendMsgRequest(control_code, input, input_length);
    if (!NetworkIsDenied() || !IsExtensionFunctionControl(control_code) ||
        IsSafeNonEgressExtensionRequest(
            control_code, input, input_length)) {
        return g_wsa_ioctl(
            socket, control_code, input, input_length, output, output_length,
            bytes_returned, overlapped, completion_routine);
    }
    if (!connect_ex_request && !send_msg_request) {
        if (!ClearBytesReturned(bytes_returned)) {
            WSASetLastError(WSAEFAULT);
            return SOCKET_ERROR;
        }
        WSASetLastError(WSAEACCES);
        return SOCKET_ERROR;
    }

    GUID extension_guid = connect_ex_request ? kConnectExGuid : kWsaSendMsgGuid;
    std::array<std::uint8_t, sizeof(LPFN_CONNECTEX)> provider_function{};
    DWORD provider_bytes = 0;
    const int provider_status = g_wsa_ioctl(
        socket, control_code, &extension_guid, sizeof(extension_guid),
        provider_function.data(), static_cast<DWORD>(provider_function.size()),
        &provider_bytes,
        nullptr, nullptr);
    if (provider_status == SOCKET_ERROR) {
        return SOCKET_ERROR;
    }
    const bool provider_valid = provider_bytes == provider_function.size() &&
        std::any_of(
            provider_function.begin(), provider_function.end(),
            [](const std::uint8_t byte) { return byte != 0; });
    const bool output_written = connect_ex_request
        ? WriteConnectExResult(output, output_length, bytes_returned)
        : WriteWsaSendMsgResult(output, output_length, bytes_returned);
    if (!provider_valid || !output_written) {
        WSASetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    return 0;
}

INT WSAAPI DetouredWsaSendMsg(
    const SOCKET socket,
    LPWSAMSG message,
    const DWORD flags,
    LPDWORD bytes_sent,
    LPWSAOVERLAPPED overlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE completion_routine) noexcept {
    static_cast<void>(socket);
    static_cast<void>(flags);
    static_cast<void>(bytes_sent);
    static_cast<void>(overlapped);
    static_cast<void>(completion_routine);
    sockaddr* destination = nullptr;
    int destination_length = 0;
    if (message == nullptr) {
        WSASetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    __try {
        destination = message->name;
        destination_length = message->namelen;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        WSASetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    DenySend(destination, destination_length);
    return SOCKET_ERROR;
}

INT WSAAPI DetouredGetAddrInfoA(
    PCSTR node_name,
    PCSTR service_name,
    const ADDRINFOA* hints,
    PADDRINFOA* results) noexcept {
    const auto* policy = g_policy.get();
    if (policy != nullptr && policy->mode() == Mode::kAllowList &&
        HasHighLevelDnsDomain(node_name)) {
        return g_get_addr_info_a(node_name, service_name, hints, results);
    }
    if ((policy != nullptr && policy->mode() == Mode::kUnrestricted) ||
        node_name == nullptr) {
        return g_get_addr_info_a(node_name, service_name, hints, results);
    }
    AddressFamily numeric_family{};
    std::array<std::uint8_t, 16> numeric_address{};
    std::size_t numeric_address_length = 0;
    if (policy != nullptr && policy->mode() == Mode::kAllowList &&
        TryParseNumericAddress(
            node_name, numeric_family, numeric_address,
            numeric_address_length)) {
        return g_get_addr_info_a(node_name, service_name, hints, results);
    }
    std::array<char, protocol::kMaximumEventDomainBytes + 1U> domain{};
    std::uint16_t port = 0;
    protocol::DnsProxyQueryFamily family{};
    if (policy != nullptr && policy->mode() == Mode::kAllowList &&
        g_dns_channel != nullptr && CopyAsciiDomain(node_name, domain) &&
        ParsePort(service_name, port) && ReadQueryFamily(hints, family)) {
        std::vector<protocol::DnsProxyAddress> addresses;
        const auto status = g_dns_channel->Resolve(
            domain.data(), port, GetTickCount64(), &addresses, family);
        if (status == DnsProxyChannelStatus::kSuccess) {
            const INT build = BuildAddressInfoResults<ADDRINFOA>(
                addresses, port, hints, results, 1);
            WSASetLastError(build);
            return build;
        }
        if (status == DnsProxyChannelStatus::kNotFound) {
            ClearAddressResults(results);
            WSASetLastError(WSAHOST_NOT_FOUND);
            return WSAHOST_NOT_FOUND;
        }
        if (status == DnsProxyChannelStatus::kResolverFailed) {
            ClearAddressResults(results);
            WSASetLastError(WSATRY_AGAIN);
            return WSATRY_AGAIN;
        }
        if (status == DnsProxyChannelStatus::kBindingFailed) {
            ClearAddressResults(results);
            WSASetLastError(WSAENOBUFS);
            return WSAENOBUFS;
        }
        if (status == DnsProxyChannelStatus::kProtocolFailed) {
            ClearAddressResults(results);
            WSASetLastError(WSAEPROTONOSUPPORT);
            return WSAEPROTONOSUPPORT;
        }
        if (status == DnsProxyChannelStatus::kTransportFailed ||
            status == DnsProxyChannelStatus::kClosed) {
            ClearAddressResults(results);
            WSASetLastError(WSAENETDOWN);
            return WSAENETDOWN;
        }
    }
    ReportDeniedResolution(node_name);
    ClearAddressResults(results);
    WSASetLastError(WSAEACCES);
    return WSAEACCES;
}

INT WSAAPI DetouredGetAddrInfoW(
    PCWSTR node_name,
    PCWSTR service_name,
    const ADDRINFOW* hints,
    PADDRINFOW* results) noexcept {
    const auto* policy = g_policy.get();
    if (policy != nullptr && policy->mode() == Mode::kAllowList &&
        HasHighLevelDnsDomain(node_name)) {
        return g_get_addr_info_w(node_name, service_name, hints, results);
    }
    if ((policy != nullptr && policy->mode() == Mode::kUnrestricted) ||
        node_name == nullptr) {
        return g_get_addr_info_w(node_name, service_name, hints, results);
    }
    AddressFamily numeric_family{};
    std::array<std::uint8_t, 16> numeric_address{};
    std::size_t numeric_address_length = 0;
    if (policy != nullptr && policy->mode() == Mode::kAllowList &&
        TryParseNumericAddress(
            node_name, numeric_family, numeric_address,
            numeric_address_length)) {
        return g_get_addr_info_w(node_name, service_name, hints, results);
    }
    std::array<char, protocol::kMaximumEventDomainBytes + 1U> domain{};
    std::uint16_t port = 0;
    protocol::DnsProxyQueryFamily family{};
    if (policy != nullptr && policy->mode() == Mode::kAllowList &&
        g_dns_channel != nullptr && CopyAsciiDomain(node_name, domain) &&
        ParsePort(service_name, port) && ReadQueryFamily(hints, family)) {
        std::vector<protocol::DnsProxyAddress> addresses;
        const auto status = g_dns_channel->Resolve(
            domain.data(), port, GetTickCount64(), &addresses, family);
        if (status == DnsProxyChannelStatus::kSuccess) {
            const INT build = BuildAddressInfoResults<ADDRINFOW>(
                addresses, port, hints, results, 2);
            WSASetLastError(build);
            return build;
        }
        if (status == DnsProxyChannelStatus::kNotFound) {
            ClearAddressResults(results);
            WSASetLastError(WSAHOST_NOT_FOUND);
            return WSAHOST_NOT_FOUND;
        }
        if (status == DnsProxyChannelStatus::kResolverFailed) {
            ClearAddressResults(results);
            WSASetLastError(WSATRY_AGAIN);
            return WSATRY_AGAIN;
        }
        if (status == DnsProxyChannelStatus::kBindingFailed) {
            ClearAddressResults(results);
            WSASetLastError(WSAENOBUFS);
            return WSAENOBUFS;
        }
        if (status == DnsProxyChannelStatus::kProtocolFailed) {
            ClearAddressResults(results);
            WSASetLastError(WSAEPROTONOSUPPORT);
            return WSAEPROTONOSUPPORT;
        }
        if (status == DnsProxyChannelStatus::kTransportFailed ||
            status == DnsProxyChannelStatus::kClosed) {
            ClearAddressResults(results);
            WSASetLastError(WSAENETDOWN);
            return WSAENETDOWN;
        }
    }
    ReportDeniedResolution(node_name);
    ClearAddressResults(results);
    WSASetLastError(WSAEACCES);
    return WSAEACCES;
}

bool ReadDnsQueryRequest(
    const PDNS_QUERY_REQUEST request,
    PCWSTR& name,
    WORD& type,
    ULONG64& options) noexcept {
    name = nullptr;
    type = 0;
    options = 0;
    if (request == nullptr) {
        return false;
    }
    __try {
        if (request->Version != DNS_QUERY_REQUEST_VERSION1) {
            return false;
        }
        name = request->QueryName;
        type = request->QueryType;
        options = request->QueryOptions;
        return name != nullptr;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool WriteDnsQuerySuccess(
    const PDNS_QUERY_RESULT results,
    const PDNS_QUERY_CANCEL cancel,
    const ULONG64 options,
    PDNS_RECORD records) noexcept {
    __try {
        if (results == nullptr) {
            return false;
        }
        results->QueryStatus = ERROR_SUCCESS;
        results->QueryOptions = options;
        results->pQueryRecords = records;
        results->Reserved = nullptr;
        if (cancel != nullptr) {
            SecureZeroMemory(cancel, sizeof(*cancel));
        }
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

template <typename Character>
DNS_STATUS ResolveDnsQueryViaProxy(
    const Character* domain,
    const WORD query_type,
    PDNS_RECORD* results) noexcept {
    ClearAddressResults(results);
    if (g_dns_channel == nullptr ||
        (query_type != DNS_TYPE_A && query_type != DNS_TYPE_AAAA)) {
        return ERROR_ACCESS_DENIED;
    }
    std::array<char, protocol::kMaximumEventDomainBytes + 1U> ascii_domain{};
    if (!CopyAsciiDomain(domain, ascii_domain)) {
        return ERROR_ACCESS_DENIED;
    }
    const auto family = query_type == DNS_TYPE_A
                            ? protocol::DnsProxyQueryFamily::kIpv4
                            : protocol::DnsProxyQueryFamily::kIpv6;
    std::vector<protocol::DnsProxyAddress> addresses;
    const auto status = g_dns_channel->Resolve(
        ascii_domain.data(), 0, GetTickCount64(), &addresses, family);
    if (status == DnsProxyChannelStatus::kSuccess) {
        return BuildDnsRecords(addresses, query_type, results);
    }
    if (status == DnsProxyChannelStatus::kNotFound) {
        return DNS_INFO_NO_RECORDS;
    }
    if (status == DnsProxyChannelStatus::kResolverFailed) {
        return ERROR_TIMEOUT;
    }
    return ERROR_ACCESS_DENIED;
}

void WSAAPI DetouredFreeAddrInfoA(PADDRINFOA results) noexcept {
    if (!TryFreeSynthetic(results)) {
        g_free_addr_info_a(results);
    }
}

void WSAAPI DetouredFreeAddrInfoW(PADDRINFOW results) noexcept {
    if (!TryFreeSynthetic(results)) {
        g_free_addr_info_w(results);
    }
}

INT WSAAPI DetouredGetAddrInfoExW(
    PCWSTR node_name,
    PCWSTR service_name,
    const DWORD name_space,
    LPGUID provider,
    const ADDRINFOEXW* hints,
    PADDRINFOEXW* results,
    timeval* timeout,
    LPOVERLAPPED overlapped,
    LPLOOKUPSERVICE_COMPLETION_ROUTINE completion_routine,
    LPHANDLE lookup_handle) noexcept {
    const auto* policy = g_policy.get();
    if (policy != nullptr && policy->mode() == Mode::kAllowList &&
        HasHighLevelDnsDomain(node_name)) {
        return g_get_addr_info_ex_w(
            node_name, service_name, name_space, provider, hints, results,
            timeout, overlapped, completion_routine, lookup_handle);
    }
    if ((policy != nullptr && policy->mode() == Mode::kUnrestricted) ||
        node_name == nullptr) {
        return g_get_addr_info_ex_w(
            node_name, service_name, name_space, provider, hints, results,
            timeout, overlapped, completion_routine, lookup_handle);
    }
    AddressFamily numeric_family{};
    std::array<std::uint8_t, 16> numeric_address{};
    std::size_t numeric_address_length = 0;
    if (policy != nullptr && policy->mode() == Mode::kAllowList &&
        TryParseNumericAddress(
            node_name, numeric_family, numeric_address,
            numeric_address_length)) {
        return g_get_addr_info_ex_w(
            node_name, service_name, name_space, provider, hints, results,
            timeout, overlapped, completion_routine, lookup_handle);
    }
    std::array<char, protocol::kMaximumEventDomainBytes + 1U> domain{};
    std::uint16_t port = 0;
    protocol::DnsProxyQueryFamily family{};
    const bool policy_allows_proxy =
        policy != nullptr && policy->mode() == Mode::kAllowList;
    const bool channel_present = g_dns_channel != nullptr;
    const bool domain_valid = CopyAsciiDomain(node_name, domain);
    const bool port_valid = ParsePort(service_name, port);
    const bool family_valid = ReadQueryFamily(hints, family);
    if (policy_allows_proxy && channel_present && domain_valid && port_valid &&
        family_valid) {
        std::vector<protocol::DnsProxyAddress> addresses;
        const auto channel_status = g_dns_channel->Resolve(
            domain.data(), port, GetTickCount64(), &addresses, family);
        if (channel_status == DnsProxyChannelStatus::kSuccess) {
            const INT build = BuildAddressInfoResults<ADDRINFOEXW>(
                addresses, port, hints, results, 4);
            if (build == 0) {
                ClearLookupHandle(lookup_handle);
            }
            WSASetLastError(build);
            return build;
        }
    }
    ReportDeniedResolution(node_name);
    ClearAddressResults(results);
    ClearLookupHandle(lookup_handle);
    WSASetLastError(WSAEACCES);
    return WSAEACCES;
}

INT WSAAPI DetouredGetAddrInfoExA(
    PCSTR node_name,
    PCSTR service_name,
    const DWORD name_space,
    LPGUID provider,
    const ADDRINFOEXA* hints,
    PADDRINFOEXA* results,
    timeval* timeout,
    LPOVERLAPPED overlapped,
    LPLOOKUPSERVICE_COMPLETION_ROUTINE completion_routine,
    LPHANDLE lookup_handle) noexcept {
    const auto* policy = g_policy.get();
    if (policy != nullptr && policy->mode() == Mode::kAllowList &&
        HasHighLevelDnsDomain(node_name)) {
        return g_get_addr_info_ex_a(
            node_name, service_name, name_space, provider, hints, results,
            timeout, overlapped, completion_routine, lookup_handle);
    }
    if ((policy != nullptr && policy->mode() == Mode::kUnrestricted) ||
        node_name == nullptr) {
        return g_get_addr_info_ex_a(
            node_name, service_name, name_space, provider, hints, results,
            timeout, overlapped, completion_routine, lookup_handle);
    }
    AddressFamily numeric_family{};
    std::array<std::uint8_t, 16> numeric_address{};
    std::size_t numeric_address_length = 0;
    if (policy != nullptr && policy->mode() == Mode::kAllowList &&
        TryParseNumericAddress(
            node_name, numeric_family, numeric_address,
            numeric_address_length)) {
        return g_get_addr_info_ex_a(
            node_name, service_name, name_space, provider, hints, results,
            timeout, overlapped, completion_routine, lookup_handle);
    }
    std::array<char, protocol::kMaximumEventDomainBytes + 1U> domain{};
    std::uint16_t port = 0;
    protocol::DnsProxyQueryFamily family{};
    if (policy != nullptr && policy->mode() == Mode::kAllowList &&
        g_dns_channel != nullptr && CopyAsciiDomain(node_name, domain) &&
        ParsePort(service_name, port) && ReadQueryFamily(hints, family)) {
        std::vector<protocol::DnsProxyAddress> addresses;
        if (g_dns_channel->Resolve(
                domain.data(), port, GetTickCount64(), &addresses, family) ==
            DnsProxyChannelStatus::kSuccess) {
            const INT build = BuildAddressInfoResults<ADDRINFOEXA>(
                addresses, port, hints, results, 3);
            if (build == 0) {
                ClearLookupHandle(lookup_handle);
            }
            WSASetLastError(build);
            return build;
        }
    }
    ReportDeniedResolution(node_name);
    ClearAddressResults(results);
    ClearLookupHandle(lookup_handle);
    WSASetLastError(WSAEACCES);
    return WSAEACCES;
}

void WSAAPI DetouredFreeAddrInfoExW(PADDRINFOEXW results) noexcept {
    if (!TryFreeSynthetic(results)) {
        g_free_addr_info_ex_w(results);
    }
}

void WSAAPI DetouredFreeAddrInfoExA(PADDRINFOEXA results) noexcept {
    if (!TryFreeSynthetic(results)) {
        g_free_addr_info_ex_a(results);
    }
}

#if defined(_M_IX86)
bool PatchRelativeJump(
    const PVOID entry,
    const PVOID detour) noexcept {
    if (entry == nullptr || detour == nullptr) {
        return false;
    }
    const auto source = reinterpret_cast<std::uintptr_t>(entry);
    const auto destination = reinterpret_cast<std::uintptr_t>(detour);
    const auto displacement =
        static_cast<std::int64_t>(destination) -
        static_cast<std::int64_t>(source + 5U);
    if (displacement < (std::numeric_limits<std::int32_t>::min)() ||
        displacement > (std::numeric_limits<std::int32_t>::max)()) {
        return false;
    }
    std::array<std::uint8_t, 5> jump{
        0xE9, 0, 0, 0, 0};
    const auto relative = static_cast<std::int32_t>(displacement);
    std::memcpy(jump.data() + 1, &relative, sizeof(relative));
    DWORD prior_protection = 0;
    if (!VirtualProtect(
            entry, jump.size(), PAGE_EXECUTE_READWRITE,
            &prior_protection)) {
        return false;
    }
    std::memcpy(entry, jump.data(), jump.size());
    FlushInstructionCache(GetCurrentProcess(), entry, jump.size());
    DWORD ignored = 0;
    return VirtualProtect(
               entry, jump.size(), prior_protection, &ignored) != FALSE;
}

bool RestoreWinsockEntrypoints() noexcept {
    const HMODULE winsock = GetModuleHandleW(L"ws2_32.dll");
    if (winsock == nullptr) {
        return false;
    }
    struct Entrypoint {
        const char* name;
        PVOID detour;
    };
    const std::array<Entrypoint, 14> entrypoints = {{
        {"socket", reinterpret_cast<PVOID>(DetouredSocket)},
        {"WSASocketW", reinterpret_cast<PVOID>(DetouredWsaSocketW)},
        {"WSASocketA", reinterpret_cast<PVOID>(DetouredWsaSocketA)},
        {"connect", reinterpret_cast<PVOID>(DetouredConnect)},
        {"WSAConnect", reinterpret_cast<PVOID>(DetouredWsaConnect)},
        {"WSAIoctl", reinterpret_cast<PVOID>(DetouredWsaIoctl)},
        {"getaddrinfo", reinterpret_cast<PVOID>(DetouredGetAddrInfoA)},
        {"GetAddrInfoW", reinterpret_cast<PVOID>(DetouredGetAddrInfoW)},
        {"GetAddrInfoExW", reinterpret_cast<PVOID>(DetouredGetAddrInfoExW)},
        {"GetAddrInfoExA", reinterpret_cast<PVOID>(DetouredGetAddrInfoExA)},
        {"sendto", reinterpret_cast<PVOID>(DetouredSendTo)},
        {"WSASendTo", reinterpret_cast<PVOID>(DetouredWsaSendTo)},
        {"getpeername", reinterpret_cast<PVOID>(DetouredGetPeerName)},
        {"closesocket", reinterpret_cast<PVOID>(DetouredCloseSocket)},
    }};
    for (const auto& entrypoint : entrypoints) {
        const PVOID entry = GetProcAddress(winsock, entrypoint.name);
        if (!PatchRelativeJump(entry, entrypoint.detour)) {
            return false;
        }
    }
    return true;
}

int WSAAPI DetouredWsaStartup(
    const WORD version,
    LPWSADATA data) noexcept {
    const int status = g_wsa_startup(version, data);
    if (status != ERROR_SUCCESS) {
        return status;
    }
    AcquireSRWLockExclusive(&g_winsock_entrypoint_lock);
    if (!g_winsock_entrypoint_attempted) {
        g_winsock_entrypoint_attempted = true;
        g_winsock_entrypoint_succeeded = RestoreWinsockEntrypoints();
    }
    const bool succeeded = g_winsock_entrypoint_succeeded;
    ReleaseSRWLockExclusive(&g_winsock_entrypoint_lock);
    return succeeded ? ERROR_SUCCESS : WSASYSNOTREADY;
}
#endif

DNS_STATUS WINAPI DetouredDnsQueryA(
    PCSTR name,
    const WORD type,
    const DWORD options,
    PVOID extra,
    PDNS_RECORD* results,
    PVOID* reserved) noexcept {
    const auto* policy = g_policy.get();
    if ((policy != nullptr && policy->mode() == Mode::kUnrestricted) ||
        name == nullptr) {
        return g_dns_query_a(name, type, options, extra, results, reserved);
    }
    if (policy->mode() == Mode::kAllowList &&
        HasHighLevelDnsDomain(name)) {
        return g_dns_query_a(name, type, options, extra, results, reserved);
    }
    if (policy != nullptr && policy->mode() == Mode::kAllowList) {
        const DNS_STATUS status = ResolveDnsQueryViaProxy(name, type, results);
        if (status != ERROR_ACCESS_DENIED) {
            SetLastError(status);
            return status;
        }
    }
    ReportDeniedResolution(name);
    ClearAddressResults(results);
    SetLastError(ERROR_ACCESS_DENIED);
    return ERROR_ACCESS_DENIED;
}

DNS_STATUS WINAPI DetouredDnsQueryUtf8(
    PCSTR name,
    const WORD type,
    const DWORD options,
    PVOID extra,
    PDNS_RECORD* results,
    PVOID* reserved) noexcept {
    const auto* policy = g_policy.get();
    if ((policy != nullptr && policy->mode() == Mode::kUnrestricted) ||
        name == nullptr) {
        return g_dns_query_utf8(name, type, options, extra, results, reserved);
    }
    if (policy->mode() == Mode::kAllowList &&
        HasHighLevelDnsDomain(name)) {
        return g_dns_query_utf8(name, type, options, extra, results, reserved);
    }
    if (policy != nullptr && policy->mode() == Mode::kAllowList) {
        const DNS_STATUS status = ResolveDnsQueryViaProxy(name, type, results);
        if (status != ERROR_ACCESS_DENIED) {
            SetLastError(status);
            return status;
        }
    }
    ReportDeniedResolution(name);
    ClearAddressResults(results);
    SetLastError(ERROR_ACCESS_DENIED);
    return ERROR_ACCESS_DENIED;
}

DNS_STATUS WINAPI DetouredDnsQueryW(
    PCWSTR name,
    const WORD type,
    const DWORD options,
    PVOID extra,
    PDNS_RECORD* results,
    PVOID* reserved) noexcept {
    const auto* policy = g_policy.get();
    if ((policy != nullptr && policy->mode() == Mode::kUnrestricted) ||
        name == nullptr) {
        return g_dns_query_w(name, type, options, extra, results, reserved);
    }
    if (policy->mode() == Mode::kAllowList &&
        HasHighLevelDnsDomain(name)) {
        return g_dns_query_w(name, type, options, extra, results, reserved);
    }
    if (policy != nullptr && policy->mode() == Mode::kAllowList) {
        const DNS_STATUS status = ResolveDnsQueryViaProxy(name, type, results);
        if (status != ERROR_ACCESS_DENIED) {
            SetLastError(status);
            return status;
        }
    }
    ReportDeniedResolution(name);
    ClearAddressResults(results);
    SetLastError(ERROR_ACCESS_DENIED);
    return ERROR_ACCESS_DENIED;
}

void WINAPI DetouredDnsFree(
    PVOID value,
    const DNS_FREE_TYPE free_type) noexcept {
    if (free_type != DnsFreeRecordList || !TryFreeSynthetic(value)) {
        g_dns_free(value, free_type);
    }
}

DNS_STATUS WINAPI DetouredDnsQueryEx(
    PDNS_QUERY_REQUEST request,
    PDNS_QUERY_RESULT results,
    PDNS_QUERY_CANCEL cancel) noexcept {
    const auto* policy = g_policy.get();
    if (policy != nullptr && policy->mode() == Mode::kUnrestricted) {
        return g_dns_query_ex(request, results, cancel);
    }
    if (policy != nullptr && policy->mode() == Mode::kAllowList &&
        HasHighLevelDnsDomain(ReadDnsQueryName(request))) {
        return g_dns_query_ex(request, results, cancel);
    }
    if (policy != nullptr && policy->mode() == Mode::kAllowList &&
        g_dns_channel != nullptr) {
        PCWSTR name = nullptr;
        WORD type = 0;
        ULONG64 options = 0;
        if (ReadDnsQueryRequest(request, name, type, options) &&
            (type == DNS_TYPE_A || type == DNS_TYPE_AAAA)) {
            std::array<char, protocol::kMaximumEventDomainBytes + 1U> domain{};
            if (CopyAsciiDomain(name, domain)) {
                const auto family = type == DNS_TYPE_A
                                        ? protocol::DnsProxyQueryFamily::kIpv4
                                        : protocol::DnsProxyQueryFamily::kIpv6;
                std::vector<protocol::DnsProxyAddress> addresses;
                const auto channel_status = g_dns_channel->Resolve(
                    domain.data(), 0, GetTickCount64(), &addresses, family);
                if (channel_status == DnsProxyChannelStatus::kSuccess) {
                    PDNS_RECORD records = nullptr;
                    const DNS_STATUS build = BuildDnsRecords(addresses, type, &records);
                    if (build == ERROR_SUCCESS &&
                        WriteDnsQuerySuccess(results, cancel, options, records)) {
                        SetLastError(ERROR_SUCCESS);
                        return ERROR_SUCCESS;
                    }
                    if (records != nullptr) {
                        TryFreeSynthetic(records);
                    }
                }
            }
        }
    }
    ReportDeniedResolution(ReadDnsQueryName(request));
    ClearDnsQueryOutputs(results, cancel);
    SetLastError(ERROR_ACCESS_DENIED);
    return ERROR_ACCESS_DENIED;
}

int WSAAPI DetouredSendTo(
    const SOCKET socket,
    const char* buffer,
    const int length,
    const int flags,
    const sockaddr* destination,
    const int destination_length) noexcept {
    if (DenySend(destination, destination_length)) {
        return SOCKET_ERROR;
    }
    return g_send_to(
        socket, buffer, length, flags, destination, destination_length);
}

int WSAAPI DetouredWsaSendTo(
    const SOCKET socket,
    LPWSABUF buffers,
    const DWORD buffer_count,
    LPDWORD bytes_sent,
    const DWORD flags,
    const sockaddr* destination,
    const int destination_length,
    LPWSAOVERLAPPED overlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE completion_routine) noexcept {
    if (DenySend(destination, destination_length)) {
        return SOCKET_ERROR;
    }
    return g_wsa_send_to(
        socket, buffers, buffer_count, bytes_sent, flags, destination,
        destination_length, overlapped, completion_routine);
}

int WSAAPI DetouredGetPeerName(
    const SOCKET socket,
    sockaddr* const address,
    int* const address_length) noexcept {
    protocol::NetworkEndpoint endpoint{};
    if (g_socket_targets != nullptr &&
        g_socket_targets->Lookup(
            static_cast<std::uintptr_t>(socket), endpoint)) {
        return WriteEndpoint(endpoint, address, address_length) ? 0
                                                               : SOCKET_ERROR;
    }
    return g_get_peer_name(socket, address, address_length);
}

int WSAAPI DetouredCloseSocket(const SOCKET socket) noexcept {
    protocol::NetworkEndpoint endpoint{};
    const bool tracked = g_socket_targets != nullptr &&
        g_socket_targets->Lookup(
            static_cast<std::uintptr_t>(socket), endpoint);
    if (tracked) {
        g_socket_targets->Remove(static_cast<std::uintptr_t>(socket));
    }
    const int status = g_close_socket(socket);
    if (status == SOCKET_ERROR && tracked) {
        g_socket_targets->Upsert(static_cast<std::uintptr_t>(socket), endpoint);
    }
    return status;
}

}  // namespace

bool DenyHighLevelConnection(
    const char* const server,
    const std::uint16_t port,
    const bool resolve_target) noexcept {
    const auto* policy = g_policy.get();
    if (policy != nullptr && policy->mode() == Mode::kUnrestricted) {
        return false;
    }
    std::array<char, protocol::kMaximumEventDomainBytes + 1U> domain{};
    const bool valid_domain = CopyAsciiDomain(server, domain);
    if (policy != nullptr && policy->mode() == Mode::kAllowList &&
        valid_domain && port != 0 &&
        policy->DecideDomain(domain.data()) == Decision::kAllow &&
        policy->DecidePort(port) == Decision::kAllow) {
        if (!resolve_target) {
            SetLastError(ERROR_SUCCESS);
            return false;
        }
        if (g_dns_channel == nullptr) {
            SetLastError(ERROR_NETWORK_UNREACHABLE);
            return true;
        }
        const std::uint64_t now = GetTickCount64();
        std::vector<protocol::DnsProxyAddress> addresses;
        const auto status = g_dns_channel->Resolve(
            domain.data(), 0, now, &addresses);
        if (status == DnsProxyChannelStatus::kSuccess &&
            RegisterHighLevelDnsDomain(
                domain.data(), addresses, now)) {
            SetLastError(ERROR_SUCCESS);
            return false;
        }
        if (status != DnsProxyChannelStatus::kDenied) {
            SetLastError(ERROR_NETWORK_UNREACHABLE);
            return true;
        }
    }
    if (valid_domain) {
        hook::TryReportDomainNetworkViolation(
            protocol::NetworkOperation::kConnect, domain.data());
    }
    SetLastError(ERROR_ACCESS_DENIED);
    return true;
}

bool DenyHighLevelConnection(
    const wchar_t* const server,
    const std::uint16_t port,
    const bool resolve_target) noexcept {
    const auto* policy = g_policy.get();
    if (policy != nullptr && policy->mode() == Mode::kUnrestricted) {
        return false;
    }
    std::array<char, protocol::kMaximumEventDomainBytes + 1U> domain{};
    const bool valid_domain = CopyAsciiDomain(server, domain);
    if (policy != nullptr && policy->mode() == Mode::kAllowList &&
        valid_domain && port != 0 &&
        policy->DecideDomain(domain.data()) == Decision::kAllow &&
        policy->DecidePort(port) == Decision::kAllow) {
        if (!resolve_target) {
            SetLastError(ERROR_SUCCESS);
            return false;
        }
        if (g_dns_channel == nullptr) {
            SetLastError(ERROR_NETWORK_UNREACHABLE);
            return true;
        }
        const std::uint64_t now = GetTickCount64();
        std::vector<protocol::DnsProxyAddress> addresses;
        const auto status = g_dns_channel->Resolve(
            domain.data(), 0, now, &addresses);
        if (status == DnsProxyChannelStatus::kSuccess &&
            RegisterHighLevelDnsDomain(
                domain.data(), addresses, now)) {
            SetLastError(ERROR_SUCCESS);
            return false;
        }
        if (status != DnsProxyChannelStatus::kDenied) {
            SetLastError(ERROR_NETWORK_UNREACHABLE);
            return true;
        }
    }
    if (valid_domain) {
        hook::TryReportDomainNetworkViolation(
            protocol::NetworkOperation::kConnect, domain.data());
    }
    SetLastError(ERROR_ACCESS_DENIED);
    return true;
}

HookInstallStatus InstallNetworkHooks(
    const std::uint8_t* policy_payload,
    const std::size_t policy_length,
    const protocol::RuntimePayload& runtime) noexcept {
    if (g_policy != nullptr) {
        return HookInstallStatus::kTransactionFailed;
    }
    g_wsa_socket_a = reinterpret_cast<WsaSocketAFunction>(
        GetProcAddress(GetModuleHandleW(L"ws2_32.dll"), "WSASocketA"));
    if (g_wsa_socket_a == nullptr) {
        return HookInstallStatus::kTransactionFailed;
    }
    std::unique_ptr<NetworkPolicy> policy;
    if (NetworkPolicy::Load(policy_payload, policy_length, policy) !=
        PolicyLoadStatus::kValid) {
        return HookInstallStatus::kInvalidPolicy;
    }
    const bool dns_configured = runtime.dns_request_handle != 0;
    if ((policy->mode() == Mode::kAllowList) != dns_configured) {
        return HookInstallStatus::kInvalidPolicy;
    }
    if (policy->mode() == Mode::kUnrestricted) {
        if (DetourTransactionBegin() != NO_ERROR ||
            DetourUpdateThread(GetCurrentThread()) != NO_ERROR ||
            !AttachSocketCreationHooks() ||
            DetourTransactionCommit() != NO_ERROR) {
            DetourTransactionAbort();
            return HookInstallStatus::kTransactionFailed;
        }
        g_policy = std::move(policy);
        return HookInstallStatus::kSuccess;
    }
    std::unique_ptr<DnsBindingTable> bindings;
    std::unique_ptr<DnsProxyClientChannel> channel;
    std::unique_ptr<SocketTargetTable> socket_targets;
    if (dns_configured) {
        if (DnsBindingTable::Create(256, bindings) != BindingStatus::kSuccess) {
            return HookInstallStatus::kInvalidPolicy;
        }
        if (SocketTargetTable::Create(256, socket_targets) !=
            SocketTargetStatus::kSuccess) {
            return HookInstallStatus::kInvalidPolicy;
        }
        std::unique_ptr<DnsProxyHandleTransport> transport;
        if (DnsProxyHandleTransport::Create(
                HandleFromWire(runtime.dns_response_handle),
                HandleFromWire(runtime.dns_request_handle),
                runtime.dns_maximum_frame_length, transport) !=
            HandleTransportStatus::kSuccess) {
            return HookInstallStatus::kInvalidPolicy;
        }
        if (!hook::RegisterRuntimeIoHandles(
                HandleFromWire(runtime.dns_response_handle),
                HandleFromWire(runtime.dns_request_handle))) {
            return HookInstallStatus::kInvalidPolicy;
        }
        protocol::DnsProxySession session{};
        session.nonce = runtime.handshake_nonce;
        session.authentication_key = runtime.dns_authentication_key;
        if (DnsProxyClientChannel::Create(
                session, runtime.handshake_nonce, GetCurrentProcessId(),
                std::move(transport), *bindings, channel) !=
            DnsProxyChannelStatus::kSuccess) {
            return HookInstallStatus::kInvalidPolicy;
        }
    }
    if (DetourTransactionBegin() != NO_ERROR ||
        DetourUpdateThread(GetCurrentThread()) != NO_ERROR ||
        !AttachSocketCreationHooks() ||
#if defined(_M_IX86)
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_wsa_startup),
            reinterpret_cast<PVOID>(DetouredWsaStartup)) != NO_ERROR ||
#endif
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_connect),
            reinterpret_cast<PVOID>(DetouredConnect)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_wsa_connect),
            reinterpret_cast<PVOID>(DetouredWsaConnect)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_wsa_ioctl),
            reinterpret_cast<PVOID>(DetouredWsaIoctl)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_get_addr_info_a),
            reinterpret_cast<PVOID>(DetouredGetAddrInfoA)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_get_addr_info_w),
            reinterpret_cast<PVOID>(DetouredGetAddrInfoW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_free_addr_info_a),
            reinterpret_cast<PVOID>(DetouredFreeAddrInfoA)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_free_addr_info_w),
            reinterpret_cast<PVOID>(DetouredFreeAddrInfoW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_get_addr_info_ex_w),
            reinterpret_cast<PVOID>(DetouredGetAddrInfoExW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_get_addr_info_ex_a),
            reinterpret_cast<PVOID>(DetouredGetAddrInfoExA)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_free_addr_info_ex_w),
            reinterpret_cast<PVOID>(DetouredFreeAddrInfoExW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_free_addr_info_ex_a),
            reinterpret_cast<PVOID>(DetouredFreeAddrInfoExA)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_dns_query_a),
            reinterpret_cast<PVOID>(DetouredDnsQueryA)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_dns_query_utf8),
            reinterpret_cast<PVOID>(DetouredDnsQueryUtf8)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_dns_query_w),
            reinterpret_cast<PVOID>(DetouredDnsQueryW)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_dns_query_ex),
            reinterpret_cast<PVOID>(DetouredDnsQueryEx)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_dns_free),
            reinterpret_cast<PVOID>(DetouredDnsFree)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_send_to),
            reinterpret_cast<PVOID>(DetouredSendTo)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_wsa_send_to),
            reinterpret_cast<PVOID>(DetouredWsaSendTo)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_get_peer_name),
            reinterpret_cast<PVOID>(DetouredGetPeerName)) != NO_ERROR ||
        DetourAttach(
            reinterpret_cast<PVOID*>(&g_close_socket),
            reinterpret_cast<PVOID>(DetouredCloseSocket)) != NO_ERROR ||
        !AttachWinHttpHooks() || !AttachWinInetHooks() ||
        DetourTransactionCommit() != NO_ERROR) {
        DetourTransactionAbort();
        return HookInstallStatus::kTransactionFailed;
    }
    g_dns_session_id = runtime.handshake_nonce;
    g_tcp_proxy_session.nonce = runtime.handshake_nonce;
    g_tcp_proxy_session.authentication_key = runtime.dns_authentication_key;
    g_tcp_proxy_port = runtime.tcp_proxy_port;
    g_tcp_proxy_ipv6_port = runtime.tcp_proxy_ipv6_port;
    g_tcp_proxy_next_sequence = 1;
    g_tcp_proxy_ipv6_next_sequence = 1;
    g_tcp_proxy_closed = false;
    g_tcp_proxy_ipv6_closed = false;
    g_dns_bindings = std::move(bindings);
    g_dns_channel = std::move(channel);
    g_socket_targets = std::move(socket_targets);
    g_policy = std::move(policy);
    return HookInstallStatus::kSuccess;
}

}  // namespace bolt::network
