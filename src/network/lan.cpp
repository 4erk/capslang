#include "lan.hpp"
#include "pairing.hpp"
#include <iphlpapi.h>
#include <netioapi.h>
#include <algorithm>
#include <atomic>
#include <memory>

// The pinned MinGW ws2tcpip.h omits this Windows 8+ declaration.
extern "C" WINSOCK_API_LINKAGE INT WSAAPI GetAddrInfoExCancel(LPHANDLE handle);

namespace capslang::net {
Winsock::Winsock() { WSADATA data{}; error_ = static_cast<DWORD>(WSAStartup(MAKEWORD(2, 2), &data)); }
Winsock::~Winsock() { if (!error_) WSACleanup(); }
namespace {
struct Ip {
    std::array<BYTE, 16> bytes{};
    unsigned size = 0;
    ULONG scope = 0;
};
Ip Normalize(const Address& address) {
    Ip result;
    if (address.value.ss_family == AF_INET && address.size == sizeof(sockaddr_in)) {
        result.size = 4;
        const auto& value = reinterpret_cast<const sockaddr_in&>(address.value);
        std::copy_n(reinterpret_cast<const BYTE*>(&value.sin_addr), 4, result.bytes.begin());
    } else if (address.value.ss_family == AF_INET6 && address.size == sizeof(sockaddr_in6)) {
        const auto& value = reinterpret_cast<const sockaddr_in6&>(address.value);
        if (IN6_IS_ADDR_V4MAPPED(&value.sin6_addr)) {
            result.size = 4; std::copy_n(value.sin6_addr.s6_addr + 12, 4, result.bytes.begin());
        } else {
            result.size = 16; result.scope = value.sin6_scope_id;
            std::copy_n(value.sin6_addr.s6_addr, 16, result.bytes.begin());
        }
    }
    return result;
}
bool Unicast(const Ip& ip) {
    if (ip.size == 4) return ip.bytes[0] != 0 && ip.bytes[0] != 127 && ip.bytes[0] < 224;
    if (ip.size != 16 || ip.bytes[0] == 0xff) return false;
    // Exclude unspecified, loopback, deprecated IPv4-compatible addresses.
    bool first96 = false;
    for (unsigned i = 0; i < 12; ++i) first96 |= ip.bytes[i] != 0;
    return first96;
}
bool LinkLocal(const Ip& ip) { return ip.size == 16 && ip.bytes[0] == 0xfe && (ip.bytes[1] & 0xc0) == 0x80; }
bool CopyAddress(const sockaddr* value, size_t size, Address& output) {
    if (!value || !((value->sa_family == AF_INET && size == sizeof(sockaddr_in)) ||
        (value->sa_family == AF_INET6 && size == sizeof(sockaddr_in6)))) return false;
    output = {}; output.size = static_cast<int>(size); memcpy(&output.value, value, size); return true;
}
bool Cancelled(HANDLE cancel, DWORD& error) {
    if (!cancel) return false;
    const auto status = WaitForSingleObject(cancel, 0);
    if (status == WAIT_TIMEOUT) return false;
    error = status == WAIT_OBJECT_0 ? ERROR_CANCELLED : GetLastError(); return true;
}
bool Ready(SOCKET socket, bool writing, HANDLE cancel, ULONGLONG deadline, DWORD& error) {
    for (;;) {
        if (Cancelled(cancel, error)) return false;
        const auto now = GetTickCount64();
        if (now >= deadline) { error = ERROR_TIMEOUT; return false; }
        fd_set ready, failed; FD_ZERO(&ready); FD_ZERO(&failed); FD_SET(socket, &ready); FD_SET(socket, &failed);
        timeval wait{0, static_cast<long>(std::min<ULONGLONG>(25, deadline - now) * 1000)};
        const auto result = select(0, writing ? nullptr : &ready, writing ? &ready : nullptr, &failed, &wait);
        if (result == SOCKET_ERROR) { error = WSAGetLastError(); return false; }
        if (!result) continue;
        if (FD_ISSET(socket, &failed)) {
            int reason = 0, size = sizeof(reason);
            if (getsockopt(socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&reason), &size)) reason = WSAGetLastError();
            error = reason ? static_cast<DWORD>(reason) : WSAECONNABORTED; return false;
        }
        error = 0; return true;
    }
}
bool Configure(SOCKET socket, DWORD& error) {
    u_long nonblocking = 1;
    if (ioctlsocket(socket, FIONBIO, &nonblocking)) { error = WSAGetLastError(); return false; }
    const BOOL enabled = TRUE;
    if (setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&enabled), sizeof(enabled))) {
        error = WSAGetLastError(); return false;
    }
    return true;
}
struct DnsQuery {
    OVERLAPPED overlapped{}; // First member: callback owns this context, not caller stack.
    std::atomic<unsigned> references{2};
    Winsock winsock;
    HANDLE completed = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    PADDRINFOEXW results = nullptr;
    DWORD error = 0;
    std::wstring host, service;
    ADDRINFOEXW hints{};
    ~DnsQuery() { if (results) FreeAddrInfoExW(results); if (completed) CloseHandle(completed); }
    void Release() { if (references.fetch_sub(1) == 1) delete this; }
    static void CALLBACK Complete(DWORD error, DWORD, OVERLAPPED* overlapped) {
        auto* query = reinterpret_cast<DnsQuery*>(overlapped);
        query->error = error; SetEvent(query->completed); query->Release();
    }
};
struct ReleaseQuery { void operator()(DnsQuery* query) const { query->Release(); } };
bool RouteAllows(const Address& peer, const LanPrefix& prefix) {
    SOCKADDR_INET destination{}, bestSource{};
    memcpy(&destination, peer.Get(), peer.size);
    MIB_IPFORWARD_ROW2 route{};
    if (GetBestRoute2(nullptr, 0, nullptr, &destination, 0, &route, &bestSource) != NO_ERROR ||
        route.InterfaceIndex != prefix.interfaceIndex) return false;
    // A matching prefix is insufficient when a more-specific VPN/router route
    // exists. Accept only an on-link route, never traffic through a gateway.
    if (route.NextHop.si_family == AF_INET) return route.NextHop.Ipv4.sin_addr.s_addr == 0;
    return route.NextHop.si_family == AF_INET6 && IN6_IS_ADDR_UNSPECIFIED(&route.NextHop.Ipv6.sin6_addr);
}
}
bool SameSubnet(const Address& peer, const LanPrefix& prefix) {
    const auto remote = Normalize(peer), local = Normalize(prefix.local);
    if (!Unicast(remote) || !Unicast(local) || remote.size != local.size || !prefix.bits || prefix.bits > local.size * 8) return false;
    if (LinkLocal(remote) && (!LinkLocal(local) || !remote.scope || remote.scope != local.scope)) return false;
    const unsigned full = prefix.bits / 8, rest = prefix.bits % 8;
    for (unsigned i = 0; i < full; ++i) if (remote.bytes[i] != local.bytes[i]) return false;
    if (rest && ((remote.bytes[full] ^ local.bytes[full]) & (0xff << (8 - rest)))) return false;
    if (remote.size == 4 && prefix.bits < 31) {
        // Exclude directed broadcast and the network address, not just 255.255.255.255.
        bool allZero = true, allOne = true;
        for (unsigned bit = prefix.bits; bit < 32; ++bit) {
            const bool set = (remote.bytes[bit / 8] & (1u << (7 - bit % 8))) != 0;
            allZero &= !set; allOne &= set;
        }
        if (allZero || allOne) return false;
    }
    return true;
}
bool ReadLanPrefixes(std::vector<LanPrefix>& prefixes, DWORD& error) {
    prefixes.clear(); ULONG size = 15000; std::vector<BYTE> buffer;
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        if (size > 1024 * 1024) { error = ERROR_BUFFER_OVERFLOW; return false; }
        buffer.resize(size);
        error = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &size);
        if (error != ERROR_BUFFER_OVERFLOW) break;
    }
    if (error) return false;
    for (auto* adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()); adapter; adapter = adapter->Next) {
        if (adapter->OperStatus != IfOperStatusUp ||
            (adapter->IfType != IF_TYPE_ETHERNET_CSMACD && adapter->IfType != IF_TYPE_IEEE80211)) continue;
        MIB_IF_ROW2 row{}; row.InterfaceLuid = adapter->Luid;
        if (GetIfEntry2(&row) || !row.InterfaceAndOperStatusFlags.HardwareInterface) continue;
        for (auto* address = adapter->FirstUnicastAddress; address; address = address->Next) {
            if (address->DadState != IpDadStatePreferred) continue;
            LanPrefix prefix;
            if (!CopyAddress(address->Address.lpSockaddr, address->Address.iSockaddrLength, prefix.local)) continue;
            prefix.bits = address->OnLinkPrefixLength;
            prefix.interfaceIndex = prefix.local.value.ss_family == AF_INET ? adapter->IfIndex : adapter->Ipv6IfIndex;
            if (SameSubnet(prefix.local, prefix)) prefixes.push_back(prefix);
        }
    }
    if (prefixes.empty()) { error = ERROR_NETWORK_UNREACHABLE; return false; }
    error = 0; return true;
}
bool ResolveHost(const std::string& host, std::uint16_t port, HANDLE cancel, DWORD timeoutMs,
                 std::vector<Address>& addresses, DWORD& error) {
    addresses.clear();
    if (!ValidHost(host) || port < 1024 || !timeoutMs || timeoutMs > 10000) { error = ERROR_INVALID_PARAMETER; return false; }
    if (Cancelled(cancel, error)) return false;
    std::unique_ptr<DnsQuery, ReleaseQuery> query(new DnsQuery);
    if (query->winsock.Error() || !query->completed) {
        error = query->winsock.Error() ? query->winsock.Error() : GetLastError(); query->Release(); return false;
    }
    query->host.assign(host.begin(), host.end()); query->service = std::to_wstring(port);
    query->hints.ai_family = AF_UNSPEC; query->hints.ai_socktype = SOCK_STREAM; query->hints.ai_protocol = IPPROTO_TCP;
    HANDLE cancellation = nullptr;
    const auto result = GetAddrInfoExW(query->host.c_str(), query->service.c_str(), NS_DNS, nullptr,
        &query->hints, &query->results, nullptr, &query->overlapped, DnsQuery::Complete, &cancellation);
    if (result != WSA_IO_PENDING) DnsQuery::Complete(static_cast<DWORD>(result), 0, &query->overlapped);
    HANDLE waits[]{query->completed, cancel};
    const auto wait = WaitForMultipleObjects(cancel ? 2 : 1, waits, FALSE, timeoutMs);
    if (wait != WAIT_OBJECT_0) {
        error = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : wait == WAIT_OBJECT_0 + 1 ? ERROR_CANCELLED : GetLastError();
        if (result == WSA_IO_PENDING && WaitForSingleObject(query->completed, 0) == WAIT_TIMEOUT)
            GetAddrInfoExCancel(&cancellation);
        // Callback retains buffers, event and a Winsock reference until actual
        // completion. Cancellation never frees OVERLAPPED prematurely.
        return false;
    }
    if (Cancelled(cancel, error)) return false;
    if (query->error) { error = query->error; return false; }
    for (auto* address = query->results; address && addresses.size() < 32; address = address->ai_next) {
        Address value;
        if (CopyAddress(address->ai_addr, address->ai_addrlen, value)) addresses.push_back(value);
    }
    error = addresses.empty() ? WSAHOST_NOT_FOUND : 0; return !error;
}
Socket ConnectLan(const std::string& host, std::uint16_t port, HANDLE cancel, DWORD timeoutMs, DWORD& error) {
    const auto deadline = GetTickCount64() + timeoutMs;
    std::vector<Address> addresses;
    if (!ResolveHost(host, port, cancel, timeoutMs, addresses, error)) return {};
    std::vector<LanPrefix> prefixes;
    if (!ReadLanPrefixes(prefixes, error)) return {};
    error = ERROR_ACCESS_DENIED;
    for (const auto& address : addresses) for (const auto& prefix : prefixes) {
        if (Cancelled(cancel, error)) return {};
        if (GetTickCount64() >= deadline) { error = ERROR_TIMEOUT; return {}; }
        if (address.value.ss_family != prefix.local.value.ss_family || !SameSubnet(address, prefix) || !RouteAllows(address, prefix)) continue;
        Socket candidate(WSASocketW(address.value.ss_family, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT));
        if (!candidate) { error = WSAGetLastError(); continue; }
        if (!Configure(candidate.Get(), error)) continue;
        if (bind(candidate.Get(), prefix.local.Get(), prefix.local.size)) { error = WSAGetLastError(); continue; }
        if (connect(candidate.Get(), address.Get(), address.size)) {
            error = WSAGetLastError();
            if (error != WSAEWOULDBLOCK) continue;
            // A dead first address must not starve a reachable second family.
            if (!Ready(candidate.Get(), true, cancel, std::min(deadline, GetTickCount64() + 600), error)) continue;
            int reason = 0, length = sizeof(reason);
            if (getsockopt(candidate.Get(), SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&reason), &length) || reason) {
                error = reason ? static_cast<DWORD>(reason) : WSAGetLastError(); continue;
            }
        }
        error = 0; return candidate;
    }
    return {};
}
bool LanListener::Open(std::uint16_t port, DWORD& error) {
    if (socket_) { error = ERROR_ALREADY_EXISTS; return false; }
    if (port < 1024) { error = ERROR_INVALID_PARAMETER; return false; }
    Socket listener(WSASocketW(AF_INET6, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT));
    if (!listener) { error = WSAGetLastError(); return false; }
    const DWORD dual = 0; const BOOL exclusive = TRUE;
    if (setsockopt(listener.Get(), IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&dual), sizeof(dual)) ||
        setsockopt(listener.Get(), SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&exclusive), sizeof(exclusive))) {
        error = WSAGetLastError(); return false;
    }
    sockaddr_in6 address{}; address.sin6_family = AF_INET6; address.sin6_port = htons(port);
    if (bind(listener.Get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) || listen(listener.Get(), 4)) {
        error = WSAGetLastError(); return false;
    }
    if (!Configure(listener.Get(), error)) return false;
    socket_ = std::move(listener); port_ = port; error = 0; return true;
}
Socket LanListener::Accept(HANDLE cancel, DWORD timeoutMs, DWORD& error) {
    if (!socket_ || !timeoutMs || timeoutMs > 10000) { error = ERROR_INVALID_PARAMETER; return {}; }
    if (!Ready(socket_.Get(), false, cancel, GetTickCount64() + timeoutMs, error)) return {};
    Address remote; remote.size = sizeof(remote.value);
    Socket accepted(accept(socket_.Get(), reinterpret_cast<sockaddr*>(&remote.value), &remote.size));
    if (!accepted) { error = WSAGetLastError(); return {}; }
    // accept() inherits socket properties, but explicitly forbid child-process
    // inheritance and nonblocking/nodelay behavior on the accepted endpoint.
    if (!SetHandleInformation(reinterpret_cast<HANDLE>(accepted.Get()), HANDLE_FLAG_INHERIT, 0)) { error = GetLastError(); return {}; }
    if (!Configure(accepted.Get(), error)) return {};
    Address local; local.size = sizeof(local.value);
    if (getsockname(accepted.Get(), reinterpret_cast<sockaddr*>(&local.value), &local.size)) { error = WSAGetLastError(); return {}; }
    std::vector<LanPrefix> prefixes;
    if (!ReadLanPrefixes(prefixes, error)) return {};
    const auto own = Normalize(local);
    for (const auto& prefix : prefixes) {
        const auto candidate = Normalize(prefix.local);
        if (own.size == candidate.size && own.bytes == candidate.bytes && own.scope == candidate.scope && SameSubnet(remote, prefix)) {
            error = 0; return accepted;
        }
    }
    error = ERROR_ACCESS_DENIED; return {};
}
} // namespace capslang::net
