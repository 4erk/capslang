#include "../src/network/lan.hpp"
#include <cstdio>
#include <thread>

using namespace capslang::net;
namespace {
unsigned checks = 0, failures = 0;
void Check(bool value, const char* name) { ++checks; if (!value) { ++failures; std::printf("FAIL %s\n", name); } }
Address V4(const char* text) {
    Address result; result.size = sizeof(sockaddr_in);
    auto& ip = reinterpret_cast<sockaddr_in&>(result.value); ip.sin_family = AF_INET;
    inet_pton(AF_INET, text, &ip.sin_addr); return result;
}
Address V6(const char* text, ULONG scope = 0) {
    Address result; result.size = sizeof(sockaddr_in6);
    auto& ip = reinterpret_cast<sockaddr_in6&>(result.value); ip.sin6_family = AF_INET6; ip.sin6_scope_id = scope;
    inet_pton(AF_INET6, text, &ip.sin6_addr); return result;
}
void Prefixes() {
    LanPrefix v4{V4("192.168.0.198"), 24, 4};
    Check(SameSubnet(V4("192.168.0.199"), v4), "IPv4 LAN peer");
    Check(!SameSubnet(V4("192.168.1.199"), v4), "other subnet rejected");
    Check(!SameSubnet(V4("8.8.8.8"), v4), "public Internet rejected");
    Check(!SameSubnet(V4("192.168.0.255"), v4), "directed broadcast rejected");
    Check(!SameSubnet(V4("192.168.0.0"), v4), "network address rejected");
    Check(!SameSubnet(V4("127.0.0.1"), {V4("127.0.0.2"), 8, 1}), "no loopback policy bypass");
    Check(!SameSubnet(V4("224.0.0.1"), {V4("224.0.0.2"), 8, 1}), "multicast rejected");
    Check(!SameSubnet(V4("0.1.2.3"), {V4("0.1.2.4"), 8, 1}), "unspecified network rejected");
    Check(!SameSubnet(V4("192.168.0.199"), {v4.local, 0, 4}), "default-route prefix rejected");
    Check(!SameSubnet(V4("192.168.0.199"), {v4.local, 33, 4}), "oversized IPv4 prefix rejected");
    Check(SameSubnet(V6("::ffff:192.168.0.199"), v4), "dual-stack mapped peer normalized");
    Check(!SameSubnet(V6("::ffff:127.0.0.1"), v4), "mapped loopback rejected");
    for (unsigned bits = 1; bits <= 32; ++bits) {
        LanPrefix p{V4("192.168.0.198"), bits, 4};
        Check(SameSubnet(p.local, p), "own unicast accepted across IPv4 prefix lengths");
    }
    Check(SameSubnet(V4("192.168.0.199"), {v4.local, 31, 4}), "RFC3021 endpoint accepted");
    Check(!SameSubnet(V4("192.168.0.199"), {v4.local, 32, 4}), "host route excludes neighbor");
    LanPrefix v6{V6("fe80::1234", 7), 64, 7};
    Check(SameSubnet(V6("fe80::5678", 7), v6), "IPv6 link-local correct scope");
    Check(!SameSubnet(V6("fe80::5678", 8), v6), "IPv6 other adapter scope rejected");
    Check(!SameSubnet(V6("fe80::5678"), v6), "IPv6 missing scope rejected");
    Check(!SameSubnet(V6("ff02::1", 7), v6), "IPv6 multicast rejected");
    Check(!SameSubnet(V6("::"), v6) && !SameSubnet(V6("::1"), v6), "IPv6 unspecified and loopback rejected");
    LanPrefix global{V6("2001:db8:1:2::1"), 64, 4};
    Check(SameSubnet(V6("2001:db8:1:2::7"), global), "IPv6 globally addressed on-link LAN accepted");
    Check(!SameSubnet(V6("2001:db8:1:3::7"), global), "IPv6 off-link rejected");
    Address truncated = V4("192.168.0.199"); --truncated.size;
    Check(!SameSubnet(truncated, v4), "truncated sockaddr rejected");
}
void Resolver() {
    DWORD error = 0; std::vector<Address> addresses;
    Check(ResolveHost("127.0.0.1", 45329, nullptr, 1500, addresses, error) && !addresses.empty(), "bounded numeric resolution");
    Check(ResolveHost("localhost", 45329, nullptr, 1500, addresses, error) && !addresses.empty(), "bounded host resolution");
    Check(!ResolveHost("localhost|bad", 45329, nullptr, 1500, addresses, error) && addresses.empty() && error == ERROR_INVALID_PARAMETER, "invalid host clears previous results");
    Check(!ResolveHost("localhost", 1, nullptr, 1500, addresses, error), "reserved port denied");
    Check(!ResolveHost("localhost", 45329, nullptr, 0, addresses, error), "zero deadline denied");
    HANDLE stop = CreateEventW(nullptr, TRUE, TRUE, nullptr);
    Check(stop != nullptr, "cancel event created");
    const auto start = GetTickCount64();
    Check(!ResolveHost("localhost", 45329, stop, 1500, addresses, error) && error == ERROR_CANCELLED, "pre-cancelled DNS rejected");
    Check(GetTickCount64() - start < 200, "cancel does not wait for DNS timeout");
    Check(!ConnectLan("127.0.0.1", 45329, stop, 1500, error) && error == ERROR_CANCELLED, "pre-cancelled connection rejected");
    CloseHandle(stop);
    Check(!ConnectLan("127.0.0.1", 45329, nullptr, 1500, error), "production connector rejects loopback");
    Check(!ConnectLan("203.0.113.197", 45329, nullptr, 1500, error), "documentation-range off-LAN endpoint rejected before connect");
}
void Listener() {
    DWORD error = 0;
    LanListener listener;
    Check(!listener.Open(1, error) && error == ERROR_INVALID_PARAMETER, "listener reserved port denied");
    // Choose a free high port using the OS. No firewall changes, packets stay
    // on this machine, no TLS secrets/config/application state involved.
    Socket chooser(socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP));
    sockaddr_in6 address{}; address.sin6_family = AF_INET6;
    Check(chooser && bind(chooser.Get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0, "ephemeral test port bound");
    int size = sizeof(address);
    Check(getsockname(chooser.Get(), reinterpret_cast<sockaddr*>(&address), &size) == 0, "test port read");
    const auto port = ntohs(address.sin6_port); chooser.Reset();
    Check(listener.Open(port, error), "dual-stack exclusive LAN listener");
    if (error) { std::printf("Listener setup error=%lu\n", error); return; }
    Check(!listener.Open(port, error) && error == ERROR_ALREADY_EXISTS, "duplicate listener open refused");
    LanListener duplicate;
    Check(!duplicate.Open(port, error), "other listener cannot hijack bound port");
    HANDLE stop = CreateEventW(nullptr, TRUE, TRUE, nullptr);
    Check(!listener.Accept(stop, 1000, error) && error == ERROR_CANCELLED, "accept cancellation");
    CloseHandle(stop);
    const auto start = GetTickCount64();
    Check(!listener.Accept(nullptr, 80, error) && error == ERROR_TIMEOUT, "idle accept bounded");
    Check(GetTickCount64() - start < 500, "idle accept returns promptly");
    Socket client(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    sockaddr_in local{}; local.sin_family = AF_INET; local.sin_port = htons(port); local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    Check(connect(client.Get(), reinterpret_cast<sockaddr*>(&local), sizeof(local)) == 0, "loopback reaches dual-stack socket");
    Check(!listener.Accept(nullptr, 1500, error) && error == ERROR_ACCESS_DENIED, "listener refuses loopback before any TLS or application request");
    listener.Close(); listener.Close();
    Check(!listener.Accept(nullptr, 100, error) && error == ERROR_INVALID_PARAMETER, "closed listener refuses accept");
}
}
int main() {
    Winsock winsock;
    if (winsock.Error()) return 2;
    Prefixes(); Resolver(); Listener();
    std::vector<LanPrefix> prefixes; DWORD error = 0;
    const bool found = ReadLanPrefixes(prefixes, error);
    std::printf("LAN discovery: ready=%d physical_prefixes=%zu error=%lu (no addresses logged).\n", found, prefixes.size(), error);
    Check(found || (error != 0 && prefixes.empty()), "adapter discovery fails closed without physical LAN");
    std::printf("Windows LAN: %u checks, %u failures; policy and local sockets only, not two-device acceptance.\n", checks, failures);
    return failures ? 1 : 0;
}
