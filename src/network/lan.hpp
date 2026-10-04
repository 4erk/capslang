#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace capslang::net {
// Winsock must outlive sockets/channels. A pending DNS query holds its own
// Winsock reference until the asynchronous completion releases its context.
class Winsock {
public:
    Winsock();
    ~Winsock();
    Winsock(const Winsock&) = delete;
    Winsock& operator=(const Winsock&) = delete;
    DWORD Error() const { return error_; }
private:
    DWORD error_ = 0;
};
class Socket {
public:
    Socket() = default;
    explicit Socket(SOCKET value) : value_(value) {}
    ~Socket() { Reset(); }
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    Socket(Socket&& other) noexcept : value_(other.Release()) {}
    Socket& operator=(Socket&& other) noexcept { if (this != &other) Reset(other.Release()); return *this; }
    SOCKET Get() const { return value_; }
    explicit operator bool() const { return value_ != INVALID_SOCKET; }
    SOCKET Release() { const auto value = value_; value_ = INVALID_SOCKET; return value; }
    void Reset(SOCKET value = INVALID_SOCKET) { if (value_ != INVALID_SOCKET) closesocket(value_); value_ = value; }
private:
    SOCKET value_ = INVALID_SOCKET;
};
struct Address {
    sockaddr_storage value{};
    int size = 0;
    const sockaddr* Get() const { return reinterpret_cast<const sockaddr*>(&value); }
};
struct LanPrefix {
    Address local;
    unsigned bits = 0;
    ULONG interfaceIndex = 0;
};
bool SameSubnet(const Address& peer, const LanPrefix& prefix);
bool ReadLanPrefixes(std::vector<LanPrefix>& prefixes, DWORD& error);
bool ResolveHost(const std::string& host, std::uint16_t port, HANDLE cancel,
                 DWORD timeoutMs, std::vector<Address>& addresses, DWORD& error);
// No test/CLI override to accept non-LAN addresses. Both directions check
// physical Ethernet/Wi-Fi on-link prefixes. Outbound additionally verifies
// the best route and binds the chosen local address (no VPN route bypass).
Socket ConnectLan(const std::string& host, std::uint16_t port, HANDLE cancel,
                  DWORD timeoutMs, DWORD& error);
class LanListener {
public:
    bool Open(std::uint16_t port, DWORD& error);
    Socket Accept(HANDLE cancel, DWORD timeoutMs, DWORD& error);
    void Close() { socket_.Reset(); port_ = 0; }
    std::uint16_t Port() const { return port_; }
private:
    Socket socket_;
    std::uint16_t port_ = 0;
};
} // namespace capslang::net
