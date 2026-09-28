#pragma once
#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#include <winsock2.h>
#include "../platform/windows_support.hpp"
#include <security.h>
#include <schannel.h>
#include <ncrypt.h>
#include <wincrypt.h>
#include <array>
#include <memory>

namespace capslang::net {
using Pin = std::array<BYTE, 32>;
bool EqualPin(const Pin& a, const Pin& b);
bool CertificatePin(PCCERT_CONTEXT certificate, Pin& pin);
class Identity {
public:
    Identity() = default;
    ~Identity();
    Identity(const Identity&) = delete;
    Identity& operator=(const Identity&) = delete;
    bool Generate(DWORD& error);
    PCCERT_CONTEXT Certificate() const { return certificate_; }
    Pin Fingerprint() const;
private:
    NCRYPT_PROV_HANDLE provider_ = 0;
    NCRYPT_KEY_HANDLE key_ = 0;
    PCCERT_CONTEXT certificate_ = nullptr;
};
// Socket ownership stays with caller. No roots are installed; the peer must
// prove possession of the private key for the exact out-of-band pinned cert.
// Only the invitation listener can explicitly opt into a temporary unpinned
// client; that channel MUST NOT carry state until separate pairing approval.
class TlsChannel {
public:
    explicit TlsChannel(SOCKET socket, HANDLE cancel = nullptr);
    ~TlsChannel();
    TlsChannel(const TlsChannel&) = delete;
    TlsChannel& operator=(const TlsChannel&) = delete;
    bool Handshake(const Identity& identity, bool server, const Pin& expected,
                   bool temporaryInvitationClient = false);
    bool Send(const void* data, size_t bytes);
    bool Receive(std::vector<BYTE>& data);
    DWORD Error() const;
    Pin Peer() const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace capslang::net
