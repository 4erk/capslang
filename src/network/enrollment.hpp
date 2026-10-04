#pragma once
#include "pairing.hpp"
#include <functional>

namespace capslang::net {
enum class PairApproval { Pending, Allow, Deny };
// Called by an ordinary, network-capable worker, never by the elevated engine.
// Approval callback is nonblocking and represents a UI reply for the EXACT pin.
// On return the caller closes this TLS connection, including on success. The
// next connection must mutually pin both certificates before state can flow.
bool EnrollServer(TlsChannel& channel, InvitationGate& gate, const std::wstring& pairPath,
                  const std::function<PairApproval(const Pin&)>& approval, DWORD& error);
bool EnrollClient(TlsChannel& channel, const Identity& identity, const InvitationCode& invitation,
                  const std::wstring& pairPath, DWORD& error);
// Recover an uncertain confirmation/delivery using the already-approved pair.
// The server must have authenticated this exact peer with its persisted pin.
// No new invitation or user approval is bypassed for an unknown certificate.
bool ResumeEnrollmentServer(TlsChannel& channel, const PairRecord& approved, DWORD& error);
bool ResumeEnrollmentClient(TlsChannel& channel, const Identity& identity, const InvitationCode& endpoint,
                            const std::wstring& pairPath, DWORD& error);
} // namespace capslang::net
