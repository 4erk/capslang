#pragma once
#include "application_mode.hpp"
#include "enrollment.hpp"
#include "session.hpp"

namespace capslang::net {
// Caller owns sockets, identity and cancellation. Paths and callbacks are
// selected by the ordinary application, never received from the peer.
bool ServePairedConnection(TlsChannel& channel, const Identity& identity,
    const PairRecord& pair, const SessionEndpoint& endpoint, HANDLE cancel, DWORD& error);
bool OpenPairedConnection(TlsChannel& channel, const Identity& identity,
    const PairRecord& pair, const SessionEndpoint& endpoint, HANDLE cancel, DWORD& error);
bool ServeInvitationConnection(TlsChannel& channel, const Identity& identity,
    InvitationGate& gate, const std::wstring& pairPath,
    const std::function<PairApproval(const Pin&)>& approval, DWORD& error);
bool OpenInvitationConnection(TlsChannel& channel, const Identity& identity,
    const InvitationCode& code, const std::wstring& pairPath, bool resume, DWORD& error);
} // namespace capslang::net
