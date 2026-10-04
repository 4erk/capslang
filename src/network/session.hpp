#pragma once
#include "tls.hpp"
#include "../core/session_wire.hpp"
#include <functional>

namespace capslang::net {
enum class SessionPhase { Reconciling, AwaitInput, Active, Ended };
struct SessionStatus {
    SessionPhase phase = SessionPhase::Reconciling;
    sync::Language target = sync::Language::Unknown;
    sync::Applied peerApplied = sync::Applied::None;
    DWORD error = 0;
};
struct SessionEndpoint {
    // Must sample the actual engine and a separately verified recipient source.
    std::function<bool(sync::LocalState&)> read;
    std::function<bool(const sync::ApplyCommand&)> queue;
    std::function<void(const SessionStatus&)> publish;
};
// Single ordinary worker owns TLS and IPC. Local hooks never wait on it.
// coordinator is a transport role only. Connection IDs are random, identities
// derive from the mutually pinned certificates, and all requests are absolute.
bool RunSession(TlsChannel& tls, const Identity& identity, bool coordinator,
                const SessionEndpoint& endpoint, HANDLE cancel, DWORD& error);
} // namespace capslang::net
