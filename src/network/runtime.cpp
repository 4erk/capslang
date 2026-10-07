#include "runtime.hpp"
#include <atomic>
#include <mutex>
#include <thread>

namespace capslang::net {
namespace {
void Wipe(std::string& value) { if (!value.empty()) SecureZeroMemory(value.data(),value.size()); value.clear(); }
bool OrdinaryToken(DWORD& error) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)) { error = GetLastError(); return false; }
    TOKEN_ELEVATION elevation{}; DWORD bytes = 0;
    const bool read = GetTokenInformation(token,TokenElevation,&elevation,sizeof(elevation),&bytes) != FALSE;
    error = read ? elevation.TokenIsElevated ? ERROR_ACCESS_DENIED : ERROR_SUCCESS : GetLastError();
    CloseHandle(token); return read && !elevation.TokenIsElevated;
}
}
struct NetworkRuntime::Impl {
    enum class Action { None, Invite, Join, Unpair };
    std::wstring directory, identityPath, pairPath;
    SessionEndpoint engine;
    std::shared_ptr<ReconnectCheckpoint> checkpoint = std::make_shared<ReconnectCheckpoint>();
    mutable std::mutex mutex;
    NetworkStatus status;
    Action action = Action::None;
    std::string argument;
    std::uint16_t port = 0;
    PairApproval approval = PairApproval::Pending;
    std::uint64_t nextTicket = 0;
    HANDLE wake = nullptr, cancel = nullptr;
    std::thread worker;
    std::atomic<bool> stopping{false};
    Impl(std::wstring root, SessionEndpoint endpoint) : directory(std::move(root)), engine(std::move(endpoint)) {
        identityPath = directory + L"\\identity.dat"; pairPath = directory + L"\\pair.dat";
    }
    ~Impl() { if (wake) CloseHandle(wake); if (cancel) CloseHandle(cancel); Wipe(argument); Wipe(status.invitation); }
    void Publish(NetworkPhase phase, DWORD error = 0) {
        std::lock_guard<std::mutex> lock(mutex); status.phase = phase; status.error = error;
        if (error) { status.lastError = error; status.lastErrorAt = GetTickCount64(); }
        if (phase != NetworkPhase::Inviting && phase != NetworkPhase::AwaitApproval) Wipe(status.invitation);
        if (phase != NetworkPhase::AwaitApproval) { status.pendingPeer = {}; status.approvalTicket = 0; approval = PairApproval::Pending; }
        if (phase != NetworkPhase::Active && phase != NetworkPhase::AwaitInput) status.session = {};
    }
    bool Submit(Action kind, std::string value, std::uint16_t selectedPort, DWORD& error) {
        std::lock_guard<std::mutex> lock(mutex);
        if (!worker.joinable() || stopping || status.phase == NetworkPhase::Error || status.phase == NetworkPhase::Stopped) {
            Wipe(value); error = ERROR_NOT_READY; return false;
        }
        if (kind == Action::Unpair && action == Action::Unpair) { Wipe(value); error = 0; return true; }
        if (action != Action::None || (kind != Action::Unpair && status.paired) ||
            (kind != Action::Unpair && status.phase != NetworkPhase::Unpaired)) {
            Wipe(value); error = ERROR_BUSY; return false;
        }
        action = kind; argument = std::move(value); port = selectedPort;
        // Reset and submission share the mutex: cancellation cannot be lost
        // between checking an empty command slot and entering a socket wait.
        SetEvent(cancel); SetEvent(wake); error = 0; return true;
    }
    PairApproval ApprovalFor(const Pin& peer) {
        std::lock_guard<std::mutex> lock(mutex);
        if (stopping || action != Action::None) return PairApproval::Deny;
        if (status.phase != NetworkPhase::AwaitApproval) {
            status.phase = NetworkPhase::AwaitApproval; status.pendingPeer = peer;
            status.approvalTicket = ++nextTicket; approval = PairApproval::Pending;
        }
        return EqualPin(status.pendingPeer,peer) ? approval : PairApproval::Deny;
    }
    void InviteLoop(const Identity& identity, const std::string& host, std::uint16_t selectedPort, LanListener& listener) {
        DWORD error = 0; InvitationGate gate;
        if (listener.Port() != selectedPort) listener.Close();
        if (!gate.Open(identity,host,selectedPort,GetTickCount64(),error) ||
            (!listener.Port() && !listener.Open(selectedPort,error))) {
            Publish(NetworkPhase::Unpaired,error); return;
        }
        std::string code;
        if (!gate.Code(GetTickCount64(),code)) { Publish(NetworkPhase::Unpaired,ERROR_TIMEOUT); return; }
        { std::lock_guard<std::mutex> lock(mutex); status.phase = NetworkPhase::Inviting; status.error = 0; status.invitation = code; }
        Wipe(code);
        while (!stopping && WaitForSingleObject(cancel,0) != WAIT_OBJECT_0 && gate.State(GetTickCount64()) == InvitationState::Open) {
            auto connection = listener.Accept(cancel,500,error);
            if (!connection) { if (error == ERROR_TIMEOUT) continue; break; }
            TlsChannel tls(connection.Get(),cancel);
            const bool complete = ServeInvitationConnection(tls,identity,gate,pairPath,
                [this](const Pin& peer) { return ApprovalFor(peer); },error);
            // A saved confirmation is durable even if its final delivery was
            // lost. Main loop reloads it and accepts mutually pinned Resume.
            PairRecord saved; DWORD loadError = 0;
            if (complete || LoadPair(pairPath,identity.Fingerprint(),saved,loadError)) break;
            Publish(NetworkPhase::Inviting,error);
        }
        gate.Cancel(); Publish(NetworkPhase::Unpaired,error);
    }
    void JoinOnce(const Identity& identity, const std::string& code) {
        InvitationCode invitation;
        if (!DecodeInvitation(code,invitation)) { Publish(NetworkPhase::Unpaired,ERROR_INVALID_DATA); return; }
        struct WipeProof { InvitationSecret& value; ~WipeProof() { SecureZeroMemory(value.data(),value.size()); } } wipe{invitation.secret};
        Publish(NetworkPhase::Joining);
        DWORD error = 0;
        // First recover an already-approved pair. An unpaired server refuses
        // this mode without displaying an approval or accepting language data.
        for (bool resume : {true,false}) {
            if (stopping || WaitForSingleObject(cancel,0) == WAIT_OBJECT_0) break;
            auto connection = ConnectLan(invitation.host,invitation.port,cancel,1500,error);
            if (!connection) break;
            TlsChannel tls(connection.Get(),cancel);
            if (OpenInvitationConnection(tls,identity,invitation,pairPath,resume,error)) break;
            PairRecord saved; DWORD loadError = 0;
            if (LoadPair(pairPath,identity.Fingerprint(),saved,loadError)) break;
        }
        Publish(NetworkPhase::Unpaired,error);
    }
    void PairedRound(const Identity& identity, const PairRecord& pair, LanListener& listener) {
        DWORD error = 0;
        SessionEndpoint endpoint = engine;
        endpoint.checkpoint = checkpoint;
        endpoint.publish = [this](const SessionStatus& value) {
            { std::lock_guard<std::mutex> lock(mutex); status.session = value; }
            Publish(value.phase == SessionPhase::Active ? NetworkPhase::Active :
                    value.phase == SessionPhase::AwaitInput ? NetworkPhase::AwaitInput : NetworkPhase::Connecting,value.error);
            if (engine.publish) engine.publish(value);
        };
        Publish(NetworkPhase::Connecting);
        sync::LocalState local;
        // The paired listener must also remain available for half-committed
        // enrollment recovery while MWB is stopped. RunSession itself refuses
        // language synchronization unless both endpoints report ready MWB.
        if (!pair.listener && (!engine.read(local) || !local.snapshot.mwb)) {
            Publish(NetworkPhase::Connecting,ERROR_SERVICE_NOT_ACTIVE); return;
        }
        if (pair.listener && listener.Port() != pair.port) listener.Close();
        if (pair.listener && !listener.Port() && !listener.Open(pair.port,error)) { Publish(NetworkPhase::Connecting,error); return; }
        auto connection = pair.listener ? listener.Accept(cancel,1000,error) : ConnectLan(pair.host,pair.port,cancel,1500,error);
        if (!connection) { Publish(NetworkPhase::Connecting,error); return; }
        TlsChannel tls(connection.Get(),cancel);
        if (pair.listener) ServePairedConnection(tls,identity,pair,endpoint,cancel,error);
        else OpenPairedConnection(tls,identity,pair,endpoint,cancel,error);
        Publish(NetworkPhase::Connecting,error);
    }
    void Run() {
        DWORD error = 0;
        Winsock winsock;
        if (winsock.Error()) { Publish(NetworkPhase::Error,winsock.Error()); return; }
        // The parent directory is the current user's chosen app-data directory.
        if (!CreateDirectoryW(directory.c_str(),nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) {
            Publish(NetworkPhase::Error,GetLastError()); return;
        }
        Identity identity;
        if (!identity.Load(identityPath,error)) {
            if (error != ERROR_FILE_NOT_FOUND || !identity.Generate(error) || !identity.Save(identityPath,error)) {
                Publish(NetworkPhase::Error,error); return;
            }
        }
        { std::lock_guard<std::mutex> lock(mutex); status.local = identity.Fingerprint(); }
        // Keep the exclusive listener across TLS disconnects, invite approval
        // and subsequent Resume. Closing/rebinding it every round can turn a
        // normal TCP TIME_WAIT into a minutes-long reconnection failure.
        // Unpair cancels/ends its active connection. No sockets are accepted
        // while unpaired without an explicit invite. Stop closes the listener.
        LanListener listener;
        while (!stopping) {
            Action current; std::string value; std::uint16_t selectedPort;
            {
                std::lock_guard<std::mutex> lock(mutex);
                if (stopping) break;
                current = action; action = Action::None; value.swap(argument); selectedPort = port;
                ResetEvent(cancel);
            }
            if (current == Action::Unpair) {
                if (!RemovePair(pairPath,error)) { Publish(NetworkPhase::Error,error); return; }
                *checkpoint = {};
            }
            PairRecord pair;
            const bool paired = LoadPair(pairPath,identity.Fingerprint(),pair,error);
            if (!paired && error != ERROR_FILE_NOT_FOUND) { Wipe(value); Publish(NetworkPhase::Error,error); return; }
            { std::lock_guard<std::mutex> lock(mutex);
              status.paired = paired; status.listener = paired && pair.listener; status.peer = paired ? pair.peer : Pin{}; }
            if (paired) PairedRound(identity,pair,listener);
            else if (current == Action::Invite) InviteLoop(identity,value,selectedPort,listener);
            else if (current == Action::Join) JoinOnce(identity,value);
            else Publish(NetworkPhase::Unpaired);
            Wipe(value);
            if (!stopping) WaitForSingleObject(wake,paired ? 750 : 100);
        }
        Publish(NetworkPhase::Stopped);
    }
};
NetworkRuntime::NetworkRuntime(std::wstring root, SessionEndpoint engine)
    : impl_(std::make_unique<Impl>(std::move(root),std::move(engine))) {}
NetworkRuntime::~NetworkRuntime() { Stop(); }
bool NetworkRuntime::Start() {
    auto& self = *impl_;
    if (self.worker.joinable()) return true;
    DWORD error = 0;
    if (!OrdinaryToken(error) || self.directory.empty() || !self.engine.read || !self.engine.queue) {
        self.Publish(NetworkPhase::Error,error ? error : ERROR_INVALID_PARAMETER); return false;
    }
    if (!self.wake) self.wake = CreateEventW(nullptr,FALSE,FALSE,nullptr);
    if (!self.cancel) self.cancel = CreateEventW(nullptr,TRUE,FALSE,nullptr);
    if (!self.wake || !self.cancel) { self.Publish(NetworkPhase::Error,GetLastError()); return false; }
    self.stopping = false; self.Publish(NetworkPhase::Starting);
    try {
        self.worker = std::thread([&self] {
            try { self.Run(); } catch (...) { self.Publish(NetworkPhase::Error,ERROR_UNHANDLED_EXCEPTION); }
        });
    } catch (...) { self.Publish(NetworkPhase::Error,ERROR_NOT_ENOUGH_MEMORY); return false; }
    return true;
}
void NetworkRuntime::Stop() {
    auto& self = *impl_; if (!self.worker.joinable()) return;
    { std::lock_guard<std::mutex> lock(self.mutex); self.stopping = true;
      self.action = Impl::Action::None; Wipe(self.argument); self.approval = PairApproval::Deny;
      SetEvent(self.cancel); SetEvent(self.wake); }
    self.worker.join();
}
NetworkStatus NetworkRuntime::Status() const { std::lock_guard<std::mutex> lock(impl_->mutex); return impl_->status; }
bool NetworkRuntime::Invite(std::string host, std::uint16_t port, DWORD& error) {
    if (!ValidHost(host) || port < 1024) { error = ERROR_INVALID_PARAMETER; return false; }
    return impl_->Submit(Impl::Action::Invite,std::move(host),port,error);
}
bool NetworkRuntime::Join(const std::string& code, DWORD& error) {
    InvitationCode parsed;
    if (!DecodeInvitation(code,parsed)) { error = ERROR_INVALID_DATA; return false; }
    SecureZeroMemory(parsed.secret.data(),parsed.secret.size());
    return impl_->Submit(Impl::Action::Join,code,0,error);
}
bool NetworkRuntime::Confirm(std::uint64_t ticket, const Pin& peer, bool allow, DWORD& error) {
    auto& self = *impl_; std::lock_guard<std::mutex> lock(self.mutex);
    if (self.stopping || self.status.phase != NetworkPhase::AwaitApproval || !ticket ||
        ticket != self.status.approvalTicket || !EqualPin(peer,self.status.pendingPeer)) { error = ERROR_INVALID_STATE; return false; }
    self.approval = allow ? PairApproval::Allow : PairApproval::Deny; error = 0; return true;
}
bool NetworkRuntime::Unpair(DWORD& error) {
    // An explicit unpair can repair a corrupt pair record; never silently
    // replace an unreadable identity or create a new peer on its behalf.
    if (Status().phase == NetworkPhase::Error) {
        Stop();
        if (!RemovePair(impl_->pairPath,error)) return false;
        if (!Start()) { error = Status().error; return false; }
        error = 0; return true;
    }
    return impl_->Submit(Impl::Action::Unpair,{},0,error);
}
} // namespace capslang::net
