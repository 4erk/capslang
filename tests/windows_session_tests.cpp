#include "../src/network/session.hpp"
#include "../src/network/lan.hpp"
#include <mutex>
#include <thread>
#include <cstdio>

using namespace capslang;
using namespace capslang::net;
namespace {
unsigned checks = 0, failures = 0;
void Check(bool value, const char* name) { ++checks; if (!value) { ++failures; std::printf("FAIL %s\n", name); } }
template<class Predicate> bool Until(Predicate predicate, DWORD timeout = 3000) {
    const auto deadline = GetTickCount64() + timeout;
    do { if (predicate()) return true; Sleep(10); } while (GetTickCount64() < deadline);
    return predicate();
}
struct Model {
    std::mutex mutex;
    sync::LocalState state;
    SessionStatus status;
    ULONGLONG at = GetTickCount64(), due = 0;
    bool refuse = false;
    unsigned queued = 0;
    Model(core::Language language, unsigned age) {
        state = {{1, 0, 1, language, {age, age, true}, true}, language, core::ApplyState::Applied, false};
    }
    SessionEndpoint Endpoint() {
        return {
            [this](sync::LocalState& result) {
                std::lock_guard<std::mutex> lock(mutex);
                const auto now = GetTickCount64();
                if (due && now >= due && !state.locked) {
                    if (!refuse) { state.actual = state.snapshot.language; state.apply = core::ApplyState::Applied; }
                    else state.apply = core::ApplyState::Failed;
                    due = 0;
                }
                result = state;
                if (result.snapshot.activity.known) {
                    result.snapshot.activity.minimum += now - at; result.snapshot.activity.maximum += now - at;
                }
                return true;
            },
            [this](const sync::ApplyCommand& command) {
                std::lock_guard<std::mutex> lock(mutex);
                if (state.snapshot.engineEpoch != command.engineEpoch || state.snapshot.userRevision != command.expectedRevision) return false;
                ++queued; state.snapshot.language = command.language;
                state.apply = state.locked ? core::ApplyState::Locked : core::ApplyState::Pending;
                due = GetTickCount64() + 200; return true;
            },
            [this](const SessionStatus& value) { std::lock_guard<std::mutex> lock(mutex); status = value; }
        };
    }
    void Manual(core::Language language) {
        std::lock_guard<std::mutex> lock(mutex);
        ++state.snapshot.userRevision; ++state.snapshot.activitySerial;
        state.snapshot.language = state.actual = language; state.apply = core::ApplyState::Applied;
        state.snapshot.activity = {0, 0, true}; at = GetTickCount64(); due = 0;
    }
    void Activity() {
        std::lock_guard<std::mutex> lock(mutex);
        ++state.snapshot.activitySerial; state.snapshot.activity = {0, 0, true}; at = GetTickCount64();
    }
    sync::LocalState Read() { sync::LocalState result; Endpoint().read(result); return result; }
    SessionStatus Status() { std::lock_guard<std::mutex> lock(mutex); return status; }
    unsigned Commands() { std::lock_guard<std::mutex> lock(mutex); return queued; }
};
struct Connection {
    Socket listener, client, accepted;
    HANDLE cancel = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    std::thread serverThread, clientThread;
    DWORD serverError = 0, clientError = 0;
    bool serverHandshake = false, clientHandshake = false;
    bool Start(const Identity& serverIdentity, const Identity& clientIdentity, Model& server, Model& peer) {
        listener.Reset(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
        sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        int size = sizeof(address);
        if (!cancel || !listener || bind(listener.Get(), reinterpret_cast<sockaddr*>(&address), size) ||
            listen(listener.Get(), 1) || getsockname(listener.Get(), reinterpret_cast<sockaddr*>(&address), &size)) return false;
        client.Reset(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
        if (!client || connect(client.Get(), reinterpret_cast<sockaddr*>(&address), size)) return false;
        accepted.Reset(accept(listener.Get(), nullptr, nullptr)); if (!accepted) return false;
        listener.Reset();
        serverThread = std::thread([&, this] {
            TlsChannel tls(accepted.Get(), cancel); serverHandshake = tls.Handshake(serverIdentity, true, clientIdentity.Fingerprint());
            if (serverHandshake) RunSession(tls, serverIdentity, true, server.Endpoint(), cancel, serverError);
            else serverError = tls.Error();
            shutdown(accepted.Get(), SD_BOTH);
        });
        clientThread = std::thread([&, this] {
            TlsChannel tls(client.Get(), cancel); clientHandshake = tls.Handshake(clientIdentity, false, serverIdentity.Fingerprint());
            if (clientHandshake) RunSession(tls, clientIdentity, false, peer.Endpoint(), cancel, clientError);
            else clientError = tls.Error();
            shutdown(client.Get(), SD_BOTH);
        });
        return true;
    }
    void Stop() {
        if (cancel) SetEvent(cancel);
        if (serverThread.joinable()) serverThread.join(); if (clientThread.joinable()) clientThread.join();
    }
    ~Connection() { Stop(); if (cancel) CloseHandle(cancel); }
};
bool Active(Model& a, Model& b) { return a.Status().phase == SessionPhase::Active && b.Status().phase == SessionPhase::Active; }
bool Applied(Model& a, Model& b, core::Language language) {
    return a.Read().actual == language && b.Read().actual == language &&
        a.Status().peerApplied == sync::Applied::Yes && b.Status().peerApplied == sync::Applied::Yes;
}
void Online(const Identity& server, const Identity& client) {
    Model coordinator(core::Language::English, 10000), follower(core::Language::Russian, 100);
    Connection connection;
    Check(connection.Start(server, client, coordinator, follower), "real TLS broker connection started");
    Check(Until([&] { return Active(coordinator, follower) && Applied(coordinator, follower, core::Language::Russian); }),
          "newer follower wins negotiation and actual application is acknowledged both ways");
    Check(coordinator.Read().snapshot.userRevision == 0 && follower.Read().snapshot.userRevision == 0,
          "negotiated application does not forge local user revisions");
    follower.Manual(core::Language::English);
    Check(Until([&] { return Applied(coordinator, follower, core::Language::English); }, 1000), "manual follower change synchronized and confirmed under one second");
    coordinator.Manual(core::Language::Russian);
    Check(Until([&] { return Applied(coordinator, follower, core::Language::Russian); }, 1000), "manual coordinator change synchronized and confirmed under one second");
    { std::lock_guard<std::mutex> lock(follower.mutex); follower.state.locked = true; follower.state.apply = core::ApplyState::Locked; }
    coordinator.Manual(core::Language::English);
    Check(Until([&] { return coordinator.Status().peerApplied == sync::Applied::Locked; }), "locked peer reports Locked, not success");
    Check(follower.Read().actual == core::Language::Russian, "locked model receives target without changing its desktop");
    { std::lock_guard<std::mutex> lock(follower.mutex); follower.state.locked = false; follower.state.apply = core::ApplyState::Pending; }
    Check(Until([&] { return Applied(coordinator, follower, core::Language::English); }, 1500), "unlock applies latest target and refreshes acknowledgement");
    { std::lock_guard<std::mutex> lock(follower.mutex); follower.refuse = true; }
    coordinator.Manual(core::Language::Russian);
    Check(Until([&] { return coordinator.Status().peerApplied == sync::Applied::Failed; }), "refusing peer cannot produce false synchronized status");
    Check(follower.Read().actual == core::Language::English, "refused target remains visibly unapplied");
    { std::lock_guard<std::mutex> lock(follower.mutex); follower.state.snapshot.mwb = false; }
    Check(Until([&] { return coordinator.Status().phase == SessionPhase::Ended && follower.Status().phase == SessionPhase::Ended; }), "MWB stop ends sync session");
    connection.Stop();
    Check(connection.serverHandshake && connection.clientHandshake, "both broker endpoints mutually authenticated");
    std::printf("Online broker ending errors: server=%lu client=%lu (MWB stop expected).\n", connection.serverError, connection.clientError);
}
void Ambiguous(const Identity& server, const Identity& client) {
    Model coordinator(core::Language::English, 0), follower(core::Language::Russian, 0);
    coordinator.state.snapshot.activity = {}; follower.state.snapshot.activity = {};
    Connection connection;
    Check(connection.Start(server, client, coordinator, follower), "ambiguous reconnect started");
    Check(Until([&] { return coordinator.Status().phase == SessionPhase::AwaitInput && follower.Status().phase == SessionPhase::AwaitInput; }),
          "unknown histories wait for fresh input instead of choosing server language");
    Check(coordinator.Commands() == 0 && follower.Commands() == 0 && coordinator.Read().actual != follower.Read().actual,
          "ambiguous negotiation preserves both local states");
    follower.Activity();
    Check(Until([&] { return Active(coordinator, follower) && Applied(coordinator, follower, core::Language::Russian); }),
          "fresh recipient activity resolves ambiguity without wall clock comparison");
    { std::lock_guard<std::mutex> lock(coordinator.mutex); ++coordinator.state.snapshot.engineEpoch; }
    Check(Until([&] { return coordinator.Status().phase == SessionPhase::Ended; }), "engine incarnation change ends old session");
    connection.Stop();
}
}
int main() {
    Winsock winsock; if (winsock.Error()) return 2;
    Identity server, client; DWORD error = 0;
    if (!server.Generate(error) || !client.Generate(error)) return 3;
    Online(server, client); Ambiguous(server, client);
    std::printf("Windows broker session: %u checks, %u failures; real TLS, model endpoints, no input desktop changes.\n", checks, failures);
    return failures ? 1 : 0;
}
