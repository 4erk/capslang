#include "enrollment.hpp"
#include <algorithm>

namespace capslang::net {
namespace {
enum class Kind : BYTE { Proof = 1, Waiting, Approved, Stored, Complete, Denied, Resume };
using Frame = std::array<BYTE, 32>;
class EnrollmentStream {
public:
    explicit EnrollmentStream(TlsChannel& value) : channel_(value) {}
    ~EnrollmentStream() { Clear(); }
    bool Send(Kind kind, const InvitationSecret& proof = {}) {
        Frame frame{};
        frame[0] = 'C'; frame[1] = 'L'; frame[2] = 'E'; frame[3] = 'P'; frame[4] = 1;
        frame[5] = static_cast<BYTE>(kind);
        if (kind == Kind::Proof) std::copy(proof.begin(), proof.end(), frame.begin() + 8);
        const bool sent = channel_.Send(frame.data(), frame.size());
        SecureZeroMemory(frame.data(), frame.size());
        error_ = sent ? 0 : channel_.Error(); return sent;
    }
    bool Read(Kind& kind, InvitationSecret& secret) {
        secret = {};
        const auto deadline = GetTickCount64() + 1500;
        while (pending_.size() < Frame{}.size()) {
            const auto now = GetTickCount64();
            if (now >= deadline) { error_ = ERROR_TIMEOUT; return false; }
            std::vector<BYTE> part;
            if (!channel_.Receive(part, static_cast<DWORD>(deadline - now))) { error_ = channel_.Error(); return false; }
            if (part.empty() || part.size() > 1024 || pending_.size() + part.size() > 1055) {
                if (!part.empty()) SecureZeroMemory(part.data(), part.size());
                error_ = ERROR_INVALID_DATA; return false;
            }
            pending_.insert(pending_.end(), part.begin(), part.end());
            SecureZeroMemory(part.data(), part.size());
        }
        Frame frame{}; std::copy_n(pending_.begin(), frame.size(), frame.begin());
        std::vector<BYTE> remaining(pending_.begin() + frame.size(), pending_.end());
        Clear(); pending_ = std::move(remaining);
        bool valid = frame[0] == 'C' && frame[1] == 'L' && frame[2] == 'E' && frame[3] == 'P' &&
            frame[4] == 1 && frame[5] >= static_cast<BYTE>(Kind::Proof) && frame[5] <= static_cast<BYTE>(Kind::Resume) && !frame[6] && !frame[7];
        kind = static_cast<Kind>(frame[5]);
        for (size_t i = 8; i < frame.size(); ++i)
            if ((kind != Kind::Proof || i >= 24) && frame[i]) valid = false;
        if (valid && kind == Kind::Proof) std::copy_n(frame.begin() + 8, secret.size(), secret.begin());
        SecureZeroMemory(frame.data(), frame.size());
        error_ = valid ? 0 : ERROR_INVALID_DATA; return valid;
    }
    DWORD Error() const { return error_; }
private:
    void Clear() { if (!pending_.empty()) SecureZeroMemory(pending_.data(), pending_.size()); pending_.clear(); }
    TlsChannel& channel_;
    std::vector<BYTE> pending_;
    DWORD error_ = 0;
};
bool CompleteServer(EnrollmentStream& stream, DWORD& error) {
    if (!stream.Send(Kind::Approved)) { error = stream.Error(); return false; }
    Kind kind{}; InvitationSecret unused{};
    if (!stream.Read(kind, unused)) { error = stream.Error(); return false; }
    if (kind != Kind::Stored) { error = ERROR_INVALID_DATA; return false; }
    if (!stream.Send(Kind::Complete)) { error = stream.Error(); return false; }
    error = 0; return true;
}
bool Client(TlsChannel& channel, const Identity& identity, const InvitationCode& invitation,
            const std::wstring& path, bool resume, DWORD& error) {
    // Pin supplied via invitation must agree with the actual TLS identity.
    if (!channel.Paired() || !EqualPin(channel.Peer(), invitation.server)) { error = ERROR_ACCESS_DENIED; return false; }
    const PairRecord record{identity.Fingerprint(), invitation.server, invitation.host, invitation.port, false};
    if (!ValidPair(record)) { error = ERROR_INVALID_PARAMETER; return false; }
    EnrollmentStream stream(channel);
    if (!stream.Send(resume ? Kind::Resume : Kind::Proof, invitation.secret)) { error = stream.Error(); return false; }
    const auto deadline = GetTickCount64() + 300000;
    while (GetTickCount64() < deadline) {
        Kind kind{}; InvitationSecret unused{};
        if (!stream.Read(kind, unused)) { error = stream.Error(); return false; }
        if (kind == Kind::Waiting && !resume) continue;
        if (kind == Kind::Denied) { error = ERROR_ACCESS_DENIED; return false; }
        if (kind != Kind::Approved) { error = ERROR_INVALID_DATA; return false; }
        if (!SavePair(path, record, error)) return false;
        if (!stream.Send(Kind::Stored) || !stream.Read(kind, unused)) { error = stream.Error(); return false; }
        if (kind != Kind::Complete) { error = ERROR_INVALID_DATA; return false; }
        error = 0; return true;
    }
    error = ERROR_TIMEOUT; return false;
}
}
bool EnrollServer(TlsChannel& channel, InvitationGate& gate, const std::wstring& path,
                  const std::function<PairApproval(const Pin&)>& approval, DWORD& error) {
    if (channel.Paired() || !approval || gate.State(GetTickCount64()) != InvitationState::Open) {
        error = ERROR_INVALID_STATE; return false;
    }
    EnrollmentStream stream(channel);
    Kind kind{}; InvitationSecret proof{};
    if (!stream.Read(kind, proof)) { error = stream.Error(); return false; }
    const bool submitted = kind == Kind::Proof && gate.Submit(channel.Peer(), proof, GetTickCount64());
    SecureZeroMemory(proof.data(), proof.size());
    if (!submitted) { stream.Send(Kind::Denied); error = ERROR_ACCESS_DENIED; return false; }
    // Disconnect/cancel must dismiss this approval; its fingerprint cannot
    // silently be carried over to a later connection or invite.
    struct CancelPending { InvitationGate& gate; ~CancelPending() {
        if (gate.State(GetTickCount64()) == InvitationState::AwaitConfirmation) gate.Cancel();
    }} cancel{gate};
    const auto peer = channel.Peer();
    while (gate.State(GetTickCount64()) == InvitationState::AwaitConfirmation) {
        const auto answer = approval(peer);
        if (answer == PairApproval::Deny) { gate.Cancel(); stream.Send(Kind::Denied); error = ERROR_CANCELLED; return false; }
        if (answer == PairApproval::Allow) {
            PairRecord record;
            if (!gate.Confirm(peer, GetTickCount64(), record)) { error = ERROR_TIMEOUT; return false; }
            if (!SavePair(path, record, error)) { stream.Send(Kind::Denied); return false; }
            // Once persisted, do not roll back on uncertain delivery: the peer
            // might have stored the approval. Mutual-pin Resume handles it.
            return CompleteServer(stream, error);
        }
        if (!stream.Send(Kind::Waiting)) { error = stream.Error(); return false; }
        Sleep(250);
    }
    stream.Send(Kind::Denied); error = ERROR_TIMEOUT; return false;
}
bool EnrollClient(TlsChannel& channel, const Identity& identity, const InvitationCode& invitation,
                  const std::wstring& path, DWORD& error) {
    return Client(channel, identity, invitation, path, false, error);
}
bool ResumeEnrollmentServer(TlsChannel& channel, const PairRecord& approved, DWORD& error) {
    if (!channel.Paired() || !ValidPair(approved) || !approved.listener || !EqualPin(channel.Peer(), approved.peer)) {
        error = ERROR_ACCESS_DENIED; return false;
    }
    EnrollmentStream stream(channel);
    Kind kind{}; InvitationSecret unused{};
    if (!stream.Read(kind, unused)) { error = stream.Error(); return false; }
    if (kind != Kind::Resume) { error = ERROR_INVALID_DATA; return false; }
    return CompleteServer(stream, error);
}
bool ResumeEnrollmentClient(TlsChannel& channel, const Identity& identity, const InvitationCode& endpoint,
                            const std::wstring& path, DWORD& error) {
    return Client(channel, identity, endpoint, path, true, error);
}
} // namespace capslang::net
