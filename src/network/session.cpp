#include "session.hpp"
#include <bcrypt.h>

namespace capslang::net {
namespace {
using namespace sync;
class Stream {
public:
    explicit Stream(TlsChannel& tls) : tls_(tls) {}
    bool Send(const Control& value) {
        ControlWire wire;
        if (!tls_.Paired() || !EncodeControl(value, wire)) { error_ = ERROR_INVALID_DATA; return false; }
        if (!tls_.Send(wire.data(), wire.size())) { error_ = tls_.Error(); return false; }
        return true;
    }
    bool Read(Control& value) {
        const auto deadline = GetTickCount64() + 1500;
        while (buffer_.size() < ControlWire{}.size()) {
            const auto now = GetTickCount64();
            if (now >= deadline) { error_ = ERROR_TIMEOUT; return false; }
            std::vector<BYTE> part;
            if (!tls_.Receive(part, static_cast<DWORD>(deadline - now))) { error_ = tls_.Error(); return false; }
            if (part.empty() || buffer_.size() + part.size() > 1279) { error_ = ERROR_INVALID_DATA; return false; }
            buffer_.insert(buffer_.end(), part.begin(), part.end());
        }
        if (!DecodeControl(buffer_.data(), ControlWire{}.size(), value)) {
            error_ = buffer_.size() >= 5 && buffer_[0]=='C' && buffer_[1]=='L' && buffer_[2]=='B' &&
                buffer_[3]=='P' && buffer_[4]!=2 ? ERROR_REVISION_MISMATCH : ERROR_INVALID_DATA;
            return false;
        }
        buffer_.erase(buffer_.begin(), buffer_.begin() + ControlWire{}.size()); return true;
    }
    DWORD Error() const { return error_; }
private:
    TlsChannel& tls_;
    std::vector<BYTE> buffer_;
    DWORD error_ = 0;
};
class Session {
public:
    Session(TlsChannel& tls, const Identity& identity, bool coordinator, const SessionEndpoint& endpoint, HANDLE cancel)
        : stream_(tls), coordinator_(coordinator), endpoint_(endpoint), cancel_(cancel) {
        const auto local = identity.Fingerprint(), peer = tls.Peer();
        std::copy_n(local.begin(), 16, localId_.begin()); std::copy_n(peer.begin(), 16, peerId_.begin());
    }
    bool Run() {
        Publish(SessionPhase::Reconciling);
        LocalState local;
        if (!ReadLocal(local)) return false;
        if (coordinator_) {
            if (BCryptGenRandom(nullptr, session_.data(), static_cast<ULONG>(session_.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) || !Nonzero(session_)) return Fail(NTE_FAIL);
            if (!Coordinate(local)) return false;
        } else if (!Follow(local)) return false;
        Publish(SessionPhase::Active);
        return Exchange();
    }
    DWORD Error() const { return error_; }
    void Finish() { Publish(SessionPhase::Ended); }
private:
    bool Fail(DWORD error) { error_ = error; return false; }
    bool Stopped() {
        if (!cancel_) return false;
        const auto status = WaitForSingleObject(cancel_, 0);
        if (status == WAIT_TIMEOUT) return false;
        error_ = status == WAIT_OBJECT_0 ? ERROR_CANCELLED : GetLastError(); return true;
    }
    bool Pause() {
        if (!cancel_) { Sleep(100); return true; }
        const auto status = WaitForSingleObject(cancel_, 100);
        return status == WAIT_TIMEOUT || Fail(status == WAIT_OBJECT_0 ? ERROR_CANCELLED : GetLastError());
    }
    bool ReadLocal(LocalState& value) {
        if (Stopped()) return false;
        if (!endpoint_.read(value) || !Valid(value.snapshot)) return Fail(ERROR_NOT_READY);
        if (!value.snapshot.mwb) return Fail(ERROR_SERVICE_NOT_ACTIVE);
        return true;
    }
    void Publish(SessionPhase phase) {
        if (endpoint_.publish) endpoint_.publish({phase, broker_ ? broker_->Target() : Language::Unknown,
            broker_ ? broker_->PeerApplied() : Applied::None, error_});
    }
    Control Packet(ControlKind kind, const Snapshot* snapshot = nullptr) const {
        Control packet; packet.kind = kind; packet.session = session_; packet.round = round_;
        if (snapshot) packet.first = *snapshot;
        return packet;
    }
    bool Send(const Control& packet) { return stream_.Send(packet) || Fail(stream_.Error()); }
    bool Read(Control& packet, bool first = false) {
        if (!stream_.Read(packet)) return Fail(stream_.Error());
        if (!first && (packet.session != session_ || packet.round != round_)) return Fail(ERROR_INVALID_DATA);
        return true;
    }
    void StartBroker(const Proposal& proposal, const LocalState& current) {
        auto initial = current;
        initial.snapshot = coordinator_ ? proposal.coordinator : proposal.follower;
        const auto coordinatorId = coordinator_ ? localId_ : peerId_, followerId = coordinator_ ? peerId_ : localId_;
        const auto author = proposal.authority == Authority::Coordinator ? coordinatorId :
            proposal.authority == Authority::Follower ? followerId : std::min(localId_, peerId_);
        broker_ = std::make_unique<BrokerState>(localId_, peerId_, session_, proposal.target, initial, author);
        peerEpoch_ = coordinator_ ? proposal.follower.engineEpoch : proposal.coordinator.engineEpoch;
    }
    bool Coordinate(LocalState local) {
        round_ = 1;
        auto started = GetTickCount64();
        if (!Send(Packet(ControlKind::Hello, &local.snapshot))) return false;
        Control reply;
        if (!Read(reply) || reply.kind != ControlKind::SampleReply) return Fail(error_ ? error_ : ERROR_INVALID_DATA);
        const auto localBaseline = Mark(local.snapshot), peerBaseline = Mark(reply.first);
        const auto localEpoch = local.snapshot.engineEpoch, peerEpoch = reply.first.engineEpoch;
        for (;;) {
            if (!ReadLocal(local)) return false;
            if (local.snapshot.engineEpoch != localEpoch || reply.first.engineEpoch != peerEpoch) return Fail(ERROR_REVISION_MISMATCH);
            Proposal proposal;
            const auto decision = Propose(session_, round_, local.snapshot, reply.first, localBaseline, peerBaseline,
                                           GetTickCount64() - started, proposal);
            if (decision == ReconnectState::Disabled) return Fail(ERROR_SERVICE_NOT_ACTIVE);
            if (decision == ReconnectState::Invalid) return Fail(ERROR_INVALID_DATA);
            if (decision == ReconnectState::Proposed) {
                auto offer = Packet(ControlKind::Offer, &proposal.coordinator);
                offer.second = proposal.follower; offer.authority = proposal.authority; offer.target = proposal.target;
                if (!Send(offer) || !Read(reply)) return false;
                if (reply.kind != ControlKind::Accepted && reply.kind != ControlKind::Rejected) return Fail(ERROR_INVALID_DATA);
                if (!ReadLocal(local)) return false;
                if (reply.kind == ControlKind::Accepted && StillCurrent(proposal, true, local.snapshot)) {
                    if (!Send(Packet(ControlKind::Commit)) || !Read(reply)) return false;
                    if (reply.kind == ControlKind::Committed) {
                        // Preserve the proposal's revision baseline: fresh local
                        // input during this exchange must be published next.
                        StartBroker(proposal, local); return true;
                    }
                    if (reply.kind != ControlKind::Rejected) return Fail(ERROR_INVALID_DATA);
                }
            } else Publish(SessionPhase::AwaitInput);
            if (!Pause() || !ReadLocal(local)) return false;
            if (++round_ == 0) return Fail(ERROR_ARITHMETIC_OVERFLOW);
            started = GetTickCount64();
            if (!Send(Packet(ControlKind::Sample, &local.snapshot)) || !Read(reply) || reply.kind != ControlKind::SampleReply)
                return Fail(error_ ? error_ : ERROR_INVALID_DATA);
        }
    }
    bool Follow(LocalState local) {
        Control incoming;
        if (!Read(incoming, true) || incoming.kind != ControlKind::Hello || incoming.round != 1) return Fail(error_ ? error_ : ERROR_INVALID_DATA);
        session_ = incoming.session; round_ = incoming.round;
        const auto peerEpoch = incoming.first.engineEpoch, localEpoch = local.snapshot.engineEpoch;
        FollowerAgreement agreement(session_);
        if (!ReadLocal(local) || !Send(Packet(ControlKind::SampleReply, &local.snapshot))) return false;
        for (;;) {
            if (!stream_.Read(incoming)) return Fail(stream_.Error());
            if (incoming.session != session_) return Fail(ERROR_INVALID_DATA);
            if (!ReadLocal(local)) return false;
            if (local.snapshot.engineEpoch != localEpoch) return Fail(ERROR_REVISION_MISMATCH);
            if (incoming.kind == ControlKind::Sample) {
                if (incoming.round <= round_ || incoming.first.engineEpoch != peerEpoch) return Fail(ERROR_INVALID_DATA);
                round_ = incoming.round; agreement.Cancel(); Publish(SessionPhase::AwaitInput);
                if (!Send(Packet(ControlKind::SampleReply, &local.snapshot))) return false;
            } else if (incoming.kind == ControlKind::Offer && incoming.round == round_) {
                Proposal proposal{session_, round_, incoming.first, incoming.second, incoming.authority, incoming.target};
                if (proposal.coordinator.engineEpoch != peerEpoch) return Fail(ERROR_REVISION_MISMATCH);
                const bool accepted = agreement.Offer(proposal, local.snapshot);
                if (!Send(Packet(accepted ? ControlKind::Accepted : ControlKind::Rejected))) return false;
            } else if (incoming.kind == ControlKind::Commit && incoming.round == round_) {
                Proposal proposal;
                if (!agreement.Commit(session_, round_, local.snapshot, proposal)) {
                    if (!Send(Packet(ControlKind::Rejected))) return false;
                } else {
                    StartBroker(proposal, local);
                    if (!Send(Packet(ControlKind::Committed))) return false;
                    return true;
                }
            } else return Fail(ERROR_INVALID_DATA);
        }
    }
    bool Collect(const LocalState& local) {
        if (!broker_->Observe(local, GetTickCount64())) return Fail(ERROR_REVISION_MISMATCH);
        auto output = broker_->TakeOutput();
        if (output.apply) broker_->ApplyQueued(endpoint_.queue(*output.apply));
        if (pendingUpdate_ && !(pendingUpdate_->version == broker_->Current())) pendingUpdate_.reset();
        if (pendingAck_ && !(pendingAck_->version == broker_->Current())) pendingAck_.reset();
        if (output.update) { pendingUpdate_ = output.update; pendingAck_.reset(); }
        if (output.acknowledgement) pendingAck_ = output.acknowledgement;
        return true;
    }
    bool ReceiveUpdates(const Control& packet, const LocalState& local) {
        if (!packet.first.mwb) return Fail(ERROR_SERVICE_NOT_ACTIVE);
        if (packet.first.engineEpoch != peerEpoch_) return Fail(ERROR_REVISION_MISMATCH);
        if (packet.update && !broker_->Remote(*packet.update, local, GetTickCount64())) return Fail(ERROR_INVALID_DATA);
        if (packet.ack && !broker_->Remote(*packet.ack, local, GetTickCount64()) && !broker_->Ready()) return Fail(ERROR_INVALID_DATA);
        return Collect(local);
    }
    bool SendUpdates(ControlKind kind, const LocalState& local) {
        auto packet = Packet(kind, &local.snapshot); packet.update = pendingUpdate_; packet.ack = pendingAck_;
        if (!Send(packet)) return false;
        pendingUpdate_.reset(); pendingAck_.reset(); return true;
    }
    bool Exchange() {
        for (;;) {
            LocalState local; Control packet;
            if (coordinator_) {
                if (!ReadLocal(local) || !Collect(local)) return false;
                if (++round_ == 0) return Fail(ERROR_ARITHMETIC_OVERFLOW);
                if (!SendUpdates(ControlKind::Poll, local) || !Read(packet) || packet.kind != ControlKind::PollReply)
                    return Fail(error_ ? error_ : ERROR_INVALID_DATA);
                if (!ReadLocal(local) || !ReceiveUpdates(packet, local)) return false;
                Publish(SessionPhase::Active);
                if (!Pause()) return false;
            } else {
                if (!stream_.Read(packet)) return Fail(stream_.Error());
                if (packet.session != session_ || packet.kind != ControlKind::Poll || packet.round != round_ + 1 || !packet.round)
                    return Fail(ERROR_INVALID_DATA);
                round_ = packet.round;
                if (!ReadLocal(local) || !ReceiveUpdates(packet, local) || !SendUpdates(ControlKind::PollReply, local)) return false;
                Publish(SessionPhase::Active);
            }
        }
    }
    Stream stream_;
    bool coordinator_;
    const SessionEndpoint& endpoint_;
    HANDLE cancel_;
    Id localId_{}, peerId_{}, session_{};
    std::uint64_t round_ = 0, peerEpoch_ = 0;
    DWORD error_ = 0;
    std::unique_ptr<BrokerState> broker_;
    std::optional<Message> pendingUpdate_, pendingAck_;
};
}
bool RunSession(TlsChannel& tls, const Identity& identity, bool coordinator,
                const SessionEndpoint& endpoint, HANDLE cancel, DWORD& error) {
    if (!tls.Paired() || !identity.Certificate() || !endpoint.read || !endpoint.queue) { error = ERROR_ACCESS_DENIED; return false; }
    Session session(tls, identity, coordinator, endpoint, cancel);
    const bool result = session.Run(); session.Finish(); error = session.Error(); return result;
}
} // namespace capslang::net
