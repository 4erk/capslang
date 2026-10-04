#pragma once
#include "sync.hpp"

namespace capslang::sync {
// Wire-independent reconciliation policy. All times are monotonic AGES, never
// machine clock timestamps. activitySerial/activity are retained wire field
// names for the last EXPLICIT language choice. Pointer activity never enters
// this model. A restarted process without an age waits for a fresh choice.
struct Snapshot {
    std::uint64_t engineEpoch = 0, userRevision = 0, activitySerial = 0;
    Language language = Language::Unknown;
    Age activity{};
    bool mwb = false;
};
inline bool Valid(const Snapshot& value) {
    return value.engineEpoch && core::Supported(value.language) &&
        (!value.activity.known || (value.activitySerial && value.activity.minimum <= value.activity.maximum));
}
struct Baseline { std::uint64_t engineEpoch = 0, activitySerial = 0; };
inline Baseline Mark(const Snapshot& value) { return {value.engineEpoch, value.activitySerial}; }
inline bool Fresh(const Snapshot& value, Baseline baseline) {
    return value.activity.known && baseline.engineEpoch == value.engineEpoch &&
        value.activitySerial > baseline.activitySerial;
}
enum class ReconnectState { Invalid, Disabled, AwaitInput, Proposed };
enum class Authority { None, Coordinator, Follower, AlreadyEqual };
struct Proposal {
    Id session{}; // New cryptographic random nonce for this TLS connection.
    std::uint64_t round = 0;
    Snapshot coordinator{}, follower{};
    Authority authority = Authority::None;
    Language target = Language::Unknown;
};
// Coordinator is only a transport role, never the default winner. Age bounds
// refer to receipt of the follower's reply. If RTT makes intervals overlap,
// keep both languages until provably fresh user input determines the winner.
inline ReconnectState Propose(Id session, std::uint64_t round, Snapshot localAtReply,
    Snapshot peerAtSend, Baseline localBaseline, Baseline peerBaseline,
    std::uint64_t rtt, Proposal& output) {
    output = {};
    if (!Nonzero(session) || !round || !Valid(localAtReply) || !Valid(peerAtSend) || rtt > 1500)
        return ReconnectState::Invalid;
    if (!localAtReply.mwb || !peerAtSend.mwb) return ReconnectState::Disabled;
    // Do not reconcile across an engine restart using a pre-restart baseline.
    if (localBaseline.engineEpoch != localAtReply.engineEpoch ||
        peerBaseline.engineEpoch != peerAtSend.engineEpoch) return ReconnectState::AwaitInput;
    if (localAtReply.activitySerial < localBaseline.activitySerial ||
        peerAtSend.activitySerial < peerBaseline.activitySerial) return ReconnectState::Invalid;
    Proposal value{session, round, localAtReply, peerAtSend};
    if (localAtReply.language == peerAtSend.language) {
        value.authority = Authority::AlreadyEqual; value.target = localAtReply.language;
    } else {
        const bool localFresh = Fresh(localAtReply, localBaseline), peerFresh = Fresh(peerAtSend, peerBaseline);
        Winner winner = Winner::AwaitInput;
        if (localFresh != peerFresh) winner = localFresh ? Winner::Local : Winner::Peer;
        else {
            Age remote = peerAtSend.activity;
            if (remote.known) {
                if (remote.maximum > UINT64_MAX - rtt) return ReconnectState::Invalid;
                remote.maximum += rtt;
            }
            winner = Reconcile(localAtReply.activity, remote);
        }
        if (winner == Winner::AwaitInput) return ReconnectState::AwaitInput;
        value.authority = winner == Winner::Local ? Authority::Coordinator : Authority::Follower;
        value.target = winner == Winner::Local ? localAtReply.language : peerAtSend.language;
    }
    output = value;
    return ReconnectState::Proposed;
}
inline bool Valid(const Proposal& value) {
    if (!Nonzero(value.session) || !value.round || !Valid(value.coordinator) || !Valid(value.follower) ||
        !value.coordinator.mwb || !value.follower.mwb) return false;
    switch (value.authority) {
    case Authority::Coordinator: return value.target == value.coordinator.language;
    case Authority::Follower: return value.target == value.follower.language;
    case Authority::AlreadyEqual: return value.target == value.coordinator.language && value.target == value.follower.language;
    default: return false;
    }
}
// Each endpoint validates again just before committing a proposal. New input
// at the losing endpoint invalidates an old sample; continued mouse movement
// at the winning endpoint does not starve agreement. An actual language change
// at either endpoint ALWAYS invalidates the proposal, even if its HKL returned
// to the sampled language in the meantime (the userRevision catches ABA).
inline bool StillCurrent(const Proposal& proposal, bool coordinator, const Snapshot& current) {
    if (!Valid(proposal) || !Valid(current) || !current.mwb) return false;
    const auto& sampled = coordinator ? proposal.coordinator : proposal.follower;
    if (sampled.engineEpoch != current.engineEpoch || sampled.userRevision != current.userRevision ||
        sampled.language != current.language || current.activitySerial < sampled.activitySerial) return false;
    const bool localAuthority = coordinator ? proposal.authority == Authority::Coordinator : proposal.authority == Authority::Follower;
    return proposal.authority == Authority::AlreadyEqual || localAuthority || current.activitySerial == sampled.activitySerial;
}
// A follower must not apply a proposal upon receipt. It records an acceptance,
// waits for a matching COMMIT from the mutually pinned coordinator, and checks
// its local snapshot again. The broker then uses IPC SetLayoutIfRevision with
// this proposal's engineEpoch and userRevision (never unconditional SetLayout).
class FollowerAgreement {
public:
    explicit FollowerAgreement(Id connection) : connection_(connection) {}
    bool Offer(const Proposal& value, const Snapshot& current) {
        if (value.session != connection_ || value.round <= lastRound_ || !Valid(value)) return false;
        lastRound_ = value.round;
        pending_ = {}; // A newer offer invalidates any previous acceptance.
        if (!StillCurrent(value, false, current)) return false;
        pending_ = value; return true;
    }
    bool Commit(Id connection, std::uint64_t round, const Snapshot& current, Proposal& accepted) {
        accepted = {};
        if (connection != connection_ || !pending_.round || round != pending_.round) return false;
        Proposal value = pending_; pending_ = {};
        if (!StillCurrent(value, false, current)) return false;
        accepted = value; return true;
    }
    void Cancel() { pending_ = {}; }
private:
    Id connection_;
    std::uint64_t lastRound_ = 0;
    Proposal pending_{};
};
} // namespace capslang::sync
