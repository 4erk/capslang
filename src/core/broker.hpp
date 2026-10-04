#pragma once
#include "reconnect.hpp"
#include "layout.hpp"
#include <optional>

namespace capslang::sync {
struct LocalState {
    Snapshot snapshot;
    Language actual = Language::Unknown;
    core::ApplyState apply = core::ApplyState::Idle;
    bool locked = false;
};
struct ApplyCommand {
    Language language = Language::Unknown;
    std::uint64_t engineEpoch = 0, expectedRevision = 0;
};
struct BrokerOutput {
    std::optional<Message> update, acknowledgement;
    std::optional<ApplyCommand> apply;
};
// One mutually authenticated/reconciled connection. No OS or network calls.
// Local revisions are sampled BEFORE receiving a peer update, so simultaneous
// changes enter the same Lamport ordering on both nodes. Engine commands remain
// conditional, closing the race between this snapshot and the worker queue.
class BrokerState {
public:
    BrokerState(Id local, Id peer, Id session, Language agreed, const LocalState& initial, Id initialAuthor = {})
        : replica_(local, peer, session, agreed), epoch_(initial.snapshot.engineEpoch),
          revision_(initial.snapshot.userRevision) {
        ready_ = replica_.Ready() && Valid(initial.snapshot) && initial.snapshot.mwb;
        if (Nonzero(initialAuthor) && !replica_.Seed(initialAuthor)) ready_ = false;
        if (ready_ && (initial.snapshot.language != agreed || initial.actual != agreed ||
            initial.apply != core::ApplyState::Applied)) pendingApply_ = true;
    }
    bool Ready() const { return ready_; }
    Language Target() const { return replica_.Target(); }
    Applied PeerApplied() const { return replica_.PeerApplied(); }
    Version Current() const { return replica_.Current(); }
    // Latest local state replaces unsent local state; no input contents or
    // per-key history are retained. Every real local revision still orders the
    // next message after the currently known remote version.
    bool Observe(const LocalState& local, std::uint64_t now) {
        if (!ready_) return false;
        if (!Valid(local.snapshot) || !local.snapshot.mwb || local.snapshot.engineEpoch != epoch_ ||
            local.snapshot.userRevision < revision_ || (haveTime_ && now < lastTime_)) return Fail();
        haveTime_ = true; lastTime_ = now;
        if (local.snapshot.userRevision > revision_) {
            Message update;
            if (!replica_.Local(local.snapshot.language, update)) return Fail();
            revision_ = local.snapshot.userRevision; output_.update = update;
            output_.apply.reset(); pendingApply_ = false; waiting_ = false;
            lastAck_.reset(); retryAt_ = 0;
        }
        const bool confirmed = !local.locked && local.snapshot.language == replica_.Target() &&
            local.actual == replica_.Target() && local.apply == core::ApplyState::Applied;
        if (confirmed) { pendingApply_ = false; waiting_ = false; }
        if (pendingApply_ && !local.locked && local.apply != core::ApplyState::Locked && now >= retryAt_) {
            // Even a matching target needs actual confirmation; a previously
            // failed local attempt is not treated as already applied.
            if (local.snapshot.language != replica_.Target() || local.actual != replica_.Target() ||
                local.apply != core::ApplyState::Applied) {
                output_.apply = ApplyCommand{replica_.Target(), epoch_, revision_};
                waiting_ = true; deadline_ = now > UINT64_MAX - 1500 ? UINT64_MAX : now + 1500;
            }
            pendingApply_ = false;
        }
        Applied result = Applied::Pending;
        if (local.locked || local.apply == core::ApplyState::Locked) result = Applied::Locked;
        else if (local.snapshot.language == replica_.Target() && local.actual == replica_.Target() &&
                 local.apply == core::ApplyState::Applied) { result = Applied::Yes; waiting_ = false; }
        else if ((waiting_ && now >= deadline_) || (!waiting_ && local.apply == core::ApplyState::Failed)) {
            result = Applied::Failed;
            if (!pendingApply_) {
                pendingApply_ = true;
                retryAt_ = now > UINT64_MAX - 500 ? UINT64_MAX : now + 500;
            }
        }
        Message ack;
        if (replica_.Acknowledge(result, local.actual, ack) &&
            (!lastAck_ || !(lastAck_->version == ack.version) || lastAck_->applied != ack.applied)) {
            output_.acknowledgement = ack; lastAck_ = ack;
        }
        return true;
    }
    bool Remote(const Message& message, const LocalState& local, std::uint64_t now) {
        if (!Observe(local, now)) return false;
        if (message.kind == Kind::Ack) return replica_.AcceptAck(message);
        const auto result = replica_.Remote(message);
        if (result == Receive::Rejected) return Fail();
        if (result == Receive::Changed) {
            // Drop an unsent update that has already lost the deterministic
            // conflict. A newer local revision will produce a newer update.
            output_.update.reset(); output_.acknowledgement.reset(); output_.apply.reset();
            lastAck_.reset(); pendingApply_ = true; waiting_ = false; retryAt_ = 0;
            return Observe(local, now);
        }
        // Duplicates and stale packets never issue another engine command.
        return true;
    }
    void ApplyQueued(bool success) {
        if (!success && waiting_) { deadline_ = lastTime_; }
        // Success means only queued. Observe must still prove target+actual.
    }
    BrokerOutput TakeOutput() { auto result = std::move(output_); output_ = {}; return result; }
private:
    bool Fail() { ready_ = false; output_ = {}; return false; }
    Replica replica_;
    std::uint64_t epoch_ = 0, revision_ = 0, deadline_ = 0, lastTime_ = 0, retryAt_ = 0;
    bool ready_ = false, pendingApply_ = false, waiting_ = false, haveTime_ = false;
    std::optional<Message> lastAck_;
    BrokerOutput output_;
};
} // namespace capslang::sync
