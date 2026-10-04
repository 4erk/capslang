#include "../src/core/reconnect.hpp"
#include <cstdio>
using namespace capslang::sync;
int main() {
    unsigned checks = 0, failures = 0;
    auto check = [&](bool value, const char* name) { ++checks; if (!value) { ++failures; std::printf("FAIL %s\n", name); } };
    Id session{}; session[0] = 19;
    const Snapshot local{100, 3, 10, Language::English, {900, 900, true}, true};
    const Snapshot peer{200, 7, 20, Language::Russian, {100, 100, true}, true};
    const auto lb = Mark(local), pb = Mark(peer);
    Proposal proposal;
    check(Propose(session, 1, local, peer, lb, pb, 20, proposal) == ReconnectState::Proposed &&
        proposal.authority == Authority::Follower && proposal.target == Language::Russian,
        "newest recipient wins, not listening computer");
    auto closeLocal = local; closeLocal.activity = {115, 115, true};
    check(Propose(session, 1, closeLocal, peer, lb, pb, 30, proposal) == ReconnectState::AwaitInput,
          "uncertain RTT ordering preserves distinct states");
    auto unknown = local; unknown.activity = {}; unknown.activitySerial = 0;
    check(Propose(session, 1, unknown, peer, Mark(unknown), pb, 20, proposal) == ReconnectState::AwaitInput,
          "missing activity history never selects server by default");
    auto freshPeer = peer; ++freshPeer.activitySerial;
    check(Propose(session, 1, unknown, freshPeer, Mark(unknown), pb, 20, proposal) == ReconnectState::Proposed &&
        proposal.target == Language::Russian, "first fresh peer input resolves unknown local history");
    auto freshLocal = local; ++freshLocal.activitySerial; freshLocal.activity = {0, 0, true};
    auto unknownPeer = peer; unknownPeer.activity = {}; unknownPeer.activitySerial = 0;
    check(Propose(session, 2, freshLocal, unknownPeer, lb, Mark(unknownPeer), 20, proposal) == ReconnectState::Proposed &&
        proposal.target == Language::English, "first fresh local input resolves unknown peer history");
    freshPeer.activity = {0, 0, true};
    check(Propose(session, 3, freshLocal, freshPeer, lb, pb, 20, proposal) == ReconnectState::AwaitInput,
          "nearly simultaneous fresh inputs remain ambiguous");
    auto stopped = peer; stopped.mwb = false;
    check(Propose(session, 3, local, stopped, lb, pb, 20, proposal) == ReconnectState::Disabled,
          "peer MWB off disables sync without deciding local layout");
    auto restarted = local; ++restarted.engineEpoch;
    check(Propose(session, 3, restarted, peer, lb, pb, 20, proposal) == ReconnectState::AwaitInput,
          "engine restart invalidates connection activity baseline");
    auto backwards = peer; --backwards.activitySerial;
    check(Propose(session, 3, local, backwards, lb, pb, 20, proposal) == ReconnectState::Invalid,
          "activity sequence cannot go backwards within an engine incarnation");
    check(Propose(session, 0, local, peer, lb, pb, 20, proposal) == ReconnectState::Invalid, "zero round rejected");
    check(Propose({}, 1, local, peer, lb, pb, 20, proposal) == ReconnectState::Invalid, "zero session rejected");
    check(Propose(session, 1, local, peer, lb, pb, 1501, proposal) == ReconnectState::Invalid, "late sample rejected");
    auto overflow = peer; overflow.activity = {UINT64_MAX, UINT64_MAX, true};
    check(Propose(session, 1, local, overflow, lb, pb, 1, proposal) == ReconnectState::Invalid, "remote age overflow rejected");
    auto equal = unknownPeer; equal.language = local.language;
    check(Propose(session, 4, unknown, equal, Mark(unknown), Mark(equal), 20, proposal) == ReconnectState::Proposed &&
        proposal.authority == Authority::AlreadyEqual, "already equal languages require no arbitrary winner");
    Propose(session, 5, local, peer, lb, pb, 20, proposal);
    check(StillCurrent(proposal, true, local) && StillCurrent(proposal, false, peer), "both sampled states can accept");
    auto movedWinner = peer; movedWinner.activitySerial += 1000;
    check(StillCurrent(proposal, false, movedWinner), "continuous movement on winner does not starve agreement");
    auto movedLoser = local; ++movedLoser.activitySerial;
    check(!StillCurrent(proposal, true, movedLoser), "new input on other endpoint invalidates stale proposal");
    auto aba = peer; aba.userRevision += 2;
    check(!StillCurrent(proposal, false, aba), "two manual toggles cannot hide stale intent through ABA");
    check(!StillCurrent(proposal, true, restarted), "restart invalidates proposed local apply");
    check(!StillCurrent(proposal, false, stopped), "MWB shutdown between sample and commit cancels sync");
    FollowerAgreement follower(session);
    Proposal committed;
    check(!follower.Commit(session, 5, peer, committed), "unsolicited commit cannot change layout");
    check(follower.Offer(proposal, peer), "follower records proposal without applying it");
    check(!follower.Offer(proposal, peer), "duplicate proposal does not replay");
    Id other = session; ++other[0];
    check(!follower.Commit(other, 5, peer, committed), "different connection commit rejected");
    check(follower.Commit(session, 5, peer, committed) && committed.target == Language::Russian,
          "matching commit returns sampled epoch and revision for conditional IPC");
    check(!follower.Commit(session, 5, peer, committed), "commit replay rejected");
    ++proposal.round;
    check(follower.Offer(proposal, peer) && !follower.Commit(session, 6, aba, committed),
          "user input after acceptance invalidates commit");
    ++proposal.round;
    check(follower.Offer(proposal, peer), "next proposal accepted after aborted commit");
    follower.Cancel();
    check(!follower.Commit(session, 7, peer, committed), "disconnect drops pending commitment");
    ++proposal.round;
    check(follower.Offer(proposal, peer), "new round can be offered after cancellation");
    ++proposal.round;
    check(!follower.Offer(proposal, aba) && !follower.Commit(session, 8, peer, committed),
          "newer rejected proposal invalidates an earlier acceptance");
    auto malformed = proposal; malformed.target = Language::English;
    check(!Valid(malformed), "target must equal the selected recipient language");
    for (std::uint64_t gap = 0; gap < 1000; ++gap) {
        auto older = local; older.activity = {100 + gap, 100 + gap, true};
        const auto result = Propose(session, gap + 10, older, peer, lb, pb, 20, proposal);
        check(gap > 120 ? result == ReconnectState::Proposed && proposal.authority == Authority::Follower :
            result == ReconnectState::AwaitInput, "RTT plus ambiguity boundary has no clock-dependent winner");
    }
    std::printf("Reconnect policy: %u checks, %u failures; physical recipient and broker transport not simulated as acceptance.\n", checks, failures);
    return failures ? 1 : 0;
}
