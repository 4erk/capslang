#include "../src/core/broker.hpp"
#include "../src/core/session_wire.hpp"
#include <cstdio>

using namespace capslang::sync;
namespace {
unsigned checks = 0, failures = 0;
void Check(bool value, const char* name) { ++checks; if (!value) { ++failures; std::printf("FAIL %s\n", name); } }
Id IdOf(unsigned value) { Id id{}; id[0] = static_cast<std::uint8_t>(value); return id; }
LocalState State(Language language = Language::English) {
    return {{17, 0, 1, language, {10, 10, true}, true}, language, capslang::core::ApplyState::Applied, false};
}
void Apply(LocalState& state, const ApplyCommand& command) {
    if (state.snapshot.engineEpoch == command.engineEpoch && state.snapshot.userRevision == command.expectedRevision) {
        state.snapshot.language = command.language; state.actual = command.language;
        state.apply = capslang::core::ApplyState::Applied;
    }
}
void ConfirmedOnly() {
    auto local = State();
    BrokerState broker(IdOf(1), IdOf(2), IdOf(3), Language::English, local);
    Replica peer(IdOf(2), IdOf(1), IdOf(3), Language::English);
    Message message; peer.Local(Language::Russian, message);
    Check(broker.Remote(message, local, 100), "peer update accepted");
    auto output = broker.TakeOutput();
    Check(output.apply && output.apply->engineEpoch == 17 && output.apply->expectedRevision == 0 &&
        output.apply->language == Language::Russian, "remote update becomes conditional engine command");
    Check(output.acknowledgement && output.acknowledgement->applied == Applied::Pending, "delivery is pending, not applied");
    broker.ApplyQueued(true);
    local.snapshot.language = Language::Russian; local.apply = capslang::core::ApplyState::Pending;
    Check(broker.Observe(local, 200), "queued target observed");
    Check(!broker.TakeOutput().acknowledgement, "queued target with old actual not acknowledged");
    local.actual = Language::Russian;
    broker.Observe(local, 220);
    Check(!broker.TakeOutput().acknowledgement, "matching actual with pending worker not yet acknowledged");
    local.apply = capslang::core::ApplyState::Applied; broker.Observe(local, 240);
    output = broker.TakeOutput();
    Check(output.acknowledgement && output.acknowledgement->applied == Applied::Yes, "target+actual+worker applied confirmed");
    Check(peer.AcceptAck(*output.acknowledgement) && peer.PeerApplied() == Applied::Yes, "peer receives verified application");
    for (unsigned i = 0; i < 100; ++i) {
        Check(broker.Remote(message, local, 250 + i), "duplicate update accepted idempotently");
        Check(!broker.TakeOutput().apply, "duplicate never queues another application");
    }
    local.locked = true; broker.Observe(local, 400); output = broker.TakeOutput();
    Check(output.acknowledgement && output.acknowledgement->applied == Applied::Locked, "lock revokes applied status");
    local.locked = false; local.apply = capslang::core::ApplyState::Pending;
    broker.Observe(local, 410); output = broker.TakeOutput();
    // Pending is a legitimate post-unlock status, not initial network ordering.
    Check(output.acknowledgement && output.acknowledgement->applied == Applied::Pending, "unlock waits for reapplication");
    Check(peer.AcceptAck(*output.acknowledgement) && peer.PeerApplied() == Applied::Pending, "peer revokes old success during unlock reapplication");
}
void ConflictAndRaces() {
    auto a = State(), b = State();
    BrokerState one(IdOf(1), IdOf(2), IdOf(3), Language::English, a), two(IdOf(2), IdOf(1), IdOf(3), Language::English, b);
    a.snapshot.userRevision = 2; // two quick presses returning to EN still an intent
    b.snapshot.userRevision = 1; b.snapshot.language = b.actual = Language::Russian;
    one.Observe(a, 100); two.Observe(b, 100);
    const auto first = one.TakeOutput(), second = two.TakeOutput();
    Check(first.update && second.update, "both local revision changes are published including ABA");
    one.Remote(*second.update, a, 110); two.Remote(*first.update, b, 110);
    auto outA = one.TakeOutput(), outB = two.TakeOutput();
    Check(one.Target() == Language::Russian && two.Target() == Language::Russian, "simultaneous conflict converges by version and author");
    Check(outA.apply && !outB.apply, "only losing node needs application");
    // User changes after sampling but before command reaches the engine.
    a.snapshot.userRevision = 3; a.snapshot.language = a.actual = Language::English;
    Apply(a, *outA.apply);
    Check(a.actual == Language::English, "stale conditional command cannot overwrite intervening local Caps");
    one.Observe(a, 120); outA = one.TakeOutput();
    Check(outA.update && outA.update->version.counter == 2, "new local intent orders after observed remote version");
    two.Remote(*outA.update, b, 130); outB = two.TakeOutput();
    Check(outB.apply && two.Target() == Language::English, "newer local intent reaches other machine");
    Apply(b, *outB.apply); two.Observe(b, 140); outB = two.TakeOutput();
    Check(!outB.update && outB.acknowledgement && outB.acknowledgement->applied == Applied::Yes, "own remote application has no update echo");
    Check(one.Remote(*outB.acknowledgement, a, 150) && one.PeerApplied() == Applied::Yes, "sender sees peer actually applied");
    // A stale ACK is ordinary delayed traffic, not a fresh state change.
    const auto staleAck = *outB.acknowledgement;
    a.snapshot.userRevision = 4; a.snapshot.language = a.actual = Language::Russian;
    one.Observe(a, 160); one.TakeOutput();
    Check(!one.Remote(staleAck, a, 170) && one.Ready(), "old ACK cannot confirm newer intent or kill valid session");
    a.snapshot.engineEpoch = 18;
    Check(!one.Observe(a, 180) && !one.Ready(), "engine restart requires new reconciliation");
}
void Failures() {
    auto local = State();
    for (bool queued : {false, true}) {
        BrokerState broker(IdOf(1), IdOf(2), IdOf(3), Language::English, local);
        Replica peer(IdOf(2), IdOf(1), IdOf(3), Language::English); Message update; peer.Local(Language::Russian, update);
        broker.Remote(update, local, 100); broker.TakeOutput(); broker.ApplyQueued(queued);
        broker.Observe(local, queued ? 1600 : 101);
        const auto out = broker.TakeOutput();
        Check(out.acknowledgement && out.acknowledgement->applied == Applied::Failed, "refused or unconfirmed application reports failure");
        Check(!out.apply, "failure never loops synthetic or unbounded retries");
    }
    BrokerState disabled(IdOf(1), IdOf(2), IdOf(3), Language::English, local);
    local.snapshot.mwb = false;
    Check(!disabled.Observe(local, 1) && !disabled.Ready() && !disabled.TakeOutput().apply, "MWB off cancels sync with no local change");
    local = State(); BrokerState invalid(IdOf(1), IdOf(2), IdOf(3), Language::English, local);
    Replica stranger(IdOf(4), IdOf(1), IdOf(3), Language::English); Message wrong; stranger.Local(Language::Russian, wrong);
    Check(!invalid.Remote(wrong, local, 1) && !invalid.Ready(), "foreign author refused");
    BrokerState initial(IdOf(1), IdOf(2), IdOf(3), Language::Russian, local);
    initial.Observe(local, 1); auto out = initial.TakeOutput();
    Check(out.apply && !out.update && !out.acknowledgement, "reconciled initial target queues without inventing local input");
}
void ControlCodec() {
    for (unsigned kind = 1; kind <= 10; ++kind) {
        Control value; value.kind = static_cast<ControlKind>(kind); value.session = IdOf(9); value.round = 17;
        if (wire_detail::HasSnapshot(value.kind)) value.first = State().snapshot;
        if (value.kind == ControlKind::Offer) {
            value.second = State().snapshot; value.authority = Authority::AlreadyEqual; value.target = Language::English;
        }
        if (value.kind == ControlKind::Poll || value.kind == ControlKind::PollReply) {
            value.update = Message{Kind::Update, value.session, {7, IdOf(1)}, Language::Russian, Applied::None};
            value.ack = Message{Kind::Ack, value.session, {7, IdOf(1)}, Language::Russian, Applied::Pending};
        }
        ControlWire wire; Control decoded;
        Check(EncodeControl(value, wire) && DecodeControl(wire.data(), wire.size(), decoded) &&
            decoded.kind == value.kind && decoded.round == 17 && decoded.session == value.session, "control message strict round trip");
        Check(!DecodeControl(wire.data(), wire.size() - 1, decoded), "truncated control message refused");
        auto corrupt = wire; corrupt[7] = 1;
        Check(!DecodeControl(corrupt.data(), corrupt.size(), decoded), "reserved control header refused");
        corrupt = wire; corrupt[6] |= 128;
        Check(!DecodeControl(corrupt.data(), corrupt.size(), decoded), "unknown control flags refused");
        if (wire_detail::HasSnapshot(value.kind)) {
            for (unsigned offset : {42U, 43U, 44U, 45U, 46U, 47U}) {
                corrupt = wire; corrupt[32 + offset] = 2;
                Check(!DecodeControl(corrupt.data(), corrupt.size(), decoded), "noncanonical snapshot field refused");
            }
        }
        if (value.kind != ControlKind::Poll && value.kind != ControlKind::PollReply) {
            corrupt = wire; corrupt[255] = 1;
            Check(!DecodeControl(corrupt.data(), corrupt.size(), decoded), "hidden trailing payload refused");
        }
    }
    Control value; value.kind = ControlKind::Hello; value.session = IdOf(9); value.round = 1; value.first = State().snapshot;
    value.first.activity = {}; ControlWire wire; Control decoded;
    Check(EncodeControl(value, wire), "unknown activity serializes without fabricated age");
    wire[56] = 1;
    Check(!DecodeControl(wire.data(), wire.size(), decoded), "unknown activity cannot smuggle timestamp");
    auto local = State(); BrokerState seeded(IdOf(1), IdOf(2), IdOf(3), Language::English, local, IdOf(2));
    seeded.Observe(local, 1); const auto out = seeded.TakeOutput();
    Check(out.acknowledgement && out.acknowledgement->applied == Applied::Yes && !out.update,
        "initial negotiated language is verified without inventing a user change");
}
}
int main() {
    ConfirmedOnly(); ConflictAndRaces(); Failures(); ControlCodec();
    std::printf("Broker state: %u checks, %u failures; deterministic model, not physical recipient acceptance.\n", checks, failures);
    return failures ? 1 : 0;
}
