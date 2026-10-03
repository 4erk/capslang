#include "../src/core/sync.hpp"
#include <cstdio>
#include <vector>
using namespace capslang::sync;
int main() {
    unsigned checks = 0, failures = 0;
    auto check = [&](bool value, const char* name) { ++checks; if (!value) { ++failures; std::printf("FAIL %s\n", name); } };
    Id a{}, b{}, session{}; a[0] = 1; b[0] = 2; session[0] = 3;
    Replica left(a, b, session, Language::English), right(b, a, session, Language::English);
    Message first, second, ack;
    check(left.Local(Language::Russian, first), "local absolute language event");
    check(right.Remote(first) == Receive::Changed && right.Target() == Language::Russian, "peer receives absolute target");
    check(right.Remote(first) == Receive::Duplicate, "duplicate does not toggle");
    check(left.Remote(first) == Receive::Duplicate, "own echo does not toggle");
    check(!right.Acknowledge(Applied::Yes, Language::English, ack), "receipt cannot masquerade as applied layout");
    check(right.Acknowledge(Applied::Pending, Language::English, ack) && left.AcceptAck(ack) && left.PeerApplied() == Applied::Pending, "pending application distinct from success");
    check(right.Acknowledge(Applied::Yes, Language::Russian, ack) && left.AcceptAck(ack) && left.PeerApplied() == Applied::Yes, "actual matching language acknowledges success");
    check(right.Acknowledge(Applied::Pending, Language::English, ack) && !left.AcceptAck(ack), "late pending cannot overwrite final status");
    check(right.Acknowledge(Applied::Failed, Language::English, ack) && left.AcceptAck(ack) && left.PeerApplied() == Applied::Failed, "application failure visible");
    check(right.Acknowledge(Applied::Locked, Language::English, ack) && left.AcceptAck(ack), "locked desktop explicit");
    check(left.Local(Language::English, second) && !left.AcceptAck(ack), "stale acknowledgement rejected");
    check(right.Remote(second) == Receive::Changed && right.Remote(first) == Receive::Stale, "out of order update cannot rewind target");
    auto invalid = second; invalid.language = Language::Russian;
    check(right.Remote(invalid) == Receive::Rejected, "conflicting payload for same event rejected");
    invalid = second; invalid.session[1] = 1;
    check(right.Remote(invalid) == Receive::Rejected, "old connection session rejected");
    invalid = second; invalid.version.author = b; invalid.version.counter += 5;
    check(right.Remote(invalid) == Receive::Rejected, "peer cannot forge local event");
    invalid.version.author[3] = 9;
    check(right.Remote(invalid) == Receive::Rejected, "third device rejected");
    Replica x(a, b, session, Language::English), y(b, a, session, Language::English);
    x.Local(Language::Russian, first); y.Local(Language::English, second);
    x.Remote(second); y.Remote(first);
    check(x.Target() == y.Target() && x.Current() == y.Current(), "simultaneous changes converge deterministically");
    check(x.Local(Language::Russian, first) && y.Remote(first) == Receive::Changed && y.Target() == Language::Russian, "later causally ordered event beats tie");
    std::vector<Message> rapid;
    for (int i = 0; i < 1000; ++i) { x.Local(capslang::core::Opposite(x.Target()), first); rapid.push_back(first); }
    check(y.Remote(rapid.back()) == Receive::Changed, "last rapid event delivered first");
    for (auto i = rapid.rbegin(); i != rapid.rend(); ++i) {
        y.Remote(*i);
        check(y.Current() == x.Current() && y.Target() == x.Target(), "reordered rapid events preserve final state");
    }
    Wire wire{}; Message decoded;
    check(Encode(first, wire) && Decode(wire.data(), wire.size(), decoded) && decoded.version == first.version && decoded.language == first.language, "fixed wire round trip");
    for (std::size_t size = 0; size < 70; ++size) if (size != 64) check(!Decode(wire.data(), size, decoded), "wire rejects wrong size before access");
    for (unsigned i : {0u, 1u, 2u, 3u, 4u, 6u, 7u, 51u, 52u, 63u}) {
        auto bad = wire; bad[i] ^= 0xff;
        check(!Decode(bad.data(), bad.size(), decoded), "magic version reserved bytes validated");
    }
    for (unsigned i : {5u, 48u, 49u, 50u}) {
        auto bad = wire; bad[i] = 0xff;
        check(!Decode(bad.data(), bad.size(), decoded), "unknown enum values rejected");
    }
    check(!Decode(nullptr, 64, decoded), "null frame refused");
    check(Reconcile({100, 100, true}, RemoteAge(1000, 30)) == Winner::Local, "more recent local recipient wins");
    check(Reconcile({1000, 1000, true}, RemoteAge(100, 30)) == Winner::Peer, "more recent remote recipient wins");
    check(Reconcile({100, 100, true}, RemoteAge(95, 30)) == Winner::AwaitInput, "RTT ambiguity waits for fresh input");
    check(Reconcile({}, RemoteAge(100, 30)) == Winner::AwaitInput, "restart with missing activity does not pick server");
    check(Reconcile({100, 90, true}, RemoteAge(1000, 30)) == Winner::AwaitInput, "invalid activity interval refused");
    check(!RemoteAge(UINT64_MAX, 1).known, "age overflow refused");
    check(Reconcile({100, 100, true}, {200, 200, true}) == Winner::AwaitInput, "near simultaneous activity awaits input");
    Replica unusable(a, a, session, Language::English);
    check(!unusable.Local(Language::English, first), "cannot pair device with itself");
    invalid = second; invalid.version.counter = UINT64_MAX;
    check(!Valid(invalid), "counter wrap refused");
    std::printf("Sync protocol: %u checks, %u failures; model only, no MWB recipient acceptance.\n", checks, failures);
    return failures ? 1 : 0;
}
