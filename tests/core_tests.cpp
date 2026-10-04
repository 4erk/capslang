#include "../src/core/keyboard.hpp"
#include "../src/core/layout.hpp"
#include <cstdio>
#include <initializer_list>

using namespace capslang::core;
int main() {
    unsigned checks = 0, failed = 0;
    auto check = [&](bool ok, const char* name) { ++checks; if (!ok) { ++failed; std::printf("FAIL %s\n", name); } };
    for (const bool injected : {false, true}) {
        // Injection origin intentionally does not exclude MWB keyboard input.
        (void)injected;
        for (const bool shift : {false, true}) {
            KeyboardState keys;
            const auto down = keys.Caps(Edge::Down, shift, false, false);
            check(down.suppress == !shift && down.toggle == !shift, "first Caps edge");
            for (int repeat = 0; repeat < 100; ++repeat) {
                const auto held = keys.Caps(Edge::Down, !shift, false, false);
                check(held.suppress == !shift && !held.toggle, "repeat and modifier changes preserve decision");
            }
            const auto up = keys.Caps(Edge::Up, !shift, false, false);
            check(up.suppress == !shift && !up.toggle && !keys.Held(), "matched release");
            check(!keys.Caps(Edge::Up, false, false, false).suppress, "orphan release passes");
        }
    }
    KeyboardState keys;
    check(!keys.Caps(Edge::Down, false, true, false).toggle && !keys.Held(), "own events ignored");
    check(!keys.Caps(Edge::Down, false, false, true).toggle && !keys.Held(), "MWB forwarded source ignored");
    keys.Caps(Edge::Down, false, false, false);
    check(!keys.Caps(Edge::Down, false, false, false).toggle, "rehook does not reset held key");
    check(!keys.Caps(Edge::Down, false, false, false).toggle, "lost up does not guess new press");
    keys.Caps(Edge::Up, false, false, false);
    check(keys.Caps(Edge::Down, false, false, false).toggle, "next complete sequence recovers");
    keys.PhysicalReleaseObserved(1);
    check(!keys.Held(), "raw physical release recovers missing hook up");
    for (bool shift : {false, true}) {
        KeyboardState held;
        check(held.CanRefresh(false) && !held.CanRefresh(true), "other delivered keys defer maintenance");
        held.Caps(Edge::Down, shift, false, false, 100);
        check(!held.CanRefresh(false), "suppressed Caps also defers maintenance with async state clear");
        check(!held.PhysicalReleaseObserved(99) && !held.PhysicalReleaseObserved(100) && held.Held(),
              "stale or equal-time Raw break cannot clear current press");
        held.Caps(Edge::Down, !shift, false, false, 150);
        check(!held.PhysicalReleaseObserved(140), "break older than repeat cannot clear an ambiguous newer down");
        check(held.PhysicalReleaseObserved(160), "break newer than latest down releases lost-up latch");
        check(held.CanRefresh(false), "delivered break after lost hook enables maintenance");
        const auto fresh = held.Caps(Edge::Down, shift, false, false, 200);
        check(fresh.toggle == !shift && fresh.suppress == !shift, "press after observed release retains Shift behavior");
        check(!held.PhysicalReleaseObserved(140) && held.Held(), "queued old break does not clear newer press");
        held.Caps(Edge::Up, false, false, false, 210);
        check(!held.PhysicalReleaseObserved(211) && held.CanRefresh(false), "duplicate break after normal up is harmless");
    }
    KeyboardState wrap;
    wrap.Caps(Edge::Down, false, false, false, 0xfffffff0U);
    check(wrap.PhysicalReleaseObserved(10), "release timestamps survive DWORD clock wrap");
    wrap.Caps(Edge::Down, false, false, false, 20);
    check(!wrap.PhysicalReleaseObserved(0xfffffff0U) && wrap.Held(), "pre-wrap stale release is rejected");
    check(!wrap.PhysicalReleaseObserved(0x80000014U), "half-clock distance is ambiguous");

    LayoutState layout;
    layout.Initialize(Language::English);
    check(!layout.Request(Language::Unknown, Origin::Peer, 0), "reject unknown peer language");
    layout.Toggle(10);
    const auto old = layout.Generation();
    check(layout.Target() == Language::Russian && layout.UserRevision() == 1 && layout.Due(10), "absolute Caps target");
    layout.Sent(old, 10);
    check(!layout.Due(100) && layout.Due(160), "bounded retry delay");
    layout.Toggle(20);
    layout.Observe(Language::Russian, old, 30);
    check(layout.Target() == Language::English && layout.State() == ApplyState::Pending, "stale acknowledgement ignored");
    layout.Observe(Language::English, layout.Generation(), 40);
    check(layout.State() == ApplyState::Applied, "actual language confirms latest target");
    const auto revision = layout.UserRevision();
    layout.FocusChanged(50);
    check(layout.Target() == Language::English && layout.UserRevision() == revision, "focus cannot publish remembered language");
    layout.Request(Language::Russian, Origin::Peer, 100);
    layout.Observe(Language::English, layout.Generation(), 1099);
    check(layout.State() == ApplyState::Pending, "asynchronous acknowledgement allowed");
    layout.Observe(Language::English, layout.Generation(), 1100);
    check(layout.State() == ApplyState::Failed && !layout.Due(1101), "failed target backs off instead of spinning");
    check(layout.UserRevision() == revision, "peer changes do not echo as local input");
    layout.Lock(true, 1200);
    layout.Request(Language::English, Origin::Peer, 1201);
    check(layout.State() == ApplyState::Locked && !layout.Due(1201), "locked desktop not changed");
    layout.Lock(false, 1300);
    check(layout.Target() == Language::English && layout.Due(1300), "unlock applies latest target");
    for (int i = 0; i < 1000; ++i) layout.Toggle(1400 + i);
    check(layout.Target() == Language::English && layout.UserRevision() == revision + 1000, "rapid toggles preserve parity");
    const auto sampledRevision = layout.UserRevision();
    layout.Toggle(2500);
    const auto afterCaps = layout.Generation();
    check(!layout.RequestPeer(Language::English, sampledRevision, 2501) &&
        layout.Target() == Language::Russian && layout.Generation() == afterCaps,
        "late peer update cannot erase Caps intent after broker snapshot");
    check(layout.RequestPeer(Language::English, layout.UserRevision(), 2502) &&
        layout.UserRevision() == sampledRevision + 1, "matching peer revision applies without creating local intent");
    layout.Request(Language::Russian, Origin::Manual, 2503);
    check(!layout.RequestPeer(Language::English, sampledRevision + 1, 2504) &&
        layout.Target() == Language::Russian, "late peer update cannot erase manual language selection");
    const auto manualRevision = layout.UserRevision();
    layout.FocusChanged(2505);
    check(layout.RequestPeer(Language::English, manualRevision, 2506), "focus-only changes do not invalidate user intent revision");
    LayoutState retry;
    retry.Initialize(Language::English);
    retry.Request(Language::Russian, Origin::Peer, 10);
    const auto retryGeneration = retry.Generation();
    retry.Sent(retryGeneration, 10);
    retry.Observe(Language::English, retryGeneration, 1010);
    check(!retry.Due(2009) && retry.Due(2010) && retry.Target() == Language::Russian,
          "failed absolute target survives and retries at bounded frequency");
    retry.Sent(retryGeneration, 2010);
    retry.Observe(Language::Russian, retryGeneration, 2020);
    check(retry.State() == ApplyState::Applied && retry.UserRevision() == 0,
          "retry confirms without manufacturing user intent");
    retry.Observe(Language::Unknown, retryGeneration, 2030);
    check(retry.State() == ApplyState::Pending && retry.Due(2030) &&
          retry.Generation() == retryGeneration && retry.UserRevision() == 0,
          "lost confirmation revokes success while preserving request identity");
    retry.Observe(Language::Russian, retryGeneration, 2040);
    retry.Observe(Language::English, retryGeneration, 2050);
    check(retry.State() == ApplyState::Pending && retry.Target() == Language::Russian,
          "changed actual language cannot retain stale Applied");
    retry.Toggle(2060);
    retry.Observe(Language::Russian, retryGeneration, 2070);
    check(retry.Target() == Language::English && retry.State() == ApplyState::Pending,
          "old retry acknowledgement cannot overwrite newer user choice");
    std::printf("Core tests: %u checks, %u failures.\n", checks, failed);
    return failed ? 1 : 0;
}
