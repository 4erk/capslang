#include "../src/core/recipient.hpp"
#include "../src/core/mouse_correlation.hpp"
#include <cstdio>
#include <initializer_list>
using namespace capslang::core;
int main() {
    unsigned checks = 0, failures = 0;
    auto check = [&](bool yes) { ++checks; if (!yes) { ++failures; std::printf("FAIL case %u\n", checks); } };
    const RecipientContext local{true,true,true,true,true,100,50};
    for (auto kind : {DeliveredKind::PhysicalKey, DeliveredKind::InjectedKey, DeliveredKind::PhysicalMouse, DeliveredKind::InjectedMouse}) {
        RecipientState state;
        check(state.Observe(kind, 90, local, 100, false));
        check(state.Last() == 90 && state.Serial() == 1);
        check(!state.Observe(kind, 90, local, 100, false));
        check(!state.Observe(kind, 89, local, 100, false));
        check(!state.Observe(kind, 101, local, 100, false));
        check(!state.Observe(kind, 95, local, 1200, false));
        check(!state.Observe(kind, 95, local, 100, true));
        check(state.Serial() == 1);
    }
    for (unsigned mask = 0; mask < 32; ++mask) {
        RecipientContext c{bool(mask&1),bool(mask&2),bool(mask&4),bool(mask&8),bool(mask&16),100,50};
        RecipientState state;
        check(state.Observe(DeliveredKind::InjectedMouse, 90, c, 100, false) == (mask == 31));
    }
    RecipientState state;
    RecipientContext c = local; c.observedAt = 89;
    check(!state.Observe(DeliveredKind::InjectedMouse,90,c,100,false));
    c.observedAt = 101; check(!state.Observe(DeliveredKind::InjectedMouse,90,c,100,false));
    c.observedAt = 100; check(!state.Observe(DeliveredKind::InjectedMouse,90,c,851,false));
    check(state.Observe(DeliveredKind::PhysicalKey,90,{},100,false));
    check(state.Observe(DeliveredKind::PhysicalMouse,95,{},100,false));
    check(!state.Observe(DeliveredKind::InjectedKey,96,{},100,false));
    c = local; c.maintenanceDisabled = false;
    check(state.Observe(DeliveredKind::InjectedKey,96,c,100,false));
    check(!state.Observe(DeliveredKind::InjectedMouse,97,c,100,false));
    check(state.Last() == 96 && state.Serial() == 3);
    c = local; c.observedAt = 0;
    check(!state.Observe(DeliveredKind::InjectedKey,97,c,100,false));
    c.observedAt = 101;
    check(!state.Observe(DeliveredKind::InjectedKey,97,c,100,false));
    c = local; c.localSince = 97;
    check(!state.Observe(DeliveredKind::InjectedMouse,97,c,100,false));
    c.localSince = 0;
    check(!state.Observe(DeliveredKind::InjectedMouse,97,c,100,false));
    MouseCorrelation correlation;
    check(correlation.Raw(99,100,true) == MouseMatch::Unknown);
    correlation.Hook(99,100,false,true,false);
    check(correlation.Raw(99,100,true) == MouseMatch::Physical);
    check(correlation.Raw(99,100,false) == MouseMatch::Unknown);
    check(correlation.Raw(99,1100,true) == MouseMatch::Unknown);
    correlation.Hook(98,100,true,true,false);
    check(correlation.Raw(98,100,true) == MouseMatch::Injected);
    correlation.Hook(98,100,false,true,false);
    check(correlation.Raw(98,100,true) == MouseMatch::Unknown);
    correlation.Hook(99,100,false,false,false);
    check(correlation.Raw(99,100,true) == MouseMatch::Unknown);
    correlation.Hook(101,100,true,true,false);
    check(correlation.Raw(101,102,true) == MouseMatch::Unknown);
    correlation.Hook(102,102,true,true,true);
    check(correlation.Raw(102,102,true) == MouseMatch::Unknown);
    for (unsigned i = 0; i < 300; ++i) correlation.Hook(200+i,200+i,true,true,false);
    check(correlation.Raw(200,500,true) == MouseMatch::Unknown);
    check(correlation.Raw(499,500,true) == MouseMatch::Injected);
    MouseCorrelation wrap;
    wrap.Hook(0xfffffff0U, 0x100000010ULL, true, true, false);
    check(wrap.Raw(0xfffffff0U, 0x100000020ULL, true) == MouseMatch::Injected);
    check(wrap.Raw(0xfffffff0U, 0x200000020ULL, true) == MouseMatch::Unknown);
    std::printf("Recipient policy: %u checks, %u failures; adapter provenance requires live acceptance.\n",checks,failures);
    return failures ? 1 : 0;
}
