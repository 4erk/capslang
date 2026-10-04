#include "../src/runtime/recipient_input.hpp"
#include <cstdio>

using namespace capslang;
using namespace capslang::core;
namespace {
unsigned checks = 0, failures = 0;
void Check(bool yes, const char* name) { ++checks; if (!yes) { ++failures; std::printf("FAIL %s\n",name); } }
MwbSnapshot Sample(ULONGLONG at) {
    MwbSnapshot result;
    result.observedAt = at; result.localSince = 50; result.responsive = true; result.error = 0;
    auto& e = result.evidence;
    e.applications = e.helpers = e.dots = 1;
    e.supportedBinary = true; e.route = MwbRoute::LocalCandidate;
    e.settings = {true,false,true,false,0};
    return result;
}
RAWINPUT MousePacket() {
    RAWINPUT result{}; result.header.dwType = RIM_TYPEMOUSE;
    result.header.hDevice = reinterpret_cast<HANDLE>(static_cast<UINT_PTR>(1));
    result.data.mouse.usFlags = MOUSE_MOVE_ABSOLUTE;
    result.data.mouse.lLastX = 100; return result;
}
}
int main() {
    RecipientInput input;
    input.Key(false,false,true,false,90,100); // up
    input.Key(true,false,false,false,91,100); // consumed at source
    input.Key(true,false,true,true,92,100); // own marker
    input.Key(true,false,true,false,101,100); // future
    input.Sample(Sample(100),100,false);
    Check(input.State().Serial() == 0, "up, consumed, own and future key candidates excluded");
    input.Key(true,false,true,false,99,100);
    input.Sample({},100,false);
    Check(input.State().Last() == 99 && input.State().Serial() == 1, "physical passed key works offline");
    input.Key(true,true,true,false,105,110);
    input.Sample({},110,false);
    Check(input.State().Serial() == 1, "injected key with missing MWB evidence not authoritative");
    input.Key(true,true,true,false,115,120);
    input.Sample(Sample(120),120,false);
    Check(input.State().Last() == 115 && input.Accepted(DeliveredKind::InjectedKey) == 1, "delivered MWB key accepted");
    auto mouse = MousePacket();
    input.Mouse(125,130,true,true,false);
    input.RawMouse(mouse,125,130);
    input.Sample(Sample(120),130,false);
    Check(input.State().Last() == 115, "remote mouse waits for post-event route observation");
    input.Sample(Sample(140),140,false);
    Check(input.State().Last() == 125 && input.Accepted(DeliveredKind::InjectedMouse) == 1,
          "matching delivered virtual-device movement accepted after route check");
    input.Mouse(145,150,true,true,false);
    input.RawMouse(mouse,145,150);
    auto unsafe = Sample(160); unsafe.evidence.settings.maintenanceInput = true;
    input.Sample(unsafe,160,false);
    Check(input.State().Last() == 125, "awake-beat-enabled setting prevents mouse authority");
    input.Mouse(165,170,true,true,false); input.RawMouse(mouse,165,170);
    unsafe = Sample(180); unsafe.evidence.route = MwbRoute::RemoteCandidate; unsafe.localSince = 0;
    input.Sample(unsafe,180,false);
    Check(input.State().Last() == 125, "source housekeeping while route remote excluded");
    input.Mouse(185,190,true,true,false);
    mouse.data.mouse.usFlags = MOUSE_MOVE_RELATIVE;
    input.RawMouse(mouse,185,190);
    input.Sample(Sample(200),200,false);
    Check(input.State().Last() == 125, "relative injected awake jitter not promoted");
    mouse = MousePacket(); mouse.header.hDevice = nullptr;
    input.Mouse(205,210,true,true,false); input.RawMouse(mouse,205,210);
    input.Sample(Sample(220),220,false);
    Check(input.State().Last() == 125, "null-device synthetic cleanup excluded");
    mouse = MousePacket();
    input.Mouse(225,230,false,false,false); input.RawMouse(mouse,225,230);
    input.Sample(Sample(240),240,false);
    Check(input.State().Last() == 125, "consumed physical source never becomes recipient through Raw Input");
    input.Mouse(245,250,false,true,false); input.RawMouse(mouse,245,250);
    input.Sample({},260,false);
    Check(input.State().Last() == 245 && input.Accepted(DeliveredKind::PhysicalMouse) == 1, "delivered physical mouse works offline");
    input.Key(true,false,true,false,265,270); input.Sample(Sample(280),280,true);
    Check(input.State().Last() == 245, "locked desktop input excluded");
    input.Mouse(285,290,true,true,false); input.RawMouse(mouse,285,290);
    unsafe = Sample(300); unsafe.localSince = 290;
    input.Sample(unsafe,300,false);
    Check(input.State().Last() == 245, "transition housekeeping predating stable local route excluded");

    RecipientInput flooded;
    for (unsigned i = 1; i <= 1000; ++i) flooded.Key(true,false,true,false,i,i);
    Check(flooded.Dropped() == 489, "bounded producer drops overflow without waiting");
    flooded.Sample({},1000,false);
    Check(flooded.State().Serial() == 511, "every retained distinct physical event consumed exactly once");
    flooded.Key(true,false,true,false,1001,1001); flooded.Sample({},1001,false);
    Check(flooded.State().Serial() == 512 && flooded.State().Last() == 1001, "queue reusable after wrap and overflow");
    RecipientInput expired;
    expired.Mouse(90,100,true,true,false); expired.RawMouse(mouse,90,100);
    expired.Sample(Sample(80),1200,false);
    expired.Key(true,false,true,false,1201,1201); expired.Sample({},1201,false);
    Check(expired.State().Last() == 1201 && expired.State().Serial() == 1, "expired pending mouse cannot block later physical input");
    std::printf("Recipient adapter: %u checks, %u failures; synthetic packets, no SendInput.\n",checks,failures);
    return failures ? 1 : 0;
}
