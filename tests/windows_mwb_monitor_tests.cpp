#include "../src/runtime/mwb_monitor.hpp"
#include <atomic>
#include <cstdio>

using namespace capslang;
namespace {
unsigned checks = 0, failures = 0;
void Check(bool yes, const char* name) { ++checks; if (!yes) { ++failures; std::printf("FAIL %s\n", name); } }
template<class Predicate> bool Until(Predicate predicate, DWORD timeout = 2500) {
    const auto deadline = GetTickCount64() + timeout;
    do { if (predicate()) return true; Sleep(5); } while (GetTickCount64() < deadline);
    return predicate();
}
MwbEvidence Good() {
    MwbEvidence value;
    value.applications = value.helpers = value.dots = 1;
    value.supportedBinary = true; value.settings = {true,false,true,false,0};
    value.route = MwbRoute::LocalCandidate; value.helperPid = 42;
    value.dotWindow = reinterpret_cast<HWND>(static_cast<UINT_PTR>(123));
    return value;
}
}
int main() {
    std::atomic<unsigned> mode{0};
    MwbMonitor monitor;
    Check(!monitor.Status().responsive, "not-started observer is unknown");
    Check(monitor.Start([&] {
        auto result = Good();
        switch (mode.load()) {
        case 1: result.route = MwbRoute::RemoteCandidate; break;
        case 2: result.settings.maintenanceInput = true; break;
        case 3: result.helperPid = 43; break;
        case 4: result.settings.known = false; break;
        default: break;
        }
        return result;
    }), "isolated observer starts");
    Check(Until([&] { return monitor.Status().localSince != 0; }), "safe local route has a start boundary");
    const auto first = monitor.Status().localSince;
    Check(Until([&] { const auto s = monitor.Status(); return s.observedAt > first && s.localSince == first; }), "stable route retains start boundary");
    mode = 1;
    Check(Until([&] { const auto s = monitor.Status(); return s.evidence.route == MwbRoute::RemoteCandidate && !s.localSince; }), "remote route clears local continuity");
    mode = 0;
    Check(Until([&] { return monitor.Status().localSince > first; }), "return creates a new route boundary");
    mode = 2;
    Check(Until([&] { const auto s = monitor.Status(); return s.evidence.settings.maintenanceInput && !s.localSince; }), "maintenance injections disqualify mouse observations");
    mode = 0;
    Check(Until([&] { return monitor.Status().localSince != 0; }), "safe setting recovers without restart");
    const auto oldHelper = monitor.Status().localSince;
    mode = 3;
    Check(Until([&] { const auto s = monitor.Status(); return s.evidence.helperPid == 43 && s.localSince > oldHelper; }), "helper replacement resets continuity");
    mode = 4;
    Check(Until([&] { const auto s = monitor.Status(); return !s.evidence.settings.known && !s.localSince; }), "unreadable settings fail closed");
    Check(monitor.Stop() && monitor.Stop(), "shutdown idempotent");

    HANDLE entered = CreateEventW(nullptr,TRUE,FALSE,nullptr), release = CreateEventW(nullptr,TRUE,FALSE,nullptr);
    Check(entered && release, "blocking-read fixture events");
    MwbMonitor stalled;
    std::atomic<unsigned> reads{0};
    Check(stalled.Start([&] {
        if (reads++ == 0) return Good();
        SetEvent(entered); WaitForSingleObject(release,INFINITE); return Good();
    }), "controlled blocking read starts after one good result");
    Check(Until([&] { return stalled.Status().responsive; }), "valid metadata exists before the controlled stall");
    Check(WaitForSingleObject(entered,1000) == WAIT_OBJECT_0, "read reached deterministic barrier");
    Check(Until([&] { return !stalled.Status().responsive && !stalled.Status().localSince; }), "old success expires while read is blocked");
    const auto begin = GetTickCount64();
    Check(!stalled.Stop(30) && GetTickCount64()-begin < 500, "ignored cancellation does not block owner shutdown");
    MwbMonitor duplicate;
    Check(!duplicate.Start(Good) && duplicate.Error() == ERROR_BUSY, "no unbounded accumulation of stuck observers");
    SetEvent(release);
    Check(Until([&] { return duplicate.Start(Good); }), "slot reusable after blocked read really returns");
    Check(Until([&] { return duplicate.Status().responsive; }), "replacement produces fresh metadata");
    Check(duplicate.Stop(), "replacement stops");
    CloseHandle(entered); CloseHandle(release);
    std::printf("MWB monitor: %u checks, %u failures; synthetic metadata, no MWB settings changes.\n",checks,failures);
    return failures ? 1 : 0;
}
