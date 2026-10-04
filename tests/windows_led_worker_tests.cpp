#include "../src/runtime/led_worker.hpp"
#include <atomic>
#include <cstdio>

using namespace capslang;
namespace {
unsigned checks = 0, failures = 0;
void Check(bool value, const char* name) { ++checks; if (!value) { ++failures; std::printf("FAIL %s\n", name); } }
template<class Predicate> bool Until(Predicate predicate, DWORD timeout = 2500) {
    const auto deadline = GetTickCount64() + timeout;
    do { if (predicate()) return true; Sleep(5); } while (GetTickCount64() < deadline);
    return predicate();
}
}
int main() {
    std::atomic<unsigned> calls{0}, discoveries{0};
    std::atomic<core::Language> last{core::Language::Unknown};
    LedWorker worker;
    Check(worker.Start([&](core::Language language, bool discover) {
        ++calls; if (discover) ++discoveries; last = language; return LedStatus{1, 0, 0, true};
    }), "mock LED worker starts without physical device access");
    worker.Target(core::Language::Russian);
    Check(Until([&] { return worker.Status().written == 1 && last == core::Language::Russian; }), "RU processed by separate worker");
    Check(discoveries == 1, "initial discovery requested");
    worker.Target(core::Language::English);
    Check(Until([&] { return last == core::Language::English && worker.Status().written == 1; }), "new language wakes worker promptly");
    worker.Rediscover();
    Check(Until([&] { return discoveries >= 2; }), "hotplug requests rediscovery");
    for (unsigned i = 0; i < 1000; ++i) worker.Target(i % 2 ? core::Language::Russian : core::Language::English);
    worker.Target(core::Language::English);
    Check(Until([&] { return last == core::Language::English && worker.Status().written == 1; }), "rapid targets converge to latest language");
    Check(worker.Stop() && worker.Stop(), "normal shutdown idempotent");

    HANDLE entered = CreateEventW(nullptr, TRUE, FALSE, nullptr), release = CreateEventW(nullptr, TRUE, FALSE, nullptr), returned = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    Check(entered && release && returned, "blocking-driver fixture events");
    LedWorker stuck;
    Check(stuck.Start([&](core::Language, bool) {
        SetEvent(entered); WaitForSingleObject(release, INFINITE); SetEvent(returned); return LedStatus{1, 0, 0, true};
    }), "controlled blocking driver starts");
    stuck.Target(core::Language::Russian);
    Check(WaitForSingleObject(entered, 1000) == WAIT_OBJECT_0, "driver reached deterministic blocking point");
    Check(Until([&] { return stuck.Status().error == ERROR_TIMEOUT && !stuck.Status().responsive; }), "stalled operation reports timeout not stale success");
    const auto begin = GetTickCount64();
    stuck.Target(core::Language::English); stuck.Rediscover();
    Check(GetTickCount64() - begin < 100, "target and hotplug never wait on driver");
    Check(!stuck.Stop(50) && stuck.Error() == ERROR_TIMEOUT && GetTickCount64() - begin < 500,
          "shutdown stays bounded when driver ignores cancellation");
    LedWorker duplicate;
    Check(!duplicate.Start([](core::Language, bool) { return LedStatus{}; }) && duplicate.Error() == ERROR_BUSY,
          "hung worker blocks additional worker accumulation");
    SetEvent(release);
    Check(WaitForSingleObject(returned, 1000) == WAIT_OBJECT_0, "detached context remains alive until blocked operation returns");
    Check(Until([&] { return duplicate.Start([](core::Language, bool) { return LedStatus{0, 1, ERROR_NOT_SUPPORTED, true}; }); }),
          "worker slot recovers after actual completion");
    duplicate.Target(core::Language::English);
    Check(Until([&] { return duplicate.Status().error == ERROR_NOT_SUPPORTED; }), "unsupported device remains explicit without input fallback");
    Check(duplicate.Stop(), "recovered worker stops normally");
    CloseHandle(entered); CloseHandle(release); CloseHandle(returned);
    std::printf("LED worker: %u checks, %u failures; mock operations only, no keyboard writes.\n", checks, failures);
    return failures ? 1 : 0;
}
