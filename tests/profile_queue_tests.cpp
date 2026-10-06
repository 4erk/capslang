#include "../src/core/profile_queue.hpp"
#include "../src/core/profile_channel.hpp"
#include <cstdio>
#include <thread>
using namespace capslang::profile_channel;
namespace {
unsigned checks = 0, failures = 0;
void Check(bool yes, const char* name) { ++checks; if (!yes) { ++failures; std::printf("FAIL %s\n", name); } }
}
int main() {
    Queue<Event, 4> queue;
    Event out;
    Check(!queue.TryPop(out), "empty queue has no fictitious notification");
    for (std::uint64_t i = 1; i <= 4; ++i) Check(queue.TryPush({i, i, 0x409, Cause::OwnRequest}), "bounded queue fills");
    Check(!queue.TryPush({5,5,0x419,Cause::OwnRequest}), "full queue refuses overwrite");
    for (std::uint64_t i = 1; i <= 4; ++i)
        Check(queue.TryPop(out) && out.serial == i && out.generation == i, "FIFO preserves retained events");
    Check(!queue.TryPop(out), "drained queue is empty");
    for (std::uint64_t i = 5; i < 30; ++i)
        Check(queue.TryPush({i,i,0x419,Cause::OwnRequest}) && queue.TryPop(out) && out.serial == i,
              "ring slot reuse never returns stale events");
    Queue<Event, 64> concurrent;
    constexpr std::uint64_t count = 100000;
    std::atomic<bool> begin{false}, cancelled{false}, bad{false};
    std::thread producer([&] {
        while (!begin.load(std::memory_order_acquire)) std::this_thread::yield();
        for (std::uint64_t i = 1; i <= count && !cancelled; ++i) {
            const Event event{i, i ^ 0x1abc, i % 2 ? 0x409U : 0x419U, Cause::OwnRequest};
            while (!concurrent.TryPush(event)) { if (cancelled) return; std::this_thread::yield(); }
        }
    });
    std::thread consumer([&] {
        begin.store(true, std::memory_order_release);
        for (std::uint64_t i = 1; i <= count; ++i) {
            Event event;
            while (!concurrent.TryPop(event)) { if (cancelled) return; std::this_thread::yield(); }
            if (event.serial != i || event.generation != (i ^ 0x1abc) ||
                event.language != (i % 2 ? 0x409U : 0x419U) || event.cause != Cause::OwnRequest) {
                bad = true; cancelled = true; return;
            }
        }
    });
    producer.join(); consumer.join();
    Check(!bad && !concurrent.TryPop(out), "100000 concurrent notifications retain order and intact payloads");
    std::printf("Profile queue: %u checks, %u failures; producer/consumer only, no OS input.\n", checks, failures);
    return failures ? 1 : 0;
}
