#include "../src/activity.hpp"
#include <cstdio>
#include <limits>

int main() {
    using namespace capslang;
    unsigned checks = 0;
    unsigned failures = 0;
    auto check = [&](bool ok, const char* name) {
        ++checks;
        if (!ok) { std::fprintf(stderr, "FAIL: %s\n", name); ++failures; }
    };
    for (int actionable = 0; actionable < 2; ++actionable) {
        for (int own = 0; own < 2; ++own) {
            for (int consumed = 0; consumed < 2; ++consumed) {
                check(IsDeliveredActivity(actionable, own, consumed) ==
                      (actionable == 1 && own == 0 && consumed == 0), "activity truth table");
            }
        }
    }
    check(IsDeliveredActivity(true, false, false), "MWB injected input may be delivered");
    check(!IsDeliveredActivity(true, false, true), "forwarded source input is not local activity");
    check(!IsDeliveredActivity(true, true, false), "our maintenance is not user activity");
    check(CompareActivityAge(true, 10, true, 1000, 100) == ActivityWinner::Local, "local recent");
    check(CompareActivityAge(true, 1000, true, 10, 100) == ActivityWinner::Peer, "peer recent");
    check(CompareActivityAge(true, 10, true, 20, 100) == ActivityWinner::Unknown, "uncertain order");
    check(CompareActivityAge(true, 10, true, 110, 100) == ActivityWinner::Unknown, "boundary uncertain");
    check(CompareActivityAge(true, 100, true, 100, 0) == ActivityWinner::Unknown, "tie waits for input");
    check(CompareActivityAge(false, 0, true, 100, 10) == ActivityWinner::Unknown, "local restart");
    check(CompareActivityAge(true, 100, false, 0, 10) == ActivityWinner::Unknown, "peer restart");
    check(CompareActivityAge(true, 0, true, std::numeric_limits<std::uint64_t>::max(), 1) ==
          ActivityWinner::Local, "age comparison avoids addition overflow");
    std::printf("Activity tests: %u checks, %u failures. Not a live MWB acceptance test.\n", checks, failures);
    return failures ? 1 : 0;
}
