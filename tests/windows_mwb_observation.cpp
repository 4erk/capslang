// Read-only metadata sample, not a two-machine acceptance test.
#include "../src/platform/mwb.hpp"
#include <cstdio>
int main() {
    capslang::MwbObserver observer;
    const auto result = observer.Read();
    std::printf("MWB metadata: applications=%u helpers=%u supported_binary=%d dots=%u visible=%d route_candidate=%u error=%lu\n",
        result.applications, result.helpers, result.supportedBinary, result.dots, result.dotVisible,
        static_cast<unsigned>(result.route), result.error);
    return 0; // Unknown/unsupported is a valid read-only observation, not a pass.
}
