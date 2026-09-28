#pragma once
#include <cstdint>

namespace capslang {
// This decision runs AFTER CallNextHookEx. A forwarded event consumed by MWB
// is not evidence that the source computer received the user's input.
constexpr bool IsDeliveredActivity(bool actionable, bool ownEvent, bool consumedDownstream) {
    return actionable && !ownEvent && !consumedDownstream;
}

enum class ActivityWinner { Local, Peer, Unknown };

// Peers exchange age measured on their own monotonic clock, not wall-clock
// timestamps. Uncertainty covers transit time and sampling. Unknown is not an
// arbitrary machine preference: wait for fresh delivered input instead.
constexpr ActivityWinner CompareActivityAge(bool localKnown, std::uint64_t localAge,
    bool peerKnown, std::uint64_t peerAge, std::uint64_t uncertainty) {
    if (!localKnown || !peerKnown) return ActivityWinner::Unknown;
    if (localAge < peerAge && peerAge - localAge > uncertainty) return ActivityWinner::Local;
    if (peerAge < localAge && localAge - peerAge > uncertainty) return ActivityWinner::Peer;
    return ActivityWinner::Unknown;
}
} // namespace capslang
