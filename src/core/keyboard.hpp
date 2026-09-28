#pragma once
#include <cstdint>

namespace capslang::core {
enum class Edge { Down, Up };
struct KeyResult { bool suppress = false; bool toggle = false; };

// Owned solely by the hook thread. No OS calls, I/O, allocations or waits.
// The caller invokes the remainder of the hook chain first. Events forwarded
// and consumed by MWB must NOT change our local Caps/Shift state.
class KeyboardState {
public:
    KeyResult Caps(Edge edge, bool shift, bool own, bool consumedDownstream) {
        if (own || consumedDownstream) return {};
        if (edge == Edge::Down) {
            if (held_) return {!pass_, false};
            held_ = true;
            pass_ = shift;
            return {!pass_, !pass_};
        }
        // An orphan up is not ours to suppress (e.g. startup during a press).
        const bool suppress = held_ && !pass_;
        held_ = false;
        pass_ = false;
        return {suppress, false};
    }
    bool Held() const { return held_; }
    // Hook replacement deliberately has no reset operation. A missing key-up
    // conservatively consumes the next repeated down until an up arrives;
    // guessing from time alone would turn keyboard repeat into double toggles.
    void PhysicalReleaseObserved() { held_ = false; pass_ = false; }
private:
    bool held_ = false, pass_ = false;
};

enum class Language : std::uint16_t { Unknown = 0, English = 0x0409, Russian = 0x0419 };
constexpr bool Supported(Language value) {
    return value == Language::English || value == Language::Russian;
}
constexpr Language Opposite(Language value) {
    return value == Language::English ? Language::Russian :
           value == Language::Russian ? Language::English : Language::Unknown;
}
} // namespace capslang::core
