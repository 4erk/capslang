#pragma once
#include <cstdint>

namespace capslang::core {
enum class Edge { Down, Up };
struct KeyResult { bool suppress = false; bool toggle = false; bool convert = false; };

// Owned solely by the hook thread. No OS calls, I/O, allocations or waits.
// The caller invokes the remainder of the hook chain first. Events forwarded
// and consumed by MWB must NOT change our local Caps/Shift state.
class KeyboardState {
public:
    KeyResult Caps(Edge edge, bool shift, bool own, bool consumedDownstream,
                   std::uint32_t eventTime = 0, bool control = false, bool alt = false, bool win = false) {
        if (own || consumedDownstream) return {};
        if (edge == Edge::Down) {
            downTime_ = eventTime;
            if (held_) return {!pass_, false};
            held_ = true;
            pass_ = shift || (control && (alt || win));
            return {!pass_, !pass_ && !control, !pass_ && control};
        }
        // An orphan up is not ours to suppress (e.g. startup during a press).
        const bool suppress = held_ && !pass_;
        held_ = false;
        pass_ = false;
        return {suppress, false};
    }
    bool Held() const { return held_; }
    bool CanRefresh(bool deliveredKeyHeld) const { return !held_ && !deliveredKeyHeld; }
    // Hook replacement deliberately has no reset operation. A missing key-up
    // conservatively consumes the next repeated down until an up arrives;
    // guessing from time alone would turn keyboard repeat into double toggles.
    // A suppressed Caps down is absent from GetAsyncKeyState. If Windows
    // removes the hook before its up, a delivered Raw Input break can release
    // the latch. Its message timestamp must be strictly newer than our latest down:
    // an old queued break must not release a NEW press. Equal-time events are
    // ambiguous, so keep the latch rather than manufacture a second toggle.
    // Win32 input timestamps wrap at 32 bits; distances >= 2^31 are ambiguous.
    bool PhysicalReleaseObserved(std::uint32_t eventTime) {
        const auto elapsed = eventTime - downTime_;
        if (!held_ || !elapsed || elapsed >= 0x80000000U) return false;
        held_ = false; pass_ = false;
        return true;
    }
private:
    bool held_ = false, pass_ = false;
    std::uint32_t downTime_ = 0;
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
