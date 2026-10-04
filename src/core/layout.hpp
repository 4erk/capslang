#pragma once
#include "keyboard.hpp"
#include <cstdint>

namespace capslang::core {
enum class ApplyState { Idle, Pending, Applied, Failed, Locked };
enum class Origin { Startup, Caps, Manual, Peer, Focus, Unlock };

// Single-worker model. Latest absolute target wins; echoed/applied states are
// never converted into user changes. Timers use a monotonic clock only.
class LayoutState {
public:
    void Initialize(Language actual) {
        target_ = Supported(actual) ? actual : Language::English;
        actual_ = actual;
    }
    bool Request(Language language, Origin origin, std::uint64_t now) {
        if (!Supported(language)) return false;
        target_ = language;
        origin_ = origin;
        ++generation_;
        if (origin == Origin::Caps || origin == Origin::Manual) ++userRevision_;
        attempts_ = 0;
        start_ = nextAttempt_ = now;
        state_ = locked_ ? ApplyState::Locked : ApplyState::Pending;
        return true;
    }
    void Toggle(std::uint64_t now) { Request(Opposite(target_), Origin::Caps, now); }
    bool RequestPeer(Language language, std::uint64_t expectedUserRevision, std::uint64_t now) {
        if (expectedUserRevision != userRevision_) return false;
        return Request(language, Origin::Peer, now);
    }
    void FocusChanged(std::uint64_t now) { Request(target_, Origin::Focus, now); }
    void Lock(bool locked, std::uint64_t now) {
        locked_ = locked;
        if (locked) state_ = ApplyState::Locked;
        else Request(target_, Origin::Unlock, now);
    }
    bool Due(std::uint64_t now) const {
        return !locked_ && now >= nextAttempt_ &&
            ((state_ == ApplyState::Pending && attempts_ < 3) || state_ == ApplyState::Failed);
    }
    void Sent(std::uint64_t generation, std::uint64_t now) {
        if (generation != generation_ || locked_) return;
        if (state_ == ApplyState::Failed) { state_ = ApplyState::Pending; attempts_ = 0; start_ = now; }
        if (state_ != ApplyState::Pending) return;
        ++attempts_;
        nextAttempt_ = now + (attempts_ == 1 ? 150 : 300);
    }
    void Observe(Language actual, std::uint64_t generation, std::uint64_t now) {
        if (generation != generation_ || locked_) return;
        actual_ = actual;
        // An old success is not a permanent lease: losing either the window
        // or profile confirmation must revoke Applied without inventing intent.
        if (state_ == ApplyState::Applied && actual != target_) {
            state_ = ApplyState::Pending;
            attempts_ = 0;
            start_ = nextAttempt_ = now;
        }
        if (state_ != ApplyState::Pending) return;
        if (Supported(actual) && actual == target_) state_ = ApplyState::Applied;
        else if (now - start_ >= 1000) { state_ = ApplyState::Failed; nextAttempt_ = now + 1000; }
    }
    Language Target() const { return target_; }
    Language Actual() const { return actual_; }
    std::uint64_t Generation() const { return generation_; }
    std::uint64_t UserRevision() const { return userRevision_; }
    ApplyState State() const { return state_; }
    Origin LastOrigin() const { return origin_; }
private:
    Language target_ = Language::English, actual_ = Language::Unknown;
    ApplyState state_ = ApplyState::Idle;
    Origin origin_ = Origin::Startup;
    std::uint64_t generation_ = 0, userRevision_ = 0, start_ = 0, nextAttempt_ = 0;
    unsigned attempts_ = 0;
    bool locked_ = false;
};
} // namespace capslang::core
