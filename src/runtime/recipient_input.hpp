#pragma once
#include "mwb_monitor.hpp"
#include "../core/mouse_correlation.hpp"
#include "../core/recipient.hpp"
#include <array>
#include <atomic>

namespace capslang {
// Hook/pump thread is the sole producer. The layout/diagnostic worker is the
// sole consumer. Only kind and timestamp cross the boundary, never key codes,
// button identities, coordinates or device IDs. Full queue drops new evidence
// rather than blocking a low-level hook or manufacturing activity.
class RecipientInput {
public:
    void Key(bool down, bool injected, bool passed, bool own, DWORD time, ULONGLONG now) {
        if (!down || !passed || own) return;
        const auto at = EventTime(time, now);
        if (at) Push({injected ? core::DeliveredKind::InjectedKey : core::DeliveredKind::PhysicalKey, at});
    }
    void Mouse(DWORD time, ULONGLONG now, bool injected, bool passed, bool own) {
        correlation_.Hook(time, now, injected, passed, own);
    }
    void RawMouse(const RAWINPUT& input, DWORD time, ULONGLONG now) {
        if (input.header.dwType != RIM_TYPEMOUSE) return;
        const auto origin = correlation_.Raw(time, now, input.header.hDevice != nullptr);
        if (origin == core::MouseMatch::Unknown) return;
        const auto& mouse = input.data.mouse;
        if (origin == core::MouseMatch::Injected) {
            // Pinned MWB in absolute mode sends remote movement through its
            // virtual device. SendInput clicks/cleanup have no Raw device.
            // Do not promote relative Poke packets; null-device cleanup was
            // already excluded by the correlation check above.
            if (!(mouse.usFlags & MOUSE_MOVE_ABSOLUTE)) return;
        } else if (!(mouse.usFlags & MOUSE_MOVE_ABSOLUTE) &&
                   !mouse.lLastX && !mouse.lLastY && !mouse.usButtonFlags) return;
        const auto at = EventTime(time, now);
        if (at) Push({origin == core::MouseMatch::Injected ? core::DeliveredKind::InjectedMouse :
                     core::DeliveredKind::PhysicalMouse, at});
    }
    void Sample(const MwbSnapshot& observation, ULONGLONG now, bool locked) {
        core::RecipientContext context;
        context.mwbRunning = observation.responsive && observation.evidence.applications;
        context.supported = observation.responsive && observation.evidence.supportedBinary && !observation.error;
        context.maintenanceDisabled = observation.evidence.RecipientObservationAllowed() &&
            !observation.evidence.settings.relativeMouse;
        context.routeKnown = observation.responsive && observation.evidence.route != MwbRoute::Unknown;
        context.localRoute = observation.evidence.route == MwbRoute::LocalCandidate;
        context.observedAt = observation.observedAt; context.localSince = observation.localSince;
        auto read = read_.load(std::memory_order_relaxed);
        const auto write = write_.load(std::memory_order_acquire);
        while (read != write) {
            const auto event = queue_[read];
            // Allow one fresh metadata sample AFTER remote motion. Never wait
            // in the hook. Expired observations are discarded after 1 second.
            if (!locked && event.kind == core::DeliveredKind::InjectedMouse &&
                event.at <= now && now-event.at <= 1000 && observation.responsive &&
                observation.observedAt < event.at) break;
            if (state_.Observe(event.kind,event.at,context,now,locked)) ++accepted_[static_cast<unsigned>(event.kind)];
            read = (read + 1) % queue_.size();
        }
        read_.store(read,std::memory_order_release);
    }
    // Consumer thread only; owner publishes its own status snapshot.
    const core::RecipientState& State() const { return state_; }
    std::uint64_t Accepted(core::DeliveredKind kind) const { return accepted_[static_cast<unsigned>(kind)]; }
    std::uint64_t Dropped() const { return dropped_.load(std::memory_order_relaxed); }
private:
    static ULONGLONG EventTime(DWORD time, ULONGLONG now) {
        const DWORD age = static_cast<DWORD>(now) - time;
        return age <= 1000 && age < now ? now-age : 0;
    }
    struct Event { core::DeliveredKind kind{}; ULONGLONG at = 0; };
    void Push(Event event) {
        const auto write = write_.load(std::memory_order_relaxed), next = (write+1)%queue_.size();
        if (next == read_.load(std::memory_order_acquire)) { ++dropped_; return; }
        queue_[write] = event; write_.store(next,std::memory_order_release);
    }
    core::MouseCorrelation correlation_;
    std::array<Event,512> queue_{};
    std::atomic<size_t> read_{0},write_{0};
    std::atomic<std::uint64_t> dropped_{0};
    core::RecipientState state_;
    std::array<std::uint64_t,4> accepted_{};
};
} // namespace capslang
