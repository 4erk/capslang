#pragma once
#include <cstdint>

namespace capslang::core {
enum class DeliveredKind { PhysicalKey, InjectedKey, PhysicalMouse, InjectedMouse };
struct RecipientContext {
    bool mwbRunning = false, supported = false, maintenanceDisabled = false;
    bool localRoute = false, routeKnown = false;
    std::uint64_t observedAt = 0, localSince = 0;
};
// Inputs here are delivered candidates, NOT physical-source events before
// MWB. Mouse candidates additionally require a non-null Raw Input device and
// a matching unconsumed low-level event timestamp. The adapter excludes own
// markers, null-device cleanup and injected relative motion. No contents kept.
class RecipientState {
public:
    bool Observe(DeliveredKind kind, std::uint64_t eventAt, const RecipientContext& context,
                 std::uint64_t now, bool locked) {
        if (locked || !eventAt || eventAt > now || now - eventAt > 1000 || eventAt <= last_) return false;
        const bool fresh = context.observedAt && context.observedAt <= now && now - context.observedAt <= 500;
        if (kind == DeliveredKind::InjectedKey && (!context.mwbRunning || !context.supported || !fresh)) return false;
        if (kind == DeliveredKind::InjectedMouse &&
            (!context.mwbRunning || !context.supported || !context.maintenanceDisabled ||
             !context.routeKnown || !context.localRoute || context.observedAt < eventAt ||
             !fresh || !context.localSince || context.localSince >= eventAt)) return false;
        last_ = eventAt; ++serial_;
        return true;
    }
    std::uint64_t Last() const { return last_; }
    std::uint64_t Serial() const { return serial_; }
private:
    std::uint64_t last_ = 0, serial_ = 0;
};
} // namespace capslang::core
