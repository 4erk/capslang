#pragma once
#include <array>
#include <cstdint>

namespace capslang::core {
enum class MouseMatch { Unknown, Physical, Injected };
// Single hook/pump thread, fixed storage, no waits/allocations. No coordinates,
// button identity, input text or device path is retained. Raw Input alone
// cannot distinguish a physical device from MWB's virtual injection device.
class MouseCorrelation {
public:
    void Hook(std::uint32_t time, std::uint64_t now, bool injected, bool passed, bool own) {
        const auto age = static_cast<std::uint32_t>(now) - time;
        entries_[next_] = {time, age <= 1000 && age < now ? now - age : 0,
                          injected, passed && !own};
        next_ = (next_ + 1) % entries_.size();
    }
    MouseMatch Raw(std::uint32_t time, std::uint64_t now, bool hasDevice) const {
        if (!hasDevice) return MouseMatch::Unknown;
        MouseMatch result = MouseMatch::Unknown;
        for (const auto& entry : entries_) {
            if (!entry.at || entry.time != time || entry.at > now || now - entry.at > 1000) continue;
            if (!entry.passed) return MouseMatch::Unknown;
            const auto origin = entry.injected ? MouseMatch::Injected : MouseMatch::Physical;
            // Several events share a millisecond. An origin collision must
            // fail closed, never borrow a physical classification for injected.
            if (result != MouseMatch::Unknown && result != origin) return MouseMatch::Unknown;
            result = origin;
        }
        return result;
    }
private:
    struct Entry { std::uint32_t time = 0; std::uint64_t at = 0; bool injected = false, passed = false; };
    std::array<Entry, 256> entries_{};
    std::size_t next_ = 0;
};
} // namespace capslang::core
