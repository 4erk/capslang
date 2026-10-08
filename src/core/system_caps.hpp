#pragma once
#include <cstdint>
namespace capslang::system_caps {
constexpr std::uint32_t Magic = 0x4b435043, Version = 2;
enum class Action : std::uint64_t { Toggle = 0, ConvertSelection = 1 };
struct Event { std::uint64_t serial = 0, stamp = 0; Action action = Action::Toggle; };
struct Request {
    std::uint32_t magic = Magic, version = Version;
    std::uint64_t id = 0, epoch = 0, stream = 0, through = 0;
};
struct Response {
    std::uint32_t magic = Magic, version = Version, error = 0, count = 0;
    std::uint64_t id = 0, epoch = 0, stream = 0, heartbeat = 0, recoveries = 0;
    Event events[8]{};
};
static_assert(sizeof(Request) == 40 && sizeof(Response) == 248, "fixed Caps intent protocol; no key/text payload");
inline bool Valid(const Request& r) { return r.magic == Magic && r.version == Version && r.id && r.epoch && (r.stream || !r.through); }
inline bool Valid(const Response& r, const Request& q) {
    if (r.magic != Magic || r.version != Version || r.id != q.id || r.epoch != q.epoch || r.count > 8 || !r.stream) return false;
    std::uint64_t last = r.stream == q.stream ? q.through : 0;
    for (unsigned i = 0; i < 8; ++i) {
        if (i < r.count) {
            if (r.events[i].serial != last + 1 || !r.events[i].stamp ||
                (r.events[i].action != Action::Toggle && r.events[i].action != Action::ConvertSelection)) return false;
            last = r.events[i].serial;
        }
        else if (r.events[i].serial || r.events[i].stamp || r.events[i].action != Action::Toggle) return false;
    }
    return !r.error || !r.count;
}
} // namespace capslang::system_caps
