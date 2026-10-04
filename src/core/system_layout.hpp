#pragma once
#include <cstdint>

namespace capslang::system_layout {
constexpr std::uint32_t kMagic = 0x534c5043, kVersion = 1;
enum class Operation : std::uint32_t { Observe = 1, Apply = 2 };
#pragma pack(push, 1)
struct Request {
    std::uint32_t magic = kMagic, version = kVersion;
    Operation operation = Operation::Observe;
    std::uint32_t language = 0;
    std::uint64_t id = 0, reserved = 0;
};
struct Response {
    std::uint32_t magic = kMagic, version = kVersion;
    std::uint64_t id = 0;
    std::uint32_t error = 0, actual = 0, session = 0, locked = 0;
    std::int32_t changeHr = 1, profileHr = 1;
};
#pragma pack(pop)
static_assert(sizeof(Request) == 32 && sizeof(Response) == 40, "bounded system protocol v1");
inline bool Valid(const Request& r) {
    if (r.magic != kMagic || r.version != kVersion || !r.id || r.reserved) return false;
    if (r.operation == Operation::Observe) return r.language == 0;
    return r.operation == Operation::Apply && (r.language == 0x409 || r.language == 0x419);
}
inline bool Valid(const Response& r, std::uint64_t id, std::uint32_t session) {
    return r.magic == kMagic && r.version == kVersion && r.id == id && r.session == session &&
        r.locked <= 1 && (r.actual == 0 || r.actual == 0x409 || r.actual == 0x419);
}
} // namespace capslang::system_layout
