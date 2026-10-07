#pragma once
#include "profile_channel.hpp"

namespace capslang::system_profile {
constexpr std::uint32_t kMagic = 0x53545043, kVersion = 1;
enum class Operation : std::uint32_t { Apply = 1, Release = 2 };
#pragma pack(push, 1)
struct Request {
    std::uint32_t magic = kMagic, version = kVersion;
    Operation operation = Operation::Apply;
    std::uint32_t language = 0;
    std::uint64_t id = 0, epoch = 0, generation = 0, binding = 0, eventsThrough = 0;
};
struct Response {
    std::uint32_t magic = kMagic, version = kVersion;
    std::uint64_t id = 0, epoch = 0;
    std::uint32_t error = 0, reserved = 0;
    profile_channel::Report report{};
};
#pragma pack(pop)
static_assert(sizeof(Request) == 56 && sizeof(Response) == 360, "fixed SYSTEM profile ABI; no paths or input data");
inline bool Valid(const Request& value) {
    if (value.magic != kMagic || value.version != kVersion || !value.id || !value.epoch ||
        (!value.binding && value.eventsThrough)) return false;
    switch (value.operation) {
    case Operation::Apply: return profile_channel::Language(value.language) && value.generation;
    case Operation::Release: return !value.language && !value.generation && !value.binding && !value.eventsThrough;
    default: return false;
    }
}
inline bool Valid(const Response& value, const Request& request) {
    if (value.magic != kMagic || value.version != kVersion || value.id != request.id ||
        value.epoch != request.epoch || value.reserved) return false;
    const auto& report = value.report;
    if (!report.binding) {
        if (!value.error && request.operation != Operation::Release) return false;
        if (report.magic != profile_channel::kMagic || report.version != profile_channel::kVersion ||
            report.poll || report.process || report.thread || report.processedCommand ||
            report.confirmedGeneration || report.sampled || report.actual || report.profile || report.error || report.count)
            return false;
        for (const auto& event : report.events) if (!profile_channel::Empty(event)) return false;
        return true;
    }
    return request.operation == Operation::Apply &&
        profile_channel::Valid(report, report.binding, report.process, report.thread) &&
        report.confirmedGeneration <= request.generation && (!value.error || !report.confirmedGeneration);
}
} // namespace capslang::system_profile
