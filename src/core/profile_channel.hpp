#pragma once
#include <array>
#include <cstddef>
#include <cstdint>

namespace capslang::profile_channel {
// Local module <-> elevated engine messages. This is NOT the peer/LAN protocol.
// Transport must authenticate SID, session, protected server image and the
// pinned process incarnation in BOTH directions before using these records.
constexpr std::uint32_t kMagic = 0x504f4c43, kVersion = 2;
constexpr std::size_t kBatch = 8;
enum class Cause : std::uint32_t { Baseline = 0, OwnRequest = 1, Observed = 2 };
enum class Operation : std::uint32_t { Observe = 1, Apply = 2, Detach = 3 };
constexpr bool Language(std::uint32_t language) { return language == 0x0409 || language == 0x0419; }
#pragma pack(push, 1)
struct Event {
    std::uint64_t serial = 0, generation = 0;
    std::uint32_t language = 0;
    Cause cause = Cause::Observed;
    std::uint64_t occurred = 0; // Local QPC, not wall time or LAN time.
};
struct Report {
    std::uint32_t magic = kMagic, version = kVersion;
    std::uint64_t binding = 0, poll = 0;
    std::uint32_t process = 0, thread = 0;
    std::uint64_t processedCommand = 0, confirmedGeneration = 0;
    std::uint64_t sampled = 0; // GetTickCount64 on the host UI thread, not IPC heartbeat.
    std::uint32_t actual = 0, profile = 0, error = 0, count = 0;
    std::array<Event, kBatch> events{};
};
struct Command {
    std::uint32_t magic = kMagic, version = kVersion;
    std::uint64_t binding = 0, poll = 0, command = 0;
    Operation operation = Operation::Observe;
    std::uint32_t language = 0;
    std::uint64_t generation = 0, eventsThrough = 0;
};
#pragma pack(pop)
static_assert(sizeof(Event) == 32 && sizeof(Report) == 328 && sizeof(Command) == 56,
              "identical fixed ABI for x64 and x86; no pointers/HKL/text");
inline bool Empty(const Event& event) {
    return !event.serial && !event.generation && !event.language && !event.occurred && event.cause == Cause::Observed;
}
inline bool Valid(const Event& event) {
    if (!event.serial || !event.occurred || !Language(event.language)) return false;
    switch (event.cause) {
    case Cause::Baseline: case Cause::Observed: return event.generation == 0;
    case Cause::OwnRequest: return event.generation != 0;
    default: return false;
    }
}
inline bool Valid(const Report& report, std::uint64_t binding, std::uint32_t pid, std::uint32_t tid) {
    if (report.magic != kMagic || report.version != kVersion || !binding || report.binding != binding ||
        !pid || !tid || report.process != pid || report.thread != tid || !report.poll || report.count > kBatch)
        return false;
    if ((report.actual && !Language(report.actual)) || (report.profile && !Language(report.profile))) return false;
    if (!report.error && (!report.sampled || !Language(report.actual) || !Language(report.profile))) return false;
    if (report.confirmedGeneration && (!report.processedCommand || report.error || report.actual != report.profile))
        return false;
    for (std::size_t i = 0; i < kBatch; ++i) {
        if (i >= report.count) { if (!Empty(report.events[i])) return false; }
        else if (!Valid(report.events[i]) || (i && report.events[i].serial <= report.events[i - 1].serial)) return false;
    }
    return true;
}
inline bool Valid(const Command& command, std::uint64_t binding, std::uint64_t poll) {
    if (command.magic != kMagic || command.version != kVersion || !binding || command.binding != binding ||
        !poll || command.poll != poll || !command.command) return false;
    switch (command.operation) {
    case Operation::Observe: case Operation::Detach: return !command.language && !command.generation;
    case Operation::Apply: return Language(command.language) && command.generation;
    default: return false;
    }
}
// Delivery accounting only; never infer manual intent from an Observed event.
// Partial batches and retries retain unacknowledged events. A gap is a lost
// observation, not permission to silently synchronize whichever value remains.
class EventCursor {
public:
    bool Accept(const Report& report) {
        if (report.count > kBatch) return false;
        auto next = through_;
        for (std::size_t i = 0; i < report.count; ++i) {
            if (!Valid(report.events[i]) || (i && report.events[i].serial <= report.events[i - 1].serial)) return false;
            const auto serial = report.events[i].serial;
            if (serial <= next) continue; // Idempotent redelivery.
            if (next == UINT64_MAX || serial != next + 1) return false;
            next = serial;
        }
        through_ = next; return true;
    }
    std::uint64_t Through() const { return through_; }
private:
    std::uint64_t through_ = 0;
};
// One local ordered stream. Focus establishes a baseline, never a choice.
// Delayed events predating a newer explicit request cannot overwrite it.
// Native-picker/focus behavior still requires live acceptance: this class
// orders evidence, it does not turn arbitrary reads into user intention.
class IntentOrder {
public:
    void Boundary(std::uint64_t stamp) { if (stamp > through_) through_ = stamp; }
    bool Accept(const Event& event) {
        if (!Valid(event) || event.cause != Cause::Observed || event.occurred <= through_) return false;
        through_ = event.occurred; return true;
    }
private:
    std::uint64_t through_ = 0;
};
} // namespace capslang::profile_channel
