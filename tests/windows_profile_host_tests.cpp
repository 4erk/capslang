#include "../src/runtime/profile_host.hpp"
#include <cstdio>
using namespace capslang;
namespace pc = capslang::profile_channel;
namespace {
unsigned checks = 0, failures = 0;
void Check(bool yes, const char* name) { ++checks; if (!yes) { ++failures; std::printf("FAIL %s\n", name); } }
}
int main() {
    wchar_t executable[32768]{}; GetModuleFileNameW(nullptr, executable, ARRAYSIZE(executable));
    ProfileHost host(GetCurrentProcessId(), GetCurrentThreadId());
    Check(host.Start() && host.Binding(), "process-pinned module host starts");
    Check(!host.Take().confirmed, "absence of module response never confirms application");
    pc::Report report; report.binding = host.Binding(); report.poll = 1;
    report.process = GetCurrentProcessId(); report.thread = GetCurrentThreadId();
    report.actual = report.profile = 0x409;
    DWORD error = 0; pc::Command reply;
    bool refreshUiSample = true;
    const auto exchange = [&] {
        if (refreshUiSample) report.sampled = GetTickCount64();
        return ipc::Exchange(host.Endpoint(), executable, false, &report, sizeof(report), &reply, sizeof(reply), error) &&
            pc::Valid(reply, report.binding, report.poll);
    };
    Check(exchange() && reply.operation == pc::Operation::Observe, "authenticated initial poll is observation only");
    Check(host.Request(0x419, 3), "owner queues absolute RU with generation");
    ++report.poll;
    Check(exchange() && reply.operation == pc::Operation::Apply && reply.language == 0x419 && reply.generation == 3,
          "module receives the latest fixed command");
    const auto ruCommand = reply.command;
    Check(!host.Take().confirmed, "delivery alone is not application");
    report.processedCommand = ruCommand; report.actual = report.profile = 0x419; report.confirmedGeneration = 3;
    ++report.poll; Check(exchange() && host.Take().confirmed, "matching fresh outcome confirms current request");
    Check(host.Request(0x409, 4) && !host.Take().confirmed, "new target revokes earlier confirmation immediately");
    ++report.poll;
    Check(exchange() && reply.generation == 4 && !host.Take().confirmed,
          "late old success cannot confirm a new command");
    report.processedCommand = reply.command; report.actual = report.profile = 0x409; report.confirmedGeneration = 4;
    ++report.poll; Check(exchange() && host.Take().confirmed, "new generation can be independently confirmed");
    Check(!host.Request(0x419, 3) && !host.Request(0x419, 4) && !host.Request(0x407, 5) && !host.Request(0x409, 0),
          "stale/conflicting/unsupported/zero requests refused by host too");
    Check(host.Request(0x409, 4), "same desired request is idempotent");
    ++report.poll; Check(exchange(), "repeat sample accepted");
    const auto stableCommand = reply.command;
    ++report.poll; Check(exchange() && reply.command == stableCommand, "duplicate delivery does not create another command");
    report.confirmedGeneration = 0; report.error = ERROR_ACCESS_DENIED;
    ++report.poll; Check(exchange() && !host.Take().confirmed, "real module error clears confirmation");
    report.error = 0;
    report.count = 2;
    report.events[0] = {1, 0, 0x409, pc::Cause::Baseline, 1};
    report.events[1] = {2, 0, 0x419, pc::Cause::Observed, 2};
    ++report.poll; Check(exchange() && reply.eventsThrough == 2, "accepted observation batch acknowledged");
    auto sample = host.Take();
    Check(sample.count == 2 && sample.events[0].cause == pc::Cause::Baseline &&
        sample.events[1].cause == pc::Cause::Observed, "host preserves origin, does not invent manual intent");
    ++report.poll; Check(exchange() && host.Take().count == 0, "lost reply/redelivery does not replay events");
    report.error = ERROR_ACCESS_DENIED;
    report.count = 1; report.events = {};
    report.events[0] = {3, 0, 0x409, pc::Cause::Observed, 3};
    ++report.poll;
    Check(exchange() && reply.eventsThrough == 3, "manual notification acknowledged despite failed UI measurement");
    sample = host.Take();
    Check(sample.error == ERROR_ACCESS_DENIED && !sample.confirmed && sample.count == 1 &&
          sample.events[0].serial == 3 && sample.events[0].language == 0x409,
          "failed measurement retains authenticated manual intent without claiming application");
    Check(host.Take().count == 0, "failed-measurement notification consumed exactly once");
    report.error = 0;
    report.count = 0; report.events = {}; report.confirmedGeneration = 4;
    ++report.poll; Check(exchange() && host.Take().confirmed, "fresh module sample restores valid confirmation");
    Sleep(1010);
    Check(!host.Take().confirmed && host.Take().error == ERROR_TIMEOUT, "expired report cannot keep synchronized status");
    refreshUiSample = false; ++report.poll;
    Check(exchange() && !host.Take().confirmed && host.Take().error == ERROR_TIMEOUT,
          "healthy IPC worker cannot refresh an old UI-thread measurement");
    refreshUiSample = true;
    Check(host.Detach(), "detach is an explicit closed operation");
    ++report.poll;
    Check(exchange() && reply.operation == pc::Operation::Detach && !reply.language && !reply.generation,
          "old in-flight success cannot prevent delivery of detach");
    Check(!host.Take().confirmed && !host.Request(0x419, 5), "detaching host cannot accept another apply");
    host.Stop(); Check(!host.Take().confirmed && !host.Start(), "stopped binding is never reused");
    ProfileHost gap(GetCurrentProcessId(), GetCurrentThreadId());
    Check(gap.Start() && gap.Binding() != host.Binding(), "next host has a fresh unpredictable binding");
    report = {}; report.binding = gap.Binding(); report.poll = 1;
    report.process = GetCurrentProcessId(); report.thread = GetCurrentThreadId();
    report.actual = report.profile = 0x409; report.count = 1;
    report.sampled = GetTickCount64();
    report.events[0] = {2, 0, 0x419, pc::Cause::Observed, 2}; // Event 1 was lost.
    const bool delivered = ipc::Exchange(gap.Endpoint(), executable, false, &report, sizeof(report), &reply, sizeof(reply), error);
    Check(delivered && !pc::Valid(reply,report.binding,report.poll) && gap.Take().error == ERROR_MORE_DATA,
          "observation loss fails closed instead of acknowledging a partial choice history");
    Check(!gap.Request(0x419, 1), "lost-observation binding cannot issue apply commands");
    gap.Stop();
    std::printf("Profile host: %u checks, %u failures; real local IPC with model reports, no hooks or layout changes.\n", checks, failures);
    return failures ? 1 : 0;
}
