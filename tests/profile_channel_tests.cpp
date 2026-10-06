#include "../src/core/profile_channel.hpp"
#include <cstdio>
using namespace capslang::profile_channel;
namespace {
unsigned checks = 0, failures = 0;
void Check(bool yes, const char* name) { ++checks; if (!yes) { ++failures; std::printf("FAIL %s\n", name); } }
}
int main() {
    Report report; report.binding = 7; report.poll = 1; report.process = 8; report.thread = 9;
    report.sampled = 123;
    report.actual = report.profile = 0x0409;
    const auto valid = [](const Report& value) { return Valid(value, 7, 8, 9); };
    Check(valid(report), "unconfirmed observation can be read without claiming application");
    for (auto language : {0U, 0x407U, 0x10409U, UINT32_MAX}) {
        auto bad = report; bad.actual = language; Check(!valid(bad), "actual language must be exact EN/RU");
        bad = report; bad.profile = language; Check(!valid(bad), "profile language must be exact EN/RU");
    }
    auto bad = report; bad.confirmedGeneration = 1;
    Check(!valid(bad), "confirmation without a processed command rejected");
    bad = report; bad.sampled = 0; Check(!valid(bad), "successful profile read needs a UI-thread measurement time");
    bad = report; bad.confirmedGeneration = 1;
    bad.processedCommand = 2; Check(valid(bad), "paired actual/profile with command can carry confirmation");
    bad.profile = 0x419; Check(!valid(bad), "different profile cannot confirm actual language");
    bad = report; bad.error = 5; bad.confirmedGeneration = 1; bad.processedCommand = 2;
    Check(!valid(bad), "failed application cannot carry confirmation");
    bad = report; bad.actual = bad.profile = 0; bad.error = 21;
    Check(valid(bad), "not-ready report has unknown observations, not fake EN/RU");
    for (unsigned field = 0; field < 7; ++field) {
        bad = report;
        switch (field) {
        case 0: ++bad.magic; break; case 1: ++bad.version; break; case 2: ++bad.binding; break;
        case 3: ++bad.process; break; case 4: ++bad.thread; break; case 5: bad.poll = 0; break;
        case 6: bad.count = kBatch + 1; break;
        }
        Check(!valid(bad), "wrong binding/identity/version or oversized batch rejected");
    }
    report.count = 3;
    report.events[0] = {1, 0, 0x409, Cause::Baseline, 1};
    report.events[1] = {2, 12, 0x419, Cause::OwnRequest, 2};
    report.events[2] = {3, 0, 0x409, Cause::Observed, 3};
    Check(valid(report), "baseline, own generation and external observation remain distinct");
    for (auto cause : {Cause::Baseline, Cause::Observed}) {
        bad = report; bad.events[0].cause = cause; bad.events[0].generation = 1;
        Check(!valid(bad), "unattributed event cannot invent an own generation");
    }
    bad = report; bad.events[1].generation = 0; Check(!valid(bad), "own event requires a generation");
    bad = report; bad.events[2].cause = static_cast<Cause>(3); Check(!valid(bad), "unknown event cause rejected");
    bad = report; bad.events[3] = report.events[0]; Check(!valid(bad), "hidden trailing event rejected");
    bad = report; bad.events[2].serial = 2; Check(!valid(bad), "duplicate in one batch rejected");
    EventCursor cursor;
    bad = report; bad.count = UINT32_MAX;
    Check(!cursor.Accept(bad) && cursor.Through() == 0, "cursor independently refuses an oversized batch");
    Check(cursor.Accept(report) && cursor.Through() == 3, "complete batch advances once");
    Check(cursor.Accept(report) && cursor.Through() == 3, "repeat delivery is idempotent");
    bad = report; bad.events[0].serial = 0;
    Check(!cursor.Accept(bad) && cursor.Through() == 3, "cursor independently refuses malformed events");
    auto gap = report; gap.count = 2; gap.events = {}; gap.events[0] = {4, 0, 0x419, Cause::Observed, 4};
    gap.events[1] = {6, 0, 0x409, Cause::Observed, 5};
    Check(valid(gap) && !cursor.Accept(gap) && cursor.Through() == 3, "lost observation rejects whole advancement");
    gap.events[1].serial = 5;
    Check(cursor.Accept(gap) && cursor.Through() == 5, "delivery can retry after a rejected gap");
    Command command; command.binding = 7; command.poll = 1; command.command = 2;
    Check(Valid(command,7,1), "observe command is closed and empty");
    command.operation = Operation::Apply; command.language = 0x409; command.generation = 3;
    Check(Valid(command,7,1), "absolute generation-bound application allowed");
    for (auto language : {0U, 0x407U, 0x10409U, UINT32_MAX}) {
        auto invalid = command; invalid.language = language;
        Check(!Valid(invalid,7,1), "command refuses any language beyond exact EN/RU");
    }
    for (unsigned field = 0; field < 8; ++field) {
        auto invalid = command;
        switch (field) {
        case 0: ++invalid.magic; break; case 1: ++invalid.version; break; case 2: ++invalid.binding; break;
        case 3: ++invalid.poll; break; case 4: invalid.command = 0; break; case 5: invalid.generation = 0; break;
        case 6: invalid.operation = Operation::Observe; break; case 7: invalid.operation = static_cast<Operation>(4); break;
        }
        Check(!Valid(invalid,7,1), "malformed or extra-operation command rejected");
    }
    command.operation = Operation::Detach; command.language = 0; command.generation = 0;
    Check(Valid(command,7,1), "detach cannot carry a layout operation");
    IntentOrder order;
    order.Boundary(3);
    Check(!order.Accept(report.events[2]), "event preceding focus/explicit boundary is not a new choice");
    auto choice = report.events[2]; choice.occurred = 4;
    Check(order.Accept(choice) && !order.Accept(choice), "fresh external event accepted exactly once");
    choice.occurred = 5; choice.cause = Cause::Baseline;
    Check(!order.Accept(choice), "focus baseline never creates intent");
    choice.cause = Cause::OwnRequest; choice.generation = 12;
    Check(!order.Accept(choice), "own apply never creates intent");
    order.Boundary(8); order.Boundary(2);
    choice = report.events[2]; choice.occurred = 7;
    Check(!order.Accept(choice), "delayed event cannot overwrite a newer explicit request");
    choice.occurred = 9;
    Check(order.Accept(choice), "immediate later manual choice needs no suppression interval");
    std::printf("Profile channel: %u checks, %u failures\n", checks, failures);
    return failures ? 1 : 0;
}
