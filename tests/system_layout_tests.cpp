#include "../src/core/system_layout.hpp"
#include "../src/core/system_profile.hpp"
#include "../src/core/system_caps.hpp"
#include <cstdio>
#include <cstring>
using namespace capslang::system_layout;
int main() {
    unsigned count = 0, failed = 0;
    auto check = [&](bool ok) { ++count; if (!ok) ++failed; };
    Request request; check(!Valid(request)); request.id = 1; check(Valid(request));
    for (std::uint32_t value = 0; value < 65536; ++value) {
        request.operation = Operation::Apply; request.language = value;
        check(Valid(request) == (value == 0x409 || value == 0x419));
    }
    request.language = 0x10409; check(!Valid(request));
    request.language = 0x409; request.operation = static_cast<Operation>(3); check(!Valid(request));
    request.operation = Operation::Apply; request.reserved = 1; check(!Valid(request));
    request.reserved = 0; ++request.version; check(!Valid(request));
    --request.version; request.magic ^= 1; check(!Valid(request));
    Response response; response.id = 4; response.session = 2;
    check(Valid(response,4,2)); check(!Valid(response,5,2)); check(!Valid(response,4,1));
    response.actual = 0x419; check(Valid(response,4,2));
    response.actual = 0x10419; check(!Valid(response,4,2));
    response.actual = 0x409; response.locked = 2; check(!Valid(response,4,2));
    {
        namespace profile = capslang::system_profile;
        profile::Request command;
        check(!profile::Valid(command)); command.id = 1; command.epoch = 2;
        command.language = 0x409; command.generation = 3;
        check(profile::Valid(command));
        for (std::uint32_t language = 0; language < 65536; ++language) {
            command.language = language;
            check(profile::Valid(command) == (language == 0x409 || language == 0x419));
        }
        command.language = 0x409; command.eventsThrough = 1;
        check(!profile::Valid(command)); command.binding = 4; check(profile::Valid(command));
        profile::Response result; result.id = command.id; result.epoch = command.epoch;
        check(!profile::Valid(result, command)); result.error = 5; check(profile::Valid(result, command));
        result.report.binding = 4; result.report.poll = 1; result.report.process = 7; result.report.thread = 8;
        result.report.error = 5;
        check(profile::Valid(result, command));
        result.report.confirmedGeneration = 3; check(!profile::Valid(result, command));
        result.error = result.report.error = 0; result.report.actual = result.report.profile = 0x409;
        result.report.sampled = 100; result.report.processedCommand = 1;
        check(profile::Valid(result, command));
        result.report.confirmedGeneration = 4; check(!profile::Valid(result, command));
        result.report.confirmedGeneration = 3; result.reserved = 1; check(!profile::Valid(result, command));
        result.reserved = 0; result.report.count = 9; check(!profile::Valid(result, command));
        command.operation = profile::Operation::Release;
        check(!profile::Valid(command));
        command.language = 0; command.generation = 0; command.binding = command.eventsThrough = 0;
        check(profile::Valid(command));
        result.report = {}; check(profile::Valid(result, command));
        result.report.events[7].language = 0x409; check(!profile::Valid(result, command));
    }
    {
        namespace caps = capslang::system_caps;
        caps::Request request; check(!caps::Valid(request));
        request.id = 1; request.epoch = 2; check(caps::Valid(request));
        request.through = 1; check(!caps::Valid(request)); request.stream = 3; check(caps::Valid(request));
        caps::Response response; response.id = 1; response.epoch = 2; response.stream = 3;
        check(caps::Valid(response,request));
        response.count = 1; response.events[0] = {2,99}; check(caps::Valid(response,request));
        response.events[0].serial = 1; check(!caps::Valid(response,request)); // duplicate ACK
        response.events[0].serial = 3; check(!caps::Valid(response,request)); // lost intent
        response.events[0] = {2,0}; check(!caps::Valid(response,request));
        response.events[0] = {2,99}; response.events[7] = {8,100}; check(!caps::Valid(response,request));
        response.events[7] = {}; response.error = 5; check(!caps::Valid(response,request));
        response.count = 0; response.events[0] = {}; check(caps::Valid(response,request));
        response.error = 0; response.stream = 4; response.count = 1; response.events[0] = {1,100};
        check(caps::Valid(response,request)); // restarted worker has a new stream
        response.events[0].serial = 2; check(!caps::Valid(response,request));
        response.count = 9; check(!caps::Valid(response,request));
        response.count = 0; response.events[0] = {}; ++response.version; check(!caps::Valid(response,request));
        --response.version; ++response.epoch; check(!caps::Valid(response,request));
        --response.epoch; ++response.id; check(!caps::Valid(response,request));
        ++request.version; check(!caps::Valid(request));
    }
    std::printf("SYSTEM protocol: %u checks, %u failures; no OS changes.\n", count, failed);
    return failed ? 1 : 0;
}
