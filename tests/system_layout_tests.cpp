#include "../src/core/system_layout.hpp"
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
    std::printf("SYSTEM protocol: %u checks, %u failures; no OS changes.\n", count, failed);
    return failed ? 1 : 0;
}
