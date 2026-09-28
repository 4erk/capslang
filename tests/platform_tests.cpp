#include "../src/platform/windows_support.hpp"
#include <cstdio>

int main() {
    using namespace capslang;
    unsigned checks = 0, failures = 0;
    auto check = [&](bool ok, const char* name) {
        ++checks;
        if (!ok) { ++failures; std::fprintf(stderr, "FAIL: %s\n", name); }
    };
    check(IsSupportedLanguage(kEnglish), "EN supported");
    check(IsSupportedLanguage(kRussian), "RU supported");
    check(!IsSupportedLanguage(0), "unknown rejected");
    check(!IsSupportedLanguage(0x0407), "unconfigured language rejected");
    check(FindLayout(0) == nullptr, "no layout for invalid identifier");
    LayoutTarget invalid;
    check(!TargetStillValid(invalid), "empty target rejected");
    check(TargetLanguage(invalid) == 0, "empty target has no language");
    const auto rejected = RequestLayout(invalid, nullptr);
    check(!rejected.posted && rejected.postError == ERROR_INVALID_PARAMETER,
          "invalid request does not post");
    check(rejected.threadManager == E_UNEXPECTED && rejected.changeLanguage == E_UNEXPECTED &&
          rejected.activateProfile == E_UNEXPECTED, "invalid request does not call TSF");
    const auto elevation = ProcessElevation(GetCurrentProcessId());
    check(elevation.known, "own elevation can be inspected");
    check(!ProcessElevation(0xffffffff).known, "unknown elevation not assumed low");
    KeyboardLeds leds;
    USHORT flags = 0x1234;
    DWORD error = 0;
    check(!leds.ReadFlags(0, flags, error) && error == ERROR_INVALID_HANDLE,
          "invalid LED read is rejected");
    check(flags == 0x1234, "failed read preserves caller output");
    check(!leds.SetScroll(0, true, error) && error == ERROR_INVALID_HANDLE,
          "invalid LED write is rejected");
    check(leds.Devices().empty(), "construction does not open devices");
    std::printf("Platform tests: %u checks, %u failures. No input or LED changes performed.\n", checks, failures);
    return failures ? 1 : 0;
}
