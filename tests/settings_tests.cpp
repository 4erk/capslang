#include "../src/core/json_bool.hpp"
#include <cstdio>
#include <vector>
using namespace capslang::core;
int main() {
    unsigned checks = 0, failures = 0;
    auto check = [&](bool value) { ++checks; if (!value) { ++failures; std::printf("FAIL case %u\n", checks); } };
    const auto read = [](std::string_view value) { return ReadSettingBool(value, "BlockScreenSaverOnOtherMachines"); };
    const std::string off = R"({"properties":{"BlockScreenSaverOnOtherMachines":{"value":false}}})";
    const std::string on = R"({"properties":{"BlockScreenSaverOnOtherMachines":{"value":true}}})";
    check(read(off) == JsonBool::False); check(read(on) == JsonBool::True);
    check(read("\xef\xbb\xbf" + off) == JsonBool::False);
    check(read(" \r\n" + off + "\t") == JsonBool::False);
    for (size_t i = 0; i < off.size(); ++i) check(read(off.substr(0, i)) == JsonBool::Unknown);
    for (const auto& input : std::vector<std::string>{
        "", "null", "[]", "{}", "{", off + "false", off + ",", "[" + off + "]",
        R"({"properties":{"BlockScreenSaverOnOtherMachines":{"value":"false"}}})",
        R"({"properties":{"BlockScreenSaverOnOtherMachines":{"value":0}}})",
        R"({"properties":{"BlockScreenSaverOnOtherMachines":{"value":null}}})",
        R"({"properties":{"BlockScreenSaverOnOtherMachines":{"value":false,"value":true}}})",
        R"({"properties":{"BlockScreenSaverOnOtherMachines":{},"BlockScreenSaverOnOtherMachines":{"value":false}}})",
        R"({"properties":{},"properties":{"BlockScreenSaverOnOtherMachines":{"value":false}}})",
        R"({"wrong":{"BlockScreenSaverOnOtherMachines":{"value":false}}})",
        R"({"properties":[{"BlockScreenSaverOnOtherMachines":{"value":false}}]})",
        R"({"properties":{"BlockScreenSaverOnOtherMachines":{"value":false,}}})",
        R"({"properties":{"BlockScreenSaverOnOtherMachines":{"value":false}},"n":01})",
        R"({"properties":{"BlockScreenSaverOnOtherMachines":{"value":false}},"n":-})",
        R"({"properties":{"BlockScreenSaverOnOtherMachines":{"value":false}},"n":1.})",
        R"({"properties":{"BlockScreenSaverOnOtherMachines":{"value":false}},"n":1e})",
        R"({"properties":{"BlockScreenSaverOnOtherMachines":{"value":false}},"s":"\q"})"
    }) check(read(input) == JsonBool::Unknown);
    check(read(R"({"other":{"value":true},"properties":{"Secret":{"value":"never retained"},"BlockScreenSaverOnOtherMachines":{"value":false},"items":[null,true,-1.2e+3,{"a":"\u0419"}]}})") == JsonBool::False);
    check(read(R"({"propert\u0069es":{"BlockScreenSaverOnOtherMachines":{"val\u0075e":false}}})") == JsonBool::False);
    check(read(std::string(34, '[') + "0" + std::string(34, ']')) == JsonBool::Unknown);
    check(read(off + std::string(1024 * 1024, ' ')) == JsonBool::Unknown);
    std::printf("Selective settings: %u checks, %u failures; no real settings read.\n", checks, failures);
    return failures ? 1 : 0;
}
