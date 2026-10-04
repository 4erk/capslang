// Read-only inventory. The disruptive interactive feasibility probe is retired.
// Never stop CapsLang, elevate, install hooks, change layouts or write LEDs here.
#include "../src/platform/windows_support.hpp"
#include <shellapi.h>
#include <sstream>

using namespace capslang;
int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    int argc = 0;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    const bool inventory = argv && argc == 2 && wcscmp(argv[1], L"--inventory") == 0;
    if (argv) LocalFree(argv);
    if (!inventory) {
        MessageBoxW(nullptr,
            L"Это не обновление CapsLang. Интерактивная диагностика отключена.\n"
            L"Программа не останавливает CapsLang и не меняет настройки.\n"
            L"Для разработчика: --inventory выводит сведения без изменений.",
            L"CapsLang — только чтение", MB_OK | MB_ICONINFORMATION);
        return 2;
    }
    const auto elevation = ProcessElevation(GetCurrentProcessId());
    std::ostringstream report;
    report << "{\"event\":\"inventory\",\"read_only\":true,\"pid\":" << GetCurrentProcessId()
           << ",\"elevation_known\":" << elevation.known << ",\"elevated\":" << elevation.elevated
           << ",\"elevation_error\":" << elevation.error << ",\"en_installed\":" << !!FindLayout(kEnglish)
           << ",\"ru_installed\":" << !!FindLayout(kRussian) << "}\r\n";
    const std::string text = report.str();
    DWORD written = 0;
    const bool ok = WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), text.data(),
        static_cast<DWORD>(text.size()), &written, nullptr) && written == text.size();
    return ok ? 0 : 3;
}
