#include "../runtime/engine_host.hpp"
#include "paths.hpp"
#include "window.hpp"
#include <commctrl.h>
#include <shellapi.h>

using namespace capslang;
using namespace capslang::app;
namespace {
bool Output(const std::string &value) {
    DWORD written = 0;
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    return out && out != INVALID_HANDLE_VALUE &&
           WriteFile(out, value.data(), static_cast<DWORD>(value.size()), &written, nullptr) &&
           written == value.size();
}
int Failure(DWORD error, bool visible) {
    if (visible)
        MessageBoxW(nullptr,
                    (L"CapsLang не запущен. Код ошибки: " + std::to_wstring(error)).c_str(),
                    L"CapsLang", MB_OK | MB_ICONERROR);
    return static_cast<int>(error ? error : ERROR_GEN_FAILURE);
}
int Main(const std::vector<std::wstring> &args) {
    const auto executable = ExecutablePath();
    if (executable.empty())
        return ERROR_BAD_PATHNAME;
    const auto mode = args.empty() ? L"" : args[0];
    const bool json = args.size() == 2 && args[1] == L"--json" && mode == std::wstring(L"--status");
    if (args.size() > 1 && !json)
        return ERROR_INVALID_PARAMETER;
    DWORD error = 0;
    if (mode == std::wstring(L"--engine")) {
        const auto elevated = ProcessElevation(GetCurrentProcessId());
        if (!elevated.known || !elevated.elevated || !ProtectedExecutable(executable, error))
            return Failure(error ? error : ERROR_ACCESS_DENIED, false);
        EngineHost host;
        if (!host.Start())
            return Failure(host.Error(), false);
        WaitForSingleObject(host.ShutdownEvent(), INFINITE);
        host.Stop();
        return 0;
    }
    // This executable's privileged branch above cannot enter the ordinary UI,
    // certificate or networking code, including when explicitly launched high.
    const auto elevated = ProcessElevation(GetCurrentProcessId());
    // Read-only JSON status remains usable from remote administrative tools;
    // it opens only authenticated local IPC, never the network or user files.
    if ((!elevated.known || elevated.elevated) && !json)
        return Failure(elevated.known ? ERROR_ACCESS_DENIED : elevated.error, !json);
    ControlRequest request;
    request.id = GetTickCount64() + 1;
    ControlResponse response;
    if (mode == std::wstring(L"--status") || mode == std::wstring(L"--diagnose")) {
        if (!ControlCall(executable, request, response, error)) {
            response.status.engineError = error;
            response.status.networkError = error;
        }
        if (json) {
            Output(StatusJson(response.status, GetTickCount64()));
            return static_cast<int>(error ? error : response.error);
        }
        if (mode == std::wstring(L"--diagnose")) {
            const auto directory = DataDirectory(error);
            std::wstring path;
            if (directory.empty() ||
                !ExportDiagnosis(directory, StatusJson(response.status, GetTickCount64()), path,
                                 error))
                return Failure(error, true);
            MessageBoxW(nullptr, (L"Диагностика сохранена:\r\n" + path).c_str(), L"CapsLang",
                        MB_OK);
            return 0;
        }
        request.command = Command::Show;
        if (!ControlCall(executable, request, response, error))
            return Failure(error, true);
        return static_cast<int>(response.error);
    }
    if (mode == std::wstring(L"--restart") || mode == std::wstring(L"--stop")) {
        request.command = mode == std::wstring(L"--stop") ? Command::Stop : Command::Refresh;
        if (!ControlCall(executable, request, response, error))
            return Failure(error, false);
        return static_cast<int>(response.error);
    }
    if (mode != std::wstring(L"") && mode != std::wstring(L"--pair") &&
        mode != std::wstring(L"--background") && mode != std::wstring(L"--run-once"))
        return ERROR_INVALID_PARAMETER;
    const bool background = mode == std::wstring(L"--background");
    request.command = background ? Command::Status : Command::Show;
    if (ControlCall(executable, request, response, error))
        return static_cast<int>(response.error);
    if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PIPE_NOT_CONNECTED &&
        error != ERROR_BROKEN_PIPE)
        return Failure(error, !background);
    bool portable = mode == std::wstring(L"--run-once");
    if (!portable && !ProtectedExecutable(executable, error)) {
        if (background || mode == std::wstring(L"--pair"))
            return Failure(ERROR_NOT_READY, !background);
        TASKDIALOG_BUTTON buttons[] = {{100, L"Запустить один раз — ограниченные права"},
                                       {IDCANCEL, L"Отмена"}};
        TASKDIALOGCONFIG dialog{};
        dialog.cbSize = sizeof(dialog);
        dialog.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_USE_COMMAND_LINKS;
        dialog.pszWindowTitle = L"CapsLang 1.1 — сборка разработки";
        dialog.pszMainInstruction = L"Установщик ещё не готов";
        dialog.pszContent =
            L"Этот EXE предназначен для проверки нового приложения. Автозапуск не изменяется. "
            L"Повышенные окна в запуске без установки не поддерживаются.";
        dialog.cButtons = ARRAYSIZE(buttons);
        dialog.pButtons = buttons;
        dialog.nDefaultButton = IDCANCEL;
        int selected = IDCANCEL;
        const HRESULT hr = TaskDialogIndirect(&dialog, &selected, nullptr, nullptr);
        if (FAILED(hr))
            return static_cast<int>(hr);
        if (selected != 100)
            return 0;
        portable = true;
    }
    std::unique_ptr<EngineHost> host;
    if (portable) {
        // Do not put two keyboard remappers on the user's working desktop.
        if (FindWindowW(L"CapsLang.Reliable.HiddenWindow.1", nullptr))
            return Failure(ERROR_BUSY, true);
        host = std::make_unique<EngineHost>();
        if (!host->Start())
            return Failure(host->Error(), true);
    }
    const auto directory = DataDirectory(error);
    if (directory.empty())
        return Failure(error, !background);
    Broker broker(directory, EngineDependencies(executable, !portable));
    if (!broker.Start())
        return Failure(broker.Error(), !background);
    const int result = RunWindow(broker, directory, !background, host ? host->ShutdownEvent() : nullptr);
    // Portable engine belongs to this UI owner. Remove its endpoint before
    // joining the broker that may be waiting for shutdown confirmation.
    if (host)
        host->Stop();
    broker.Stop();
    return result ? result : static_cast<int>(broker.Error());
}
} // namespace
int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&controls);
    int count = 0;
    LPWSTR *raw = CommandLineToArgvW(GetCommandLineW(), &count);
    if (!raw)
        return ERROR_INVALID_PARAMETER;
    std::vector<std::wstring> arguments;
    for (int i = 1; i < count; ++i)
        arguments.emplace_back(raw[i]);
    LocalFree(raw);
    try {
        return Main(arguments);
    } catch (...) {
        return Failure(ERROR_UNHANDLED_EXCEPTION, false);
    }
}
