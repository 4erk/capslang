#include "../runtime/engine_host.hpp"
#include "../runtime/system_layout.hpp"
#include "../runtime/system_profile.hpp"
#include "../runtime/system_caps.hpp"
#include "profile_assets.hpp"
#include "installer.hpp"
#include "paths.hpp"
#include "tasks.hpp"
#include "window.hpp"
#include <commctrl.h>
#include <shellapi.h>

using namespace capslang;
using namespace capslang::app;
int CapsLangSaverMain();
bool StartCapsLangSaver();
void StopCapsLangSaver();
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
#ifdef CAPSLANG_SYSTEM_PROFILE_PROBE
    const bool probeStatus = args.size() == 2 && mode == std::wstring(L"--status") && args[1] == L"--json";
    if (args.size() != 1 && !probeStatus) return ERROR_INVALID_PARAMETER;
    if (mode == std::wstring(L"--profile-probe-system")) return system_layout::ProbeWorker();
    if (mode == std::wstring(L"--profile-probe-stage")) {
        const auto elevation = ProcessElevation(GetCurrentProcessId());
        const auto user = ipc::Endpoint::Current();
        DWORD error = 0;
        if (!elevation.known || !elevation.elevated || user.error || !user.session) return ERROR_ACCESS_DENIED;
        const auto installed = InstalledExecutable(error);
        if (installed.empty() || _wcsicmp(installed.c_str(), executable.c_str()) == 0) return ERROR_INVALID_PARAMETER;
        const auto root = installed.substr(0, installed.find_last_of(L'\\'));
        install::Hash hash{};
        const auto owner = L"CapsLang protected installation v1\n" + user.sid;
        std::vector<BYTE> bytes(owner.size() * sizeof(wchar_t));
        memcpy(bytes.data(), owner.data(), bytes.size());
        if (!install::CreateRoot(root, error) ||
            !install::WriteProtected(root + L"\\owner.bin", bytes, true, error) ||
            !StageProfileAssets(GetModuleHandleW(nullptr), root, error) ||
            !install::CopyProtected(executable, installed, hash, error)) return error;
        return 0;
    }
    if (mode == std::wstring(L"--profile-probe-client")) {
        DWORD error = 0;
        const auto elevation = ProcessElevation(GetCurrentProcessId());
        if (!elevation.known || !elevation.elevated || !ProtectedExecutable(executable, error)) return ERROR_ACCESS_DENIED;
        system_profile::Client client(executable);
        const auto begin = GetTickCount64();
        DWORD lastError = DWORD(-1); std::uint64_t lastPoll = 0;
        while (GetTickCount64() - begin < 60000) {
            const auto age = GetTickCount64() - begin;
            const LANGID language = age < 30000 ? 0x0419 : 0x0409;
            const auto state = client.Apply(CaptureLayoutTarget(), language, age < 30000 ? 1 : 2);
            if (state.error != lastError || (state.report.poll && age / 1000 != lastPoll)) {
                Output("{\"elapsed_ms\":" + std::to_string(age) + ",\"target\":" + std::to_string(language) +
                    ",\"actual\":" + std::to_string(state.report.actual) + ",\"profile\":" + std::to_string(state.report.profile) +
                    ",\"confirmed\":" + std::to_string(state.confirmed) + ",\"error\":" + std::to_string(state.error) + "}\n");
                lastError = state.error; lastPoll = age / 1000;
            }
            Sleep(100);
        }
        return 0;
    }
    // Full two-device diagnostic uses the ordinary production roles against
    // the isolated protected root. No install/pair/unpair commands are exposed.
    if (mode != std::wstring(L"--layout-worker") && mode != std::wstring(L"--engine") &&
        mode != std::wstring(L"--background") && !probeStatus) return ERROR_INVALID_PARAMETER;
#endif
    if (mode == std::wstring(L"--saver-guard") || mode == std::wstring(L"--saver-watch") ||
        mode == std::wstring(L"--saver-status") || mode == std::wstring(L"--saver-stop")) {
        const auto elevated = ProcessElevation(GetCurrentProcessId());
        if (!elevated.known || elevated.elevated)
            return ERROR_ACCESS_DENIED;
        return CapsLangSaverMain();
    }
    const bool json = args.size() == 2 && args[1] == L"--json" && mode == std::wstring(L"--status");
    if (args.size() > 1 && !json)
        return ERROR_INVALID_PARAMETER;
    if (mode == std::wstring(L"--layout-service")) return static_cast<int>(system_layout::ServiceMain());
    if (mode == std::wstring(L"--layout-worker")) return static_cast<int>(system_layout::WorkerMain());
    if (mode == std::wstring(L"--layout-check")) {
        system_layout::Request request; request.id = GetTickCount64() + 1;
        system_layout::Response response; DWORD failure = 0;
        system_layout::Call(executable, request, response, failure);
        return static_cast<int>(failure);
    }
    DWORD error = 0;
    if (mode == std::wstring(L"--admin-install") || mode == std::wstring(L"--admin-revert") ||
        mode == std::wstring(L"--admin-uninstall"))
        return static_cast<int>(
            AdminInstall(mode == std::wstring(L"--admin-install")  ? AdminAction::Install
                         : mode == std::wstring(L"--admin-revert") ? AdminAction::Revert
                                                                   : AdminAction::Uninstall));
    if (mode == std::wstring(L"--prepare-install"))
        return static_cast<int>(PrepareMigration());
    if (mode == std::wstring(L"--complete-install"))
        return static_cast<int>(CompleteMigration());
    if (mode == std::wstring(L"--abort-install"))
        return static_cast<int>(AbortMigration());
    if (mode == std::wstring(L"--install") || mode == std::wstring(L"--uninstall") ||
        mode == std::wstring(L"--rollback")) {
        const auto action = mode == std::wstring(L"--install")     ? UserAction::Install
                            : mode == std::wstring(L"--uninstall") ? UserAction::Uninstall
                                                                   : UserAction::Rollback;
        const auto result = UserInstall(action);
        if (result)
            return Failure(result, true);
        if (action == UserAction::Install) {
            ControlRequest show;
            show.id = 1;
            show.command = Command::Show;
            ControlResponse state;
            ControlCall(InstalledExecutable(error), show, state, error);
        }
        return 0;
    }
    if (mode == std::wstring(L"--engine")) {
        const auto elevated = ProcessElevation(GetCurrentProcessId());
        if (!elevated.known || !elevated.elevated || !ProtectedExecutable(executable, error))
            return Failure(error ? error : ERROR_ACCESS_DENIED, false);
        if (FindWindowW(L"CapsLang.Reliable.HiddenWindow.1", nullptr))
            return ERROR_BUSY;
        EngineOptions options;
        options.profileModule = InstalledProfileModule(IMAGE_FILE_MACHINE_AMD64, error);
        if (options.profileModule.empty()) return Failure(error, false);
        auto system = std::make_shared<system_profile::Client>(executable);
        options.systemProfile = [system](const LayoutTarget& target, LANGID language, std::uint64_t generation) {
            return system->Apply(target, language, generation);
        };
        options.releaseSystemProfile = [system] { system->Release(); };
        auto caps = std::make_shared<system_caps::Client>(executable);
        options.systemCaps = [caps] {
            const auto result = caps->Poll();
            EngineOptions::CapsBatch batch;
            batch.error = result.error; batch.heartbeat = result.heartbeat; batch.recoveries = result.recoveries;
            batch.count = result.count;
            for (unsigned i = 0; i < result.count && i < 8; ++i) {
                batch.stamps[i] = result.events[i].stamp;
                batch.convert[i] = result.events[i].action == system_caps::Action::ConvertSelection;
            }
            return batch;
        };
        EngineHost host(ipc::Endpoint::Current(), options);
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
        if (mode == std::wstring(L"--restart") && ProtectedExecutable(executable, error))
            return static_cast<int>(RestartInstalled());
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
    if (error == ERROR_ACCESS_DENIED && mode == std::wstring(L"")) {
        const auto installed = InstalledExecutable(error);
        if (!installed.empty() && ProtectedExecutable(installed, error) &&
            ControlCall(installed, request, response, error))
            return static_cast<int>(response.error);
    }
    if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PIPE_NOT_CONNECTED &&
        error != ERROR_BROKEN_PIPE)
        return Failure(error, !background);
    bool portable = mode == std::wstring(L"--run-once");
    if (!portable && !ProtectedExecutable(executable, error)) {
        if (background || mode == std::wstring(L"--pair"))
            return Failure(ERROR_NOT_READY, !background);
        TASKDIALOG_BUTTON buttons[] = {
            {101, L"Установить или обновить — поддержка повышенных окон"},
            {100, L"Запустить один раз — ограниченные права"},
            {IDCANCEL, L"Отмена"}};
        TASKDIALOGCONFIG dialog{};
        dialog.cbSize = sizeof(dialog);
        dialog.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_USE_COMMAND_LINKS;
        dialog.pszWindowTitle = L"CapsLang 1.1";
        dialog.pszMainInstruction = L"Переключение EN/RU и синхронизация двух устройств";
        dialog.pszContent = L"Установка запросит UAC один раз, сохранит прежнюю версию и настроит "
                            L"запуск при входе. "
                            L"Без установки повышенные окна не поддерживаются.";
        dialog.cButtons = ARRAYSIZE(buttons);
        dialog.pButtons = buttons;
        dialog.nDefaultButton = IDCANCEL;
        int selected = IDCANCEL;
        const HRESULT hr = TaskDialogIndirect(&dialog, &selected, nullptr, nullptr);
        if (FAILED(hr))
            return static_cast<int>(hr);
        if (selected == 101) {
            const DWORD result = UserInstall(UserAction::Install);
            if (result)
                return Failure(result, true);
            return 0;
        }
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
    } else {
        const auto result = EnsureInstalledEngine();
        if (result)
            return Failure(result, !background);
    }
    const auto directory = DataDirectory(error);
    if (directory.empty())
        return Failure(error, !background);
    Broker broker(directory, EngineDependencies(executable, !portable));
    if (!broker.Start())
        return Failure(broker.Error(), !background);
    // The lease runs in this ordinary owner process; only crash restoration
    // needs a separate minimal watchdog. Keep the legacy guard until migration.
#ifndef CAPSLANG_SYSTEM_PROFILE_PROBE
    if (!StartCapsLangSaver()) { broker.Stop(); return Failure(ERROR_NOT_READY,!background); }
#endif
    const int result =
        RunWindow(broker, directory, !background, host ? host->ShutdownEvent() : nullptr);
    // Portable engine belongs to this UI owner. Remove its endpoint before
    // joining the broker that may be waiting for shutdown confirmation.
    if (host)
        host->Stop();
    broker.Stop();
    StopCapsLangSaver();
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
