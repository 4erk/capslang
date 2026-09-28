// Feasibility instrument, not the CapsLang 1.1 application or an installer.
#include "../src/platform/windows_support.hpp"
#include "../src/activity.hpp"
#include <shellapi.h>
#include <commdlg.h>
#include <objbase.h>
#include <ntddkbd.h>
#include <atomic>
#include <cstdio>
#include <sstream>
#include <vector>

using namespace capslang;
namespace {
constexpr UINT kRefresh = 1, kLayoutTimer = 2, kLedTimer = 3;
constexpr int kInventoryButton = 101, kLayoutButton = 102, kLedButton = 103;
constexpr int kSaveButton = 104, kElevateButton = 105, kPauseButton = 106;
constexpr int kObserveButton = 107, kStopObserveButton = 108;
constexpr wchar_t kClass[] = L"CapsLang.FeasibilityProbe.1";
constexpr ULONG_PTR kOldInput = static_cast<ULONG_PTR>(0x434150534C414E47ULL);
constexpr ULONG_PTR kOldProbe = static_cast<ULONG_PTR>(0x4341505350524F42ULL);
HWND g_window = nullptr, g_text = nullptr;
std::string g_report;
KeyboardLeds g_leds;
HANDLE g_hookThread = nullptr, g_ready = nullptr, g_elevatedChild = nullptr;
std::atomic<DWORD> g_hookThreadId{0};
std::atomic<DWORD> g_keyboardError{0}, g_mouseError{0};
std::atomic<bool> g_keyboardInstalled{false}, g_mouseInstalled{false};
std::atomic<ULONGLONG> g_physical{0}, g_injected{0}, g_suppressed{0}, g_own{0}, g_last{0};
LayoutTarget g_target;
bool g_layoutActive = false;
int g_countdown = 0, g_layoutPhase = 0;
ULONGLONG g_phaseStarted = 0;
std::vector<bool> g_originalScroll;
bool g_ledActive = false;
unsigned g_logicalLocksBefore = 0;
std::wstring g_pausedLegacy;

std::wstring Wide(const std::string& value) {
    if (value.empty()) return {};
    const int length = MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
    std::wstring result(static_cast<size_t>(length), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(), length);
    return result;
}
void Record(const std::string& json) {
    g_report += json + "\r\n";
    if (g_text) {
        const auto text = Wide(json + "\r\n");
        SendMessageW(g_text, EM_SETSEL, static_cast<WPARAM>(-1), static_cast<LPARAM>(-1));
        SendMessageW(g_text, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(text.c_str()));
    }
}
void Inventory() {
    const auto elevation = ProcessElevation(GetCurrentProcessId());
    std::ostringstream data;
    data << "{\"event\":\"inventory\",\"probe\":\"1.1.0-gate1\",\"pid\":" << GetCurrentProcessId()
         << ",\"elevation_known\":" << elevation.known << ",\"elevated\":" << elevation.elevated
         << ",\"elevation_error\":" << elevation.error << ",\"en_installed\":" << !!FindLayout(kEnglish)
         << ",\"ru_installed\":" << !!FindLayout(kRussian) << "}";
    Record(data.str());
    g_leds.Discover();
    for (size_t i = 0; i < g_leds.Devices().size(); ++i) {
        const auto& device = g_leds.Devices()[i];
        std::ostringstream row;
        row << "{\"event\":\"led_device\",\"index\":" << i
            << ",\"class_device\":" << (device.path.find(L"GLOBALROOT") != std::wstring::npos)
            << ",\"open_error\":" << device.openError << ",\"query_error\":" << device.queryError
            << ",\"queried\":" << device.queried << ",\"flags\":" << device.flags << "}";
        Record(row.str());
    }
    Record("{\"event\":\"led_enumeration\",\"count\":" + std::to_string(g_leds.Devices().size()) +
           ",\"error\":" + std::to_string(g_leds.EnumerationError()) + "}");
}

void Observe(bool ownEvent, bool injected, LRESULT next) {
    if (ownEvent) { g_own.fetch_add(1, std::memory_order_relaxed); return; }
    if (!IsDeliveredActivity(true, ownEvent, next != 0)) {
        g_suppressed.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    (injected ? g_injected : g_physical).fetch_add(1, std::memory_order_relaxed);
    g_last.store(GetTickCount64(), std::memory_order_relaxed);
}
LRESULT CALLBACK KeyboardCallback(int code, WPARAM message, LPARAM data) {
    if (code != HC_ACTION) return CallNextHookEx(nullptr, code, message, data);
    const auto event = *reinterpret_cast<const KBDLLHOOKSTRUCT*>(data);
    const LRESULT next = CallNextHookEx(nullptr, code, message, data);
    Observe(event.dwExtraInfo == kOldInput || event.dwExtraInfo == kOldProbe,
            (event.flags & LLKHF_INJECTED) != 0, next);
    return next; // An observer never swallows or synthesizes any key.
}
LRESULT CALLBACK MouseCallback(int code, WPARAM message, LPARAM data) {
    if (code != HC_ACTION) return CallNextHookEx(nullptr, code, message, data);
    const auto event = *reinterpret_cast<const MSLLHOOKSTRUCT*>(data);
    const LRESULT next = CallNextHookEx(nullptr, code, message, data);
    Observe(event.dwExtraInfo == kOldInput || event.dwExtraInfo == kOldProbe,
            (event.flags & LLMHF_INJECTED) != 0, next);
    return next;
}
DWORD WINAPI ObserverThread(void*) {
    MSG message{};
    PeekMessageW(&message, nullptr, WM_USER, WM_USER, PM_NOREMOVE);
    g_hookThreadId.store(GetCurrentThreadId());
    const HHOOK keyboard = SetWindowsHookExW(WH_KEYBOARD_LL, KeyboardCallback, GetModuleHandleW(nullptr), 0);
    g_keyboardError.store(keyboard ? 0 : GetLastError());
    const HHOOK mouse = SetWindowsHookExW(WH_MOUSE_LL, MouseCallback, GetModuleHandleW(nullptr), 0);
    g_mouseError.store(mouse ? 0 : GetLastError());
    g_keyboardInstalled.store(keyboard != nullptr);
    g_mouseInstalled.store(mouse != nullptr);
    SetEvent(g_ready);
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    if (mouse) UnhookWindowsHookEx(mouse);
    if (keyboard) UnhookWindowsHookEx(keyboard);
    g_keyboardInstalled.store(false);
    g_mouseInstalled.store(false);
    return 0;
}
void StopObserver() {
    if (!g_hookThread) return;
    PostThreadMessageW(g_hookThreadId.load(), WM_QUIT, 0, 0);
    if (WaitForSingleObject(g_hookThread, 5000) != WAIT_OBJECT_0) {
        Record("{\"event\":\"observer_stop_timeout\"}");
        return; // Do not destroy handles still in use, or force-kill a thread.
    }
    CloseHandle(g_hookThread);
    g_hookThread = nullptr;
    CloseHandle(g_ready);
    g_ready = nullptr;
    Record("{\"event\":\"observer_stopped\"}");
}
void StartObserver() {
    if (g_hookThread) return;
    g_physical = 0; g_injected = 0; g_suppressed = 0; g_own = 0; g_last = 0;
    g_ready = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_ready) { Record("{\"event\":\"observer_event_failed\"}"); return; }
    g_hookThread = CreateThread(nullptr, 0, ObserverThread, nullptr, 0, nullptr);
    if (!g_hookThread) {
        CloseHandle(g_ready); g_ready = nullptr;
        Record("{\"event\":\"observer_thread_failed\"}"); return;
    }
    if (WaitForSingleObject(g_ready, 3000) != WAIT_OBJECT_0) {
        Record("{\"event\":\"observer_start_timeout\"}"); return;
    }
    Record("{\"event\":\"observer_started\",\"keyboard_error\":" +
           std::to_string(g_keyboardError.load()) + ",\"mouse_error\":" +
           std::to_string(g_mouseError.load()) + "}");
}
void Snapshot() {
    if (!g_hookThread) return;
    const auto last = g_last.load();
    Record("{\"event\":\"activity\",\"tick_ms\":" + std::to_string(GetTickCount64()) +
        ",\"physical_delivered\":" + std::to_string(g_physical.load()) +
        ",\"injected_delivered\":" + std::to_string(g_injected.load()) +
        ",\"suppressed\":" + std::to_string(g_suppressed.load()) +
        ",\"own_ignored\":" + std::to_string(g_own.load()) +
        ",\"age_ms\":" + (last ? std::to_string(GetTickCount64() - last) : "null") + "}");
}

bool PauseLegacy() {
    if (!g_pausedLegacy.empty()) return true;
    const auto elevation = ProcessElevation(GetCurrentProcessId());
    if (!elevation.known || elevation.elevated) {
        Record("{\"event\":\"pause_requires_normal_parent\"}");
        return false;
    }
    HWND old = FindWindowExW(HWND_MESSAGE, nullptr, L"CapsLang.Reliable.HiddenWindow.1",
                            L"CapsLang reliable background engine");
    if (!old) { Record("{\"event\":\"legacy_not_running\"}"); return true; }
    DWORD pid = 0;
    GetWindowThreadProcessId(old, &pid);
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
    if (!process) { Record("{\"event\":\"legacy_query_failed\"}"); return false; }
    wchar_t path[32768]{};
    DWORD length = ARRAYSIZE(path);
    bool ok = QueryFullProcessImageNameW(process, 0, path, &length) != FALSE;
    wchar_t localAppData[32768]{};
    const DWORD envLength = GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData, ARRAYSIZE(localAppData));
    const std::wstring expected = std::wstring(localAppData) + L"\\CapsLang\\CapsLang.exe";
    ok = ok && envLength > 0 && envLength < ARRAYSIZE(localAppData) && _wcsicmp(path, expected.c_str()) == 0;
    if (ok) ok = PostMessageW(old, WM_APP + 5, 0, 0) != FALSE;
    if (ok) ok = WaitForSingleObject(process, 5000) == WAIT_OBJECT_0;
    CloseHandle(process);
    if (ok) g_pausedLegacy = expected;
    Record(ok ? "{\"event\":\"legacy_paused_until_probe_exit\"}" : "{\"event\":\"legacy_pause_failed\"}");
    return ok;
}
void ResumeLegacy() {
    if (g_pausedLegacy.empty()) return;
    std::wstring command = L"\"" + g_pausedLegacy + L"\" --background";
    STARTUPINFOW startup{}; startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (CreateProcessW(g_pausedLegacy.c_str(), command.data(), nullptr, nullptr,
                       FALSE, 0, nullptr, nullptr, &startup, &process)) {
        CloseHandle(process.hThread); CloseHandle(process.hProcess);
        g_pausedLegacy.clear();
        Record("{\"event\":\"legacy_resumed\"}");
    } else {
        Record("{\"event\":\"legacy_resume_failed\",\"error\":" + std::to_string(GetLastError()) + "}");
        MessageBoxW(g_window, L"Не удалось вернуть CapsLang 1.0.0. Запустите его из %LOCALAPPDATA%\\CapsLang.",
                    L"CapsLang Probe", MB_OK | MB_ICONERROR);
    }
}

void RequestPhase(HKL layout) {
    const auto result = RequestLayout(g_target, layout);
    g_phaseStarted = GetTickCount64();
    Record("{\"event\":\"layout_request\",\"phase\":" + std::to_string(g_layoutPhase) +
        ",\"target_lang\":" + std::to_string(LOWORD(reinterpret_cast<ULONG_PTR>(layout))) +
        ",\"thread_manager_hr\":" + std::to_string(result.threadManager) +
        ",\"change_language_hr\":" + std::to_string(result.changeLanguage) +
        ",\"activate_profile_hr\":" + std::to_string(result.activateProfile) +
        ",\"posted\":" + std::to_string(result.posted) +
        ",\"post_error\":" + std::to_string(result.postError) + "}");
}
void EndLayout() {
    KillTimer(g_window, kLayoutTimer);
    g_layoutActive = false;
    Record("{\"event\":\"layout_probe_finished\"}");
}
void LayoutTick() {
    if (g_countdown > 0) {
        --g_countdown;
        if (g_countdown != 0) return;
        g_target = CaptureLayoutTarget();
        if (!TargetStillValid(g_target) || g_target.processId == GetCurrentProcessId() ||
            !IsSupportedLanguage(TargetLanguage(g_target))) {
            Record("{\"event\":\"layout_target_invalid_select_external_text_field\"}");
            EndLayout(); return;
        }
        const auto elevation = ProcessElevation(g_target.processId);
        Record("{\"event\":\"layout_target\",\"pid\":" + std::to_string(g_target.processId) +
            ",\"elevation_known\":" + std::to_string(elevation.known) +
            ",\"elevated\":" + std::to_string(elevation.elevated) +
            ",\"elevation_error\":" + std::to_string(elevation.error) +
            ",\"original_lang\":" + std::to_string(TargetLanguage(g_target)) + "}");
        g_layoutPhase = 0;
        SetTimer(g_window, kLayoutTimer, 50, nullptr);
        RequestPhase(FindLayout(kEnglish));
        return;
    }
    const HKL requested = g_layoutPhase == 0 ? FindLayout(kEnglish) :
                          g_layoutPhase == 1 ? FindLayout(kRussian) : g_target.original;
    if (!TargetStillValid(g_target) || g_target.foreground != GetForegroundWindow()) {
        // Do not broadcast a restore over a newly selected foreground window.
        // Restore only the original target, if it still exists.
        if (TargetStillValid(g_target)) {
            PostMessageW(g_target.focus, WM_INPUTLANGCHANGEREQUEST, 0,
                          reinterpret_cast<LPARAM>(g_target.original));
        }
        Record("{\"event\":\"layout_probe_cancelled_focus_changed\"}");
        EndLayout(); return;
    }
    const auto language = TargetLanguage(g_target);
    const bool verified = language == LOWORD(reinterpret_cast<ULONG_PTR>(requested));
    const auto elapsed = GetTickCount64() - g_phaseStarted;
    if (!verified && elapsed < 1000) return;
    Record("{\"event\":\"layout_readback\",\"phase\":" + std::to_string(g_layoutPhase) +
        ",\"actual_lang\":" + std::to_string(language) + ",\"verified\":" +
        std::to_string(verified) + ",\"elapsed_ms\":" + std::to_string(elapsed) + "}");
    if (++g_layoutPhase >= 3) { EndLayout(); return; }
    RequestPhase(g_layoutPhase == 1 ? FindLayout(kRussian) : g_target.original);
}
unsigned LogicalLocks() {
    return ((GetKeyState(VK_SCROLL) & 1) ? 1U : 0U) |
           ((GetKeyState(VK_NUMLOCK) & 1) ? 2U : 0U) |
           ((GetKeyState(VK_CAPITAL) & 1) ? 4U : 0U);
}
void RestoreLeds() {
    if (!g_ledActive) return;
    KillTimer(g_window, kLedTimer);
    for (size_t i = 0; i < g_originalScroll.size(); ++i) {
        if (!g_leds.Devices()[i].queried) continue;
        DWORD error = 0;
        const bool restored = g_leds.SetScroll(i, g_originalScroll[i], error);
        Record("{\"event\":\"led_restore\",\"index\":" + std::to_string(i) +
            ",\"ok\":" + std::to_string(restored) + ",\"error\":" + std::to_string(error) + "}");
    }
    g_ledActive = false;
    Record("{\"event\":\"logical_locks_after_led\",\"before\":" + std::to_string(g_logicalLocksBefore) +
        ",\"after\":" + std::to_string(LogicalLocks()) +
        ",\"unchanged\":" + std::to_string(g_logicalLocksBefore == LogicalLocks()) + "}");
    Record("{\"event\":\"led_visual_confirmation_required\"}");
}
void StartLeds() {
    g_leds.Discover();
    g_originalScroll.clear();
    for (const auto& device : g_leds.Devices()) {
        g_originalScroll.push_back((device.flags & KEYBOARD_SCROLL_LOCK_ON) != 0);
    }
    g_logicalLocksBefore = LogicalLocks();
    g_ledActive = true;
    unsigned written = 0;
    for (size_t i = 0; i < g_originalScroll.size(); ++i) {
        if (!g_leds.Devices()[i].queried) continue;
        DWORD error = 0;
        const bool ok = g_leds.SetScroll(i, !g_originalScroll[i], error);
        if (ok) ++written;
        Record("{\"event\":\"led_set\",\"index\":" + std::to_string(i) +
            ",\"ok\":" + std::to_string(ok) + ",\"error\":" + std::to_string(error) + "}");
        USHORT flags = 0;
        if (ok && g_leds.ReadFlags(i, flags, error)) {
            const unsigned others = static_cast<unsigned>(~KEYBOARD_SCROLL_LOCK_ON) & 0xffffU;
            Record("{\"event\":\"led_readback\",\"index\":" + std::to_string(i) +
                ",\"flags\":" + std::to_string(flags) + ",\"other_bits_preserved\":" +
                std::to_string((flags & others) == (g_leds.Devices()[i].flags & others)) + "}");
        }
    }
    Record("{\"event\":\"led_write_count\",\"count\":" + std::to_string(written) + "}");
    SetTimer(g_window, kLedTimer, 1500, nullptr);
}

void SaveReport() {
    wchar_t path[32768]{};
    const auto elevation = ProcessElevation(GetCurrentProcessId());
    wcscpy_s(path, elevation.elevated ? L"capslang-probe-elevated.jsonl" : L"capslang-probe-normal.jsonl");
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = g_window;
    dialog.lpstrFilter = L"JSON Lines (*.jsonl)\0*.jsonl\0\0";
    dialog.lpstrFile = path;
    dialog.nMaxFile = ARRAYSIZE(path);
    dialog.lpstrDefExt = L"jsonl";
    dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (!GetSaveFileNameW(&dialog)) return;
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    bool ok = false;
    if (file != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        ok = WriteFile(file, g_report.data(), static_cast<DWORD>(g_report.size()), &written, nullptr) &&
             written == g_report.size();
        CloseHandle(file);
    }
    if (!ok) MessageBoxW(g_window, L"Не удалось записать отчёт.", L"CapsLang Probe", MB_OK | MB_ICONERROR);
}
void Elevate() {
    if (g_elevatedChild || !PauseLegacy()) return;
    StopObserver();
    wchar_t path[32768]{};
    GetModuleFileNameW(nullptr, path, ARRAYSIZE(path));
    SHELLEXECUTEINFOW info{};
    info.cbSize = sizeof(info);
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.hwnd = g_window;
    info.lpVerb = L"runas";
    info.lpFile = path;
    info.lpParameters = L"--interactive";
    info.nShow = SW_SHOWNORMAL;
    if (ShellExecuteExW(&info)) {
        g_elevatedChild = info.hProcess;
        Record("{\"event\":\"elevated_probe_started\"}");
    } else {
        Record("{\"event\":\"elevated_probe_not_started\",\"error\":" + std::to_string(GetLastError()) + "}");
        ResumeLegacy();
    }
}
bool Busy() { return g_layoutActive || g_ledActive || g_elevatedChild; }

LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_COMMAND: {
        const int command = LOWORD(wParam);
        if (Busy()) return 0;
        if ((command == kLayoutButton || command == kLedButton || command == kObserveButton) &&
            FindWindowExW(HWND_MESSAGE, nullptr, L"CapsLang.Reliable.HiddenWindow.1",
                          L"CapsLang reliable background engine")) {
            Record("{\"event\":\"pause_legacy_first_to_exclude_its_injected_events\"}");
            MessageBoxW(window, L"Сначала нажмите «Приостановить 1.0.0» в обычном окне проверки. "
                        L"Иначе старые F24/Scroll Lock исказят результат.", L"CapsLang Probe", MB_OK);
            return 0;
        }
        switch (command) {
        case kInventoryButton: Inventory(); break;
        case kPauseButton: PauseLegacy(); break;
        case kObserveButton: StartObserver(); break;
        case kStopObserveButton: Snapshot(); StopObserver(); break;
        case kSaveButton: SaveReport(); break;
        case kElevateButton: Elevate(); break;
        case kLedButton: StartLeds(); break;
        case kLayoutButton:
            if (!FindLayout(kEnglish) || !FindLayout(kRussian)) {
                Record("{\"event\":\"required_layout_missing\"}"); break;
            }
            g_countdown = 5;
            g_layoutActive = true;
            Record("{\"event\":\"layout_countdown_5_seconds_focus_external_text_field\"}");
            SetTimer(window, kLayoutTimer, 1000, nullptr);
            break;
        }
        return 0;
    }
    case WM_TIMER:
        if (wParam == kRefresh) {
            if (g_elevatedChild && WaitForSingleObject(g_elevatedChild, 0) == WAIT_OBJECT_0) {
                CloseHandle(g_elevatedChild); g_elevatedChild = nullptr;
                Record("{\"event\":\"elevated_probe_exited\"}");
                ResumeLegacy();
            }
            Snapshot();
        } else if (wParam == kLayoutTimer) LayoutTick();
        else if (wParam == kLedTimer) RestoreLeds();
        return 0;
    case WM_CLOSE:
        if (g_elevatedChild || g_layoutActive) {
            MessageBoxW(window, L"Сначала завершите тест раскладки или закройте повышенное окно проверки.",
                        L"CapsLang Probe", MB_OK);
            return 0;
        }
        RestoreLeds();
        StopObserver();
        ResumeLegacy();
        DestroyWindow(window);
        return 0;
    case WM_DESTROY: PostQuitMessage(0); return 0;
    default: return DefWindowProcW(window, message, wParam, lParam);
    }
}
} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int) {
    int argc = 0;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    bool inventoryOnly = false;
    for (int i = 1; argv && i < argc; ++i) {
        if (wcscmp(argv[i], L"--inventory") == 0) inventoryOnly = true;
    }
    if (argv) LocalFree(argv);
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (inventoryOnly) {
        Inventory();
        DWORD written = 0;
        const bool ok = WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), g_report.data(),
            static_cast<DWORD>(g_report.size()), &written, nullptr) != FALSE;
        CoUninitialize();
        return ok ? 0 : 2;
    }
    WNDCLASSW cls{};
    cls.hInstance = instance;
    cls.lpfnWndProc = WindowProc;
    cls.lpszClassName = kClass;
    cls.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    cls.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
    RegisterClassW(&cls);
    const auto elevation = ProcessElevation(GetCurrentProcessId());
    g_window = CreateWindowW(kClass, elevation.elevated ? L"CapsLang Probe — администратор" : L"CapsLang Probe — обычные права",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, CW_USEDEFAULT, CW_USEDEFAULT,
        980, 670, nullptr, nullptr, instance, nullptr);
    if (!g_window) return 1;
    CreateWindowW(L"STATIC", L"Проверка предпосылок 1.1.0 — НЕ новая версия CapsLang. Автозапуск не меняется.\n"
        L"Сначала приостановите 1.0.0. Для теста языка выберите внешнее текстовое поле за 5 секунд.\n"
        L"LED мигает 1,5 секунды и возвращается назад. Сохраните отчёты обычного и повышенного окон.",
        WS_CHILD | WS_VISIBLE, 12, 10, 940, 65, g_window, nullptr, instance, nullptr);
    const struct { int id; const wchar_t* label; } buttons[] = {
        {kPauseButton, L"Приостановить 1.0.0"}, {kInventoryButton, L"Проверить устройства"},
        {kLayoutButton, L"Тест языка через 5с"}, {kLedButton, L"Мигнуть LED"},
        {kObserveButton, L"Наблюдать ввод"}, {kStopObserveButton, L"Остановить наблюдение"},
        {kElevateButton, L"Проверить с UAC"}, {kSaveButton, L"Сохранить отчёт"},
    };
    for (int i = 0; i < 8; ++i) {
        HWND button = CreateWindowW(L"BUTTON", buttons[i].label, WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            12 + (i % 4) * 237, 82 + (i / 4) * 36, 228, 30, g_window,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(buttons[i].id)), instance, nullptr);
        if (elevation.elevated && (buttons[i].id == kPauseButton || buttons[i].id == kElevateButton)) {
            EnableWindow(button, FALSE);
        }
    }
    g_text = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL |
        ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL, 12, 165, 940, 450, g_window,
        nullptr, instance, nullptr);
    SendMessageW(g_text, EM_SETLIMITTEXT, 4 * 1024 * 1024, 0);
    Inventory();
    SetTimer(g_window, kRefresh, 2000, nullptr);
    ShowWindow(g_window, SW_SHOW);
    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    CoUninitialize();
    return 0;
}
