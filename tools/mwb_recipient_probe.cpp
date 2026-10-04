// Diagnostic only: never swallows input, changes layout, sends input or opens
// MWB memory. Selectively reads safety booleans; records aggregate counts/ages
// and routing metadata only. It never prints unrelated MWB settings.
#include "../src/platform/mwb.hpp"
#include "../src/runtime/recipient_input.hpp"
#include <atomic>
#include <cstdio>
#include <cstring>
#include <thread>

namespace {
std::atomic<unsigned long> physicalPassed{0}, physicalConsumed{0}, injected{0};
std::atomic<unsigned long> ownInjected{0};
std::atomic<unsigned long> rawMouse{0}, rawKeyboard{0};
std::atomic<unsigned long> rawAbsolute{0}, rawRelative{0}, rawNullDevice{0}, rawReadErrors{0};
std::atomic<ULONGLONG> rawLast{0};
std::atomic<unsigned long> deliveredMoves{0}, deliveredClicks{0}, deliveredKeys{0};
std::atomic<unsigned long> originHardware{0}, originInjected{0}, originSystem{0}, originUnknown{0};
bool deliveryWindow = false;
bool finished = false; // Window/pump thread only.
HHOOK keyboard = nullptr, mouse = nullptr;
capslang::RecipientInput recipient;

// Compare names locally; don't publish desktop names or window contents.
int InputDesktopMatches(DWORD pumpThread, DWORD& error) {
    HDESK input = OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS);
    if (!input) { error = GetLastError(); return -1; }
    wchar_t a[256]{}, b[256]{}; DWORD needed = 0;
    const bool ok = GetUserObjectInformationW(input, UOI_NAME, a, sizeof(a), &needed) &&
        GetUserObjectInformationW(GetThreadDesktop(pumpThread), UOI_NAME, b, sizeof(b), &needed);
    error = ok ? ERROR_SUCCESS : GetLastError();
    CloseDesktop(input);
    return ok ? (wcscmp(a, b) == 0 ? 1 : 0) : -1;
}

void CountOrigin() {
    INPUT_MESSAGE_SOURCE source{};
    if (!GetCurrentInputMessageSource(&source)) { ++originUnknown; return; }
    switch (source.originId) {
    case IMO_HARDWARE: ++originHardware; break;
    case IMO_INJECTED: ++originInjected; break;
    case IMO_SYSTEM: ++originSystem; break;
    default: ++originUnknown; break;
    }
}
LRESULT CALLBACK Keyboard(int code, WPARAM wp, LPARAM lp) {
    const LRESULT next = CallNextHookEx(nullptr, code, wp, lp);
    if (code == HC_ACTION) {
        const auto& data = *reinterpret_cast<const KBDLLHOOKSTRUCT*>(lp);
        recipient.Key(wp == WM_KEYDOWN || wp == WM_SYSKEYDOWN, (data.flags & LLKHF_INJECTED) != 0,
            next == 0, data.dwExtraInfo == 0x434150534c414e47ULL || data.dwExtraInfo == 0x4341505350524f42ULL,
            data.time, GetTickCount64());
        if (data.flags & LLKHF_INJECTED) {
            ++injected;
            if (data.dwExtraInfo == 0x434150534c414e47ULL || data.dwExtraInfo == 0x4341505350524f42ULL)
                ++ownInjected;
        }
        else if (next) ++physicalConsumed;
        else ++physicalPassed;
    }
    return next;
}
LRESULT CALLBACK Mouse(int code, WPARAM wp, LPARAM lp) {
    const LRESULT next = CallNextHookEx(nullptr, code, wp, lp);
    if (code == HC_ACTION) {
        const auto& data = *reinterpret_cast<const MSLLHOOKSTRUCT*>(lp);
        recipient.Mouse(data.time, GetTickCount64(), (data.flags & LLMHF_INJECTED) != 0, next == 0,
            data.dwExtraInfo == 0x434150534c414e47ULL || data.dwExtraInfo == 0x4341505350524f42ULL);
        if (data.flags & LLMHF_INJECTED) ++injected;
        else if (next) ++physicalConsumed;
        else ++physicalPassed;
    }
    return next;
}
LRESULT CALLBACK Window(HWND window, UINT message, WPARAM wp, LPARAM lp) {
    if (deliveryWindow) {
        if (message == WM_MOUSEMOVE) { ++deliveredMoves; CountOrigin(); }
        if (message == WM_LBUTTONUP) {
            ++deliveredClicks; CountOrigin(); InvalidateRect(window, nullptr, TRUE);
        }
        if (message == WM_KEYDOWN || message == WM_SYSKEYDOWN) { ++deliveredKeys; CountOrigin(); }
        if (message == WM_CLOSE) { finished = true; return 0; }
        if (message == WM_PAINT) {
            PAINTSTRUCT paint{}; HDC dc = BeginPaint(window, &paint);
            RECT rect{}; GetClientRect(window, &rect); InflateRect(&rect, -24, -24);
            wchar_t label[256]{};
            swprintf(label, ARRAYSIZE(label),
                L"CapsLang: проверка доставки ввода\n\nНажми здесь мышью ноутбука через MWB.\n\nПолучено кликов: %lu\n\nТекст и координаты не записываются.",
                deliveredClicks.load());
            DrawTextW(dc, label, -1, &rect, DT_LEFT | DT_WORDBREAK | DT_NOPREFIX);
            EndPaint(window, &paint); return 0;
        }
    }
    if (message == WM_INPUT) {
        RAWINPUTHEADER header{};
        UINT size = sizeof(header);
        // Keyboard packets: header only. Never fetch ordinary key codes.
        if (GetRawInputData(reinterpret_cast<HRAWINPUT>(lp), RID_HEADER, &header, &size,
                           sizeof(header)) == sizeof(header)) {
            if (!header.hDevice) ++rawNullDevice;
            if (header.hDevice) {
                if (header.dwType == RIM_TYPEMOUSE) ++rawMouse;
                if (header.dwType == RIM_TYPEKEYBOARD) ++rawKeyboard;
                rawLast = GetTickCount64();
            }
            if (header.dwType == RIM_TYPEMOUSE) {
                // Win32 requires the entire fixed-size mouse packet to expose
                // usFlags. Inspect ONLY absolute/relative mode, then wipe the
                // transient buffer. Never inspect or log coordinates/buttons.
                RAWINPUT input{}; size = sizeof(input);
                const auto read = GetRawInputData(reinterpret_cast<HRAWINPUT>(lp), RID_INPUT,
                                                  &input, &size, sizeof(header));
                if (read != UINT(-1) && read >= sizeof(RAWINPUTHEADER) + sizeof(RAWMOUSE) &&
                    input.header.dwType == RIM_TYPEMOUSE) {
                    if (input.data.mouse.usFlags & MOUSE_MOVE_ABSOLUTE) ++rawAbsolute;
                    else ++rawRelative;
                    recipient.RawMouse(input, static_cast<DWORD>(GetMessageTime()), GetTickCount64());
                } else ++rawReadErrors;
                SecureZeroMemory(&input, sizeof(input));
            }
        } else ++rawReadErrors;
    }
    return DefWindowProcW(window, message, wp, lp);
}
}
int main(int argc, char** argv) {
    bool recipientCheck = false;
    if (argc == 2 && std::strcmp(argv[1], "--delivery-window") == 0) deliveryWindow = true;
    else if (argc == 2 && std::strcmp(argv[1], "--recipient-check") == 0) recipientCheck = true;
    else if (argc != 1) return 6;
    const ULONGLONG duration = recipientCheck ? 300000 : deliveryWindow ? 180000 : 90000;
    DWORD sid = 0; ProcessIdToSessionId(GetCurrentProcessId(), &sid);
    WNDCLASSW cls{}; cls.hInstance = GetModuleHandleW(nullptr);
    cls.lpszClassName = L"CapsLang.MwbRecipientEvidence"; cls.lpfnWndProc = Window;
    cls.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    cls.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    if (!RegisterClassW(&cls)) return 1;
    HWND window = CreateWindowW(cls.lpszClassName, deliveryWindow ? L"CapsLang — проверка ввода" : L"",
        deliveryWindow ? WS_OVERLAPPEDWINDOW : 0, CW_USEDEFAULT, CW_USEDEFAULT, 540, 260,
        deliveryWindow ? nullptr : HWND_MESSAGE, nullptr, cls.hInstance, nullptr);
    if (!window) return 2;
    RAWINPUTDEVICE devices[]{{1, 2, RIDEV_INPUTSINK, window}, {1, 6, RIDEV_INPUTSINK, window}};
    if (!RegisterRawInputDevices(devices, 2, sizeof(devices[0]))) return 3;
    if (deliveryWindow) ShowWindow(window, SW_SHOWNOACTIVATE);
    keyboard = SetWindowsHookExW(WH_KEYBOARD_LL, Keyboard, cls.hInstance, 0);
    mouse = SetWindowsHookExW(WH_MOUSE_LL, Mouse, cls.hInstance, 0);
    if (!keyboard || !mouse) {
        if (keyboard) UnhookWindowsHookEx(keyboard);
        if (mouse) UnhookWindowsHookEx(mouse);
        return 4;
    }
    capslang::MwbMonitor monitor;
    HANDLE observerStop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!observerStop || !monitor.Start()) {
        if (observerStop) CloseHandle(observerStop);
        UnhookWindowsHookEx(keyboard); UnhookWindowsHookEx(mouse); DestroyWindow(window); return 5;
    }
    const auto started = GetTickCount64();
    const DWORD pumpThread = GetCurrentThreadId();
    // Disk/pipe stdout can stall. Keep ALL formatting/flushing off the hook
    // thread as well as signature discovery. Counters are aggregate snapshots,
    // not an atomic per-event trace or a production activity classifier.
    std::thread logger([&] {
        std::printf("session=%lu elevated=%d delivery_window=%d duration_ms=%llu; diagnostic only\n", sid,
            capslang::ProcessElevation(GetCurrentProcessId()).elevated, deliveryWindow, duration);
        ULONGLONG nextLog = 0;
        do {
            const auto now = GetTickCount64();
            const auto observation = monitor.Status();
            const auto evidence = observation.evidence;
            const auto observationTick = observation.observedAt;
            DWORD desktopError = 0;
            const int sameDesktop = InputDesktopMatches(pumpThread, desktopError);
            recipient.Sample(observation, now, sameDesktop != 1);
            if (now < nextLog) continue;
            nextLog = now + 1000;
            const auto last = rawLast.load();
            LASTINPUTINFO lastInput{sizeof(LASTINPUTINFO), 0};
            const bool lastInputKnown = GetLastInputInfo(&lastInput) != FALSE;
            const DWORD inputAge = lastInputKnown ? GetTickCount() - lastInput.dwTime : MAXDWORD;
            std::printf("t=%llu route=%u apps=%u dots=%u supported=%d error=%lu raw_mouse=%lu raw_key=%lu raw_age=%llu passed=%lu consumed=%lu injected=%lu own_injected=%lu raw_absolute=%lu raw_relative=%lu raw_null=%lu raw_errors=%lu route_age=%llu desktop_match=%d desktop_error=%lu input_known=%d input_age=%lu delivered_move=%lu delivered_click=%lu delivered_key=%lu origin_hardware=%lu origin_injected=%lu origin_system=%lu origin_unknown=%lu settings_known=%d maintenance_input=%d observation_allowed=%d\n",
                static_cast<unsigned long long>(now - started), static_cast<unsigned>(evidence.route),
                evidence.applications, evidence.dots, evidence.supportedBinary, evidence.error,
                rawMouse.load(), rawKeyboard.load(), static_cast<unsigned long long>(last && now >= last ? now - last : UINT64_MAX),
                physicalPassed.load(), physicalConsumed.load(), injected.load(), ownInjected.load(),
                rawAbsolute.load(), rawRelative.load(), rawNullDevice.load(), rawReadErrors.load(),
                static_cast<unsigned long long>(observationTick && observationTick <= now ? now - observationTick : UINT64_MAX),
                sameDesktop, desktopError, lastInputKnown, inputAge,
                deliveredMoves.load(), deliveredClicks.load(), deliveredKeys.load(),
                originHardware.load(), originInjected.load(), originSystem.load(), originUnknown.load(),
                evidence.settings.known, evidence.settings.maintenanceInput, evidence.RecipientObservationAllowed());
            const auto recipientLast = recipient.State().Last();
            std::printf("recipient_serial=%llu age=%llu physical_key=%llu injected_key=%llu physical_mouse=%llu injected_mouse=%llu dropped=%llu observer_responsive=%d\n",
                static_cast<unsigned long long>(recipient.State().Serial()),
                static_cast<unsigned long long>(recipientLast && recipientLast <= now ? now-recipientLast : UINT64_MAX),
                static_cast<unsigned long long>(recipient.Accepted(capslang::core::DeliveredKind::PhysicalKey)),
                static_cast<unsigned long long>(recipient.Accepted(capslang::core::DeliveredKind::InjectedKey)),
                static_cast<unsigned long long>(recipient.Accepted(capslang::core::DeliveredKind::PhysicalMouse)),
                static_cast<unsigned long long>(recipient.Accepted(capslang::core::DeliveredKind::InjectedMouse)),
                static_cast<unsigned long long>(recipient.Dropped()), observation.responsive);
            std::fflush(stdout);
        } while (WaitForSingleObject(observerStop, 100) == WAIT_TIMEOUT);
    });
    while (!finished && GetTickCount64() - started < duration) {
        MSG message{};
        while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&message); DispatchMessageW(&message);
        }
        MsgWaitForMultipleObjects(0, nullptr, FALSE, 10, QS_ALLINPUT);
    }
    UnhookWindowsHookEx(keyboard); UnhookWindowsHookEx(mouse);
    DestroyWindow(window);
    SetEvent(observerStop); logger.join(); monitor.Stop(); CloseHandle(observerStop);
    return 0;
}
