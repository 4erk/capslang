// Diagnostic only: never swallows input, changes layout, sends input or opens
// MWB settings/memory. Records aggregate counts/ages and routing metadata only.
#include "../src/platform/mwb.hpp"
#include <atomic>
#include <cstdio>

namespace {
std::atomic<unsigned long> physicalPassed{0}, physicalConsumed{0}, injected{0};
unsigned long rawMouse = 0, rawKeyboard = 0;
ULONGLONG rawLast = 0;
HHOOK keyboard = nullptr, mouse = nullptr;
LRESULT CALLBACK Keyboard(int code, WPARAM wp, LPARAM lp) {
    const LRESULT next = CallNextHookEx(nullptr, code, wp, lp);
    if (code == HC_ACTION) {
        const auto& data = *reinterpret_cast<const KBDLLHOOKSTRUCT*>(lp);
        if (data.flags & LLKHF_INJECTED) ++injected;
        else if (next) ++physicalConsumed;
        else ++physicalPassed;
    }
    return next;
}
LRESULT CALLBACK Mouse(int code, WPARAM wp, LPARAM lp) {
    const LRESULT next = CallNextHookEx(nullptr, code, wp, lp);
    if (code == HC_ACTION) {
        const auto& data = *reinterpret_cast<const MSLLHOOKSTRUCT*>(lp);
        if (data.flags & LLMHF_INJECTED) ++injected;
        else if (next) ++physicalConsumed;
        else ++physicalPassed;
    }
    return next;
}
LRESULT CALLBACK Window(HWND window, UINT message, WPARAM wp, LPARAM lp) {
    if (message == WM_INPUT) {
        RAWINPUTHEADER header{};
        UINT size = sizeof(header);
        // Request only the header. Ordinary key codes and cursor coordinates
        // never enter this observer's raw-input buffer, even transiently.
        if (GetRawInputData(reinterpret_cast<HRAWINPUT>(lp), RID_HEADER, &header, &size,
                           sizeof(header)) == sizeof(header) && header.hDevice) {
            if (header.dwType == RIM_TYPEMOUSE) ++rawMouse;
            if (header.dwType == RIM_TYPEKEYBOARD) ++rawKeyboard;
            rawLast = GetTickCount64();
        }
    }
    return DefWindowProcW(window, message, wp, lp);
}
}
int main() {
    DWORD sid = 0; ProcessIdToSessionId(GetCurrentProcessId(), &sid);
    WNDCLASSW cls{}; cls.hInstance = GetModuleHandleW(nullptr);
    cls.lpszClassName = L"CapsLang.MwbRecipientEvidence"; cls.lpfnWndProc = Window;
    if (!RegisterClassW(&cls)) return 1;
    HWND window = CreateWindowW(cls.lpszClassName, L"", 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, cls.hInstance, nullptr);
    if (!window) return 2;
    RAWINPUTDEVICE devices[]{{1, 2, RIDEV_INPUTSINK, window}, {1, 6, RIDEV_INPUTSINK, window}};
    if (!RegisterRawInputDevices(devices, 2, sizeof(devices[0]))) return 3;
    keyboard = SetWindowsHookExW(WH_KEYBOARD_LL, Keyboard, cls.hInstance, 0);
    mouse = SetWindowsHookExW(WH_MOUSE_LL, Mouse, cls.hInstance, 0);
    if (!keyboard || !mouse) {
        if (keyboard) UnhookWindowsHookEx(keyboard);
        if (mouse) UnhookWindowsHookEx(mouse);
        return 4;
    }
    capslang::MwbObserver observer;
    const auto started = GetTickCount64();
    ULONGLONG next = started;
    std::printf("session=%lu elevated=%d; read-only probe 90 seconds\n", sid,
        capslang::ProcessElevation(GetCurrentProcessId()).elevated);
    std::fflush(stdout);
    while (GetTickCount64() - started < 90000) {
        MSG message{};
        while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&message); DispatchMessageW(&message);
        }
        const auto now = GetTickCount64();
        if (now >= next) {
            next = now + 1000;
            const auto evidence = observer.Read();
            std::printf("t=%llu route=%u apps=%u dots=%u supported=%d error=%lu raw_mouse=%lu raw_key=%lu raw_age=%llu passed=%lu consumed=%lu injected=%lu\n",
                static_cast<unsigned long long>(now - started), static_cast<unsigned>(evidence.route),
                evidence.applications, evidence.dots, evidence.supportedBinary, evidence.error,
                rawMouse, rawKeyboard, static_cast<unsigned long long>(rawLast ? now - rawLast : UINT64_MAX),
                physicalPassed.load(), physicalConsumed.load(), injected.load());
            std::fflush(stdout);
        }
        MsgWaitForMultipleObjects(0, nullptr, FALSE, 10, QS_ALLINPUT);
    }
    UnhookWindowsHookEx(keyboard); UnhookWindowsHookEx(mouse);
    DestroyWindow(window);
    return 0;
}
