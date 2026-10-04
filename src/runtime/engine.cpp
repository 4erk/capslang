#include "engine.hpp"
#include "led_worker.hpp"
#include "recipient_input.hpp"
#include "focus_target.hpp"
#include "../core/keyboard.hpp"
#include <objbase.h>
#include <wtsapi32.h>
#include <atomic>
#include <mutex>
#ifdef CAPSLANG_ENGINE_INTEGRATION
#include <cstdio>
#endif

namespace capslang {
namespace {
constexpr UINT kToggle = WM_APP + 21, kSet = WM_APP + 22, kManual = WM_APP + 23;
constexpr UINT kStop = WM_APP + 24, kRehook = WM_APP + 25;
constexpr UINT kConditionalSet = WM_APP + 26;
constexpr ULONG_PTR kLegacyInput = 0x434150534c414e47ULL, kLegacyProbe = 0x4341505350524f42ULL;
constexpr wchar_t kEngineClass[] = L"CapsLang.Engine.1.1";
constexpr wchar_t kRawClass[] = L"CapsLang.Engine.RawRelease.1.1";
bool Down(WPARAM message) { return message == WM_KEYDOWN || message == WM_SYSKEYDOWN; }
bool Up(WPARAM message) { return message == WM_KEYUP || message == WM_SYSKEYUP; }
bool IsModifier(DWORD key) {
    return key == VK_LSHIFT || key == VK_RSHIFT || key == VK_SHIFT ||
           key == VK_CONTROL || key == VK_LCONTROL || key == VK_RCONTROL ||
           key == VK_MENU || key == VK_LMENU || key == VK_RMENU || key == VK_LWIN || key == VK_RWIN;
}
bool AnyDeliveredKeyHeld() {
    for (int key = 1; key < 256; ++key) if (GetAsyncKeyState(key) & 0x8000) return true;
    return false;
}
}

struct Engine::Impl {
    EngineOptions options;
    mutable std::mutex statusMutex;
    EngineStatus status;
    core::LayoutState layout;
    LayoutTarget target;
    FocusTarget focusTarget;
    std::unique_ptr<LayoutApplier> applier;
    LedWorker leds;
    MwbMonitor mwb;
    RecipientInput recipient;
    HANDLE worker = nullptr, workerReady = nullptr, stopEvent = nullptr, hook = nullptr, hookReady = nullptr;
    HDESK desktop = nullptr;
    std::atomic<HWND> window{nullptr};
    std::atomic<DWORD> hookThread{0}, installError{0}, rawError{0};
    std::atomic<bool> stopping{false}, installed{false}, rehookRequested{false};
    std::atomic<ULONGLONG> hookBeat{0}, hookRecovered{0}, physicalInput{0}, injectedKeyInput{0};
    std::atomic<unsigned> recoveryCount{0};
    core::KeyboardState keys;
    HPOWERNOTIFY power = nullptr;
    bool wts = false, locked = false, ticking = false;
    ULONGLONG manualUntil = 0, ownApplyUntil = 0;
    core::Language manualBefore = core::Language::Unknown;
    static thread_local Impl* hookOwner;

    explicit Impl(EngineOptions value) : options(value) {}
    void Publish() {
        const auto now = GetTickCount64();
        const auto observation = mwb.Status();
        recipient.Sample(observation, now, locked);
        std::lock_guard<std::mutex> guard(statusMutex);
        status.target = layout.Target(); status.actual = layout.Actual(); status.apply = layout.State();
        status.generation = layout.Generation(); status.userRevision = layout.UserRevision();
        status.locked = locked; status.hookRegistered = installed.load();
        status.hookError = installError.load();
        if (!status.hookError) status.hookError = rawError.load();
        const auto heartbeat = hookBeat.load();
        status.hookThreadResponsive = heartbeat && GetTickCount64() - heartbeat < 2000;
        status.recoveries = recoveryCount.load(); status.lastRecovery = hookRecovered.load();
        status.lastPhysicalInput = physicalInput.load();
        status.lastInjectedKeyInput = injectedKeyInput.load();
        status.activitySerial = recipient.State().Serial();
        status.lastRecipientInput = recipient.State().Last();
        status.mwbError = observation.error ? observation.error : observation.evidence.settings.error;
        status.mwbRunning = observation.responsive && observation.evidence.applications;
        status.recipientAvailable = observation.responsive && observation.evidence.RecipientObservationAllowed() &&
            !observation.evidence.settings.relativeMouse;
    }
    void Error(DWORD EngineStatus::*field, DWORD error) {
        std::lock_guard<std::mutex> guard(statusMutex);
        status.*field = error;
    }
    static LRESULT CALLBACK KeyHook(int code, WPARAM message, LPARAM pointer) {
        Impl* self = hookOwner;
        if (code != HC_ACTION || !self || (!Down(message) && !Up(message)))
            return CallNextHookEx(nullptr, code, message, pointer);
        const auto data = *reinterpret_cast<const KBDLLHOOKSTRUCT*>(pointer);
        const bool own = data.dwExtraInfo == kLegacyInput || data.dwExtraInfo == kLegacyProbe;
        const LRESULT next = CallNextHookEx(nullptr, code, message, pointer);
        self->recipient.Key(Down(message), (data.flags & LLKHF_INJECTED) != 0, next == 0, own, data.time, GetTickCount64());
        // Calling the rest of the chain FIRST lets MWB forward/suppress at the
        // source regardless of hook installation order. No duplicate local toggle.
        if (own || next != 0) return next;
        const bool injected = (data.flags & LLKHF_INJECTED) != 0;
        const HWND owner = self->window.load();
        if (Down(message)) {
            if (!injected) self->physicalInput = GetTickCount64();
            else if (!IsModifier(data.vkCode)) self->injectedKeyInput = GetTickCount64();
            const bool alt = (GetAsyncKeyState(VK_MENU) & 0x8000) != 0;
            const bool shift = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
            const bool win = (GetAsyncKeyState(VK_LWIN) & 0x8000) || (GetAsyncKeyState(VK_RWIN) & 0x8000);
            if ((data.vkCode == VK_SPACE && win) ||
                ((data.vkCode == VK_LSHIFT || data.vkCode == VK_RSHIFT) && alt) ||
                ((data.vkCode == VK_LMENU || data.vkCode == VK_RMENU) && shift))
                PostMessageW(owner, kManual, 0, 0);
        }
        if (data.vkCode != VK_CAPITAL) return next;
        const bool shift = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
        const auto decision = self->keys.Caps(Down(message) ? core::Edge::Down : core::Edge::Up,
                                              shift, false, false, data.time);
        if (decision.toggle) PostMessageW(owner, kToggle, 0, 0);
        return decision.suppress ? 1 : next;
    }
    static LRESULT CALLBACK MouseHook(int code, WPARAM message, LPARAM pointer) {
        Impl* self = hookOwner;
        if (code != HC_ACTION || !self) return CallNextHookEx(nullptr, code, message, pointer);
        const auto data = *reinterpret_cast<const MSLLHOOKSTRUCT*>(pointer);
        const LRESULT next = CallNextHookEx(nullptr, code, message, pointer);
        self->recipient.Mouse(data.time, GetTickCount64(), (data.flags & LLMHF_INJECTED) != 0, next == 0,
            data.dwExtraInfo == kLegacyInput || data.dwExtraInfo == kLegacyProbe);
        // Synthetic mouse events alone are never authoritative activity.
        if (!next && !(data.flags & LLMHF_INJECTED)) self->physicalInput = GetTickCount64();
        return next;
    }
    static LRESULT CALLBACK RawRelease(HWND hwnd, UINT message, WPARAM wp, LPARAM lp) {
        if (message == WM_INPUT && hookOwner) {
            RAWINPUT data{}; UINT size = sizeof(data);
            const auto count = GetRawInputData(reinterpret_cast<HRAWINPUT>(lp), RID_INPUT,
                &data, &size, sizeof(RAWINPUTHEADER));
            if (count != UINT(-1) && count >= sizeof(RAWINPUTHEADER) + sizeof(RAWMOUSE) &&
                data.header.dwType == RIM_TYPEMOUSE)
                hookOwner->recipient.RawMouse(data, static_cast<DWORD>(GetMessageTime()), GetTickCount64());
            if (count != UINT(-1) && count >= sizeof(RAWINPUTHEADER) + sizeof(RAWKEYBOARD) &&
                data.header.dwType == RIM_TYPEKEYBOARD && data.data.keyboard.VKey == VK_CAPITAL &&
                (data.data.keyboard.Flags & RI_KEY_BREAK)) {
                hookOwner->keys.PhysicalReleaseObserved(static_cast<DWORD>(GetMessageTime()));
            }
            // No ordinary key codes, text or device identifiers are retained.
            SecureZeroMemory(&data, sizeof(data));
        }
        return DefWindowProcW(hwnd, message, wp, lp);
    }
    static void RemoveRawSink(HWND hwnd) {
        UINT count = 0;
        if (GetRegisteredRawInputDevices(nullptr, &count, sizeof(RAWINPUTDEVICE)) != 0 || !count) return;
        std::vector<RAWINPUTDEVICE> devices(count);
        if (GetRegisteredRawInputDevices(devices.data(), &count, sizeof(RAWINPUTDEVICE)) == UINT(-1)) return;
        for (const auto& device : devices) {
            if (device.usUsagePage == 1 && (device.usUsage == 6 || device.usUsage == 2) && device.hwndTarget == hwnd) {
                // Raw Input is process-wide. Don't unregister another owner's
                // newer registration during a sequential/overlapping test.
                RAWINPUTDEVICE remove{1, device.usUsage, RIDEV_REMOVE, nullptr};
                RegisterRawInputDevices(&remove, 1, sizeof(remove));
            }
        }
    }
    static DWORD WINAPI HookThread(void* context) {
        auto& self = *static_cast<Impl*>(context);
        if (!SetThreadDesktop(self.desktop)) {
            self.installError = GetLastError(); SetEvent(self.hookReady); return 1;
        }
        hookOwner = &self;
        MSG msg{};
        PeekMessageW(&msg, nullptr, WM_USER, WM_USER, PM_NOREMOVE);
        self.hookThread = GetCurrentThreadId();
        WNDCLASSW rawClass{}; rawClass.hInstance = GetModuleHandleW(nullptr);
        rawClass.lpszClassName = kRawClass; rawClass.lpfnWndProc = RawRelease;
        RegisterClassW(&rawClass);
        HWND rawWindow = CreateWindowExW(0, kRawClass, L"", 0, 0, 0, 0, 0,
            HWND_MESSAGE, nullptr, rawClass.hInstance, nullptr);
        self.rawError = rawWindow ? ERROR_SUCCESS : GetLastError();
        if (rawWindow) {
            RAWINPUTDEVICE devices[]{{1, 6, RIDEV_INPUTSINK, rawWindow}, {1, 2, RIDEV_INPUTSINK, rawWindow}};
            if (!RegisterRawInputDevices(devices, 2, sizeof(devices[0]))) self.rawError = GetLastError();
        }
        HHOOK keyboard = nullptr, mouse = nullptr;
        ULONGLONG lastInstall = 0, retryAt = 0;
        DWORD delay = 1000;
        auto install = [&] {
            // Install before removing the old handles: no intentional unhooked
            // gap, and the Caps decision is retained through replacement.
            HHOOK newKeyboard = SetWindowsHookExW(WH_KEYBOARD_LL, KeyHook, GetModuleHandleW(nullptr), 0);
            const DWORD error = newKeyboard ? 0 : GetLastError();
            HHOOK newMouse = SetWindowsHookExW(WH_MOUSE_LL, MouseHook, GetModuleHandleW(nullptr), 0);
            if (newKeyboard) {
                if (keyboard) UnhookWindowsHookEx(keyboard);
                keyboard = newKeyboard;
                if (lastInstall) { ++self.recoveryCount; self.hookRecovered = GetTickCount64(); }
                lastInstall = GetTickCount64(); delay = 1000;
                self.rehookRequested = false;
            } else { retryAt = GetTickCount64() + delay; delay = delay < 15000 ? delay * 2 : 30000; }
            if (newMouse) { if (mouse) UnhookWindowsHookEx(mouse); mouse = newMouse; }
            self.installError = error;
            self.installed = keyboard != nullptr;
        };
        install();
        self.hookBeat = GetTickCount64();
        const UINT_PTR timer = SetTimer(nullptr, 0, 100, nullptr);
        if (!timer) { self.installError = GetLastError(); self.stopping = true; }
        SetEvent(self.hookReady);
        while (!self.stopping) {
            const DWORD wait = MsgWaitForMultipleObjects(1, &self.stopEvent, FALSE, INFINITE, QS_ALLINPUT);
            if (wait == WAIT_OBJECT_0 || wait == WAIT_FAILED) break;
            while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
                if (msg.message == WM_QUIT) { self.stopping = true; break; }
                if (msg.message == WM_TIMER && msg.wParam == timer) {
                    const auto now = GetTickCount64(); self.hookBeat = now;
                    if ((self.rehookRequested || now - lastInstall >= 10000 || !keyboard) &&
                        now >= retryAt && self.keys.CanRefresh(AnyDeliveredKeyHeld())) install();
                } else { TranslateMessage(&msg); DispatchMessageW(&msg); }
            }
        }
        if (timer) KillTimer(nullptr, timer);
        if (keyboard) UnhookWindowsHookEx(keyboard);
        if (mouse) UnhookWindowsHookEx(mouse);
        if (rawWindow) { RemoveRawSink(rawWindow); DestroyWindow(rawWindow); }
        self.installed = false; self.hookThread = 0; hookOwner = nullptr;
        return 0;
    }
    void UpdateLeds() {
        if (!options.hardwareLeds) return;
        leds.Target(locked ? core::Language::Unknown : layout.Actual());
        const auto report = leds.Status();
        std::lock_guard<std::mutex> guard(statusMutex);
        status.ledWritten = report.written; status.ledUnsupported = report.unsupported;
        status.ledError = report.error;
    }
    void Tick() {
        // COM/TSF calls may pump this STA's window messages. Nested timers or
        // kSet messages must not recursively enter another TSF activation.
        // New commands still update the generation; the next outer tick sees it.
        if (ticking) return;
        ticking = true;
        struct TickGuard { bool& active; ~TickGuard() { active = false; } } guard{ticking};
        const auto now = GetTickCount64();
        if (locked) { UpdateLeds(); Publish(); return; }
        const auto focus = focusTarget.Select(options.capture(), mwb.Status());
        if (!TargetStillValid(focus)) {
            if (target.focus) { target = {}; layout.FocusChanged(now); }
            layout.Observe(core::Language::Unknown, layout.Generation(), now);
            Error(&EngineStatus::layoutError, ERROR_INVALID_WINDOW_HANDLE);
            Publish(); return;
        }
        const auto actual = static_cast<core::Language>(TargetLanguage(focus));
        const bool focusChanged = focus.focus != target.focus || focus.threadId != target.threadId || focus.processId != target.processId;
        if (focusChanged) {
            target = focus;
            if (!manualUntil) { layout.FocusChanged(now); ownApplyUntil = now + 1500; }
        }
        if (manualUntil) {
            if (core::Supported(actual) && actual != manualBefore) {
                layout.Request(actual, core::Origin::Manual, now); manualUntil = 0;
            } else if (now >= manualUntil) {
                manualUntil = 0; layout.FocusChanged(now);
            } else { Publish(); return; }
        } else if (!focusChanged && layout.State() != core::ApplyState::Pending &&
                   core::Supported(actual) && actual != layout.Actual()) {
            // External selector/manual change on the same target, not its
            // remembered language encountered during a focus transition.
            if (now < ownApplyUntil) {
                // A posted old request may finish after a newer absolute target
                // was already observed. It is not evidence of manual intent.
                if (layout.State() == core::ApplyState::Applied) layout.FocusChanged(now);
            } else layout.Request(actual, core::Origin::Manual, now);
        }
        layout.Observe(actual, layout.Generation(), now);
        // A previous inaccessible foreground (for example MWB's SYSTEM
        // helper) must not leave a stale error after actual application is
        // confirmed in the newly focused user window.
        if (layout.State() == core::ApplyState::Applied && actual == layout.Target())
            Error(&EngineStatus::layoutError, ERROR_SUCCESS);
        if (layout.Due(now)) {
            const auto generation = layout.Generation();
            const auto request = applier->Request(target, FindLayout(static_cast<LANGID>(layout.Target())));
#ifdef CAPSLANG_ENGINE_INTEGRATION
            if (request.changeMs + request.profileMs + request.cleanupMs > 100) {
                std::printf("Engine slow request: change=%llu profile=%llu post=%llu ms generation=%llu\n",
                    static_cast<unsigned long long>(request.changeMs), static_cast<unsigned long long>(request.profileMs),
                    static_cast<unsigned long long>(request.cleanupMs), static_cast<unsigned long long>(generation));
                std::fflush(stdout);
            }
#endif
            Error(&EngineStatus::layoutError, request.postError);
            layout.Sent(generation, now);
        }
        UpdateLeds();
        Publish();
    }
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM wp, LPARAM lp) {
        auto* self = reinterpret_cast<Impl*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        if (message == WM_NCCREATE) {
            self = static_cast<Impl*>(reinterpret_cast<CREATESTRUCTW*>(lp)->lpCreateParams);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        }
        if (!self) return DefWindowProcW(hwnd, message, wp, lp);
        const auto now = GetTickCount64();
        switch (message) {
        case WM_TIMER: self->Tick(); return 0;
        case kToggle:
            self->manualUntil = 0; self->ownApplyUntil = now + 1500;
            self->layout.Toggle(now); self->Tick(); return 0;
        case kConditionalSet:
            // A manual shortcut has reached the user thread but Windows may
            // not have changed its HKL yet. Do not erase this pending intent.
            if (self->manualUntil) return 0;
            if (!self->layout.RequestPeer(static_cast<core::Language>(wp), static_cast<std::uint64_t>(lp), now)) return 0;
            self->manualUntil = 0; self->ownApplyUntil = now + 1500;
            self->Tick(); return 0;
        case kSet:
            self->manualUntil = 0; self->ownApplyUntil = now + 1500;
            self->layout.Request(static_cast<core::Language>(wp), core::Origin::Peer, now);
            self->Tick(); return 0;
        case kManual:
            self->manualBefore = self->layout.Target(); self->manualUntil = now + 700; return 0;
        case kRehook: self->rehookRequested = true; return 0;
        case kStop: self->stopping = true; SetEvent(self->stopEvent); return 0;
        case WM_DEVICECHANGE: self->leds.Rediscover(); return 0;
        case WM_POWERBROADCAST:
            if (wp == PBT_APMRESUMEAUTOMATIC || wp == PBT_APMRESUMESUSPEND) {
                self->rehookRequested = true; self->leds.Rediscover();
                self->layout.FocusChanged(now);
            }
            return TRUE;
        case WM_WTSSESSION_CHANGE:
            if (wp == WTS_SESSION_LOCK || wp == WTS_SESSION_LOGOFF) {
                self->locked = true; self->layout.Lock(true, now);
            } else if (wp == WTS_SESSION_UNLOCK || wp == WTS_SESSION_LOGON ||
                       wp == WTS_CONSOLE_CONNECT || wp == WTS_REMOTE_CONNECT) {
                self->locked = false; self->layout.Lock(false, now);
                self->rehookRequested = true; self->leds.Rediscover();
            }
            self->Publish(); return 0;
        case WM_DESTROY: PostQuitMessage(0); return 0;
        default: return DefWindowProcW(hwnd, message, wp, lp);
        }
    }
    static DWORD WINAPI WorkerThread(void* context) {
        auto& self = *static_cast<Impl*>(context);
        if (!SetThreadDesktop(self.desktop)) { SetEvent(self.workerReady); return 1; }
        const HRESULT com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        if (FAILED(com)) { SetEvent(self.workerReady); return 2; }
        WNDCLASSW wc{}; wc.hInstance = GetModuleHandleW(nullptr); wc.lpfnWndProc = WindowProc; wc.lpszClassName = kEngineClass;
        RegisterClassW(&wc);
        HWND hwnd = CreateWindowExW(WS_EX_TOOLWINDOW, kEngineClass, L"", WS_POPUP, 0, 0, 0, 0,
            nullptr, nullptr, wc.hInstance, &self);
        if (!hwnd) { CoUninitialize(); SetEvent(self.workerReady); return 3; }
        self.applier = std::make_unique<LayoutApplier>();
        self.window = hwnd;
        const auto rights = ProcessElevation(GetCurrentProcessId());
        { std::lock_guard<std::mutex> guard(self.statusMutex); self.status.elevated = rights.known && rights.elevated; }
        self.target = self.options.capture();
        self.layout.Initialize(static_cast<core::Language>(TargetLanguage(self.target)));
        self.layout.Request(self.layout.Target(), core::Origin::Startup, GetTickCount64());
        self.mwb.Start(); // Failure disables recipient reconciliation, not local switching.
        if (self.options.hardwareLeds && !self.leds.Start(self.options.ledOperation)) self.Error(&EngineStatus::ledError, self.leds.Error());
        self.wts = WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION) != FALSE;
        if (!self.wts) self.Error(&EngineStatus::sessionError, GetLastError());
        self.power = RegisterSuspendResumeNotification(hwnd, DEVICE_NOTIFY_WINDOW_HANDLE);
        if (!self.power) self.Error(&EngineStatus::powerError, GetLastError());
        self.hookReady = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (self.hookReady) self.hook = CreateThread(nullptr, 0, HookThread, &self, 0, nullptr);
        if (self.hook) WaitForSingleObject(self.hookReady, 3000);
        const auto timer = SetTimer(hwnd, 1, 20, nullptr);
        self.Publish(); SetEvent(self.workerReady);
        MSG msg{};
        if (!timer) { self.Error(&EngineStatus::layoutError, GetLastError()); self.stopping = true; }
        while (!self.stopping) {
            const DWORD wait = MsgWaitForMultipleObjects(1, &self.stopEvent, FALSE, INFINITE, QS_ALLINPUT);
            if (wait == WAIT_OBJECT_0 || wait == WAIT_FAILED) break;
            while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
                if (msg.message == WM_QUIT) { self.stopping = true; break; }
                TranslateMessage(&msg); DispatchMessageW(&msg);
            }
        }
        self.stopping = true;
        SetEvent(self.stopEvent);
        const auto tid = self.hookThread.load();
        if (tid) PostThreadMessageW(tid, WM_QUIT, 0, 0);
        if (self.hook) { WaitForSingleObject(self.hook, INFINITE); CloseHandle(self.hook); self.hook = nullptr; }
        if (self.hookReady) { CloseHandle(self.hookReady); self.hookReady = nullptr; }
        if (timer) KillTimer(hwnd, timer);
        if (self.power) UnregisterSuspendResumeNotification(self.power);
        if (self.wts) WTSUnRegisterSessionNotification(hwnd);
        self.window = nullptr;
        if (!self.leds.Stop()) self.Error(&EngineStatus::ledError, self.leds.Error());
        self.mwb.Stop();
        DestroyWindow(hwnd);
        self.Publish();
        self.applier.reset(); // Release TSF on its owning STA before COM shutdown.
        CoUninitialize(); return 0;
    }
};
thread_local Engine::Impl* Engine::Impl::hookOwner = nullptr;

Engine::Engine(EngineOptions options) : impl_(std::make_unique<Impl>(options)) {}
Engine::~Engine() { Stop(); }
bool Engine::Start() {
    auto& self = *impl_;
    if (self.worker) return self.window != nullptr;
    self.desktop = GetThreadDesktop(GetCurrentThreadId());
    self.stopping = false;
    self.workerReady = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    self.stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!self.workerReady || !self.stopEvent) {
        if (self.workerReady) CloseHandle(self.workerReady);
        if (self.stopEvent) CloseHandle(self.stopEvent);
        self.workerReady = self.stopEvent = nullptr;
        return false;
    }
    self.worker = CreateThread(nullptr, 0, Impl::WorkerThread, &self, 0, nullptr);
    if (!self.worker) {
        CloseHandle(self.workerReady); CloseHandle(self.stopEvent);
        self.workerReady = self.stopEvent = nullptr; return false;
    }
    HANDLE handles[]{self.workerReady, self.worker};
    return WaitForMultipleObjects(2, handles, FALSE, 5000) == WAIT_OBJECT_0 && self.window.load();
}
void Engine::Stop() {
    auto& self = *impl_;
    if (!self.worker) return;
    self.stopping = true;
    SetEvent(self.stopEvent); // Also wakes startup/failed-start paths without an HWND.
    HWND hwnd = self.window.load();
    if (hwnd) PostMessageW(hwnd, kStop, 0, 0);
    // The owning process supervises shutdown; never free state a live callback
    // might still reference. Do not TerminateThread inside an application.
    WaitForSingleObject(self.worker, INFINITE);
    CloseHandle(self.worker); self.worker = nullptr;
    CloseHandle(self.workerReady); self.workerReady = nullptr;
    CloseHandle(self.stopEvent); self.stopEvent = nullptr;
}
bool Engine::SetTarget(core::Language language) {
    const HWND window = impl_->window.load();
    return window && !impl_->stopping && core::Supported(language) &&
        PostMessageW(window, kSet, static_cast<WPARAM>(language), 0);
}
bool Engine::RestartHook() {
    const HWND window = impl_->window.load();
    return window && !impl_->stopping && PostMessageW(window, kRehook, 0, 0) != FALSE;
}
bool Engine::SetTargetIfRevision(core::Language language, std::uint64_t expectedUserRevision) {
    static_assert(sizeof(LPARAM) == sizeof(std::uint64_t), "CapsLang 1.1 requires x64");
    const HWND window = impl_->window.load();
    return window && !impl_->stopping && core::Supported(language) &&
        PostMessageW(window, kConditionalSet, static_cast<WPARAM>(language), static_cast<LPARAM>(expectedUserRevision));
}
EngineStatus Engine::Status() const { std::lock_guard<std::mutex> guard(impl_->statusMutex); return impl_->status; }
} // namespace capslang
