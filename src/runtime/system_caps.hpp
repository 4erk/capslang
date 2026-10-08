#pragma once
#include "system_layout.hpp"
#include "../core/system_caps.hpp"
#include "../core/keyboard.hpp"
#include "../core/profile_queue.hpp"
#include "../app/paths.hpp"
#include <bcrypt.h>
#include <deque>
#include <thread>
#include <algorithm>
#include <wtsapi32.h>

namespace capslang::system_caps {
inline ipc::Endpoint Endpoint(const std::wstring& owner, DWORD session) {
    auto result = system_layout::Endpoint(owner,session);
    result.name = L"\\\\.\\pipe\\CapsLang.caps-v1."+std::to_wstring(session)+L"."+owner;
    return result;
}
// One SYSTEM hook owns Caps down/up across all foreground integrity levels.
// The callback calls downstream hooks first, then enqueues only a toggle intent.
class Server {
    static inline thread_local Server* current = nullptr;
    ipc::Endpoint endpoint;
    std::function<bool()> allowed;
    std::unique_ptr<ipc::MessageServer> pipe;
    std::thread thread;
    HANDLE ready = nullptr;
    std::atomic<DWORD> threadId{0}, hookError{ERROR_NOT_READY};
    std::atomic<DWORD> deliveryError{0}, rawError{0};
    std::atomic<ULONGLONG> beat{0}, lease{0};
    std::atomic<bool> desktopAllowed{false}, refresh{false};
    std::atomic<std::uint64_t> recoveries{0};
    profile_channel::Queue<Event,64> queue;
    core::KeyboardState keys;
    std::uint64_t produced = 0, emitted = 0, acknowledged = 0, stream = 0, epoch = 0;
    ipc::ProcessIdentity caller{};
    std::deque<Event> pending;
    static LRESULT CALLBACK Hook(int code, WPARAM message, LPARAM pointer) {
        const auto next = CallNextHookEx(nullptr,code,message,pointer);
        auto* self = current;
        if (code != HC_ACTION || !self) return next;
        const auto& data = *reinterpret_cast<const KBDLLHOOKSTRUCT*>(pointer);
        if (data.vkCode != VK_CAPITAL || next) return next;
        const bool down = message == WM_KEYDOWN || message == WM_SYSKEYDOWN;
        const bool up = message == WM_KEYUP || message == WM_SYSKEYUP;
        if (!down && !up) return next;
        if (down && (!self->desktopAllowed || GetTickCount64() - self->lease.load() > 1500 || self->hookError || self->deliveryError)) return next;
        const auto decision = self->keys.Caps(down ? core::Edge::Down : core::Edge::Up,
            (GetAsyncKeyState(VK_SHIFT)&0x8000)!=0,false,false,data.time,
            (GetAsyncKeyState(VK_CONTROL)&0x8000)!=0,(GetAsyncKeyState(VK_MENU)&0x8000)!=0,
            ((GetAsyncKeyState(VK_LWIN)|GetAsyncKeyState(VK_RWIN))&0x8000)!=0);
        if (decision.toggle || decision.convert) {
            LARGE_INTEGER stamp{}; QueryPerformanceCounter(&stamp);
            if (self->produced == UINT64_MAX || !self->queue.TryPush({++self->produced,static_cast<std::uint64_t>(stamp.QuadPart),
                decision.convert ? Action::ConvertSelection : Action::Toggle}))
                self->deliveryError = ERROR_MORE_DATA;
            self->producedSnapshot = self->produced;
        }
        return decision.suppress ? 1 : next;
    }
    static LRESULT CALLBACK Raw(HWND hwnd, UINT message, WPARAM wp, LPARAM lp) {
        if (current && message == WM_POWERBROADCAST && (wp == PBT_APMRESUMEAUTOMATIC || wp == PBT_APMRESUMESUSPEND)) current->refresh = true;
        if (current && message == WM_WTSSESSION_CHANGE) {
            if (wp == WTS_SESSION_LOCK || wp == WTS_SESSION_LOGOFF) current->desktopAllowed = false;
            else current->refresh = true;
        }
        if (message == WM_INPUT && current) {
            RAWINPUT input{}; UINT size = sizeof(input);
            const auto count = GetRawInputData(reinterpret_cast<HRAWINPUT>(lp),RID_INPUT,&input,&size,sizeof(RAWINPUTHEADER));
            if (count != UINT(-1) && count >= sizeof(RAWINPUTHEADER)+sizeof(RAWKEYBOARD) &&
                input.header.dwType == RIM_TYPEKEYBOARD && input.data.keyboard.VKey == VK_CAPITAL &&
                (input.data.keyboard.Flags & RI_KEY_BREAK))
                current->keys.PhysicalReleaseObserved(static_cast<DWORD>(GetMessageTime()));
            SecureZeroMemory(&input,sizeof(input));
        }
        return DefWindowProcW(hwnd,message,wp,lp);
    }
    void Run() {
        current = this; threadId = GetCurrentThreadId();
        MSG message{}; PeekMessageW(&message,nullptr,0,0,PM_NOREMOVE);
        WNDCLASSW wc{}; wc.hInstance = GetModuleHandleW(nullptr); wc.lpszClassName = L"CapsLang.SystemCaps.Raw.v1"; wc.lpfnWndProc = Raw;
        RegisterClassW(&wc);
        const auto raw = CreateWindowExW(0,wc.lpszClassName,L"",0,0,0,0,0,HWND_MESSAGE,nullptr,wc.hInstance,nullptr);
        RAWINPUTDEVICE device{1,6,RIDEV_INPUTSINK,raw};
        if (!raw || !RegisterRawInputDevices(&device,1,sizeof(device))) rawError = GetLastError();
        const bool notifications = raw && WTSRegisterSessionNotification(raw,NOTIFY_FOR_THIS_SESSION);
        if (!notifications) rawError = GetLastError();
        const auto power = raw ? RegisterSuspendResumeNotification(raw,DEVICE_NOTIFY_WINDOW_HANDLE) : nullptr;
        if (!power) rawError = GetLastError();
        HHOOK hook = nullptr; ULONGLONG installedAt = 0, retryAt = 0; DWORD delay = 1000;
        const auto install = [&] {
            const auto fresh = SetWindowsHookExW(WH_KEYBOARD_LL,Hook,GetModuleHandleW(nullptr),0);
            if (fresh) {
                if (hook) { UnhookWindowsHookEx(hook); ++recoveries; }
                hook = fresh; hookError = 0; installedAt = GetTickCount64(); delay = 1000; refresh = false;
            } else { hookError = GetLastError(); retryAt = GetTickCount64()+delay; delay = std::min<DWORD>(30000,delay*2); }
        };
        install(); const auto timer = SetTimer(nullptr,0,100,nullptr); SetEvent(ready);
        if (timer) while (GetMessageW(&message,nullptr,0,0)>0) {
            if (message.message == WM_TIMER) {
                beat = GetTickCount64();
                bool held = false;
                for (int key = 1; key < 256 && !held; ++key) held = (GetAsyncKeyState(key)&0x8000)!=0;
                if (keys.CanRefresh(held) && ((hook && (refresh || beat.load()-installedAt>=10000)) || (!hook && beat.load()>=retryAt))) install();
            } else { TranslateMessage(&message); DispatchMessageW(&message); }
        }
        else hookError = GetLastError();
        if (timer) KillTimer(nullptr,timer);
        if (hook) UnhookWindowsHookEx(hook);
        if (power) UnregisterSuspendResumeNotification(power);
        if (notifications) WTSUnRegisterSessionNotification(raw);
        if (raw) DestroyWindow(raw);
        current = nullptr;
    }
    Response Poll(const Request& request) {
        Response output; output.id = request.id; output.epoch = request.epoch; output.stream = stream;
        if (!Valid(request)) { output.error = ERROR_INVALID_DATA; return output; }
        const auto incoming = ipc::MessageServer::Caller();
        if (!incoming.id || !incoming.created) { output.error = ERROR_ACCESS_DENIED; return output; }
        if (caller.id != incoming.id || caller.created != incoming.created || epoch != request.epoch) {
            // A new engine does not replay presses belonging to its predecessor.
            if (lease && GetTickCount64()-lease.load()<1500) { output.error = ERROR_BUSY; return output; }
            caller = incoming; epoch = request.epoch;
            Event event; while (queue.TryPop(event)) {}
            pending.clear(); acknowledged = emitted = 0;
            // Serial rebasing belongs to the consumer; hook counter is never reset.
            baseline = producedSnapshot.load();
        }
        Event event;
        while (queue.TryPop(event)) {
            event.serial -= baseline;
            if (pending.size() == 64) { deliveryError = output.error = ERROR_MORE_DATA; return output; }
            pending.push_back(event);
        }
        if (request.stream == stream) {
            if (request.through < acknowledged || request.through > emitted) { output.error = ERROR_INVALID_DATA; return output; }
            acknowledged = request.through;
            while (!pending.empty() && pending.front().serial<=acknowledged) pending.pop_front();
        } else if (request.stream) { output.error = ERROR_REVISION_MISMATCH; return output; }
        lease = GetTickCount64();
        output.error = deliveryError ? deliveryError.load() : (hookError ? hookError.load() : rawError.load());
        output.heartbeat = beat.load(); output.recoveries = recoveries.load();
        if (!output.error) for (const auto& item : pending) {
            if (output.count == 8) break;
            output.events[output.count++] = item; emitted = item.serial;
        }
        return output;
    }
    std::uint64_t baseline = 0;
    std::atomic<std::uint64_t> producedSnapshot{0};
public:
    Server(std::wstring owner,DWORD session,std::function<bool()> permitted) : endpoint(Endpoint(owner,session)),allowed(std::move(permitted)) {
        endpoint.clientImage = app::ExecutablePath(); endpoint.requireClientElevation = true;
        BCryptGenRandom(nullptr,reinterpret_cast<PUCHAR>(&stream),sizeof(stream),BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    }
    ~Server() { Stop(); }
    bool Start() {
        if (!stream || !system_layout::IsSystem()) return false;
        ready = CreateEventW(nullptr,TRUE,FALSE,nullptr); if (!ready) return false;
        thread = std::thread([this]{Run();}); WaitForSingleObject(ready,3000);
        pipe = std::make_unique<ipc::MessageServer>(endpoint,sizeof(Request),sizeof(Response),[this](const void* in,void* out) {
            Request request; memcpy(&request,in,sizeof(request)); const auto response = Poll(request); memcpy(out,&response,sizeof(response));
        });
        return pipe->Start();
    }
    void Step() { desktopAllowed = allowed && allowed(); }
    void Stop() {
        desktopAllowed = false; lease = 0;
        if (pipe) { pipe->Stop(); pipe.reset(); }
        if (thread.joinable()) { PostThreadMessageW(threadId.load(),WM_QUIT,0,0); thread.join(); }
        if (ready) { CloseHandle(ready); ready = nullptr; }
    }
};
class Client {
    std::wstring image; ipc::Endpoint endpoint;
    std::uint64_t epoch = 0, id = 0, stream = 0, through = 0;
public:
    explicit Client(std::wstring executable) : image(std::move(executable)) {
        const auto own = ipc::Endpoint::Current(); endpoint = Endpoint(own.sid,own.session);
        BCryptGenRandom(nullptr,reinterpret_cast<PUCHAR>(&epoch),sizeof(epoch),BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    }
    Response Poll() {
        Request request; request.id = ++id; request.epoch = epoch; request.stream = stream; request.through = through;
        Response response; DWORD error = 0; ipc::ProcessIdentity server;
        if (!epoch || !Valid(request) || !ipc::Exchange(endpoint,image,true,&request,sizeof(request),&response,sizeof(response),error,&server) || !Valid(response,request)) {
            // Unknown receipt never erases the last confirmed ACK. The server
            // can resend unacknowledged intents after a transient pipe failure.
            endpoint.serverProcess = {}; response = {}; response.error = error ? error : ERROR_INVALID_DATA; return response;
        }
        endpoint.serverProcess = server;
        if (response.error == ERROR_REVISION_MISMATCH) { stream = through = 0; return response; }
        if (stream != response.stream) { stream = response.stream; through = 0; }
        if (response.count) through = response.events[response.count-1].serial;
        return response;
    }
};
} // namespace capslang::system_caps
