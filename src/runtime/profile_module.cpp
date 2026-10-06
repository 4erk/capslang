// Installed module. No test mapping, generic command, text or keyboard payload.
// Bootstrap contains only a nonce; every operation comes from the authenticated
// fixed-operation pipe. An arbitrary posted message cannot select server paths
// or execute a language operation.
#include "profile_attachment.hpp"
#include "profile_peer.hpp"
#include "../app/paths.hpp"

namespace {
thread_local capslang::ProfilePeer* peer = nullptr;
thread_local UINT_PTR timer = 0;
thread_local std::uint64_t pending = 0;
thread_local bool stepping = false;

void Cleanup() {
    if (timer) KillTimer(nullptr, timer);
    timer = 0;
    delete peer; peer = nullptr;
    pending = 0;
}
void CALLBACK Tick(HWND, UINT, UINT_PTR, DWORD) {
    if (stepping) return;
    stepping = true;
    try {
        if (!peer && pending) {
            auto endpoint = capslang::ipc::Endpoint::Current(capslang::ProfileInstance(
                GetCurrentProcessId(), GetCurrentThreadId(), pending));
            DWORD error = 0;
            std::wstring server;
#ifdef CAPSLANG_PROFILE_TEST
            // Private child and controller have this identical executable.
            server = capslang::app::ExecutablePath();
            constexpr bool high = false;
#else
            server = capslang::app::InstalledExecutable(error);
            constexpr bool high = true;
            if (!capslang::app::ProtectedExecutable(server, error)) server.clear();
#endif
            if (error || server.empty() || !capslang::ipc::IdentifyProcess(GetCurrentProcess(), endpoint.clientProcess)) Cleanup();
            else {
                peer = new capslang::ProfilePeer(endpoint, pending, server, high);
                if (!peer->Start()) Cleanup();
            }
        }
        if (peer) {
            peer->Step();
            if (peer->Detached() && peer->Finished()) Cleanup();
        }
    } catch (...) {
        // No exception crosses an application-owned message dispatch. Code is
        // pinned before any subscription; shutdown leaves no dangling code.
        Cleanup();
    }
    stepping = false;
}
}
extern "C" __declspec(dllexport) LRESULT CALLBACK CapsLangProfileHook(int code, WPARAM wp, LPARAM lp) {
    if (code == HC_ACTION && wp == PM_REMOVE) {
        const auto* message = reinterpret_cast<const MSG*>(lp);
        if (message && message->message == capslang::ProfileAttachMessage() && !peer && !pending) {
            pending = std::uint64_t(static_cast<std::uint32_t>(message->wParam)) |
                (std::uint64_t(static_cast<std::uint32_t>(message->lParam)) << 32);
            if (pending) {
                // Keep the timer callback valid even if the owner removes its
                // hook before the first tick/IPC handshake.
                HMODULE module = nullptr;
                if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                    reinterpret_cast<LPCWSTR>(&CapsLangProfileHook), &module)) timer = SetTimer(nullptr, 0, 50, Tick);
                if (!timer) pending = 0;
            }
        }
    }
    return CallNextHookEx(nullptr, code, wp, lp);
}
