// Test-only transport around the production in-thread profile component.
// Only the disposable fixture can be targeted; never installed by CapsLang.
#include "layout_message_probe.hpp"
#include "../src/runtime/thread_profile.hpp"
#include "../src/runtime/profile_peer.hpp"
#include "../src/runtime/profile_host.hpp"

namespace {
struct Page {
    HANDLE mapping = nullptr;
    capslang::test::LayoutMessageProbe* data = nullptr;
    Page() {
        mapping = OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, FALSE,
            capslang::test::ProbeName(GetCurrentProcessId()).c_str());
        if (!mapping) return;
        data = static_cast<capslang::test::LayoutMessageProbe*>(MapViewOfFile(mapping,
            FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(*data)));
        if (data && (data->magic != capslang::test::kProbeMagic ||
            data->process != GetCurrentProcessId() || data->thread != GetCurrentThreadId())) {
            UnmapViewOfFile(data); data = nullptr;
        }
    }
    ~Page() { if (data) UnmapViewOfFile(data); if (mapping) CloseHandle(mapping); }
};
enum class Event { Queued, Returned, Changed };
thread_local capslang::ThreadProfile* profile = nullptr;
thread_local capslang::ProfilePeer* peer = nullptr;
thread_local UINT_PTR peerTimer = 0;
thread_local UINT peerWake = 0;
void StopPeer();
void PeerStep() {
    if (!peer) return;
    peer->Step();
    Page page;
    if (page.data) InterlockedExchange(&page.data->peerDetached, peer->Detached());
    if (peer->Detached() && peer->Finished()) StopPeer();
}
void CALLBACK PeerTimer(HWND, UINT, UINT_PTR, DWORD) { PeerStep(); }
void StopPeer() {
    if (peerTimer) KillTimer(nullptr, peerTimer);
    peerTimer = 0;
    delete peer; peer = nullptr;
}
void StartPeer() {
    Page page;
    if (!page.data || profile || peer) return;
    auto endpoint = capslang::ipc::Endpoint::Current(capslang::ProfileInstance(GetCurrentProcessId(),
        GetCurrentThreadId(), static_cast<std::uint64_t>(page.data->channelBinding)));
    capslang::ipc::IdentifyProcess(GetCurrentProcess(), endpoint.clientProcess);
    endpoint.serverProcess = {page.data->serverProcess, static_cast<std::uint64_t>(page.data->serverCreated)};
    wchar_t image[32768]{}; GetModuleFileNameW(nullptr, image, ARRAYSIZE(image));
    // Test parent and fixture execute this exact same image. No server path
    // comes from the shared page; medium permission exists only in this test.
    peer = new capslang::ProfilePeer(endpoint, static_cast<std::uint64_t>(page.data->channelBinding), image, false);
    peerWake = capslang::ProfilePeer::WakeMessage();
    peerTimer = SetTimer(nullptr, 0, 100, PeerTimer);
    const bool started = peerTimer && peer->Start();
    if (!started) StopPeer();
    InterlockedExchange(&page.data->peerStatus, started ? S_OK : E_FAIL);
}
void Record(Event event, LANGID language) {
    if (language != capslang::kEnglish && language != capslang::kRussian) return;
    Page page;
    if (!page.data) return;
    volatile LONG* value = nullptr;
    volatile LONG* count = nullptr;
    switch (event) {
    case Event::Queued: value = &page.data->queuedLanguage; count = &page.data->queued; break;
    case Event::Returned: value = &page.data->returnedLanguage; count = &page.data->returned; break;
    case Event::Changed: value = &page.data->changedLanguage; count = &page.data->changed; break;
    }
    InterlockedExchange(value, language); InterlockedIncrement(count);
}
void ProfileEvent(void*, const capslang::ThreadProfile::Event& event) noexcept {
    // This disposable mapping transport is not used by the production owner.
    // The reusable component itself performs no I/O in the callback.
    Page page;
    if (!page.data) return;
    InterlockedExchange(&page.data->profileLanguage, event.language);
    InterlockedIncrement(&page.data->profileNotifications);
    if (event.cause == capslang::ThreadProfile::Cause::OwnRequest) {
        InterlockedIncrement(&page.data->ownProfiles);
        InterlockedExchange64(&page.data->lastOwnGeneration, static_cast<LONG64>(event.generation));
        const auto newer = InterlockedExchange64(&page.data->reenterGeneration, 0);
        if (newer && profile) {
            const auto result = profile->Apply(static_cast<LANGID>(page.data->reenterLanguage),
                static_cast<std::uint64_t>(newer));
            InterlockedExchange(&page.data->reenterResult, result.error);
        }
    } else if (event.cause == capslang::ThreadProfile::Cause::Observed) {
        InterlockedIncrement(&page.data->externalProfiles);
    }
}
HRESULT WINAPI TestManager(ITfThreadMgr** output) {
    Page page;
    *output = nullptr;
    if (page.data && InterlockedExchange(&page.data->simulateMissingManagerOnce, 0))
        return HRESULT_FROM_WIN32(ERROR_NOT_READY);
    const auto module = GetModuleHandleW(L"msctf.dll");
    const auto get = module ? reinterpret_cast<capslang::ThreadProfile::GetManager>(
        GetProcAddress(module, "TF_GetThreadMgr")) : nullptr;
    return get ? get(output) : HRESULT_FROM_WIN32(ERROR_NOT_READY);
}
// No COM destructors in DllMain/loader lock. The fixture must explicitly
// detach on its input thread before removing the hook/module.
void InitializeProfile() {
    Page page;
    if (!page.data) return;
    InterlockedExchange(&page.data->initializationStage, 1);
    if (!profile) profile = new capslang::ThreadProfile(ProfileEvent, nullptr, TestManager);
    const HRESULT result = profile->Bind();
    InterlockedExchange(&page.data->initializationStage, 5);
    InterlockedExchange(&page.data->profileError, result);
}
void ReadOnFixtureThread() {
    Page page;
    if (!page.data) return;
    capslang::ThreadProfile::Result result;
    result.error = HRESULT_FROM_WIN32(ERROR_NOT_READY);
    if (profile) result = profile->Read();
    InterlockedExchange(&page.data->commandProfile, result.profile);
    InterlockedExchange64(&page.data->confirmedGeneration, static_cast<LONG64>(result.generation));
    InterlockedExchange(&page.data->commandResult, result.error);
}
void DetachProfile() {
    Page page;
    if (!page.data) return;
    const HRESULT result = profile ? profile->Unbind() : S_OK;
    if (SUCCEEDED(result)) { delete profile; profile = nullptr; }
    InterlockedExchange(&page.data->profileError, result);
}
void ApplyOnFixtureThread() {
    Page page;
    if (!page.data) return;
    const LONG language = InterlockedCompareExchange(&page.data->commandLanguage, 0, 0);
    const LONG64 generation = InterlockedCompareExchange64(&page.data->commandGeneration, 0, 0);
    capslang::ThreadProfile::Result result;
    result.error = HRESULT_FROM_WIN32(ERROR_NOT_READY);
    if (profile && (language == capslang::kEnglish || language == capslang::kRussian) && generation > 0)
        result = profile->Apply(static_cast<LANGID>(language), static_cast<std::uint64_t>(generation));
    else if (profile) result.error = E_INVALIDARG;
    InterlockedExchange(&page.data->commandProfile, result.profile);
    InterlockedExchange64(&page.data->confirmedGeneration, static_cast<LONG64>(result.generation));
    InterlockedExchange(&page.data->commandResult, result.error);
}
}
extern "C" __declspec(dllexport) LRESULT CALLBACK ObserveQueued(int code, WPARAM wp, LPARAM lp) {
    if (code == HC_ACTION && wp == PM_REMOVE) {
        const auto* message = reinterpret_cast<const MSG*>(lp);
        if (message && message->message == WM_INPUTLANGCHANGEREQUEST)
            Record(Event::Queued, LOWORD(message->lParam));
        if (message && message->message == WM_APP + 50) InitializeProfile();
        if (message && message->message == WM_APP + 51) DetachProfile();
        if (message && message->message == WM_APP + 52) ApplyOnFixtureThread();
        if (message && message->message == WM_APP + 53) ReadOnFixtureThread();
        if (message && message->message == WM_APP + 54) StartPeer();
        if (message && message->message == WM_APP + 56) StopPeer();
        if (message && peer && message->message == peerWake) PeerStep();
    }
    return CallNextHookEx(nullptr, code, wp, lp);
}
extern "C" __declspec(dllexport) LRESULT CALLBACK ObserveReturned(int code, WPARAM wp, LPARAM lp) {
    if (code == HC_ACTION) {
        const auto* message = reinterpret_cast<const CWPRETSTRUCT*>(lp);
        if (message && message->message == WM_INPUTLANGCHANGEREQUEST)
            Record(Event::Returned, LOWORD(reinterpret_cast<ULONG_PTR>(GetKeyboardLayout(0))));
        if (message && message->message == WM_INPUTLANGCHANGE)
            Record(Event::Changed, LOWORD(message->lParam));
    }
    return CallNextHookEx(nullptr, code, wp, lp);
}
