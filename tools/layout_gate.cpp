// Development-only feasibility gate, never part of the installed application.
// Default is read-only. Explicit opt-in is required for a single layout request.
// Does not install hooks, inject input, stop CapsLang, read text, or change settings.
#include "../src/platform/windows_support.hpp"
#include <msctf.h>
#include <cstdio>
#include <cstdlib>

namespace {
using namespace capslang;
constexpr DWORD kForSession = 0x20000000;

class Profiles final : public ITfInputProcessorProfileActivationSink {
  public:
    ITfThreadMgr* threads = nullptr;
    ITfInputProcessorProfiles* profiles = nullptr;
    ITfInputProcessorProfileMgr* manager = nullptr;
    ITfSource* source = nullptr;
    DWORD cookie = TF_INVALID_COOKIE;
    HRESULT threadHr = E_UNEXPECTED, profilesHr = E_UNEXPECTED;
    HRESULT managerHr = E_UNEXPECTED, sinkHr = E_UNEXPECTED;
    ULONG references = 1;
    unsigned notifications = 0;
    LANGID notifiedLanguage = 0;
    bool activated = false;

    Profiles() {
        threadHr = CoCreateInstance(CLSID_TF_ThreadMgr, nullptr, CLSCTX_INPROC_SERVER,
                                   IID_ITfThreadMgr, reinterpret_cast<void**>(&threads));
        profilesHr = CoCreateInstance(CLSID_TF_InputProcessorProfiles, nullptr, CLSCTX_INPROC_SERVER,
                                     IID_ITfInputProcessorProfiles, reinterpret_cast<void**>(&profiles));
        if (SUCCEEDED(profilesHr))
            managerHr = profiles->QueryInterface(IID_ITfInputProcessorProfileMgr,
                                                 reinterpret_cast<void**>(&manager));
        if (threads && SUCCEEDED(threads->QueryInterface(IID_ITfSource, reinterpret_cast<void**>(&source))))
            sinkHr = source->AdviseSink(IID_ITfInputProcessorProfileActivationSink,
                                       static_cast<ITfInputProcessorProfileActivationSink*>(this), &cookie);
        // Deliberately do not Activate a TSF text-client thread manager: this is
        // an observer/controller, not a text editor. Report sink availability.
    }
    ~Profiles() {
        if (source && cookie != TF_INVALID_COOKIE) source->UnadviseSink(cookie);
        if (threads && activated) threads->Deactivate();
        if (source) source->Release();
        if (manager) manager->Release();
        if (profiles) profiles->Release();
        if (threads) threads->Release();
    }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (iid != IID_IUnknown && iid != IID_ITfInputProcessorProfileActivationSink) return E_NOINTERFACE;
        *output = static_cast<ITfInputProcessorProfileActivationSink*>(this);
        AddRef(); return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++references; }
    ULONG STDMETHODCALLTYPE Release() override { return --references; }
    HRESULT STDMETHODCALLTYPE OnActivated(DWORD, LANGID language, REFCLSID, REFGUID, REFGUID,
                                           HKL, DWORD flags) override {
        if (flags & TF_IPSINK_FLAG_ACTIVE) { ++notifications; notifiedLanguage = language; }
        return S_OK;
    }
    void Sample(ULONGLONG started) {
        TF_INPUTPROCESSORPROFILE profile{};
        const HRESULT activeHr = manager ? manager->GetActiveProfile(GUID_TFCAT_TIP_KEYBOARD, &profile) : managerHr;
        LANGID current = 0;
        const HRESULT currentHr = profiles ? profiles->GetCurrentLanguage(&current) : profilesHr;
        const auto focus = CaptureLayoutTarget();
        const auto shell = GetShellWindow();
        const DWORD shellThread = shell ? GetWindowThreadProcessId(shell, nullptr) : 0;
        const LANGID shellLanguage = shellThread ? LOWORD(reinterpret_cast<ULONG_PTR>(GetKeyboardLayout(shellThread))) : 0;
        std::printf("{\"event\":\"sample\",\"elapsed_ms\":%llu,\"active_profile_hr\":%ld,"
                    "\"probe_profile\":%u,\"current_language_hr\":%ld,\"probe_current_language\":%u,"
                    "\"foreground_pid\":%lu,\"foreground_thread\":%lu,\"foreground_language\":%u,"
                    "\"shell_thread_language\":%u,\"notifications\":%u,\"notified_language\":%u,"
                    "\"visual_indicator_verified\":false}\n",
                    static_cast<unsigned long long>(GetTickCount64()-started), activeHr,
                    activeHr == S_OK ? profile.langid : 0, currentHr, current,
                    focus.processId, focus.threadId, TargetLanguage(focus), shellLanguage,
                    notifications, notifiedLanguage);
        std::fflush(stdout);
    }
    void Apply(LANGID language, bool addressed, bool activateManager, bool directProfile) {
        const auto target = CaptureLayoutTarget();
        const auto layout = FindLayout(language);
        const auto started = GetTickCount64();
        HRESULT threadActivate = E_UNEXPECTED;
        if (activateManager && threads) {
            TfClientId client = 0;
            threadActivate = threads->Activate(&client);
            activated = threadActivate == S_OK;
        }
        HRESULT change = directProfile ? S_FALSE : profiles ? profiles->ChangeCurrentLanguage(language) : profilesHr;
        HRESULT activate = E_UNEXPECTED;
        if ((directProfile || change == S_OK) && manager && layout)
            activate = manager->ActivateProfile(TF_PROFILETYPE_KEYBOARDLAYOUT, language,
                                               CLSID_NULL, GUID_NULL, layout,
                                               kForSession | (directProfile ? 4U : 0U));
        bool posted = false;
        DWORD postError = 0;
        if (addressed) {
            if (!layout || !TargetStillValid(target)) postError = ERROR_INVALID_PARAMETER;
            else {
                posted = PostMessageW(target.focus, WM_INPUTLANGCHANGEREQUEST, 0,
                                      reinterpret_cast<LPARAM>(layout)) != FALSE;
                if (!posted) postError = GetLastError();
            }
        }
        std::printf("{\"event\":\"request\",\"language\":%u,\"change_hr\":%ld,"
                    "\"thread_activate_hr\":%ld,\"direct_profile\":%s,"
                    "\"activate_hr\":%ld,\"addressed\":%s,\"posted\":%s,\"post_error\":%lu,"
                    "\"duration_ms\":%llu,\"application_confirmed\":false}\n",
                    language, change, threadActivate, directProfile ? "true" : "false",
                    activate, addressed ? "true" : "false", posted ? "true" : "false",
                    postError, static_cast<unsigned long long>(GetTickCount64()-started));
        std::fflush(stdout);
    }
};
}

int wmain(int count, wchar_t** args) {
    unsigned seconds = 3;
    LANGID apply = 0;
    bool confirm = false, addressed = false;
    bool activateManager = false, directProfile = false;
    for (int i=1; i<count; ++i) {
        if (wcscmp(args[i], L"--seconds") == 0 && i+1<count) {
            wchar_t* end = nullptr;
            const auto value = wcstoul(args[++i], &end, 10);
            if (!end || *end || value<1 || value>30) return ERROR_INVALID_PARAMETER;
            seconds = static_cast<unsigned>(value);
        } else if (wcscmp(args[i], L"--apply") == 0 && i+1<count) {
            const auto value = args[++i];
            if (wcscmp(value,L"EN")==0) apply=kEnglish;
            else if (wcscmp(value,L"RU")==0) apply=kRussian;
            else return ERROR_INVALID_PARAMETER;
        } else if (wcscmp(args[i], L"--confirm-active-desktop") == 0) confirm=true;
        else if (wcscmp(args[i], L"--address-target") == 0) addressed=true;
        else if (wcscmp(args[i], L"--activate-manager") == 0) activateManager=true;
        else if (wcscmp(args[i], L"--direct-profile") == 0) directProfile=true;
        else return ERROR_INVALID_PARAMETER;
    }
    if ((apply && !confirm) || (!apply && (confirm || addressed || activateManager || directProfile))) return ERROR_INVALID_PARAMETER;
    if (apply && !FindLayout(apply)) return ERROR_NOT_SUPPORTED;
    const HRESULT com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(com)) return 2;
    {
        Profiles profiles;
        const auto elevation = ProcessElevation(GetCurrentProcessId());
        DWORD session = 0; ProcessIdToSessionId(GetCurrentProcessId(), &session);
        std::printf("{\"event\":\"start\",\"read_only\":%s,\"pid\":%lu,\"session\":%lu,"
                    "\"elevation_known\":%s,\"elevated\":%s,\"thread_hr\":%ld,"
                    "\"profiles_hr\":%ld,\"manager_hr\":%ld,\"sink_hr\":%ld}\n",
                    apply ? "false" : "true", GetCurrentProcessId(), session,
                    elevation.known ? "true":"false", elevation.elevated ? "true":"false",
                    profiles.threadHr, profiles.profilesHr, profiles.managerHr, profiles.sinkHr);
        const auto started = GetTickCount64();
        profiles.Sample(started);
        if (apply) profiles.Apply(apply,addressed,activateManager,directProfile);
        while (GetTickCount64()-started < seconds*1000ULL) {
            MSG message{};
            while (PeekMessageW(&message,nullptr,0,0,PM_REMOVE)) {
                TranslateMessage(&message); DispatchMessageW(&message);
            }
            MsgWaitForMultipleObjects(0,nullptr,FALSE,200,QS_ALLINPUT);
            profiles.Sample(started);
        }
    }
    CoUninitialize();
    // An observer finishing successfully is never a live acceptance pass.
    return 0;
}
