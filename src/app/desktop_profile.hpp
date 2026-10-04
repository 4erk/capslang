#pragma once
#include "../runtime/local_ipc.hpp"
#include <msctf.h>

namespace capslang::app {
// Lives entirely on the ordinary broker's STA. Notifications are evidence of
// profile changes, never proof of text entered or the taskbar's pixels.
class DesktopProfile final : public ITfInputProcessorProfileActivationSink {
    HRESULT com_ = E_UNEXPECTED, error_ = E_UNEXPECTED, sinkError_ = E_UNEXPECTED;
    ITfThreadMgr* thread_ = nullptr;
    ITfInputProcessorProfiles* profiles_ = nullptr;
    ITfInputProcessorProfileMgr* manager_ = nullptr;
    ITfSource* source_ = nullptr;
    DWORD cookie_ = TF_INVALID_COOKIE;
    ULONG refs_ = 1;
    bool own_ = false;
    LANGID external_ = 0, issued_ = 0;
    HWND observedFocus_ = nullptr, notificationFocus_ = nullptr;
    std::uint64_t generation_ = 0, epoch_ = 0;
    ULONGLONG nextAttempt_ = 0;
public:
    DesktopProfile() {
        com_ = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        error_ = com_;
        if (FAILED(com_)) return;
        error_ = CoCreateInstance(CLSID_TF_ThreadMgr,nullptr,CLSCTX_INPROC_SERVER,IID_ITfThreadMgr,reinterpret_cast<void**>(&thread_));
        if (FAILED(error_)) return;
        error_ = CoCreateInstance(CLSID_TF_InputProcessorProfiles,nullptr,CLSCTX_INPROC_SERVER,
            IID_ITfInputProcessorProfiles,reinterpret_cast<void**>(&profiles_));
        if (FAILED(error_)) return;
        error_ = profiles_->QueryInterface(IID_ITfInputProcessorProfileMgr,reinterpret_cast<void**>(&manager_));
        if (FAILED(error_)) return;
        error_ = thread_->QueryInterface(IID_ITfSource,reinterpret_cast<void**>(&source_));
        if (SUCCEEDED(error_)) error_ = source_->AdviseSink(IID_ITfInputProcessorProfileActivationSink,this,&cookie_);
        sinkError_ = error_;
        observedFocus_ = GetForegroundWindow();
    }
    ~DesktopProfile() {
        if (source_ && cookie_ != TF_INVALID_COOKIE) source_->UnadviseSink(cookie_);
        if (source_) source_->Release();
        if (manager_) manager_->Release();
        if (profiles_) profiles_->Release();
        if (thread_) thread_->Release();
        if (SUCCEEDED(com_)) CoUninitialize();
    }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (iid != IID_IUnknown && iid != IID_ITfInputProcessorProfileActivationSink) return E_NOINTERFACE;
        *output = static_cast<ITfInputProcessorProfileActivationSink*>(this); AddRef(); return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++refs_; }
    ULONG STDMETHODCALLTYPE Release() override { return --refs_; }
    HRESULT STDMETHODCALLTYPE OnActivated(DWORD,LANGID language,REFCLSID,REFGUID,REFGUID,HKL,DWORD flags) override {
        if ((flags & TF_IPSINK_FLAG_ACTIVE) && !own_ && language != issued_ && IsSupportedLanguage(language)) {
            external_ = language; notificationFocus_ = GetForegroundWindow();
        }
        return S_OK;
    }
    template<class Report> void Update(const ipc::Response& engine, Report report) {
        if (FAILED(sinkError_)) { report(0,engine.generation,static_cast<DWORD>(sinkError_),false); return; }
        TF_INPUTPROCESSORPROFILE profile{};
        HRESULT read = manager_ ? manager_->GetActiveProfile(GUID_TFCAT_TIP_KEYBOARD,&profile) : error_;
        const auto foreground = GetForegroundWindow();
        const bool focusChanged = foreground != observedFocus_;
        observedFocus_ = foreground;
        if (engine.flags & ipc::Locked) {
            external_ = 0;
            report(0,engine.generation,ERROR_NOT_READY,false);
            return;
        }
        if (external_) {
            const auto language = external_; external_ = 0;
            // A remembered layout on a newly focused window is not a choice.
            // Keyboard shortcuts are also observed by the engine independently.
            if (!focusChanged && notificationFocus_ == foreground && read == S_OK &&
                profile.langid == language && engine.actual == language && language != engine.target) {
                if (!report(language,engine.generation,0,true)) external_ = language;
                return; // Do not restore an old target over a new explicit selection.
            }
        }
        const bool fresh = epoch_ == engine.engineEpoch && generation_ == engine.generation;
        const auto now = GetTickCount64();
        if (!fresh || ((read != S_OK || profile.langid != engine.target || FAILED(error_)) && now >= nextAttempt_)) {
            epoch_ = engine.engineEpoch; generation_ = engine.generation;
            issued_ = static_cast<LANGID>(engine.target);
            const auto layout = FindLayout(issued_);
            error_ = layout && profiles_ && manager_ ? S_OK : E_FAIL;
            own_ = true;
            if (SUCCEEDED(error_)) error_ = profiles_->ChangeCurrentLanguage(issued_);
            if (SUCCEEDED(error_)) error_ = manager_->ActivateProfile(TF_PROFILETYPE_KEYBOARDLAYOUT,
                issued_,CLSID_NULL,GUID_NULL,layout,0x20000000);
            own_ = false; nextAttempt_ = now + 500;
            read = manager_ ? manager_->GetActiveProfile(GUID_TFCAT_TIP_KEYBOARD,&profile) : error_;
        }
        DWORD failure = FAILED(error_) ? static_cast<DWORD>(error_) :
            read != S_OK ? static_cast<DWORD>(read == S_FALSE ? E_FAIL : read) :
            profile.langid != engine.target ? ERROR_NOT_READY : 0;
        report(failure ? 0 : profile.langid,engine.generation,failure,false);
    }
};
} // namespace capslang::app
