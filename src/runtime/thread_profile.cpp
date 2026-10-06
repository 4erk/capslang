#include "thread_profile.hpp"
#include <limits>
#include <new>

namespace capslang {
namespace {
constexpr LANGID kEn = 0x0409, kRu = 0x0419;
bool Supported(LANGID language) { return language == kEn || language == kRu; }
HRESULT WINAPI ExistingManager(ITfThreadMgr** output) {
    if (!output) return E_POINTER;
    *output = nullptr;
    const HMODULE module = GetModuleHandleW(L"msctf.dll");
    const auto get = module ? reinterpret_cast<ThreadProfile::GetManager>(
        GetProcAddress(module, "TF_GetThreadMgr")) : nullptr;
    return get ? get(output) : HRESULT_FROM_WIN32(ERROR_NOT_READY);
}
HKL InstalledLayout(LANGID language) {
    // Bound memory/work; fail rather than silently use a partial/truncated list.
    HKL layouts[64]{};
    const int required = GetKeyboardLayoutList(0, nullptr);
    if (required <= 0 || required > static_cast<int>(ARRAYSIZE(layouts))) return nullptr;
    const int count = GetKeyboardLayoutList(ARRAYSIZE(layouts), layouts);
    for (int i = 0; i < count; ++i)
        if (LOWORD(reinterpret_cast<ULONG_PTR>(layouts[i])) == language) return layouts[i];
    return nullptr;
}
}
struct ThreadProfile::Impl final : ITfInputProcessorProfileActivationSink {
    DWORD threadId = GetCurrentThreadId();
    Notify notify;
    void* context;
    GetManager get;
    ITfThreadMgr* thread = nullptr;
    ITfInputProcessorProfiles* profiles = nullptr;
    ITfInputProcessorProfileMgr* manager = nullptr;
    ITfSource* source = nullptr;
    DWORD cookie = TF_INVALID_COOKIE;
    ULONG references = 1;
    HRESULT error = HRESULT_FROM_WIN32(ERROR_NOT_READY);
    std::uint64_t serial = 0, latest = 0, active = 0, confirmed = 0, invalidated = 0;
    LANGID requested = 0, activeLanguage = 0;
    bool binding = false, busy = false, interrupted = false, closing = false, resolving = false;
    Impl(Notify callback, void* owner, GetManager getter)
        : notify(callback), context(owner), get(getter ? getter : ExistingManager) {}
    bool SameThread() const { return GetCurrentThreadId() == threadId; }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** out) override {
        if (!out) return E_POINTER;
        *out = nullptr;
        if (iid != IID_IUnknown && iid != IID_ITfInputProcessorProfileActivationSink) return E_NOINTERFACE;
        *out = static_cast<ITfInputProcessorProfileActivationSink*>(this);
        AddRef(); return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++references; }
    ULONG STDMETHODCALLTYPE Release() override {
        const ULONG remaining = --references;
        if (!remaining) delete this;
        return remaining;
    }
    HRESULT STDMETHODCALLTYPE OnActivated(DWORD type, LANGID language, REFCLSID, REFGUID category,
        REFGUID, HKL, DWORD flags) override {
        if (!SameThread() || closing || !(flags & TF_IPSINK_FLAG_ACTIVE) || !Supported(language) ||
            (type != TF_PROFILETYPE_KEYBOARDLAYOUT &&
             (type != TF_PROFILETYPE_INPUTPROCESSOR || category != GUID_TFCAT_TIP_KEYBOARD))) return S_OK;
        if (serial == std::numeric_limits<std::uint64_t>::max()) {
            error = HRESULT_FROM_WIN32(ERROR_ARITHMETIC_OVERFLOW); confirmed = 0; return S_OK;
        }
        // A callback from the old operation remains its echo even if a newer
        // command was queued reentrantly. Its generation makes it stale, not
        // an external/user choice.
        const bool own = busy && language == activeLanguage;
        if (!binding && !own) {
            confirmed = 0; invalidated = latest;
            if (busy) interrupted = true;
        }
        LARGE_INTEGER stamp{};
        QueryPerformanceCounter(&stamp);
        Event event{++serial, own ? active : 0, language,
            binding ? Cause::Baseline : own ? Cause::OwnRequest : Cause::Observed,
            static_cast<std::uint64_t>(stamp.QuadPart)};
        if (notify) notify(context, event);
        return S_OK;
    }
    HRESULT Unbind() {
        if (!SameThread()) return HRESULT_FROM_WIN32(ERROR_INVALID_THREAD_ID);
        if (busy || binding || resolving) return HRESULT_FROM_WIN32(ERROR_BUSY);
        closing = true;
        // Do not release a live sink after a failed Unadvise. Caller must keep
        // the containing module loaded and report the failure instead.
        if (source && cookie != TF_INVALID_COOKIE) {
            const auto result = source->UnadviseSink(cookie);
            if (FAILED(result)) { error = result; return result; }
            cookie = TF_INVALID_COOKIE;
        }
        if (source) { source->Release(); source = nullptr; }
        if (manager) { manager->Release(); manager = nullptr; }
        if (profiles) { profiles->Release(); profiles = nullptr; }
        if (thread) { thread->Release(); thread = nullptr; }
        confirmed = 0; error = HRESULT_FROM_WIN32(ERROR_NOT_READY);
        closing = false; return S_OK;
    }
    HRESULT Bind() {
        if (!SameThread()) return HRESULT_FROM_WIN32(ERROR_INVALID_THREAD_ID);
        if (busy || binding) return HRESULT_FROM_WIN32(ERROR_BUSY);
        if (cookie != TF_INVALID_COOKIE && !closing && SUCCEEDED(error)) return S_OK;
        const auto cleanup = Unbind();
        if (FAILED(cleanup)) return cleanup;
        binding = true;
        error = get(&thread);
        if (SUCCEEDED(error) && !thread) error = HRESULT_FROM_WIN32(ERROR_NOT_READY);
        if (SUCCEEDED(error)) error = thread->QueryInterface(IID_ITfSource, reinterpret_cast<void**>(&source));
        if (SUCCEEDED(error)) error = source->AdviseSink(IID_ITfInputProcessorProfileActivationSink, this, &cookie);
        binding = false;
        const auto result = error;
        if (FAILED(result)) { Unbind(); error = result; }
        return result;
    }
    HRESULT EnsureProfiles() {
        if (manager) return S_OK;
        if (resolving) return HRESULT_FROM_WIN32(ERROR_RETRY);
        resolving = true;
        ITfInputProcessorProfiles* newProfiles = nullptr;
        ITfInputProcessorProfileMgr* newManager = nullptr;
        HRESULT result = CoCreateInstance(CLSID_TF_InputProcessorProfiles, nullptr,
            CLSCTX_INPROC_SERVER, IID_ITfInputProcessorProfiles, reinterpret_cast<void**>(&newProfiles));
        if (SUCCEEDED(result)) result = newProfiles->QueryInterface(IID_ITfInputProcessorProfileMgr,
            reinterpret_cast<void**>(&newManager));
        if (SUCCEEDED(result)) { profiles = newProfiles; manager = newManager; }
        else {
            if (newManager) newManager->Release();
            if (newProfiles) newProfiles->Release();
        }
        resolving = false;
        return result;
    }
    Result Read() {
        Result result;
        if (!SameThread()) { result.error = HRESULT_FROM_WIN32(ERROR_INVALID_THREAD_ID); return result; }
        if (closing || cookie == TF_INVALID_COOKIE) { result.error = HRESULT_FROM_WIN32(ERROR_NOT_READY); return result; }
        if (FAILED(error)) { result.error = error; return result; }
        result.error = EnsureProfiles();
        if (FAILED(result.error)) return result;
        TF_INPUTPROCESSORPROFILE profile{};
        result.error = manager->GetActiveProfile(GUID_TFCAT_TIP_KEYBOARD, &profile);
        result.actual = LOWORD(reinterpret_cast<ULONG_PTR>(GetKeyboardLayout(0)));
        result.sampled = GetTickCount64();
        if (result.error == S_FALSE) result.error = HRESULT_FROM_WIN32(ERROR_NOT_READY);
        if (SUCCEEDED(result.error)) result.profile = profile.langid;
        if (SUCCEEDED(result.error) && (!Supported(result.actual) || !Supported(result.profile)))
            result.error = HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
        if (SUCCEEDED(result.error) && confirmed == latest && latest &&
            requested == result.actual && requested == result.profile) result.generation = confirmed;
        return result;
    }
    Result Apply(LANGID language, std::uint64_t generation) {
        Result result;
        if (!SameThread()) { result.error = HRESULT_FROM_WIN32(ERROR_INVALID_THREAD_ID); return result; }
        if (!Supported(language) || !generation) { result.error = E_INVALIDARG; return result; }
        if (generation <= invalidated || generation < latest || (generation == latest && requested != language)) {
            result.error = HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH); return result;
        }
        latest = generation; requested = language;
        if (busy || binding) { result.error = HRESULT_FROM_WIN32(ERROR_RETRY); return result; }
        result.error = Bind();
        if (FAILED(result.error)) return result;
        result.error = EnsureProfiles();
        if (FAILED(result.error)) return result;
        if (latest != generation) { result.error = HRESULT_FROM_WIN32(ERROR_RETRY); return result; }
        const HKL layout = InstalledLayout(language);
        if (!layout) { result.error = HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED); return result; }
        busy = true; active = generation; activeLanguage = language; interrupted = false; confirmed = 0;
        const auto current = [&] { return latest == generation && !interrupted; };
        result.error = profiles->ChangeCurrentLanguage(language);
        if (SUCCEEDED(result.error) && current()) result.error = manager->ActivateProfile(
            TF_PROFILETYPE_KEYBOARDLAYOUT, language, CLSID_NULL, GUID_NULL, layout, 0);
        if (SUCCEEDED(result.error) && current() && !ActivateKeyboardLayout(layout, 0))
            result.error = HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
        if (SUCCEEDED(result.error) && !current()) result.error = HRESULT_FROM_WIN32(ERROR_RETRY);
        if (SUCCEEDED(result.error)) {
            const auto read = Read();
            result.actual = read.actual; result.profile = read.profile; result.error = read.error; result.sampled = read.sampled;
            if (SUCCEEDED(result.error) && (!current() || result.actual != language || result.profile != language))
                result.error = HRESULT_FROM_WIN32(ERROR_RETRY);
            if (SUCCEEDED(result.error)) result.generation = confirmed = generation;
        }
        busy = false; active = 0; activeLanguage = 0;
        return result;
    }
};
ThreadProfile::ThreadProfile(Notify notify, void* context, GetManager get)
    : impl_(new Impl(notify, context, get)) {}
ThreadProfile::~ThreadProfile() {
    // Explicit Unbind is required before module unload. On failure retain the
    // COM-held object, but prevent access to the now-dead owner's context.
    impl_->notify = nullptr; impl_->context = nullptr;
    impl_->Unbind(); impl_->Release();
}
HRESULT ThreadProfile::Bind() { return impl_->Bind(); }
HRESULT ThreadProfile::Unbind() { return impl_->Unbind(); }
ThreadProfile::Result ThreadProfile::Read() { return impl_->Read(); }
ThreadProfile::Result ThreadProfile::Apply(LANGID language, std::uint64_t generation) { return impl_->Apply(language, generation); }
} // namespace capslang
