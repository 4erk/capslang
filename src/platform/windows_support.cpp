#include "windows_support.hpp"

#include <msctf.h>

namespace capslang {
namespace {
// LLVM-MinGW's msctf.h declares ActivateProfile but omits TF_IPPMF_FORSESSION.
// Value from Microsoft's WinSDK msctf.h (microsoft/win32metadata).
constexpr DWORD kProfileForSession = 0x20000000;

} // namespace

Elevation ProcessElevation(DWORD processId) {
    Elevation result;
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!process) { result.error = GetLastError(); return result; }
    HANDLE token = nullptr;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) {
        result.error = GetLastError();
    } else {
        TOKEN_ELEVATION value{};
        DWORD bytes = 0;
        result.known = GetTokenInformation(token, TokenElevation, &value,
                                           sizeof(value), &bytes) != FALSE;
        result.error = result.known ? ERROR_SUCCESS : GetLastError();
        result.elevated = value.TokenIsElevated != 0;
        CloseHandle(token);
    }
    CloseHandle(process);
    return result;
}

bool IsSupportedLanguage(LANGID language) {
    return language == kEnglish || language == kRussian;
}

HKL FindLayout(LANGID language) {
    if (!IsSupportedLanguage(language)) return nullptr;
    const int count = GetKeyboardLayoutList(0, nullptr);
    if (count <= 0) return nullptr;
    std::vector<HKL> layouts(static_cast<size_t>(count));
    const int actual = GetKeyboardLayoutList(count, layouts.data());
    for (int i = 0; i < actual; ++i) {
        if (LOWORD(reinterpret_cast<ULONG_PTR>(layouts[i])) == language) return layouts[i];
    }
    return nullptr;
}

LayoutTarget CaptureLayoutTarget() {
    LayoutTarget target;
    target.foreground = GetForegroundWindow();
    if (!target.foreground) return target;
    const DWORD foregroundThread = GetWindowThreadProcessId(target.foreground, nullptr);
    GUITHREADINFO info{};
    info.cbSize = sizeof(info);
    if (!GetGUIThreadInfo(foregroundThread, &info)) return {};
    target.focus = info.hwndFocus ? info.hwndFocus : target.foreground;
    target.threadId = GetWindowThreadProcessId(target.focus, &target.processId);
    if (target.threadId) target.original = GetKeyboardLayout(target.threadId);
    return target;
}

bool TargetStillValid(const LayoutTarget& target) {
    if (!target.threadId || !target.focus || !IsWindow(target.focus)) return false;
    DWORD process = 0;
    return GetWindowThreadProcessId(target.focus, &process) == target.threadId &&
           process == target.processId;
}

LANGID TargetLanguage(const LayoutTarget& target) {
    if (!TargetStillValid(target)) return 0;
    return LOWORD(reinterpret_cast<ULONG_PTR>(GetKeyboardLayout(target.threadId)));
}

struct LayoutApplier::Impl {
    DWORD owner = GetCurrentThreadId();
    ITfThreadMgr* threadManager = nullptr;
    ITfInputProcessorProfiles* profiles = nullptr;
    ITfInputProcessorProfileMgr* manager = nullptr;
    HRESULT threadResult = E_UNEXPECTED, profilesResult = E_UNEXPECTED, managerResult = E_UNEXPECTED;
    Impl() {
        // ChangeCurrentLanguage needs a thread manager, but this background
        // controller is not a TSF text client. Do not Activate it: on the
        // two-STA regression it makes the first foreign layout handler wait
        // on a mutex owned by this process. Creating the manager is sufficient
        // for ChangeCurrentLanguage and FORSESSION ActivateProfile (verified).
        threadResult = CoCreateInstance(CLSID_TF_ThreadMgr, nullptr, CLSCTX_INPROC_SERVER,
            IID_ITfThreadMgr, reinterpret_cast<void**>(&threadManager));
        profilesResult = CoCreateInstance(CLSID_TF_InputProcessorProfiles, nullptr, CLSCTX_INPROC_SERVER,
            IID_ITfInputProcessorProfiles, reinterpret_cast<void**>(&profiles));
        if (SUCCEEDED(profilesResult)) managerResult = profiles->QueryInterface(
            IID_ITfInputProcessorProfileMgr, reinterpret_cast<void**>(&manager));
    }
    ~Impl() {
        if (manager) manager->Release();
        if (profiles) profiles->Release();
        if (threadManager) threadManager->Release();
    }
};
LayoutApplier::LayoutApplier() : impl_(std::make_unique<Impl>()) {}
LayoutApplier::~LayoutApplier() = default;
LayoutRequestResult LayoutApplier::Request(const LayoutTarget& target, HKL layout) {
    LayoutRequestResult result;
    auto& self = *impl_;
    if (GetCurrentThreadId() != self.owner) { result.postError = ERROR_INVALID_THREAD_ID; return result; }
    if (!TargetStillValid(target) || !layout ||
        !IsSupportedLanguage(LOWORD(reinterpret_cast<ULONG_PTR>(layout)))) {
        result.postError = ERROR_INVALID_PARAMETER;
        return result;
    }

    auto stage = GetTickCount64();
    result.threadManager = self.threadResult;
    result.threadMs = GetTickCount64() - stage; stage = GetTickCount64();
    result.changeLanguage = self.profilesResult;
    if (SUCCEEDED(result.changeLanguage)) {
        const LANGID language = LOWORD(reinterpret_cast<ULONG_PTR>(layout));
        result.changeLanguage = self.profiles->ChangeCurrentLanguage(language);
        result.changeMs = GetTickCount64() - stage; stage = GetTickCount64();
        result.activateProfile = self.managerResult;
        if (SUCCEEDED(result.activateProfile)) {
            result.activateProfile = self.manager->ActivateProfile(TF_PROFILETYPE_KEYBOARDLAYOUT,
                language, CLSID_NULL, GUID_NULL, layout, kProfileForSession);
        }
    }
    result.profileMs = GetTickCount64() - stage; stage = GetTickCount64();
    // Explicit HKL, never HKL_NEXT/HKL_PREV: repeat delivery is idempotent.
    result.posted = PostMessageW(target.focus, WM_INPUTLANGCHANGEREQUEST, 0,
                                 reinterpret_cast<LPARAM>(layout)) != FALSE;
    result.postError = result.posted ? ERROR_SUCCESS : GetLastError();
    result.cleanupMs = GetTickCount64() - stage;
    return result;
}

LayoutRequestResult RequestLayout(const LayoutTarget& target, HKL layout) {
    if (!TargetStillValid(target) || !layout || !IsSupportedLanguage(LOWORD(reinterpret_cast<ULONG_PTR>(layout)))) {
        LayoutRequestResult rejected; rejected.postError = ERROR_INVALID_PARAMETER; return rejected;
    }
    LayoutApplier applier;
    return applier.Request(target, layout);
}

} // namespace capslang
