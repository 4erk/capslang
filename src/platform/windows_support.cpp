#include "windows_support.hpp"

#include <msctf.h>
#include <setupapi.h>
#include <winioctl.h>
#include <ntddkbd.h>
#include <algorithm>

namespace capslang {
namespace {
// GUID_DEVINTERFACE_KEYBOARD from ntddkbd.h; a local value avoids INITGUID
// defining unrelated Windows COM IDs in this translation unit.
constexpr GUID kKeyboardInterface = {
    0x884b96c3, 0x56ef, 0x11d1, {0xbc, 0x8c, 0x00, 0xa0, 0xc9, 0x14, 0x05, 0xdd}};
// LLVM-MinGW's msctf.h declares ActivateProfile but omits TF_IPPMF_FORSESSION.
// Value from Microsoft's WinSDK msctf.h (microsoft/win32metadata).
constexpr DWORD kProfileForSession = 0x20000000;

bool QueryIndicators(HANDLE handle, KEYBOARD_INDICATOR_PARAMETERS& value, DWORD& error) {
    DWORD bytes = 0;
    if (!DeviceIoControl(handle, IOCTL_KEYBOARD_QUERY_INDICATORS, nullptr, 0,
                         &value, sizeof(value), &bytes, nullptr)) {
        error = GetLastError();
        return false;
    }
    if (bytes < sizeof(value)) {
        error = ERROR_INVALID_DATA;
        return false;
    }
    error = ERROR_SUCCESS;
    return true;
}
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

KeyboardLeds::~KeyboardLeds() { Close(); }

void KeyboardLeds::Close() {
    for (auto& device : devices_) {
        if (device.handle != INVALID_HANDLE_VALUE) CloseHandle(device.handle);
    }
    devices_.clear();
}

void KeyboardLeds::Add(const std::wstring& path) {
    if (std::any_of(devices_.begin(), devices_.end(), [&](const Device& device) {
        return _wcsicmp(device.path.c_str(), path.c_str()) == 0;
    })) return;
    Device device;
    device.path = path;
    // Keyboard read access is reserved by Windows. Request only write access
    // for the indicator IOCTLs, and do not read keyboard data.
    device.handle = CreateFileW(path.c_str(), GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (device.handle == INVALID_HANDLE_VALUE) {
        device.openError = GetLastError();
    } else {
        KEYBOARD_INDICATOR_PARAMETERS indicators{};
        device.queried = QueryIndicators(device.handle, indicators, device.queryError);
        device.unitId = indicators.UnitId;
        device.flags = indicators.LedFlags;
    }
    devices_.push_back(device);
}

void KeyboardLeds::Discover() {
    Close();
    enumerationError_ = ERROR_SUCCESS;
    HDEVINFO set = SetupDiGetClassDevsW(&kKeyboardInterface, nullptr, nullptr,
                                       DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (set == INVALID_HANDLE_VALUE) {
        enumerationError_ = GetLastError();
    } else {
        for (DWORD i = 0;; ++i) {
            SP_DEVICE_INTERFACE_DATA data{};
            data.cbSize = sizeof(data);
            if (!SetupDiEnumDeviceInterfaces(set, nullptr, &kKeyboardInterface, i, &data)) {
                if (GetLastError() != ERROR_NO_MORE_ITEMS) enumerationError_ = GetLastError();
                break;
            }
            DWORD bytes = 0;
            SetupDiGetDeviceInterfaceDetailW(set, &data, nullptr, 0, &bytes, nullptr);
            if (bytes < sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W) || bytes > 65536) continue;
            std::vector<BYTE> buffer(bytes);
            auto* detail = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W*>(buffer.data());
            detail->cbSize = sizeof(*detail);
            if (SetupDiGetDeviceInterfaceDetailW(set, &data, detail, bytes, nullptr, nullptr)) {
                Add(detail->DevicePath);
            }
        }
        SetupDiDestroyDeviceInfoList(set);
    }
    // Obtain class-device names from Windows' device map, not guessed indices
    // or persistent DOS-device aliases. Some drivers expose indicator IOCTLs
    // only through the class device rather than the interface path.
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DEVICEMAP\\KeyboardClass",
                     0, KEY_QUERY_VALUE, &key) == ERROR_SUCCESS) {
        for (DWORD i = 0;; ++i) {
            wchar_t name[512]{};
            DWORD size = ARRAYSIZE(name);
            const LSTATUS status = RegEnumValueW(key, i, name, &size,
                                                 nullptr, nullptr, nullptr, nullptr);
            if (status == ERROR_NO_MORE_ITEMS) break;
            if (status != ERROR_SUCCESS) { enumerationError_ = status; break; }
            const std::wstring native(name, size);
            if (native.rfind(L"\\Device\\KeyboardClass", 0) == 0) {
                Add(L"\\\\?\\GLOBALROOT" + native);
            }
        }
        RegCloseKey(key);
    }
}

bool KeyboardLeds::ReadFlags(size_t index, USHORT& flags, DWORD& error) {
    if (index >= devices_.size() || devices_[index].handle == INVALID_HANDLE_VALUE) {
        error = ERROR_INVALID_HANDLE;
        return false;
    }
    KEYBOARD_INDICATOR_PARAMETERS value{};
    if (!QueryIndicators(devices_[index].handle, value, error)) return false;
    flags = value.LedFlags;
    return true;
}

bool KeyboardLeds::SetScroll(size_t index, bool on, DWORD& error) {
    if (index >= devices_.size() || devices_[index].handle == INVALID_HANDLE_VALUE) {
        error = ERROR_INVALID_HANDLE;
        return false;
    }
    auto& device = devices_[index];
    KEYBOARD_INDICATOR_PARAMETERS value{};
    if (!QueryIndicators(device.handle, value, error)) return false;
    if (on) value.LedFlags |= KEYBOARD_SCROLL_LOCK_ON;
    else value.LedFlags &= static_cast<USHORT>(~KEYBOARD_SCROLL_LOCK_ON);
    DWORD bytes = 0;
    if (!DeviceIoControl(device.handle, IOCTL_KEYBOARD_SET_INDICATORS,
                         &value, sizeof(value), nullptr, 0, &bytes, nullptr)) {
        error = GetLastError();
        return false;
    }
    KEYBOARD_INDICATOR_PARAMETERS actual{};
    if (!QueryIndicators(device.handle, actual, error)) return false;
    if ((actual.LedFlags & KEYBOARD_SCROLL_LOCK_ON) != (value.LedFlags & KEYBOARD_SCROLL_LOCK_ON)) {
        // Several virtual/unsupported devices acknowledge SET but ignore it.
        error = ERROR_NOT_SUPPORTED;
        return false;
    }
    error = ERROR_SUCCESS;
    return true;
}
} // namespace capslang
