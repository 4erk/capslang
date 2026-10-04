#pragma once

#ifndef UNICODE
#define UNICODE
#define _UNICODE
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <string>
#include <vector>
#include <memory>

namespace capslang {

constexpr LANGID kEnglish = 0x0409;
constexpr LANGID kRussian = 0x0419;

struct Elevation {
    bool known = false;
    bool elevated = false;
    DWORD error = ERROR_SUCCESS;
};
Elevation ProcessElevation(DWORD processId);
bool IsSupportedLanguage(LANGID language);
HKL FindLayout(LANGID language);

struct LayoutTarget {
    HWND foreground = nullptr;
    HWND focus = nullptr;
    DWORD processId = 0;
    DWORD threadId = 0;
    HKL original = nullptr;
};
LayoutTarget CaptureLayoutTarget();
bool TargetStillValid(const LayoutTarget& target);
LANGID TargetLanguage(const LayoutTarget& target);

struct LayoutRequestResult {
    HRESULT threadManager = E_UNEXPECTED;
    HRESULT changeLanguage = E_UNEXPECTED;
    HRESULT activateProfile = E_UNEXPECTED;
    DWORD postError = ERROR_SUCCESS;
    bool posted = false;
    ULONGLONG threadMs = 0, changeMs = 0, profileMs = 0, cleanupMs = 0;
};

// Caller owns a COM STA and performs bounded, asynchronous read-back. Never
// call from a keyboard callback. Success of an API is not proof of a change.
LayoutRequestResult RequestLayout(const LayoutTarget& target, HKL layout);

// Construct/use/destroy on one initialized COM STA, before CoUninitialize.
// Keep TSF objects on the worker for its lifetime, not per keystroke. This
// layout controller creates a ThreadMgr but does not activate a text client.
class LayoutApplier {
public:
    LayoutApplier();
    ~LayoutApplier();
    LayoutApplier(const LayoutApplier&) = delete;
    LayoutApplier& operator=(const LayoutApplier&) = delete;
    LayoutRequestResult Request(const LayoutTarget& target, HKL layout);
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

class KeyboardLeds {
public:
    struct Device {
        std::wstring path;
        HANDLE handle = INVALID_HANDLE_VALUE;
        DWORD openError = ERROR_SUCCESS;
        DWORD queryError = ERROR_SUCCESS;
        USHORT unitId = 0;
        USHORT flags = 0;
        bool queried = false;
    };

    KeyboardLeds() = default;
    ~KeyboardLeds();
    KeyboardLeds(const KeyboardLeds&) = delete;
    KeyboardLeds& operator=(const KeyboardLeds&) = delete;
    void Discover();
    const std::vector<Device>& Devices() const { return devices_; }
    // Only the Scroll LED bit is changed. No keyboard input is synthesized.
    bool SetScroll(size_t index, bool on, DWORD& error);
    bool ReadFlags(size_t index, USHORT& flags, DWORD& error);
    DWORD EnumerationError() const { return enumerationError_; }

private:
    void Close();
    void Add(const std::wstring& path);
    std::vector<Device> devices_;
    DWORD enumerationError_ = ERROR_SUCCESS;
};

} // namespace capslang
