#pragma once
#ifndef UNICODE
#define UNICODE
#endif
#include <windows.h>
#include <initializer_list>

namespace capslang::saver {
// Shared only with our watchdog, using an inherited anonymous mapping.
struct Lease {
    volatile LONG held = 0;
    BOOL original = FALSE;
    DWORD profile = 2; // 2 = not configured
};
inline DWORD Profile() {
    wchar_t value[8]{};
    DWORD bytes = sizeof(value);
    if (RegGetValueW(HKEY_CURRENT_USER, L"Control Panel\\Desktop", L"ScreenSaveActive",
                     RRF_RT_REG_SZ, nullptr, value, &bytes) != ERROR_SUCCESS) return 2;
    return wcscmp(value, L"1") == 0 ? 1 : wcscmp(value, L"0") == 0 ? 0 : 2;
}
inline bool Managed() {
    for (HKEY root : {HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE}) {
        HKEY key = nullptr;
        if (RegOpenKeyExW(root, L"Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop",
                          0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) continue;
        const LONG result = RegQueryValueExW(key, L"ScreenSaveActive", nullptr, nullptr, nullptr, nullptr);
        RegCloseKey(key);
        if (result == ERROR_SUCCESS) return true;
    }
    return false;
}
inline bool Active(BOOL& value) {
    return SystemParametersInfoW(SPI_GETSCREENSAVEACTIVE, 0, &value, 0) != FALSE;
}
inline bool Set(BOOL value) {
    // No SPIF_UPDATEINIFILE: never persist the override in the user profile.
    if (!SystemParametersInfoW(SPI_SETSCREENSAVEACTIVE, value, nullptr, 0)) return false;
    BOOL actual = FALSE;
    if (!Active(actual)) return false;
    if (actual != value) { SetLastError(ERROR_WRITE_FAULT); return false; }
    return true;
}
inline bool Release(Lease& lease) {
    if (!InterlockedCompareExchange(&lease.held, 0, 0)) return true;
    const DWORD profile = Profile();
    // A user's persistent change made during our lease takes precedence.
    const BOOL desired = profile != lease.profile && profile < 2 ? profile == 1 : lease.original;
    if (!Set(desired)) return false;
    InterlockedExchange(&lease.held, 0);
    return true;
}
inline bool Acquire(Lease& lease) {
    if (Managed()) { SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY); return false; }
    BOOL active = FALSE;
    if (!Active(active)) return false;
    if (!active) return true;
    if (!InterlockedCompareExchange(&lease.held, 0, 0)) {
        lease.original = active;
        lease.profile = Profile();
        // Publish before modifying Windows, so a crash at any later point is recoverable.
        InterlockedExchange(&lease.held, 1);
    }
    return Set(FALSE);
}
} // namespace capslang::saver
