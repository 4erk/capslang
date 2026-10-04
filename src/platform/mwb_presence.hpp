#pragma once
#include "windows_support.hpp"
#include <tlhelp32.h>

namespace capslang {
// Presence is only the user's enable condition, not proof of MWB connectivity.
// No routing windows, private settings, keys, versions or pointer activity.
inline bool MwbRunningInSession(DWORD session, DWORD& error) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) { error = GetLastError(); return false; }
    PROCESSENTRY32W entry{}; entry.dwSize = sizeof(entry);
    bool found = false;
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, L"PowerToys.MouseWithoutBorders.exe")) continue;
            DWORD actual = 0;
            if (ProcessIdToSessionId(entry.th32ProcessID, &actual) && actual == session) { found = true; break; }
        } while (Process32NextW(snapshot, &entry));
        error = 0;
    } else error = GetLastError();
    CloseHandle(snapshot); return found;
}
} // namespace capslang
