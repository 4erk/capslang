// Standalone user-session companion, not the unfinished CapsLang 1.1 app.
#include <initializer_list>
#include "../src/platform/screensaver.hpp"
#include <wtsapi32.h>
#include <sddl.h>
#include <shellapi.h>
#include <cstdio>
#include <string>
#include <vector>

using namespace capslang;
namespace {
struct Handle {
    HANDLE h = nullptr;
    explicit Handle(HANDLE value = nullptr) : h(value) {}
    ~Handle() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
};
struct Shared { saver::Lease lease; volatile LONG ready = 0; };
HANDLE stopEvent = nullptr;
std::wstring Name(const wchar_t* suffix) {
    Handle token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.h)) return {};
    DWORD bytes = 0;
    GetTokenInformation(token.h, TokenUser, nullptr, 0, &bytes);
    std::vector<BYTE> data(bytes);
    if (!GetTokenInformation(token.h, TokenUser, data.data(), bytes, &bytes)) return {};
    LPWSTR sid = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(data.data())->User.Sid, &sid)) return {};
    const auto result = std::wstring(L"Local\\CapsLang.MwbSaverGuard.") + sid + suffix;
    LocalFree(sid);
    return result;
}
// Elevated MWB need not be opened: WTS enumerates names and session IDs.
bool MwbRunning(bool& running) {
    running = false;
    DWORD session = 0, count = 0;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &session)) return false;
    WTS_PROCESS_INFOW* entries = nullptr;
    if (!WTSEnumerateProcessesW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &entries, &count)) return false;
    for (DWORD i = 0; i < count; ++i) {
        if (entries[i].SessionId == session && entries[i].pProcessName &&
            _wcsicmp(entries[i].pProcessName, L"PowerToys.MouseWithoutBorders.exe") == 0) running = true;
    }
    WTSFreeMemory(entries);
    return true;
}
LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM wp, LPARAM lp) {
    if (message == WM_QUERYENDSESSION) return TRUE;
    if (message == WM_ENDSESSION && wp) SetEvent(stopEvent);
    return DefWindowProcW(window, message, wp, lp);
}
int Watch(HANDLE parent, HANDLE mapping, HANDLE instance, HANDLE done) {
    auto* shared = static_cast<Shared*>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(Shared)));
    if (!shared) return 2;
    InterlockedExchange(&shared->ready, 1);
    HANDLE events[]{done, parent};
    const DWORD wait = WaitForMultipleObjects(2, events, FALSE, INFINITE);
    bool restored = wait == WAIT_OBJECT_0;
    // Normal exit already restored. After a crash, keep the singleton alive
    // until restoration succeeds (e.g. unlock after ERROR_OPERATION_IN_PROGRESS).
    while (!restored) {
        restored = saver::Release(shared->lease);
        if (!restored) Sleep(1000);
    }
    UnmapViewOfFile(shared);
    CloseHandle(instance);
    return 0;
}
int Run(bool testStop, bool testCrash) {
    const auto mutexName = Name(L".instance"), eventName = Name(L".stop");
    if (mutexName.empty()) return 2;
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    Handle instance(CreateMutexW(&sa, FALSE, mutexName.c_str()));
    if (!instance.h) return 3;
    if (GetLastError() == ERROR_ALREADY_EXISTS) return ERROR_ALREADY_EXISTS;
    Handle stop(CreateEventW(nullptr, TRUE, FALSE, eventName.c_str()));
    Handle done(CreateEventW(&sa, TRUE, FALSE, nullptr));
    Handle parent(OpenProcess(SYNCHRONIZE, TRUE, GetCurrentProcessId()));
    Handle mapping(CreateFileMappingW(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0, sizeof(Shared), nullptr));
    if (!stop.h || !done.h || !parent.h || !mapping.h) return 4;
    auto* shared = static_cast<Shared*>(MapViewOfFile(mapping.h, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(Shared)));
    if (!shared) return 5;
    *shared = {};
    wchar_t executable[32768]{};
    if (!GetModuleFileNameW(nullptr, executable, ARRAYSIZE(executable))) return 6;
    wchar_t args[33000]{};
    swprintf_s(args, L"\"%s\" --watch %llu %llu %llu %llu", executable,
        reinterpret_cast<unsigned long long>(parent.h), reinterpret_cast<unsigned long long>(mapping.h),
        reinterpret_cast<unsigned long long>(instance.h), reinterpret_cast<unsigned long long>(done.h));
    SIZE_T bytes = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
    std::vector<BYTE> storage(bytes);
    auto* attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
    if (!InitializeProcThreadAttributeList(attributes, 1, 0, &bytes)) return 7;
    HANDLE inherited[]{parent.h, mapping.h, instance.h, done.h};
    if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                   inherited, sizeof(inherited), nullptr, nullptr)) {
        DeleteProcThreadAttributeList(attributes); return 8;
    }
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup); startup.lpAttributeList = attributes;
    PROCESS_INFORMATION child{};
    const bool spawned = CreateProcessW(executable, args, nullptr, nullptr, TRUE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, nullptr, nullptr, &startup.StartupInfo, &child) != FALSE;
    DeleteProcThreadAttributeList(attributes);
    if (!spawned) return 9;
    Handle childProcess(child.hProcess), childThread(child.hThread);
    const ULONGLONG readyDeadline = GetTickCount64() + 5000;
    while (!InterlockedCompareExchange(&shared->ready, 0, 0)) {
        if (GetTickCount64() >= readyDeadline || WaitForSingleObject(child.hProcess, 10) == WAIT_OBJECT_0) {
            SetEvent(done.h); return 10;
        }
    }
    stopEvent = stop.h;
    WNDCLASSW cls{}; cls.lpfnWndProc = WindowProc;
    cls.hInstance = GetModuleHandleW(nullptr); cls.lpszClassName = L"CapsLang.MwbSaverGuard";
    RegisterClassW(&cls);
    HWND window = CreateWindowExW(0, cls.lpszClassName, L"", 0, 0, 0, 0, 0, nullptr, nullptr, cls.hInstance, nullptr);
    if (!window) { SetEvent(done.h); return 11; }
    const ULONGLONG started = GetTickCount64();
    HANDLE events[]{stop.h, child.hProcess};
    DWORD exitCode = 0, lastError = 0;
    bool wasHeld = false;
    for (;;) {
        const DWORD wait = MsgWaitForMultipleObjects(2, events, FALSE, 500, QS_ALLINPUT);
        if (wait == WAIT_OBJECT_0 || wait == WAIT_OBJECT_0 + 1 || wait == WAIT_FAILED) {
            if (wait != WAIT_OBJECT_0) exitCode = 12;
            break;
        }
        MSG message{};
        while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&message); DispatchMessageW(&message);
        }
        bool running = false;
        const bool known = MwbRunning(running);
        const bool inhibit = known && running && !saver::Managed();
        const bool success = inhibit ? saver::Acquire(shared->lease) : saver::Release(shared->lease);
        const DWORD error = success ? 0 : GetLastError();
        const bool held = InterlockedCompareExchange(&shared->lease.held, 0, 0) != 0;
        if (held != wasHeld || error != lastError) {
            std::printf("lease=%d mwb=%d error=%lu\n", held, running, error); std::fflush(stdout);
            wasHeld = held; lastError = error;
        }
        if ((testStop || testCrash) && GetTickCount64() - started >= 2000) {
            if (!held) exitCode = 13;
            if (testCrash && held) TerminateProcess(GetCurrentProcess(), 77);
            break;
        }
    }
    // Do not leave a session override behind on ordinary stop. A locked
    // desktop can reject restoration; the watchdog retries after we exit.
    if (saver::Release(shared->lease)) SetEvent(done.h);
    else exitCode = 14;
    WaitForSingleObject(child.hProcess, 2000);
    DestroyWindow(window);
    UnmapViewOfFile(shared);
    return static_cast<int>(exitCode);
}
}
int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    int count = 0;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &count);
    if (!argv) return 1;
    int result = 0;
    if (count == 6 && wcscmp(argv[1], L"--watch") == 0) {
        HANDLE handles[4]{};
        for (int i = 0; i < 4; ++i) handles[i] = reinterpret_cast<HANDLE>(_wcstoui64(argv[i + 2], nullptr, 10));
        result = Watch(handles[0], handles[1], handles[2], handles[3]);
    } else if (count == 2 && wcscmp(argv[1], L"--status") == 0) {
        BOOL active = FALSE; bool running = false;
        const bool got = saver::Active(active), known = MwbRunning(running);
        const auto name = Name(L".instance");
        Handle mutex(name.empty() ? nullptr : OpenMutexW(SYNCHRONIZE, FALSE, name.c_str()));
        std::printf("{\"guardRunning\":%s,\"mwbKnown\":%s,\"mwbRunning\":%s,\"screensaverKnown\":%s,\"screensaverActive\":%s,\"profileActive\":%lu,\"managed\":%s}\n",
            mutex.h ? "true" : "false", known ? "true" : "false", running ? "true" : "false",
            got ? "true" : "false", active ? "true" : "false", saver::Profile(), saver::Managed() ? "true" : "false");
        result = got && known ? 0 : 1;
    } else if (count == 2 && wcscmp(argv[1], L"--stop") == 0) {
        const auto name = Name(L".stop");
        Handle stop(name.empty() ? nullptr : OpenEventW(EVENT_MODIFY_STATE, FALSE, name.c_str()));
        if (stop.h) result = SetEvent(stop.h) ? 0 : 1;
    } else if (count == 1 || (count == 2 && (wcscmp(argv[1], L"--exercise-stop") == 0 || wcscmp(argv[1], L"--exercise-crash") == 0))) {
        result = Run(count == 2 && wcscmp(argv[1], L"--exercise-stop") == 0,
                     count == 2 && wcscmp(argv[1], L"--exercise-crash") == 0);
    } else result = ERROR_INVALID_PARAMETER;
    LocalFree(argv);
    return result;
}
