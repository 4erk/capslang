// Real Win32 cross-process tests on a private, never-activated desktop.
// No SendInput, hooks, device writes, foreground changes, or legacy stop IPC.
#include "../src/platform/windows_support.hpp"
#include <objbase.h>
#include <sddl.h>
#include <cstdio>
#include <functional>
#include <string>
#include <vector>

using namespace capslang;
namespace {
constexpr UINT kReset = WM_APP + 1;
constexpr UINT kDestroy = WM_APP + 2;
struct Shared {
    HWND window;
    DWORD pid, tid;
    volatile LONG requests, changes, mode, resetCount;
    DWORD tokenError, postError, controlError, integrityRid;
    BOOL lowered, posted, controlPosted;
};
Shared* g_shared = nullptr;
HKL g_pending = nullptr;

LRESULT CALLBACK FixtureProc(HWND window, UINT message, WPARAM wp, LPARAM lp) {
    switch (message) {
    case kReset:
        KillTimer(window, 1);
        g_pending = nullptr;
        ActivateKeyboardLayout(FindLayout(kEnglish), 0);
        InterlockedIncrement(&g_shared->resetCount);
        return 0;
    case kDestroy: DestroyWindow(window); return 0;
    case WM_INPUTLANGCHANGEREQUEST:
        InterlockedIncrement(&g_shared->requests);
        if (InterlockedCompareExchange(&g_shared->mode, 0, 0) == 1) return 0;
        if (InterlockedCompareExchange(&g_shared->mode, 0, 0) == 2) {
            g_pending = reinterpret_cast<HKL>(lp);
            SetTimer(window, 1, 180, nullptr);
            return 0;
        }
        break;
    case WM_TIMER:
        if (wp == 1 && g_pending) {
            KillTimer(window, 1);
            const HKL pending = g_pending;
            g_pending = nullptr;
            return DefWindowProcW(window, WM_INPUTLANGCHANGEREQUEST, 0,
                                   reinterpret_cast<LPARAM>(pending));
        }
        break;
    case WM_INPUTLANGCHANGE: InterlockedIncrement(&g_shared->changes); break;
    }
    return DefWindowProcW(window, message, wp, lp);
}

bool PumpUntil(const std::function<bool()>& done, DWORD timeout = 1200) {
    const ULONGLONG start = GetTickCount64();
    do {
        MSG message{};
        while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        if (done()) return true;
        MsgWaitForMultipleObjects(0, nullptr, FALSE, 10, QS_ALLINPUT);
    } while (GetTickCount64() - start < timeout);
    return done();
}

int FixtureMain(HANDLE mapping, HANDLE ready, HANDLE stop) {
    g_shared = static_cast<Shared*>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(Shared)));
    if (!g_shared) return 10;
    WNDCLASSW wc{};
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = L"CapsLang.TestFixture.PrivateDesktop";
    wc.lpfnWndProc = FixtureProc;
    if (!RegisterClassW(&wc)) return 11;
    HWND window = CreateWindowW(wc.lpszClassName, L"Test fixture", WS_OVERLAPPED,
        0, 0, 200, 100, nullptr, nullptr, wc.hInstance, nullptr);
    if (!window) return 12;
    ActivateKeyboardLayout(FindLayout(kEnglish), 0);
    g_shared->window = window;
    g_shared->pid = GetCurrentProcessId();
    g_shared->tid = GetCurrentThreadId();
    SetEvent(ready);
    while (WaitForSingleObject(stop, 0) != WAIT_OBJECT_0) {
        const DWORD wait = MsgWaitForMultipleObjects(1, &stop, FALSE, 100, QS_ALLINPUT);
        if (wait == WAIT_OBJECT_0 || wait == WAIT_FAILED) break;
        MSG message{};
        while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    if (IsWindow(window)) DestroyWindow(window);
    UnmapViewOfFile(g_shared);
    CloseHandle(mapping); CloseHandle(ready); CloseHandle(stop);
    return 0;
}

HANDLE LowToken() {
    HANDLE source = nullptr, token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY |
            TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT, &source)) return nullptr;
    const bool restricted = CreateRestrictedToken(source, DISABLE_MAX_PRIVILEGE,
        0, nullptr, 0, nullptr, 0, nullptr, &token) != FALSE;
    CloseHandle(source);
    if (!restricted) return nullptr;
    PSID sid = nullptr;
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_MANDATORY_LABEL_AUTHORITY;
    if (!AllocateAndInitializeSid(&authority, 1, SECURITY_MANDATORY_LOW_RID, 0, 0, 0, 0, 0, 0, 0, &sid)) {
        CloseHandle(token); return nullptr;
    }
    TOKEN_MANDATORY_LABEL label{{sid, SE_GROUP_INTEGRITY}};
    const bool lowered = SetTokenInformation(token, TokenIntegrityLevel, &label,
        static_cast<DWORD>(sizeof(label) + GetLengthSid(sid))) != FALSE;
    FreeSid(sid);
    if (!lowered) { CloseHandle(token); return nullptr; }
    return token;
}

int LowSenderMain(HANDLE mapping, HANDLE ready, HANDLE stop) {
    auto* data = static_cast<Shared*>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(Shared)));
    if (!data) return 14;
    // The parent starts this disposable process with a restricted low token.
    // Lowering an ALREADY initialized Win32 process is not a valid UIPI test.
    HANDLE token = nullptr;
    alignas(TOKEN_MANDATORY_LABEL) BYTE storage[256]{};
    DWORD bytes = 0;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) &&
        GetTokenInformation(token, TokenIntegrityLevel, storage, sizeof(storage), &bytes)) {
        const auto* label = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(storage);
        const UCHAR count = *GetSidSubAuthorityCount(label->Label.Sid);
        data->integrityRid = count ? *GetSidSubAuthority(label->Label.Sid, count - 1) : 0;
        data->lowered = data->integrityRid == SECURITY_MANDATORY_LOW_RID;
    } else data->tokenError = GetLastError();
    if (token) CloseHandle(token);
    if (data->lowered) {
        data->controlPosted = PostMessageW(data->window, WM_APP + 3, 0, 0);
        data->controlError = data->controlPosted ? ERROR_SUCCESS : GetLastError();
        SetLastError(ERROR_SUCCESS);
        data->posted = PostMessageW(data->window, WM_INPUTLANGCHANGEREQUEST, 0,
                                    reinterpret_cast<LPARAM>(FindLayout(kRussian)));
        data->postError = data->posted ? ERROR_SUCCESS : GetLastError();
    }
    SetEvent(ready);
    WaitForSingleObject(stop, 5000);
    UnmapViewOfFile(data);
    CloseHandle(mapping); CloseHandle(ready); CloseHandle(stop);
    return 0;
}

struct Fixture {
    HANDLE mapping = nullptr, ready = nullptr, stop = nullptr, process = nullptr, job = nullptr;
    Shared* data = nullptr;
    ~Fixture() {
        if (stop) SetEvent(stop);
        if (process) WaitForSingleObject(process, 2000);
        // This job contains only the child test fixture; kills it if hung.
        if (job) CloseHandle(job);
        if (process) CloseHandle(process);
        if (data) UnmapViewOfFile(data);
        if (mapping) CloseHandle(mapping);
        if (ready) CloseHandle(ready);
        if (stop) CloseHandle(stop);
    }
    bool Start(std::wstring desktop, const LayoutTarget* destination = nullptr) {
        SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
        mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0, sizeof(Shared), nullptr);
        ready = CreateEventW(&sa, TRUE, FALSE, nullptr);
        stop = CreateEventW(&sa, TRUE, FALSE, nullptr);
        if (!mapping || !ready || !stop) return false;
        data = static_cast<Shared*>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(Shared)));
        if (!data) return false;
        *data = {};
        if (destination) data->window = destination->focus;
        job = CreateJobObjectW(nullptr, nullptr);
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!job || !SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) return false;
        SIZE_T bytes = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
        std::vector<BYTE> buffer(bytes);
        STARTUPINFOEXW startup{};
        startup.StartupInfo.cb = sizeof(startup);
        startup.StartupInfo.lpDesktop = desktop.data();
        startup.lpAttributeList = reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(buffer.data());
        if (!InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &bytes)) return false;
        HANDLE inherited[]{mapping, ready, stop};
        const bool attributes = UpdateProcThreadAttribute(startup.lpAttributeList, 0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, sizeof(inherited), nullptr, nullptr) != FALSE;
        wchar_t path[32768]{};
        GetModuleFileNameW(nullptr, path, ARRAYSIZE(path));
        std::wstring command = L"\"" + std::wstring(path) +
            (destination ? L"\" --low-sender " : L"\" --fixture ") +
            std::to_wstring(reinterpret_cast<ULONG_PTR>(mapping)) + L" " +
            std::to_wstring(reinterpret_cast<ULONG_PTR>(ready)) + L" " +
            std::to_wstring(reinterpret_cast<ULONG_PTR>(stop));
        PROCESS_INFORMATION child{};
        HANDLE lowToken = destination ? LowToken() : nullptr;
        constexpr DWORD flags = CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT;
        const bool created = attributes && (destination
            ? lowToken && CreateProcessAsUserW(lowToken, path, command.data(), nullptr, nullptr, TRUE,
                flags, nullptr, nullptr, &startup.StartupInfo, &child)
            : CreateProcessW(path, command.data(), nullptr, nullptr, TRUE,
                flags, nullptr, nullptr, &startup.StartupInfo, &child));
        const DWORD createError = created ? 0 : GetLastError();
        if (lowToken) CloseHandle(lowToken);
        DeleteProcThreadAttributeList(startup.lpAttributeList);
        if (!created) { std::printf("Create fixture error=%lu\n", createError); return false; }
        process = child.hProcess;
        const bool assigned = AssignProcessToJobObject(job, process) != FALSE;
        if (assigned) ResumeThread(child.hThread);
        else TerminateProcess(process, 13); // Only our not-yet-started test child.
        CloseHandle(child.hThread);
        if (!assigned) return false;
        HANDLE waits[]{ready, process};
        return WaitForMultipleObjects(2, waits, FALSE, 5000) == WAIT_OBJECT_0;
    }
    LayoutTarget Target() const {
        return {data->window, data->window, data->pid, data->tid, GetKeyboardLayout(data->tid)};
    }
    bool Reset(LONG mode) {
        InterlockedExchange(&data->mode, mode);
        const LONG previous = InterlockedCompareExchange(&data->resetCount, 0, 0);
        if (!PostMessageW(data->window, kReset, 0, 0)) return false;
        return PumpUntil([&] { return InterlockedCompareExchange(&data->resetCount, 0, 0) != previous; });
    }
};

unsigned checks = 0, failures = 0;
void Check(bool ok, const char* name) {
    ++checks;
    if (!ok) ++failures;
    std::printf("%s %s\n", ok ? "PASS" : "FAIL", name);
    std::fflush(stdout);
}

void Tests(const std::wstring& desktop) {
    Fixture fixture;
    if (!fixture.Start(desktop)) {
        std::printf("Fixture start error=%lu\n", GetLastError());
        Check(false, "cross-process fixture ready"); return;
    }
    Check(true, "cross-process fixture ready on isolated desktop");
    LayoutTarget target = fixture.Target();
    Check(TargetStillValid(target), "real target identity validated");
    Check(TargetLanguage(target) == kEnglish, "fixture initial EN");
    const HKL ru = FindLayout(kRussian), en = FindLayout(kEnglish);
    for (int i = 0; i < 20; ++i) {
        const HKL desired = i % 2 == 0 ? ru : en;
        const auto result = RequestLayout(target, desired);
        const bool verified = PumpUntil([&] {
            return TargetLanguage(target) == LOWORD(reinterpret_cast<ULONG_PTR>(desired));
        });
        if (i == 0 || !verified) {
            std::printf("layout request: thread_hr=0x%08lx change_hr=0x%08lx profile_hr=0x%08lx posted=%d error=%lu actual=%04x\n",
                static_cast<unsigned long>(result.threadManager), static_cast<unsigned long>(result.changeLanguage),
                static_cast<unsigned long>(result.activateProfile), result.posted, result.postError, TargetLanguage(target));
        }
        Check(result.posted && verified, "absolute language reaches real foreign window");
    }
    RequestLayout(target, en);
    Check(PumpUntil([&] { return TargetLanguage(target) == kEnglish; }), "repeated EN does not toggle");
    auto wrong = target;
    wrong.processId = GetCurrentProcessId();
    const auto invalid = RequestLayout(wrong, ru);
    Check(!invalid.posted && invalid.postError == ERROR_INVALID_PARAMETER, "foreign identity mismatch refused");

    {
        Fixture low;
        const bool started = low.Start(desktop, &target);
        Check(started && low.data->lowered, "disposable sender lowered to low integrity");
        if (started) {
            std::printf("UIPI: low=%d rid=%lu token_error=%lu posted=%d post_error=%lu control_posted=%d control_error=%lu\n",
                low.data->lowered, low.data->integrityRid, low.data->tokenError, low.data->posted,
                low.data->postError, low.data->controlPosted, low.data->controlError);
            Check(!low.data->controlPosted && low.data->controlError == ERROR_ACCESS_DENIED,
                  "UIPI control message denied for genuinely low process");
            Check(low.data->lowered && !low.data->posted && low.data->postError == ERROR_ACCESS_DENIED,
                  "real UIPI boundary rejects lower-integrity layout sender");
            const bool changed = PumpUntil([&] { return TargetLanguage(target) != kEnglish; }, 300);
            Check(!changed, "denied lower-integrity request leaves target unchanged after processing");
        }
    }

    Check(fixture.Reset(1), "rejecting fixture reset");
    const LONG prior = InterlockedCompareExchange(&fixture.data->requests, 0, 0);
    const bool posted = PostMessageW(target.focus, WM_INPUTLANGCHANGEREQUEST, 0, reinterpret_cast<LPARAM>(ru));
    const bool received = PumpUntil([&] { return InterlockedCompareExchange(&fixture.data->requests, 0, 0) > prior; });
    Check(posted && received && TargetLanguage(target) == kEnglish,
          "successful PostMessage is NOT proof of application (real refusing window)");
    Check(fixture.Reset(2), "delayed fixture reset");
    PostMessageW(target.focus, WM_INPUTLANGCHANGEREQUEST, 0, reinterpret_cast<LPARAM>(ru));
    Check(TargetLanguage(target) == kEnglish, "delayed request not prematurely acknowledged");
    Check(PumpUntil([&] { return TargetLanguage(target) == kRussian; }), "delayed acknowledgement verified");
    Check(PostMessageW(target.focus, kDestroy, 0, 0) && PumpUntil([&] { return !TargetStillValid(target); }),
          "destroyed target invalidated");
    const auto gone = RequestLayout(target, en);
    Check(!gone.posted && gone.postError == ERROR_INVALID_PARAMETER, "destroyed target not applied");
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc == 2 && wcscmp(argv[1], L"--elevated-report") == 0) {
        wchar_t path[32768]{};
        GetModuleFileNameW(nullptr, path, ARRAYSIZE(path));
        const std::wstring executable(path);
        const std::wstring report = executable.substr(0, executable.find_last_of(L"\\/")) +
            L"\\windows-elevated-results.txt";
        FILE* output = nullptr;
        if (_wfreopen_s(&output, report.c_str(), L"w", stdout) != 0) return 15;
        const auto elevation = ProcessElevation(GetCurrentProcessId());
        if (!elevation.known || !elevation.elevated) {
            std::printf("FAIL elevated suite requires actual elevated process\n");
            return 16;
        }
        std::printf("Elevated suite: current process elevated=true; fixtures inherit this token.\n");
    }
    if (argc == 5 && wcscmp(argv[1], L"--low-sender") == 0) {
        return LowSenderMain(reinterpret_cast<HANDLE>(wcstoull(argv[2], nullptr, 10)),
            reinterpret_cast<HANDLE>(wcstoull(argv[3], nullptr, 10)),
            reinterpret_cast<HANDLE>(wcstoull(argv[4], nullptr, 10)));
    }
    if (argc == 5 && wcscmp(argv[1], L"--fixture") == 0) {
        return FixtureMain(reinterpret_cast<HANDLE>(wcstoull(argv[2], nullptr, 10)),
            reinterpret_cast<HANDLE>(wcstoull(argv[3], nullptr, 10)),
            reinterpret_cast<HANDLE>(wcstoull(argv[4], nullptr, 10)));
    }
    const HDESK original = GetThreadDesktop(GetCurrentThreadId());
    const std::wstring name = L"CapsLangTests-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64());
    // No DESKTOP_SWITCHDESKTOP: even this handle cannot activate the test desktop.
    // Allow the low-integrity test child to JOIN this disposable desktop.
    // Its medium/high target windows retain their own UIPI protection. The
    // user's Default desktop and existing objects are never relabeled.
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"S:(ML;;NW;;;LW)",
            SDDL_REVISION_1, &descriptor, nullptr)) return 17;
    SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
    const HDESK desktop = CreateDesktopW(name.c_str(), nullptr, nullptr, 0,
        DESKTOP_CREATEWINDOW | DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS | DESKTOP_ENUMERATE, &security);
    LocalFree(descriptor);
    if (!desktop || !SetThreadDesktop(desktop)) {
        std::fprintf(stderr, "Cannot isolate tests; refusing to run: %lu\n", GetLastError());
        if (desktop) CloseDesktop(desktop);
        return 2;
    }
    const HRESULT com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (SUCCEEDED(com) && FindLayout(kEnglish) && FindLayout(kRussian)) Tests(name);
    else Check(false, "COM and installed EN/RU required; no layouts are installed by test");
    if (SUCCEEDED(com)) CoUninitialize();
    if (SetThreadDesktop(original)) CloseDesktop(desktop);
    std::printf("Windows layout integration: %u checks, %u failures; no input desktop switch.\n", checks, failures);
    return failures ? 1 : 0;
}
