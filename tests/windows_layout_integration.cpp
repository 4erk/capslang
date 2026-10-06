// Real Win32 cross-process tests on a private, never-activated desktop.
// No SendInput, device writes, foreground changes or legacy stop IPC. The
// separate MESSAGE_PROBE build hooks only its owned disposable fixture thread.
#include "../src/platform/windows_support.hpp"
#include <objbase.h>
#include <sddl.h>
#include <wct.h>
#include <cstdio>
#include <functional>
#include <string>
#include <vector>
#ifdef CAPSLANG_PROFILE_ENGINE
#include "../src/runtime/engine.hpp"
#include <mutex>
#endif
#ifdef CAPSLANG_MESSAGE_PROBE
#include "layout_message_probe.hpp"
#include "../src/runtime/profile_host.hpp"
#include "../src/runtime/profile_attachment.hpp"
#include <msctf.h>
#endif
#ifdef CAPSLANG_ENGINE_INTEGRATION
#include "../src/runtime/engine.hpp"
#include "../src/runtime/focus_target.hpp"
#include "../src/runtime/engine_host.hpp"
#include "../src/runtime/engine_client.hpp"
#include "../src/network/session.hpp"
#include "../src/network/lan.hpp"
#include "../src/platform/mwb.hpp"
#include "../src/runtime/local_ipc.hpp"
#include <atomic>
#include <mutex>
#include <thread>
#endif

using namespace capslang;
namespace {
constexpr UINT kReset = WM_APP + 1;
constexpr UINT kDestroy = WM_APP + 2;
#ifdef CAPSLANG_MESSAGE_PROBE
constexpr UINT kEnableTsf = WM_APP + 4;
constexpr UINT kQueryTsf = WM_APP + 5;
constexpr UINT kHostSelectLanguage = WM_APP + 6;
ITfThreadMgr* g_fixtureTsf = nullptr;
bool g_fixtureCom = false, g_fixtureActive = false;
#endif
struct Shared {
    HWND window;
    DWORD pid, tid;
    volatile LONG requests, changes, mode, resetCount;
    DWORD tokenError, postError, controlError, integrityRid;
    BOOL lowered, posted, controlPosted;
    volatile LONG handlingLayout;
    ULONGLONG layoutEntered, layoutReturned;
#ifdef CAPSLANG_MESSAGE_PROBE
    volatile LONG tsfResult = E_PENDING;
    volatile LONG managerPresent = -1;
    volatile LONG managerResult = E_PENDING;
    BOOL visibleFixture = FALSE;
#endif
};
Shared* g_shared = nullptr;
HKL g_pending = nullptr;
#ifdef CAPSLANG_PROFILE_ENGINE
std::mutex profileTargetMutex;
LayoutTarget profileTarget;
LayoutTarget CaptureProfileFixture() {
    std::lock_guard<std::mutex> guard(profileTargetMutex);
    return profileTarget;
}
void SelectProfileFixture(LayoutTarget target) {
    std::lock_guard<std::mutex> guard(profileTargetMutex);
    profileTarget = target;
}
#endif

LRESULT CALLBACK FixtureProc(HWND window, UINT message, WPARAM wp, LPARAM lp) {
    switch (message) {
    case kReset:
        KillTimer(window, 1);
        g_pending = nullptr;
        ActivateKeyboardLayout(FindLayout(kEnglish), 0);
        InterlockedIncrement(&g_shared->resetCount);
        return 0;
    case kDestroy: DestroyWindow(window); return 0;
#ifdef CAPSLANG_MESSAGE_PROBE
    case kHostSelectLanguage: {
        // Host-side change, deliberately outside the observer's own operation.
        // This tests provenance; it is not called a native-picker simulation.
        HRESULT result = E_INVALIDARG;
        if (wp == kEnglish || wp == kRussian) {
            ITfInputProcessorProfiles* profiles = nullptr;
            ITfInputProcessorProfileMgr* manager = nullptr;
            result = CoCreateInstance(CLSID_TF_InputProcessorProfiles, nullptr, CLSCTX_INPROC_SERVER,
                IID_ITfInputProcessorProfiles, reinterpret_cast<void**>(&profiles));
            if (SUCCEEDED(result)) result = profiles->QueryInterface(IID_ITfInputProcessorProfileMgr,
                reinterpret_cast<void**>(&manager));
            if (SUCCEEDED(result)) result = profiles->ChangeCurrentLanguage(static_cast<LANGID>(wp));
            if (SUCCEEDED(result)) result = manager->ActivateProfile(TF_PROFILETYPE_KEYBOARDLAYOUT,
                static_cast<LANGID>(wp), CLSID_NULL, GUID_NULL, FindLayout(static_cast<LANGID>(wp)), 0);
            if (SUCCEEDED(result) && !ActivateKeyboardLayout(FindLayout(static_cast<LANGID>(wp)), 0)) result = E_FAIL;
            if (manager) manager->Release();
            if (profiles) profiles->Release();
        }
        InterlockedExchange(&g_shared->tsfResult, result); return 0;
    }
    case kQueryTsf: {
        using GetManager = HRESULT (WINAPI*)(ITfThreadMgr**);
        const auto module = GetModuleHandleW(L"msctf.dll");
        const auto get = module ? reinterpret_cast<GetManager>(GetProcAddress(module, "TF_GetThreadMgr")) : nullptr;
        ITfThreadMgr* manager = nullptr;
        const HRESULT result = get ? get(&manager) : S_OK;
        const LONG present = SUCCEEDED(result) ? (manager ? 1 : 0) : -2;
        if (manager) manager->Release();
        InterlockedExchange(&g_shared->managerResult, result);
        InterlockedExchange(&g_shared->managerPresent, present);
        return 0;
    }
    case kEnableTsf: {
        if (g_fixtureTsf && g_fixtureActive) {
            InterlockedExchange(&g_shared->tsfResult, S_OK);
            return 0;
        }
        HRESULT result = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        g_fixtureCom = SUCCEEDED(result);
        if (SUCCEEDED(result)) result = CoCreateInstance(CLSID_TF_ThreadMgr, nullptr, CLSCTX_INPROC_SERVER,
            IID_ITfThreadMgr, reinterpret_cast<void**>(&g_fixtureTsf));
        if (SUCCEEDED(result)) {
            TfClientId client = 0;
            result = g_fixtureTsf->Activate(&client);
            g_fixtureActive = SUCCEEDED(result);
        }
        InterlockedExchange(&g_shared->tsfResult, result);
        return 0;
    }
#endif
    case WM_INPUTLANGCHANGEREQUEST:
        InterlockedIncrement(&g_shared->requests);
        if (InterlockedCompareExchange(&g_shared->mode, 0, 0) == 1) return 0;
        if (InterlockedCompareExchange(&g_shared->mode, 0, 0) == 2 ||
            (InterlockedCompareExchange(&g_shared->mode, 0, 0) == 3 && LOWORD(lp) == kRussian)) {
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
    if (message == WM_INPUTLANGCHANGEREQUEST) {
        g_shared->layoutEntered = GetTickCount64();
        InterlockedExchange(&g_shared->handlingLayout, 1);
        const auto result = DefWindowProcW(window, message, wp, lp);
        g_shared->layoutReturned = GetTickCount64();
        InterlockedExchange(&g_shared->handlingLayout, 0);
        return result;
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

#if defined(CAPSLANG_ENGINE_INTEGRATION) || defined(CAPSLANG_MESSAGE_PROBE)
// Read only our test fixture's wait chain on failure. Never collect object
// names, window titles or user input. Lack of debug privilege is reported.
void PrintFixtureWait(DWORD tid, DWORD otherFixture) {
    // LLVM-MinGW declares WCT APIs but omits these constants from the SDK.
    // microsoft/win32metadata: generation/WinSDK/RecompiledIdlHeaders/um/wct.h
    constexpr DWORD maxNodes = 16, outOfProcess = 0x1;
    HWCT session = OpenThreadWaitChainSession(0, nullptr);
    if (!session) { std::printf("Wait chain unavailable: %lu\n", GetLastError()); return; }
    WAITCHAIN_NODE_INFO nodes[maxNodes]{};
    DWORD count = maxNodes;
    BOOL cycle = FALSE;
    const bool ok = GetThreadWaitChain(session, 0, outOfProcess, tid, &count, nodes, &cycle) != FALSE;
    const DWORD error = ok ? 0 : GetLastError();
    std::printf("Fixture wait chain: ok=%d error=%lu cycle=%d nodes=%lu test_pid=%lu test_tid=%lu other_fixture_pid=%lu\n",
        ok, error, cycle, count, GetCurrentProcessId(), GetCurrentThreadId(), otherFixture);
    if (ok || error == ERROR_MORE_DATA || error == ERROR_TOO_MANY_THREADS) {
        for (DWORD i = 0; i < count && i < maxNodes; ++i) {
            std::printf("  node=%lu type=%u status=%u", i, static_cast<unsigned>(nodes[i].ObjectType),
                static_cast<unsigned>(nodes[i].ObjectStatus));
            if (nodes[i].ObjectType == WctThreadType)
                std::printf(" pid=%lu tid=%lu wait_ms=%lu", nodes[i].ThreadObject.ProcessId,
                    nodes[i].ThreadObject.ThreadId, nodes[i].ThreadObject.WaitTime);
            std::printf("\n");
        }
    }
    CloseThreadWaitChainSession(session);
}
#endif

struct FixtureSecurity {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    PSECURITY_DESCRIPTOR processDescriptor = nullptr;
    std::wstring sid;
    FixtureSecurity() {
        HANDLE token = nullptr;
        DWORD size = 0;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return;
        GetTokenInformation(token, TokenUser, nullptr, 0, &size);
        std::vector<BYTE> user(size);
        wchar_t* text = nullptr;
        if (size && GetTokenInformation(token, TokenUser, user.data(), size, &size) &&
            ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid, &text)) {
            sid = text; LocalFree(text);
            // Only this test's disposable objects: never Default desktop or a
            // production pipe. High-token default DACLs can grant only Admins,
            // a SID deliberately disabled in our low/medium test children.
            const std::wstring dacl = L"O:" + sid + L"G:SYD:P(A;;GA;;;SY)(A;;GA;;;" + sid + L")";
            ConvertStringSecurityDescriptorToSecurityDescriptorW(dacl.c_str(), SDDL_REVISION_1, &processDescriptor, nullptr);
            const std::wstring low = dacl + L"S:(ML;;NW;;;LW)";
            ConvertStringSecurityDescriptorToSecurityDescriptorW(low.c_str(), SDDL_REVISION_1, &descriptor, nullptr);
        }
        CloseHandle(token);
    }
    ~FixtureSecurity() {
        if (descriptor) LocalFree(descriptor);
        if (processDescriptor) LocalFree(processDescriptor);
    }
    FixtureSecurity(const FixtureSecurity&) = delete;
    FixtureSecurity& operator=(const FixtureSecurity&) = delete;
    bool SetTokenDefault(HANDLE token) const {
        BOOL present = FALSE, defaulted = FALSE;
        TOKEN_DEFAULT_DACL value{};
        return descriptor && GetSecurityDescriptorDacl(descriptor, &present, &value.DefaultDacl, &defaulted) && present &&
            SetTokenInformation(token, TokenDefaultDacl, &value, sizeof(value));
    }
};

int FixtureMain(HANDLE mapping, HANDLE ready, HANDLE stop) {
    g_shared = static_cast<Shared*>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(Shared)));
    if (!g_shared) return 10;
    WNDCLASSW wc{};
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = L"CapsLang.TestFixture.PrivateDesktop";
    wc.lpfnWndProc = FixtureProc;
    if (!RegisterClassW(&wc)) return 11;
    bool visible = false;
#ifdef CAPSLANG_MESSAGE_PROBE
    visible = g_shared->visibleFixture != FALSE;
#endif
    HWND window = CreateWindowW(wc.lpszClassName,
        visible ? L"CapsLang — тест смены языка (закроется через 3 минуты)" : L"Test fixture",
        visible ? WS_OVERLAPPEDWINDOW : WS_OVERLAPPED,
        visible ? CW_USEDEFAULT : 0, visible ? CW_USEDEFAULT : 0,
        visible ? 680 : 200, visible ? 220 : 100, nullptr, nullptr, wc.hInstance, nullptr);
    if (!window) return 12;
    ActivateKeyboardLayout(FindLayout(kEnglish), 0);
    g_shared->window = window;
    g_shared->pid = GetCurrentProcessId();
    g_shared->tid = GetCurrentThreadId();
    if (visible) {
        CreateWindowW(L"STATIC", L"Нажми на это окно. Через индикатор Windows выбери English, затем Русский.\n"
            L"Текст можно набрать ниже: он не сохраняется и не попадает в отчёт.",
            WS_CHILD | WS_VISIBLE, 12, 12, 635, 55, window, nullptr, wc.hInstance, nullptr);
        CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
            12, 85, 635, 35, window, nullptr, wc.hInstance, nullptr);
        // Showing our own test UI is not permission to steal another window's
        // focus. The user activates it explicitly for the coordinated test.
        ShowWindow(window, SW_SHOWNOACTIVATE);
    }
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
#ifdef CAPSLANG_MESSAGE_PROBE
    if (g_fixtureTsf && g_fixtureActive) g_fixtureTsf->Deactivate();
    if (g_fixtureTsf) g_fixtureTsf->Release();
    if (g_fixtureCom) CoUninitialize();
#endif
    UnmapViewOfFile(g_shared);
    CloseHandle(mapping); CloseHandle(ready); CloseHandle(stop);
    return 0;
}

HANDLE LowToken(DWORD integrity = SECURITY_MANDATORY_LOW_RID) {
    HANDLE source = nullptr, token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY |
            TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT, &source)) return nullptr;
    BYTE adminStorage[SECURITY_MAX_SID_SIZE]{};
    DWORD adminSize = sizeof(adminStorage);
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, adminStorage, &adminSize)) {
        CloseHandle(source); return nullptr;
    }
    SID_AND_ATTRIBUTES admin{adminStorage, 0};
    const bool restricted = CreateRestrictedToken(source, DISABLE_MAX_PRIVILEGE,
        1, &admin, 0, nullptr, 0, nullptr, &token) != FALSE;
    CloseHandle(source);
    if (!restricted) return nullptr;
    const FixtureSecurity security;
    if (!security.SetTokenDefault(token)) { CloseHandle(token); return nullptr; }
    PSID sid = nullptr;
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_MANDATORY_LABEL_AUTHORITY;
    if (!AllocateAndInitializeSid(&authority, 1, integrity, 0, 0, 0, 0, 0, 0, 0, &sid)) {
        CloseHandle(token); return nullptr;
    }
    TOKEN_MANDATORY_LABEL label{{sid, SE_GROUP_INTEGRITY}};
    const bool lowered = SetTokenInformation(token, TokenIntegrityLevel, &label,
        static_cast<DWORD>(sizeof(label) + GetLengthSid(sid))) != FALSE;
    FreeSid(sid);
    if (!lowered) { CloseHandle(token); return nullptr; }
    return token;
}

bool RestrictedDesktopAccess(PSECURITY_DESCRIPTOR descriptor, bool expected) {
    // Isolate the disabled-Admins DACL condition from mandatory integrity.
    // Actual low-integrity delivery is checked separately with real children.
    HANDLE primary = LowToken(SECURITY_MANDATORY_MEDIUM_RID), impersonation = nullptr;
    bool ok = primary && DuplicateToken(primary, SecurityImpersonation, &impersonation);
    if (ok) {
        GENERIC_MAPPING mapping{DESKTOP_READOBJECTS, DESKTOP_WRITEOBJECTS, DESKTOP_ENUMERATE, 0x01ff};
        BOOL present = FALSE, defaulted = FALSE;
        PACL source = nullptr;
        PSID owner = nullptr, group = nullptr;
        if (!GetSecurityDescriptorDacl(descriptor, &present, &source, &defaulted) || !present || !source ||
            !GetSecurityDescriptorOwner(descriptor, &owner, &defaulted) ||
            !GetSecurityDescriptorGroup(descriptor, &group, &defaulted)) {
            CloseHandle(primary); CloseHandle(impersonation); return false;
        }
        // Object creation normally maps generic ACE masks to object-specific
        // rights. This direct AccessCheck fixture must perform that step too.
        std::vector<BYTE> mapped(source->AclSize);
        CopyMemory(mapped.data(), source, mapped.size());
        auto* acl = reinterpret_cast<ACL*>(mapped.data());
        for (DWORD index = 0; index < acl->AceCount; ++index) {
            void* ace = nullptr;
            if (GetAce(acl, index, &ace) &&
                (static_cast<ACE_HEADER*>(ace)->AceType == ACCESS_ALLOWED_ACE_TYPE ||
                 static_cast<ACE_HEADER*>(ace)->AceType == ACCESS_DENIED_ACE_TYPE))
                MapGenericMask(&static_cast<ACCESS_ALLOWED_ACE*>(ace)->Mask, &mapping);
        }
        SECURITY_DESCRIPTOR checkDescriptor{};
        InitializeSecurityDescriptor(&checkDescriptor, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorOwner(&checkDescriptor, owner, FALSE);
        SetSecurityDescriptorGroup(&checkDescriptor, group, FALSE);
        SetSecurityDescriptorDacl(&checkDescriptor, TRUE, acl, FALSE);
        alignas(PRIVILEGE_SET) BYTE storage[1024]{};
        DWORD bytes = sizeof(storage), granted = 0;
        BOOL allowed = FALSE;
        ok = AccessCheck(&checkDescriptor, impersonation, DESKTOP_CREATEWINDOW, &mapping,
            reinterpret_cast<PRIVILEGE_SET*>(storage), &bytes, &granted, &allowed) && (allowed != FALSE) == expected;
    }
    if (primary) CloseHandle(primary);
    if (impersonation) CloseHandle(impersonation);
    return ok;
}

void DescribeTokenAcl(HANDLE token, const char* label) {
    DWORD bytes = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &bytes);
    std::vector<BYTE> user(bytes);
    if (!bytes || !GetTokenInformation(token, TokenUser, user.data(), bytes, &bytes)) {
        std::printf("Token ACL %s: user_error=%lu\n", label, GetLastError()); return;
    }
    GetTokenInformation(token, TokenDefaultDacl, nullptr, 0, &bytes);
    std::vector<BYTE> data(bytes);
    if (!bytes || !GetTokenInformation(token, TokenDefaultDacl, data.data(), bytes, &bytes)) {
        std::printf("Token ACL %s: acl_error=%lu\n", label, GetLastError()); return;
    }
    const auto acl = reinterpret_cast<TOKEN_DEFAULT_DACL*>(data.data())->DefaultDacl;
    DWORD userAllow = 0;
    for (DWORD i = 0; acl && i < acl->AceCount; ++i) {
        void* ace = nullptr;
        if (GetAce(acl, i, &ace) && static_cast<ACE_HEADER*>(ace)->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            auto* allow = static_cast<ACCESS_ALLOWED_ACE*>(ace);
            if (EqualSid(&allow->SidStart, reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid)) userAllow |= allow->Mask;
        }
    }
    SECURITY_DESCRIPTOR descriptor{};
    InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION);
    const auto sid = reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid;
    SetSecurityDescriptorOwner(&descriptor, sid, FALSE);
    SetSecurityDescriptorGroup(&descriptor, sid, FALSE);
    SetSecurityDescriptorDacl(&descriptor, TRUE, acl, FALSE);
    const bool allowed = RestrictedDesktopAccess(&descriptor, true);
    const bool denied = RestrictedDesktopAccess(&descriptor, false);
    std::printf("Token ACL %s: null=%d ace_count=%u explicit_current_user_allow=0x%08lx restricted_desktop_allowed=%d denied=%d\n",
        label, !acl, acl ? acl->AceCount : 0, userAllow, allowed, denied);
}

int TokenInventory() {
    HANDLE own = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &own)) return 1;
    DescribeTokenAcl(own, "own");
    TOKEN_LINKED_TOKEN linked{};
    DWORD bytes = 0;
    if (GetTokenInformation(own, TokenLinkedToken, &linked, sizeof(linked), &bytes)) {
        DescribeTokenAcl(linked.LinkedToken, "linked-query-only");
        CloseHandle(linked.LinkedToken);
    } else std::printf("Token linked query error=%lu\n", GetLastError());
    CloseHandle(own);
    return 0;
}
#ifdef CAPSLANG_ENGINE_INTEGRATION
int IpcClientMain(HANDLE mapping, HANDLE ready, HANDLE stop) {
    auto* data = static_cast<Shared*>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(Shared)));
    if (!data) return 21;
    HANDLE token = nullptr;
    alignas(TOKEN_MANDATORY_LABEL) BYTE storage[256]{};
    DWORD bytes = 0;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) &&
        GetTokenInformation(token, TokenIntegrityLevel, storage, sizeof(storage), &bytes)) {
        const auto* label = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(storage);
        const UCHAR count = *GetSidSubAuthorityCount(label->Label.Sid);
        data->integrityRid = count ? *GetSidSubAuthority(label->Label.Sid, count - 1) : 0;
    }
    if (token) CloseHandle(token);
    wchar_t executable[32768]{};
    GetModuleFileNameW(nullptr, executable, ARRAYSIZE(executable));
    const auto endpoint = ipc::Endpoint::Current(L"engine-test-" + std::to_wstring(data->pid));
    ipc::Request request{}; request.id = 1;
    ipc::Response response{};
    data->posted = ipc::Call(endpoint, executable, data->lowered, request, response, data->postError);
    data->controlError = response.error;
    SetEvent(ready);
    WaitForSingleObject(stop, 5000);
    UnmapViewOfFile(data);
    CloseHandle(mapping); CloseHandle(ready); CloseHandle(stop);
    return 0;
}
#endif

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
    bool Start(std::wstring desktop, const LayoutTarget* destination = nullptr, DWORD ipcIntegrity = 0,
               bool visibleFixture = false) {
        const FixtureSecurity security;
        if (!security.descriptor || !security.processDescriptor) { std::printf("Fixture security error=%lu\n", GetLastError()); return false; }
        SECURITY_ATTRIBUTES sa{sizeof(sa), security.descriptor, TRUE};
        mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0, sizeof(Shared), nullptr);
        ready = CreateEventW(&sa, TRUE, FALSE, nullptr);
        stop = CreateEventW(&sa, TRUE, FALSE, nullptr);
        if (!mapping || !ready || !stop) return false;
        data = static_cast<Shared*>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(Shared)));
        if (!data) return false;
        *data = {};
#ifdef CAPSLANG_MESSAGE_PROBE
        data->visibleFixture = visibleFixture;
#else
        (void)visibleFixture;
#endif
        if (destination) data->window = destination->focus;
        if (ipcIntegrity) {
            data->pid = GetCurrentProcessId();
            data->lowered = ProcessElevation(GetCurrentProcessId()).elevated;
        }
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
            (ipcIntegrity ? L"\" --ipc-client " : destination ? L"\" --low-sender " : L"\" --fixture ") +
            std::to_wstring(reinterpret_cast<ULONG_PTR>(mapping)) + L" " +
            std::to_wstring(reinterpret_cast<ULONG_PTR>(ready)) + L" " +
            std::to_wstring(reinterpret_cast<ULONG_PTR>(stop));
        PROCESS_INFORMATION child{};
        SECURITY_ATTRIBUTES childSecurity{sizeof(childSecurity), security.processDescriptor, FALSE};
        const bool restricted = destination || ipcIntegrity;
        HANDLE lowToken = restricted ? LowToken(ipcIntegrity ? ipcIntegrity : SECURITY_MANDATORY_LOW_RID) : nullptr;
        constexpr DWORD flags = CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT;
        const bool created = attributes && (restricted
            ? lowToken && CreateProcessAsUserW(lowToken, path, command.data(), &childSecurity, &childSecurity, TRUE,
                flags, nullptr, nullptr, &startup.StartupInfo, &child)
            : CreateProcessW(path, command.data(), &childSecurity, &childSecurity, TRUE,
                flags, nullptr, nullptr, &startup.StartupInfo, &child));
        const DWORD createError = created ? 0 : GetLastError();
        if (lowToken) CloseHandle(lowToken);
        DeleteProcThreadAttributeList(startup.lpAttributeList);
        if (!created) { std::printf("Create fixture error=%lu\n", createError); return false; }
        process = child.hProcess;
        const bool assigned = AssignProcessToJobObject(job, process) != FALSE;
        const DWORD assignError = assigned ? 0 : GetLastError();
        if (assigned) {
            if (ResumeThread(child.hThread) == static_cast<DWORD>(-1)) {
                std::printf("Resume fixture error=%lu\n", GetLastError());
                CloseHandle(child.hThread); return false;
            }
        } else TerminateProcess(process, 13); // Only our not-yet-started test child.
        CloseHandle(child.hThread);
        if (!assigned) { std::printf("Assign fixture job error=%lu\n", assignError); return false; }
        HANDLE waits[]{ready, process};
        const DWORD waited = WaitForMultipleObjects(2, waits, FALSE, 5000);
        if (waited != WAIT_OBJECT_0) {
            DWORD exitCode = 0;
            GetExitCodeProcess(process, &exitCode);
            std::printf("Fixture startup: wait=%lu exit=0x%08lx restricted=%d requested_rid=%lu\n",
                waited, exitCode, restricted, ipcIntegrity ? ipcIntegrity : SECURITY_MANDATORY_LOW_RID);
        }
        return waited == WAIT_OBJECT_0;
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
    static const ULONGLONG began = GetTickCount64();
    ++checks;
    if (!ok) ++failures;
    std::printf("%s %s [elapsed=%llu ms]\n", ok ? "PASS" : "FAIL", name,
                static_cast<unsigned long long>(GetTickCount64() - began));
    std::fflush(stdout);
}

#ifdef CAPSLANG_MESSAGE_PROBE
void MessageObservationTests(const std::wstring& desktop, bool interactive = false) {
    // Only a thread of this test's owned child on the private inactive desktop.
    // There is intentionally no "attach to foreground" or global-hook mode.
    Fixture fixture;
    if (!fixture.Start(desktop, nullptr, 0, interactive)) { Check(false, "message probe fixture starts"); return; }
    const auto managerPresent = [&] {
        InterlockedExchange(&fixture.data->managerPresent, -1);
        if (!PostMessageW(fixture.data->window, kQueryTsf, 0, 0) || !PumpUntil([&] {
            return InterlockedCompareExchange(&fixture.data->managerPresent, 0, 0) != -1;
        })) return LONG(-3);
        return InterlockedCompareExchange(&fixture.data->managerPresent, 0, 0);
    };
    const LONG hostManagerBefore = managerPresent();
    const auto managerResult = fixture.data->managerResult;
    Check(hostManagerBefore >= 0 || (hostManagerBefore == -2 && FAILED(managerResult)),
        "host TSF lookup returns an explicit result without creating a client");
    std::printf("Host TSF lookup before initialization: presence=%ld hr=0x%08lx\n",
        hostManagerBefore, static_cast<unsigned long>(managerResult));
    wchar_t executable[32768]{}; GetModuleFileNameW(nullptr, executable, ARRAYSIZE(executable));
    const std::wstring path(executable);
    const auto dll = path.substr(0, path.find_last_of(L"\\/")) + L"\\layout_message_probe.dll";
    HMODULE module = LoadLibraryExW(dll.c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    Check(module != nullptr, "test observer DLL loads from exact test output directory");
    if (!module) return;
    const FixtureSecurity security;
    SECURITY_ATTRIBUTES sa{sizeof(sa), security.processDescriptor, FALSE};
    HANDLE mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0,
        sizeof(test::LayoutMessageProbe), test::ProbeName(fixture.data->pid).c_str());
    const DWORD created = GetLastError();
    auto* data = mapping && created != ERROR_ALREADY_EXISTS ?
        static_cast<test::LayoutMessageProbe*>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(test::LayoutMessageProbe))) : nullptr;
    Check(data != nullptr, "fresh fixture-only observation page created");
    if (!data) { if (mapping) CloseHandle(mapping); FreeLibrary(module); return; }
    *data = {};
    data->process = fixture.data->pid; data->thread = fixture.data->tid;
    const auto queuedProc = reinterpret_cast<HOOKPROC>(GetProcAddress(module, "ObserveQueued"));
    const auto returnedProc = reinterpret_cast<HOOKPROC>(GetProcAddress(module, "ObserveReturned"));
    HHOOK queuedHook = queuedProc ? SetWindowsHookExW(WH_GETMESSAGE, queuedProc, module, fixture.data->tid) : nullptr;
    HHOOK returnedHook = returnedProc ? SetWindowsHookExW(WH_CALLWNDPROCRET, returnedProc, module, fixture.data->tid) : nullptr;
    Check(queuedHook && returnedHook, "both hooks attach only to the owned private fixture thread");
    if (queuedHook && returnedHook) {
        PostThreadMessageW(fixture.data->tid, WM_APP + 50, 0, 0);
        Check(PumpUntil([&] { return data->profileError != E_PENDING; }) &&
            (hostManagerBefore == 1 ? data->profileError == S_OK : hostManagerBefore == 0 ?
                data->profileError == HRESULT_FROM_WIN32(ERROR_NOT_READY) :
                hostManagerBefore == -2 && data->profileError == managerResult),
            "first subscription respects the host's existing TSF readiness");
        Check(managerPresent() == hostManagerBefore, "observer does not create a TSF manager in the target");
        Check(PostMessageW(fixture.data->window, kEnableTsf, 0, 0) && PumpUntil([&] {
            return fixture.data->tsfResult != E_PENDING;
        }) && fixture.data->tsfResult == S_OK, "fixture explicitly initializes its own TSF client");
        InterlockedExchange(&data->profileError, E_PENDING);
        PostThreadMessageW(fixture.data->tid, WM_APP + 50, 0, 0);
        const bool initialized = PumpUntil([&] { return data->profileError != E_PENDING; }) && data->profileError == S_OK;
        Check(initialized,
            "profile sink binds or retries after the host initializes TSF");
        std::printf("Probe initial host TSF manager: %ld; final subscription: 0x%08lx\n",
            hostManagerBefore, static_cast<unsigned long>(data->profileError));
        if (!initialized) {
            std::printf("Probe initialization failure: stage=%ld hr=0x%08lx\n",
                data->initializationStage, static_cast<unsigned long>(data->profileError));
            PrintFixtureWait(fixture.data->tid, 0);
        }
        if (!interactive && initialized) {
            // Windows can create a manager implicitly even in a plain window.
            // Exercise the not-ready retry deterministically, without claiming
            // that this host naturally had a late-initializing TSF client.
            const auto before = fixture.data->resetCount;
            Check(PostThreadMessageW(fixture.data->tid, WM_APP + 51, 0, 0) &&
                PostMessageW(fixture.data->window, kReset, 0, 0) && PumpUntil([&] {
                    return fixture.data->resetCount != before;
                }), "observer detaches on its target thread before fault injection");
            InterlockedExchange(&data->simulateMissingManagerOnce, 1);
            InterlockedExchange(&data->profileError, E_PENDING);
            Check(PostThreadMessageW(fixture.data->tid, WM_APP + 50, 0, 0) && PumpUntil([&] {
                return data->profileError != E_PENDING;
            }) && data->profileError == HRESULT_FROM_WIN32(ERROR_NOT_READY),
                "injected missing-manager result is reported, not an observation success");
            Check(managerPresent() == 1, "failed observer lookup leaves the host's manager intact");
            InterlockedExchange(&data->profileError, E_PENDING);
            Check(PostThreadMessageW(fixture.data->tid, WM_APP + 50, 0, 0) && PumpUntil([&] {
                return data->profileError != E_PENDING;
            }) && data->profileError == S_OK, "subscription retries successfully after transient lookup failure");
        }
    }
    if (queuedHook && returnedHook && interactive) {
        PostMessageW(fixture.data->window, kEnableTsf, 0, 0);
        Check(PumpUntil([&] { return fixture.data->tsfResult != E_PENDING; }) && fixture.data->tsfResult == S_OK,
            "interactive owned fixture activates TSF");
        std::printf("{\"event\":\"interactive_ready\",\"seconds\":180,\"observer_only\":true}\n");
        std::fflush(stdout);
        const auto began = GetTickCount64();
        LONG queued = -1, returned = -1, changed = -1, profiles = -1; LANGID actual = 0;
        while (TargetStillValid(fixture.Target()) && GetTickCount64() - began < 180000) {
            const LONG nextQueued = InterlockedCompareExchange(&data->queued, 0, 0);
            const LONG nextReturned = InterlockedCompareExchange(&data->returned, 0, 0);
            const LANGID nextActual = TargetLanguage(fixture.Target());
            const LONG nextChanged = InterlockedCompareExchange(&data->changed, 0, 0);
            const LONG nextProfiles = InterlockedCompareExchange(&data->profileNotifications, 0, 0);
            if (nextQueued != queued || nextReturned != returned || nextActual != actual ||
                nextChanged != changed || nextProfiles != profiles) {
                std::printf("{\"event\":\"message_sample\",\"elapsed_ms\":%llu,\"queued\":%ld,"
                    "\"requested_language\":%ld,\"returned\":%ld,\"actual\":%u,"
                    "\"changed\":%ld,\"changed_language\":%ld,\"profile_notifications\":%ld,\"profile_language\":%ld}\n",
                    static_cast<unsigned long long>(GetTickCount64()-began), nextQueued,
                    data->queuedLanguage, nextReturned, nextActual, nextChanged, data->changedLanguage,
                    nextProfiles, data->profileLanguage);
                std::fflush(stdout);
                queued = nextQueued; returned = nextReturned; actual = nextActual;
                changed = nextChanged; profiles = nextProfiles;
            }
            PumpUntil([] { return false; }, 50);
        }
        std::printf("{\"event\":\"interactive_complete\",\"acceptance_verified\":false}\n");
    } else if (queuedHook && returnedHook) {
        const auto target = fixture.Target();
        const auto ru = FindLayout(kRussian), en = FindLayout(kEnglish);
        const auto queuedCount = [&] { return InterlockedCompareExchange(&data->queued, 0, 0); };
        const auto returnedCount = [&] { return InterlockedCompareExchange(&data->returned, 0, 0); };
        Check(PostMessageW(target.focus, WM_INPUTLANGCHANGEREQUEST, 0, reinterpret_cast<LPARAM>(ru)) &&
            PumpUntil([&] { return queuedCount() == 1 && TargetLanguage(target) == kRussian; }),
            "posted external request is observed and actually applies RU");
        Check(data->queuedLanguage == kRussian, "posted intent carries absolute RU, not an inferred toggle");
        Check(data->changed > 0 && data->changedLanguage == kRussian,
            "target-thread observer sees completed input-language notification");
        const auto before = returnedCount();
        DWORD_PTR result = 0;
        const bool sent = SendMessageTimeoutW(target.focus, WM_INPUTLANGCHANGEREQUEST, 0,
            reinterpret_cast<LPARAM>(en), SMTO_ABORTIFHUNG | SMTO_ERRORONEXIT, 500, &result) != 0;
        Check(sent && PumpUntil([&] { return returnedCount() > before && TargetLanguage(target) == kEnglish; }),
            "bounded own send applies EN and completes on target thread");
        Check(queuedCount() == 1 && data->returnedLanguage == kEnglish,
            "own synchronous request is not reclassified as posted manual intent");
        Check(fixture.Reset(1), "rejecting message probe fixture ready");
        Check(PostMessageW(target.focus, WM_INPUTLANGCHANGEREQUEST, 0, reinterpret_cast<LPARAM>(ru)) &&
            PumpUntil([&] { return queuedCount() == 2; }) && TargetLanguage(target) == kEnglish,
            "rejected external intent remains observable but is not application success");
        Check(fixture.Reset(2), "delayed message probe fixture ready");
        Check(PostMessageW(target.focus, WM_INPUTLANGCHANGEREQUEST, 0, reinterpret_cast<LPARAM>(ru)) &&
            PumpUntil([&] { return queuedCount() == 3; }) && TargetLanguage(target) == kEnglish,
            "external intent arrives before asynchronous application");
        Check(PumpUntil([&] { return TargetLanguage(target) == kRussian; }),
            "delayed external application is verified separately from intent");
        Check(fixture.Reset(0), "normal message probe fixture restored");
        const auto prior = queuedCount();
        {
            // Directly measure whether our session-wide TSF calls themselves
            // produce queued request messages on the foreign target.
            const HRESULT com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
            ITfInputProcessorProfiles* profiles = nullptr;
            ITfInputProcessorProfileMgr* manager = nullptr;
            const HRESULT made = CoCreateInstance(CLSID_TF_InputProcessorProfiles, nullptr, CLSCTX_INPROC_SERVER,
                IID_ITfInputProcessorProfiles, reinterpret_cast<void**>(&profiles));
            HRESULT changed = E_FAIL, applied = E_FAIL;
            if (SUCCEEDED(made) && SUCCEEDED(profiles->QueryInterface(IID_ITfInputProcessorProfileMgr,
                reinterpret_cast<void**>(&manager)))) {
                changed = profiles->ChangeCurrentLanguage(kRussian);
                applied = manager->ActivateProfile(TF_PROFILETYPE_KEYBOARDLAYOUT, kRussian,
                    CLSID_NULL, GUID_NULL, ru, 0x20000000);
            }
            if (manager) manager->Release();
            if (profiles) profiles->Release();
            if (SUCCEEDED(com)) CoUninitialize();
            Check(SUCCEEDED(changed) && SUCCEEDED(applied), "TSF-origin observation exercise really executed");
        }
        PumpUntil([] { return false; }, 400);
        Check(queuedCount() == prior, "own TSF calls did not manufacture posted external intent in this fixture");
        // Match a modern text client's TSF participation, rather than proving
        // the observer only in a plain Win32 window without a thread manager.
        InterlockedExchange(&fixture.data->tsfResult, E_PENDING);
        Check(PostMessageW(target.focus, kEnableTsf, 0, 0) && PumpUntil([&] {
            return InterlockedCompareExchange(&fixture.data->tsfResult, 0, 0) != E_PENDING;
        }) && fixture.data->tsfResult == S_OK, "foreign fixture activates its own TSF text client");
        Check(fixture.Reset(0), "active TSF fixture starts at EN");
        const auto activeBefore = queuedCount();
        Check(PostMessageW(target.focus, WM_INPUTLANGCHANGEREQUEST, 0, reinterpret_cast<LPARAM>(ru)) &&
            PumpUntil([&] { return queuedCount() == activeBefore + 1 && TargetLanguage(target) == kRussian; }),
            "posted RU selection remains observable in an active TSF client");
        Check(SendMessageTimeoutW(target.focus, WM_INPUTLANGCHANGEREQUEST, 0,
            reinterpret_cast<LPARAM>(en), SMTO_ABORTIFHUNG | SMTO_ERRORONEXIT, 500, &result) &&
            TargetLanguage(target) == kEnglish && queuedCount() == activeBefore + 1,
            "own synchronous EN remains distinct in an active TSF client");
        // Deterministic deferred own completion: the externally posted EN
        // choice must survive even though the old RU completes later. The
        // classifier gets an event for EN, and none for the stale own RU.
        Check(fixture.Reset(3), "fixture delays only an own RU command");
        const auto delayedBefore = queuedCount();
        Check(SendMessageTimeoutW(target.focus, WM_INPUTLANGCHANGEREQUEST, 0,
            reinterpret_cast<LPARAM>(ru), SMTO_ABORTIFHUNG | SMTO_ERRORONEXIT, 500, &result) &&
            TargetLanguage(target) == kEnglish, "own RU is accepted but not yet applied");
        Check(PostMessageW(target.focus, WM_INPUTLANGCHANGEREQUEST, 0, reinterpret_cast<LPARAM>(en)) &&
            PumpUntil([&] { return queuedCount() == delayedBefore + 1; }) && data->queuedLanguage == kEnglish,
            "explicit EN choice is observed even when HKL did not change");
        Check(PumpUntil([&] { return TargetLanguage(target) == kRussian; }) &&
            queuedCount() == delayedBefore + 1 && data->queuedLanguage == kEnglish,
            "late own RU completion cannot fabricate another explicit choice");
        const auto externalBefore = InterlockedCompareExchange(&data->externalProfiles, 0, 0);
        const auto ownBefore = InterlockedCompareExchange(&data->ownProfiles, 0, 0);
        for (int i = 0; i < 20; ++i) {
            const LONG language = i % 2 ? kRussian : kEnglish;
            InterlockedExchange(&data->commandLanguage, language);
            InterlockedExchange64(&data->commandGeneration, i + 1);
            InterlockedExchange(&data->commandResult, E_PENDING);
            Check(PostThreadMessageW(fixture.data->tid, WM_APP + 52, 0, 0) &&
                PumpUntil([&] { return data->commandResult != E_PENDING; }) && data->commandResult == S_OK &&
                data->commandProfile == language && data->confirmedGeneration == i + 1 && TargetLanguage(target) == language,
                "in-thread absolute operation confirms both actual HKL and target-local TSF profile");
        }
        PumpUntil([] { return false; }, 400); // Detect any delayed callback echoes too.
        std::printf("Probe origin counts: own_before=%ld own_after=%ld external_before=%ld external_after=%ld\n",
            ownBefore, data->ownProfiles, externalBefore, data->externalProfiles);
        Check(data->ownProfiles > ownBefore && data->externalProfiles == externalBefore,
            "own in-thread operations do not become external profile changes, including delayed callbacks");
        const auto apply = [&](LONG language, LONG64 generation) {
            InterlockedExchange(&data->commandLanguage, language);
            InterlockedExchange64(&data->commandGeneration, generation);
            InterlockedExchange(&data->commandResult, E_PENDING);
            return PostThreadMessageW(fixture.data->tid, WM_APP + 52, 0, 0) && PumpUntil([&] {
                return data->commandResult != E_PENDING;
            });
        };
        Check(data->lastOwnGeneration == 20, "own callback carries the producing request's generation");
        InterlockedExchange(&data->reenterLanguage, kRussian);
        InterlockedExchange64(&data->reenterGeneration, 22);
        Check(apply(kEnglish, 21) && data->commandResult == HRESULT_FROM_WIN32(ERROR_RETRY) &&
            data->reenterResult == HRESULT_FROM_WIN32(ERROR_RETRY) && data->confirmedGeneration == 0,
            "new command during the real TSF callback cancels old confirmation without recursive apply");
        Check(apply(kEnglish, 21) && data->commandResult == HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH),
            "superseded generation cannot apply later");
        Check(apply(kRussian, 22) && data->commandResult == S_OK && data->confirmedGeneration == 22 &&
            data->commandProfile == kRussian && TargetLanguage(target) == kRussian,
            "new command applies after reentrant cancellation and confirms the new generation");
        Check(apply(kEnglish, 22) && data->commandResult == HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH) &&
            TargetLanguage(target) == kRussian, "same generation cannot be reused for a different language");
        Check(apply(kRussian, 22) && data->commandResult == S_OK && data->confirmedGeneration == 22,
            "identical delivery is idempotent");
        Check(apply(0x0407, 23) && data->commandResult == E_INVALIDARG && TargetLanguage(target) == kRussian,
            "unsupported language is rejected without affecting the target");
        Check(apply(kEnglish, 0) && data->commandResult == E_INVALIDARG && TargetLanguage(target) == kRussian,
            "zero generation is rejected without affecting the target");
        const auto externalAtApply = data->externalProfiles;
        InterlockedExchange(&fixture.data->tsfResult, E_PENDING);
        Check(PostMessageW(target.focus, kHostSelectLanguage, kEnglish, 0) && PumpUntil([&] {
            return fixture.data->tsfResult != E_PENDING;
        }) && fixture.data->tsfResult == S_OK && data->externalProfiles > externalAtApply &&
            TargetLanguage(target) == kEnglish, "immediate host language change is observed without a suppression timer");
        InterlockedExchange(&data->commandResult, E_PENDING);
        Check(PostThreadMessageW(fixture.data->tid, WM_APP + 53, 0, 0) && PumpUntil([&] {
            return data->commandResult != E_PENDING;
        }) && data->commandResult == S_OK && data->commandProfile == kEnglish && !data->confirmedGeneration,
            "external change revokes the old application confirmation");
        Check(apply(kRussian, 22) && data->commandResult == HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH) &&
            TargetLanguage(target) == kEnglish, "old retry cannot overwrite a subsequent host language choice");
        Check(apply(kEnglish, 23) && data->commandResult == S_OK && data->confirmedGeneration == 23,
            "controller can acknowledge the observed language with a fresh generation");
        // Now exercise the actual module -> queue -> authenticated local IPC
        // -> host -> command -> target-thread API chain, not shared-page Apply.
        const auto resetBefore = fixture.data->resetCount;
        Check(PostThreadMessageW(fixture.data->tid, WM_APP + 51, 0, 0) &&
            PostMessageW(target.focus, kReset, 0, 0) && PumpUntil([&] {
                return fixture.data->resetCount != resetBefore;
            }), "legacy test observer detached before secure-channel exercise");
        ProfileHost host(fixture.data->pid, fixture.data->tid);
        Check(host.Start(), "real module host pins the foreign fixture's process incarnation");
        const auto endpoint = host.Endpoint();
        data->serverProcess = endpoint.serverProcess.id;
        InterlockedExchange64(&data->serverCreated, static_cast<LONG64>(endpoint.serverProcess.created));
        InterlockedExchange64(&data->channelBinding, static_cast<LONG64>(host.Binding()));
        InterlockedExchange(&data->peerStatus, E_PENDING);
        Check(PostThreadMessageW(fixture.data->tid, WM_APP + 54, 0, 0) && PumpUntil([&] {
            return data->peerStatus != E_PENDING;
        }) && data->peerStatus == S_OK, "module starts private IPC worker without UI-thread network waits");
        Check(PumpUntil([&] {
            const auto state = host.Take();
            return state.sampled && !state.error && !state.confirmed && state.report.actual == kEnglish;
        }, 3000), "real UI-thread read crosses authenticated channel without fake application success");
        Check(host.Request(kRussian, 1) && PumpUntil([&] {
            return host.Take().confirmed && TargetLanguage(target) == kRussian;
        }, 3000), "absolute RU applies through real module IPC and both target states confirm");
        InterlockedExchange(&fixture.data->tsfResult, E_PENDING);
        bool sawExternalEnglish = false;
        Check(PostMessageW(target.focus, kHostSelectLanguage, kEnglish, 0) && PumpUntil([&] {
            const auto state = host.Take();
            for (std::size_t i = 0; i < state.count; ++i)
                if (state.events[i].cause == profile_channel::Cause::Observed && state.events[i].language == kEnglish)
                    sawExternalEnglish = true;
            return sawExternalEnglish && state.report.actual == kEnglish && !state.confirmed;
        }, 3000), "genuine external TSF event crosses the worker/channel and revokes peer confirmation");
        Check(host.Request(kEnglish, 2) && PumpUntil([&] { return host.Take().confirmed; }, 3000),
            "controller adopts the new explicit target through the same secure channel");
        Check(host.Detach() && PumpUntil([&] { return data->peerDetached != 0; }, 3000),
            "cooperative detach unsubscribes inside target thread without waiting in its hook");
        host.Stop();
        Check(PostThreadMessageW(fixture.data->tid, WM_APP + 56, 0, 0), "test bridge cleanup queued");
    }
    if (queuedHook) {
        PostThreadMessageW(fixture.data->tid, WM_APP + 51, 0, 0);
        // Barrier through the same target queue before unloading the test DLL.
        const auto before = fixture.data->resetCount;
        PostMessageW(fixture.data->window, kReset, 0, 0);
        PumpUntil([&] { return fixture.data->resetCount != before; });
        Check(UnhookWindowsHookEx(queuedHook) != FALSE, "queued observer detached");
    }
    if (returnedHook) Check(UnhookWindowsHookEx(returnedHook) != FALSE, "returned observer detached");
    if (!interactive) {
        const auto target = fixture.Target();
        wchar_t executable[32768]{};
        GetModuleFileNameW(nullptr, executable, ARRAYSIZE(executable));
        const auto image = std::wstring(executable);
        const auto productionModule = image.substr(0, image.find_last_of(L'\\')) + L"\\profile_module_test.dll";
        ProfileAttachment denied(fixture.data->pid, fixture.data->tid);
        Check(!denied.Start(productionModule + L".other") && denied.Error() == ERROR_ACCESS_DENIED,
            "attachment refuses a module outside its trusted path policy");
        ProfileAttachment attachment(fixture.data->pid, fixture.data->tid);
        Check(attachment.Start(productionModule), "production hook owner attaches without the test mapping or command messages");
        Check(PumpUntil([&] { return !attachment.Take().error; }, 3000),
            "production module authenticates its fixed server and reports a real UI-thread read");
        Check(attachment.Request(kRussian, 1) && PumpUntil([&] {
            const auto state = attachment.Take();
            return state.confirmed && state.report.actual == kRussian && state.report.profile == kRussian;
        }, 3000), "production attachment applies RU and confirms both target states");
        bool observedEnglish = false;
        Check(PostMessageW(target.focus, kHostSelectLanguage, kEnglish, 0) && PumpUntil([&] {
            const auto state = attachment.Take();
            for (std::size_t i = 0; i < state.count; ++i)
                if (state.events[i].cause == profile_channel::Cause::Observed && state.events[i].language == kEnglish)
                    observedEnglish = true;
            return observedEnglish && !state.confirmed && state.report.actual == kEnglish;
        }, 3000), "production attachment delivers external change without classifying its own application as manual");
        // Remove endpoint and hook without a cooperative detach command. Only
        // the DLL's own timer can release the old subscription now.
        attachment.Stop();
        Check(!attachment.Take().confirmed, "closed owner immediately revokes confirmation");
        ProfileAttachment replacement(fixture.data->pid, fixture.data->tid);
        Check(replacement.Start(productionModule) && replacement.Request(kRussian, 1) && PumpUntil([&] {
            return replacement.Take().confirmed && TargetLanguage(target) == kRussian;
        }, 4000), "owner-loss timer releases old peer and replacement binding works in the same live application");
        replacement.Stop();
#ifdef CAPSLANG_PROFILE_ENGINE
        SelectProfileFixture(target);
        EngineOptions options;
        options.capture = CaptureProfileFixture;
        options.profileModule = productionModule;
        Engine engine(options);
        Check(engine.Start(), "actual engine starts with module-backed profile controller");
        const auto applied = [&](core::Language language) {
            const auto state = engine.Status();
            return state.target == language && state.actual == language && state.profileConfirmed &&
                state.profileLanguage == static_cast<LANGID>(language) && state.apply == core::ApplyState::Applied;
        };
        Check(engine.SetTarget(core::Language::English) && PumpUntil([&] { return applied(core::Language::English); }, 4000),
            "engine -> authenticated module -> real target confirms absolute EN without broker TSF");
        const auto revision = engine.Status().userRevision;
        Check(PostMessageW(target.focus, kHostSelectLanguage, kRussian, 0) && PumpUntil([&] {
            return applied(core::Language::Russian) && engine.Status().userRevision == revision + 1;
        }, 3000), "engine adopts immediate external RU without the legacy suppression interval");
        Check(PostMessageW(target.focus, kHostSelectLanguage, kEnglish, 0) && PumpUntil([&] {
            return applied(core::Language::English) && engine.Status().userRevision == revision + 2;
        }, 3000), "second immediate external change creates one new intent, not an echo loop");
        const auto beforeRapid = engine.Status().generation;
        Check(engine.SetTarget(core::Language::Russian) && engine.SetTarget(core::Language::English) && PumpUntil([&] {
            return engine.Status().generation >= beforeRapid + 2 && applied(core::Language::English) &&
                engine.Status().userRevision == revision + 2;
        }, 3000), "rapid absolute requests finish at latest EN without inventing manual revisions");
        Check(!engine.ProfileReport(kRussian, engine.Status().generation, 0, true),
            "obsolete broker profile reports cannot compete with target-thread controller");
        SelectProfileFixture({});
        Check(PumpUntil([&] { return engine.Status().apply != core::ApplyState::Applied && !engine.Status().profileConfirmed; }),
            "missing target revokes profile success instead of retaining stale synchronization");
        InterlockedExchange(&fixture.data->tsfResult, E_PENDING);
        Check(PostMessageW(target.focus, kHostSelectLanguage, kRussian, 0) && PumpUntil([&] {
            return fixture.data->tsfResult == S_OK;
        }), "inactive test window remembers a different language");
        SelectProfileFixture(target);
        Check(PumpUntil([&] {
            return applied(core::Language::English) && engine.Status().userRevision == revision + 2;
        }, 4000), "returning focus reapplies shared EN, remembered RU is not a user choice");
        engine.Stop();
        SelectProfileFixture({});
#endif
    }
    // End the owned child before unloading the module/mapping: no callback can
    // retain a stale observation page after teardown.
    SetEvent(fixture.stop);
    Check(WaitForSingleObject(fixture.process, 2000) == WAIT_OBJECT_0, "observed fixture exits cleanly");
    UnmapViewOfFile(data); CloseHandle(mapping); FreeLibrary(module);
}
#endif

void Tests(const std::wstring& desktop) {
    LayoutApplier applier;
    {
        const FixtureSecurity security;
        PSECURITY_DESCRIPTOR adminDefault = nullptr;
        const auto dacl = L"O:" + security.sid + L"G:SYD:P(A;;GA;;;BA)(A;;GA;;;SY)(A;;GR;;;BU)";
        const bool made = ConvertStringSecurityDescriptorToSecurityDescriptorW(dacl.c_str(), SDDL_REVISION_1, &adminDefault, nullptr);
        Check(made && RestrictedDesktopAccess(adminDefault, false) && RestrictedDesktopAccess(security.processDescriptor, true),
              "Admin-only default DACL denies restricted child; explicit test-user ACL permits it");
        if (adminDefault) LocalFree(adminDefault);
    }
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
    ULONGLONG slowest = 0;
    for (int i = 0; i < 20; ++i) {
        const HKL desired = i % 2 == 0 ? ru : en;
        const auto requestStart = GetTickCount64();
        const auto result = applier.Request(target, desired);
        slowest = (std::max)(slowest, GetTickCount64() - requestStart);
        if (result.threadMs + result.changeMs + result.profileMs + result.cleanupMs > 100) {
            std::printf("Slow layout stage: thread=%llu change=%llu profile=%llu cleanup=%llu ms\n",
                static_cast<unsigned long long>(result.threadMs), static_cast<unsigned long long>(result.changeMs),
                static_cast<unsigned long long>(result.profileMs), static_cast<unsigned long long>(result.cleanupMs));
        }
        const bool verified = PumpUntil([&] {
            return TargetLanguage(target) == LOWORD(reinterpret_cast<ULONG_PTR>(desired));
        });
        if (i == 0 || !verified) {
            std::printf("layout request: thread_hr=0x%08lx change_hr=0x%08lx profile_hr=0x%08lx posted=%d error=%lu actual=%04x\n",
                static_cast<unsigned long>(result.threadManager), static_cast<unsigned long>(result.changeLanguage),
                static_cast<unsigned long>(result.activateProfile), result.posted, result.postError, TargetLanguage(target));
        }
        Check(result.posted && verified, "absolute language reaches real foreign window");
        Check(result.threadManager == S_OK && result.changeLanguage == S_OK && result.activateProfile == S_OK,
              "TSF manager, language change and session profile succeed (not WM-only fallback)");
    }
    Check(slowest < 1000, "steady layout application avoids repeated TSF activation stalls");
    applier.Request(target, en);
    Check(PumpUntil([&] { return TargetLanguage(target) == kEnglish; }), "repeated EN does not toggle");
    auto wrong = target;
    wrong.processId = GetCurrentProcessId();
    const auto invalid = applier.Request(wrong, ru);
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
    const auto gone = applier.Request(target, en);
    Check(!gone.posted && gone.postError == ERROR_INVALID_PARAMETER, "destroyed target not applied");
}
#ifdef CAPSLANG_ENGINE_INTEGRATION
std::atomic<HWND> capturedWindow{nullptr};
LayoutTarget CaptureFixture() {
    const HWND window = capturedWindow.load();
    DWORD pid = 0;
    const DWORD tid = GetWindowThreadProcessId(window, &pid);
    return {window, window, pid, tid, GetKeyboardLayout(tid)};
}
HWND EngineRawSink(USHORT usage = 6) {
    UINT count = 0;
    if (GetRegisteredRawInputDevices(nullptr, &count, sizeof(RAWINPUTDEVICE)) != 0 || !count) return nullptr;
    std::vector<RAWINPUTDEVICE> devices(count);
    if (GetRegisteredRawInputDevices(devices.data(), &count, sizeof(RAWINPUTDEVICE)) == UINT(-1)) return nullptr;
    for (const auto& device : devices) {
        wchar_t name[128]{};
        if (device.usUsagePage == 1 && device.usUsage == usage && (device.dwFlags & RIDEV_INPUTSINK) &&
            GetClassNameW(device.hwndTarget, name, ARRAYSIZE(name)) &&
            wcscmp(name, L"CapsLang.Engine.RawRelease.1.1") == 0) return device.hwndTarget;
    }
    return nullptr;
}
void EngineTests(const std::wstring& desktop) {
    using core::Language;
    using core::ApplyState;
    Fixture first, second;
    if (!first.Start(desktop) || !second.Start(desktop)) {
        Check(false, "engine foreign fixtures ready"); return;
    }
    capturedWindow = first.data->window;
    {
        ShowWindow(first.data->window,SW_SHOWNOACTIVATE); // Private, inactive desktop only.
        FocusTarget selector;MwbSnapshot snapshot;snapshot.responsive=true;
        auto& evidence=snapshot.evidence;evidence.applications=1;evidence.helpers=1;
        evidence.supportedBinary=true;evidence.dots=1;evidence.helperPid=second.data->pid;
        evidence.dotWindow=second.data->window;evidence.settings.known=true;
        evidence.settings.maintenanceInput=false;evidence.settings.hideCursor=true;
        Check(selector.Select(first.Target(),snapshot).focus==first.data->window,"real user target remembered before MWB routing");
        const auto behind=selector.Select(second.Target(),snapshot);
        Check(behind.focus==first.data->window,"MWB dot focus selects previous text window without click");
        LayoutApplier apply;
        Check(apply.Request(behind,FindLayout(kRussian)).posted && PumpUntil([&]{return TargetLanguage(first.Target())==kRussian;}),"background text window receives language while MWB owns foreground");
        Check(TargetLanguage(second.Target())==kEnglish,"service dot is not a layout target");
        snapshot.responsive=false;
        Check(selector.Select(second.Target(),snapshot).focus==second.data->window,"stale MWB evidence cannot redirect a target");
        Check(first.Reset(0),"background focus regression fixture reset");
    }
    Engine engine({CaptureFixture});
    Check(!engine.SetTarget(Language::Russian) && !engine.RestartHook(), "stopped engine rejects work");
    Check(engine.Start(), "real engine worker starts on private desktop");
    Check(PumpUntil([&] { return engine.Status().hookRegistered && engine.Status().hookThreadResponsive; }),
          "real low-level hooks installed and dedicated thread responsive");
    const HWND rawSink = EngineRawSink();
    Check(rawSink && !engine.Status().hookError, "dedicated hook thread registered Raw Input release observer");
    Check(rawSink && !EngineRawSink(2), "engine does not register a mouse Raw Input observer");
    const auto rawRevision = engine.Status().userRevision;
    if (rawSink) {
        DWORD_PTR ignored = 0;
        Check(SendMessageTimeoutW(rawSink, WM_INPUT, RIM_INPUTSINK, 0,
            SMTO_ABORTIFHUNG, 1000, &ignored) != 0, "invalid Raw Input handle is handled without blocking");
        Check(engine.Status().userRevision == rawRevision, "invalid Raw Input does not manufacture Caps input");
    }
    {
        const auto endpoint = ipc::Endpoint::Current(L"engine-test-" + std::to_wstring(GetCurrentProcessId()));
        ipc::Server server(endpoint, [&](const ipc::Request&) {
            ipc::Response response{};
            response.target = static_cast<DWORD>(engine.Status().target);
            return response;
        });
        Check(server.Start(), "engine local IPC starts with SID/session ACL");
        Fixture medium;
        const bool mediumStarted = medium.Start(desktop, nullptr, SECURITY_MANDATORY_MEDIUM_RID);
        Check(mediumStarted && medium.data->integrityRid == SECURITY_MANDATORY_MEDIUM_RID &&
            medium.data->posted && !medium.data->controlError, "real medium-integrity child can use engine IPC");
        Fixture low;
        const bool lowStarted = low.Start(desktop, nullptr, SECURITY_MANDATORY_LOW_RID);
        Check(lowStarted && low.data->integrityRid == SECURITY_MANDATORY_LOW_RID && !low.data->posted &&
            low.data->postError == ERROR_ACCESS_DENIED, "real low-integrity child cannot use engine IPC");
        std::printf("IPC boundary: elevated_server=%d medium_started=%d medium_rid=%lu medium_sent=%d error=%lu low_started=%d low_rid=%lu low_sent=%d error=%lu\n",
            engine.Status().elevated, mediumStarted, medium.data ? medium.data->integrityRid : 0,
            medium.data ? medium.data->posted : 0, medium.data ? medium.data->postError : 0,
            lowStarted, low.data ? low.data->integrityRid : 0, low.data ? low.data->posted : 0, low.data ? low.data->postError : 0);
    }
    for (int i = 0; i < 40; ++i) {
        const auto language = i % 2 ? Language::English : Language::Russian;
        const bool applied = engine.SetTarget(language) && PumpUntil([&] {
            const auto state = engine.Status();
            return state.target == language && state.actual == language && state.apply == ApplyState::Applied &&
                TargetLanguage(first.Target()) == static_cast<LANGID>(language);
        });
        if (!applied) {
            const auto state = engine.Status();
            std::printf("Apply failure: index=%d desired=%04x target=%04x actual=%04x window=%04x apply=%u error=%lu generation=%llu\n",
                i, static_cast<unsigned>(language), static_cast<unsigned>(state.target), static_cast<unsigned>(state.actual),
                TargetLanguage(first.Target()), static_cast<unsigned>(state.apply), state.layoutError,
                static_cast<unsigned long long>(state.generation));
            std::printf("Fixture state: requests=%ld changes=%ld mode=%ld handling=%ld entered_ago=%llu returned_ago=%llu\n",
                first.data->requests, first.data->changes, first.data->mode, first.data->handlingLayout,
                static_cast<unsigned long long>(GetTickCount64() - first.data->layoutEntered),
                static_cast<unsigned long long>(GetTickCount64() - first.data->layoutReturned));
            PrintFixtureWait(first.data->tid, second.data->pid);
        }
        Check(applied, "production engine confirms absolute language in foreign process");
        Check(!engine.Status().layoutError, "confirmed layout has no stale application error");
    }
    Check(engine.Status().userRevision == 0, "own application never echoed as manual activity");
    Check(first.Reset(3), "fixture delays old RU but applies newer EN immediately");
    const LONG beforeDelay = InterlockedCompareExchange(&first.data->requests, 0, 0);
    Check(engine.SetTarget(Language::Russian) && PumpUntil([&] {
        return InterlockedCompareExchange(&first.data->requests, 0, 0) > beforeDelay;
    }), "old request is actually queued in the foreign process");
    Check(engine.SetTarget(Language::English), "new target supersedes pending old request");
    PumpUntil([] { return false; }, 650); // Let the deliberately stale callback fire.
    Check(engine.Status().target == Language::English && engine.Status().actual == Language::English &&
        engine.Status().userRevision == 0 && TargetLanguage(first.Target()) == kEnglish,
        "late old acknowledgement cannot become a manual change or overwrite latest target");
    Check(first.Reset(0), "fixture returns to ordinary message handling");
    Check(engine.SetTarget(Language::Russian) && engine.SetTarget(Language::English) && engine.SetTarget(Language::Russian) &&
        PumpUntil([&] { return engine.Status().actual == Language::Russian && engine.Status().apply == ApplyState::Applied; }),
        "queued latest target wins");
    const auto revision = engine.Status().userRevision;
    capturedWindow = second.data->window;
    Check(PumpUntil([&] { return TargetLanguage(second.Target()) == kRussian; }), "new focus receives shared language");
    Check(engine.Status().target == Language::Russian && engine.Status().userRevision == revision,
          "remembered focus layout does not become a local event");
    const auto recovery = engine.Status().recoveries;
    Check(engine.RestartHook() && PumpUntil([&] { return engine.Status().recoveries > recovery; }),
          "hook refresh completes without F24");
    Check(PumpUntil([&] { return engine.Status().recoveries > recovery + 1; }, 11500),
          "automatic ten-second hook maintenance runs without input");
    const auto stopStart = GetTickCount64();
    engine.Stop();
    Check(GetTickCount64() - stopStart < 2000 && !engine.Status().hookRegistered, "engine orderly shutdown removes hooks");
    Check(!EngineRawSink() && !EngineRawSink(2) && !IsWindow(rawSink), "engine shutdown removes both owned Raw Input registrations and window");
    Check(!engine.SetTarget(Language::English) && !engine.RestartHook(), "post-stop work rejected");
    const auto hostEndpoint = ipc::Endpoint::Current(L"host-test-" + std::to_wstring(GetCurrentProcessId()));
    EngineHost host(hostEndpoint, {CaptureFixture});
    Check(host.Start() && host.Start(), "production IPC engine host starts idempotently");
    {
        EngineHost duplicate(hostEndpoint, {CaptureFixture});
        Check(!duplicate.Start() && duplicate.Error() == ERROR_ACCESS_DENIED,
              "duplicate host is rejected before it can start a second engine");
    }
    wchar_t executable[32768]{}; GetModuleFileNameW(nullptr, executable, ARRAYSIZE(executable));
    ipc::Request request{}; request.id = 1;
    ipc::Response response{}; DWORD error = 0;
    auto call = [&] {
        ++request.id;
        return ipc::Call(hostEndpoint, executable, false, request, response, error) && !response.error;
    };
    Check(call() && (response.flags & ipc::HookRegistered) && (response.flags & ipc::HookResponsive),
          "production host returns real hook health via protected IPC");
    request.operation = ipc::Operation::SetLayout; request.language = kEnglish;
    Check(call(), "host accepts exact EN request, not a synthetic key sequence");
    request.operation = ipc::Operation::Status; request.language = 0;
    Check(PumpUntil([&] {
        return call() && response.target == kEnglish && response.actual == kEnglish &&
            response.apply == static_cast<DWORD>(ApplyState::Applied) && TargetLanguage(second.Target()) == kEnglish;
    }), "IPC-to-production-engine-to-foreign-window EN is actually confirmed");
    request.operation = ipc::Operation::SetLayout; request.language = kRussian;
    Check(call(), "host accepts exact RU request");
    request.operation = ipc::Operation::Status; request.language = 0;
    Check(PumpUntil([&] {
        return call() && response.target == kRussian && response.actual == kRussian &&
            response.apply == static_cast<DWORD>(ApplyState::Applied) && TargetLanguage(second.Target()) == kRussian;
    }), "IPC-to-production-engine-to-foreign-window RU is actually confirmed");
    Check(response.revision == 0 && response.activitySerial == 0 && response.activityAge == UINT64_MAX,
          "IPC application cannot masquerade as an explicit local language choice");
    const auto epoch = response.engineEpoch;
    Check(epoch != 0, "host publishes a random nonzero incarnation");
    request.operation = ipc::Operation::SetLayoutIfRevision; request.language = kEnglish;
    request.expectedRevision = 1; request.engineEpoch = epoch;
    Check(call(), "conditional peer request is queued without claiming it was applied");
    request.operation = ipc::Operation::Status; request.language = 0;
    request.expectedRevision = 0; request.engineEpoch = 0;
    PumpUntil([] { return false; }, 150);
    Check(call() && response.target == kRussian && TargetLanguage(second.Target()) == kRussian,
          "worker refuses peer request with a stale local intent snapshot");
    request.operation = ipc::Operation::SetLayoutIfRevision; request.language = kEnglish;
    request.engineEpoch = epoch;
    Check(call(), "conditional peer request with matching revision is queued");
    request.operation = ipc::Operation::Status; request.language = 0;
    request.engineEpoch = 0;
    Check(PumpUntil([&] { return call() && response.actual == kEnglish && response.target == kEnglish; }),
          "matching conditional update reaches actual target");
    {
        EngineClient client(executable, hostEndpoint, false);
        ipc::Response sample;
        Check(client.Read(sample), "ordinary broker client reads validated engine endpoint");
        sync::LocalState local;
        Check(EngineClient::MakeState(sample, 0, {}, true, local) && !local.snapshot.activity.known,
              "broker does not invent recipient activity from IPC input counters");
        auto malformed = sample; malformed.flags |= 128;
        sync::LocalState invalid;
        Check(!EngineClient::MakeState(malformed, 0, {}, true, invalid), "broker rejects unknown status flags");
        Check(!EngineClient::MakeState(sample, 0, {0, 0, true}, true, invalid), "known activity requires actual activity serial");
        Check(client.ReadState(invalid) && !invalid.snapshot.activity.known,
              "no explicit language change means no invented choice age");
        auto recipientSample = sample;
        recipientSample.activitySerial = 1; recipientSample.activityAge = 10;
        recipientSample.mwbFlags = ipc::MwbRunning | ipc::RecipientAvailable;
        Check(EngineClient::RecipientState(recipientSample,20,invalid) && invalid.snapshot.mwb &&
              invalid.snapshot.activity.minimum == 10 && invalid.snapshot.activity.maximum == 30,
              "recipient age interval includes bounded IPC round trip");
        recipientSample.mwbFlags = ipc::MwbRunning;
        Check(EngineClient::RecipientState(recipientSample,20,invalid) && invalid.snapshot.mwb,
              "MWB presence enables synchronization without recipient metadata");
        recipientSample.mwbFlags = ipc::RecipientAvailable;
        Check(!EngineClient::RecipientState(recipientSample,20,invalid), "available recipient without MWB rejected");
        recipientSample.mwbFlags = 0; recipientSample.activitySerial = 0;
        Check(!EngineClient::RecipientState(recipientSample,20,invalid), "recipient age without serial rejected");
        recipientSample.activitySerial = 1; recipientSample.activityAge = UINT64_MAX-1;
        Check(!EngineClient::RecipientState(recipientSample,20,invalid), "recipient age overflow rejected");
        sync::Id localId{}, peerId{}, session{}; localId[0] = 1; peerId[0] = 2; session[0] = 3;
        sync::BrokerState broker(localId, peerId, session, Language::English, local);
        sync::Replica peer(peerId, localId, session, Language::English);
        sync::Message message;
        Check(peer.Local(Language::Russian, message) && broker.Remote(message, local, GetTickCount64()),
              "broker receives exact peer target");
        auto actions = broker.TakeOutput();
        Check(actions.apply && actions.acknowledgement && actions.acknowledgement->applied == sync::Applied::Pending,
              "broker emits conditional command and pending, never premature success");
        const bool queued = actions.apply && client.Queue(*actions.apply);
        broker.ApplyQueued(queued);
        Check(queued, "broker command crosses protected IPC into real engine");
        bool confirmed = false, echoed = false;
        Check(PumpUntil([&] {
            if (!client.Read(sample) || !EngineClient::MakeState(sample, 0, {}, true, local) ||
                !broker.Observe(local, GetTickCount64())) return false;
            const auto output = broker.TakeOutput();
            echoed |= output.update.has_value();
            if (output.acknowledgement && output.acknowledgement->applied == sync::Applied::Yes)
                confirmed = peer.AcceptAck(*output.acknowledgement);
            return confirmed && TargetLanguage(second.Target()) == kRussian;
        }), "peer confirmed only after broker->IPC->engine changes actual foreign-window language");
        Check(!echoed && sample.revision == 0 && peer.PeerApplied() == sync::Applied::Yes,
              "verified remote application has no local-input echo");
        Check(!client.Queue({Language::English, epoch ^ UINT64_MAX, 0}) && client.Error() == ERROR_REVISION_MISMATCH,
              "broker refuses command bound to stale engine incarnation");
        EngineClient wrongBinary(L"C:\\Windows\\not-capslang.exe", hostEndpoint, false);
        Check(!wrongBinary.Read(sample), "broker rejects endpoint hosted by a different executable");
        if (!ProcessElevation(GetCurrentProcessId()).elevated) {
            EngineClient needElevated(executable, hostEndpoint);
            Check(!needElevated.Read(sample), "full-mode broker refuses non-elevated engine");
        }
    }
    {
        // Full authenticated transport -> broker -> protected IPC -> real
        // worker -> foreign process. Activity and the opposite endpoint are
        // controlled fixtures; no physical-recipient acceptance is implied.
        net::Winsock winsock;
        net::Identity serverIdentity, peerIdentity; DWORD networkError = 0;
        bool prepared = !winsock.Error() && serverIdentity.Generate(networkError) && peerIdentity.Generate(networkError);
        net::Socket listener(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
        sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        int length = sizeof(address);
        prepared = prepared && listener && !bind(listener.Get(), reinterpret_cast<sockaddr*>(&address), length) &&
            !listen(listener.Get(), 1) && !getsockname(listener.Get(), reinterpret_cast<sockaddr*>(&address), &length);
        net::Socket connector(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
        prepared = prepared && connector && !connect(connector.Get(), reinterpret_cast<sockaddr*>(&address), length);
        net::Socket accepted(prepared ? accept(listener.Get(), nullptr, nullptr) : INVALID_SOCKET);
        HANDLE cancel = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        prepared = prepared && accepted && cancel;
        Check(prepared, "full broker/engine network fixture prepared on loopback");
        if (prepared) {
            std::mutex peerStatusMutex;
            net::SessionStatus peerStatus;
            std::atomic<bool> changePeer{false};
            DWORD serverResult = 0, peerResult = 0;
            bool serverAuthenticated = false, peerAuthenticated = false;
            const auto origin = GetTickCount64();
            std::thread server([&] {
                EngineClient client(executable, hostEndpoint, false);
                net::TlsChannel channel(accepted.Get(), cancel);
                serverAuthenticated = channel.Handshake(serverIdentity, true, peerIdentity.Fingerprint());
                if (serverAuthenticated) {
                    net::SessionEndpoint endpoint{
                        [&](sync::LocalState& value) {
                            ipc::Response valueFromEngine;
                            const auto age = 10000 + GetTickCount64() - origin;
                            return client.Read(valueFromEngine) && EngineClient::MakeState(valueFromEngine, 1, {age, age, true}, true, value);
                        },
                        [&](const sync::ApplyCommand& command) { return client.Queue(command); }, {}};
                    net::RunSession(channel, serverIdentity, true, endpoint, cancel, serverResult);
                } else serverResult = channel.Error();
                shutdown(accepted.Get(), SD_BOTH);
            });
            std::thread peer([&] {
                net::TlsChannel channel(connector.Get(), cancel);
                peerAuthenticated = channel.Handshake(peerIdentity, false, serverIdentity.Fingerprint());
                if (peerAuthenticated) {
                    sync::LocalState state{{27, 0, 1, Language::English, {0, 0, true}, true}, Language::English, ApplyState::Applied, false};
                    net::SessionEndpoint endpoint{
                        [&](sync::LocalState& value) {
                            if (changePeer.load() && !state.snapshot.userRevision) {
                                state.snapshot.userRevision = 1; state.snapshot.activitySerial = 2;
                                state.actual = state.snapshot.language = Language::Russian;
                            }
                            value = state; const auto age = GetTickCount64() - origin;
                            value.snapshot.activity = {age, age, true}; return true;
                        },
                        [&](const sync::ApplyCommand& command) {
                            if (state.snapshot.engineEpoch != command.engineEpoch || state.snapshot.userRevision != command.expectedRevision) return false;
                            state.snapshot.language = state.actual = command.language; return true;
                        },
                        [&](const net::SessionStatus& value) { std::lock_guard<std::mutex> lock(peerStatusMutex); peerStatus = value; }};
                    net::RunSession(channel, peerIdentity, false, endpoint, cancel, peerResult);
                } else peerResult = channel.Error();
                shutdown(connector.Get(), SD_BOTH);
            });
            auto peerConfirmed = [&](Language language) {
                std::lock_guard<std::mutex> lock(peerStatusMutex);
                return peerStatus.phase == net::SessionPhase::Active && peerStatus.target == language &&
                    peerStatus.peerApplied == sync::Applied::Yes && TargetLanguage(second.Target()) == static_cast<LANGID>(language);
            };
            Check(PumpUntil([&] { return peerConfirmed(Language::English); }, 5000),
                  "real TLS reconciliation applies EN through broker and IPC, confirmed by foreign window");
            changePeer = true;
            Check(PumpUntil([&] { return peerConfirmed(Language::Russian); }, 2000),
                  "live peer update applies RU through full network-to-engine chain without synthetic keys");
            SetEvent(cancel); server.join(); peer.join();
            Check(serverAuthenticated && peerAuthenticated, "full engine path uses mutually pinned certificates");
            std::printf("Full-chain stop: server=%lu peer=%lu (cancellation/disconnect expected)\n", serverResult, peerResult);
        }
        if (cancel) CloseHandle(cancel);
    }
    request.operation = ipc::Operation::Stop;
    Check(call() && WaitForSingleObject(host.ShutdownEvent(), 0) == WAIT_OBJECT_0,
          "stop request signals the owner without joining IPC from its own callback");
    host.Stop(); host.Stop();
    request.operation = ipc::Operation::Status;
    Check(!call(), "stopped host endpoint is gone");
    Check(host.Start(), "host restarts cleanly after complete shutdown");
    Check(call() && response.engineEpoch && response.engineEpoch != epoch, "restart changes the engine incarnation");
    request.operation = ipc::Operation::SetLayoutIfRevision; request.language = kEnglish; request.engineEpoch = epoch;
    Check(!call() && response.error == ERROR_REVISION_MISMATCH,
          "old broker request rejected after restart even when revision numbers match");
    host.Stop();
    {
        EngineOptions options{CaptureFixture};
        options.requireDesktopProfile = true;
        Engine verified(options);
        Check(verified.Start(), "profile-confirmed engine starts on isolated desktop");
        Check(verified.SetTarget(Language::English) && PumpUntil([&] {
            return verified.Status().actual == Language::English;
        }), "window applies independently of desktop profile confirmation");
        auto state = verified.Status();
        Check(state.apply != ApplyState::Applied && !state.profileConfirmed,
              "actual window alone cannot acknowledge desktop-wide success");
        Check(verified.ProfileReport(kEnglish, state.generation - 1, 0, false),
              "stale profile report can enter queue for worker validation");
        PumpUntil([] { return false; }, 80);
        Check(!verified.Status().profileConfirmed, "worker rejects stale profile generation");
        Check(verified.ProfileReport(kEnglish, state.generation, 0, false) && PumpUntil([&] {
            return verified.Status().profileConfirmed && verified.Status().apply == ApplyState::Applied;
        }), "both current profile and window confirmations are required");
        Check(PumpUntil([&] {
            return !verified.Status().profileConfirmed && verified.Status().apply != ApplyState::Applied;
        }, 1600), "lost broker reports expire rather than retaining Applied forever");
        Check(verified.ProfileReport(0, state.generation, ERROR_ACCESS_DENIED, false) && PumpUntil([&] {
            return verified.Status().profileError == ERROR_ACCESS_DENIED;
        }), "profile failure survives into status");
        Check(verified.ProfileReport(kEnglish, state.generation, 0, false) && PumpUntil([&] {
            return verified.Status().apply == ApplyState::Applied;
        }), "temporary profile failure recovers without a new user toggle");
        Check(verified.SetTarget(Language::Russian) && PumpUntil([&] {
            return verified.Status().target == Language::Russian;
        }), "new choice supersedes profile request");
        verified.ProfileReport(kEnglish, state.generation, 0, false);
        PumpUntil([] { return false; }, 80);
        Check(!verified.Status().profileConfirmed && verified.Status().apply != ApplyState::Applied,
              "late old profile success cannot acknowledge a newer choice");
        verified.Stop();
    }
    capturedWindow = nullptr;
}
#endif
} // namespace

int wmain(int argc, wchar_t** argv) {
#ifdef CAPSLANG_MESSAGE_PROBE
    if (argc == 2 && wcscmp(argv[1], L"--interactive-message-observer") == 0) {
        wchar_t desktopName[128]{}; DWORD size = 0;
        if (!GetUserObjectInformationW(GetThreadDesktop(GetCurrentThreadId()), UOI_NAME,
            desktopName, sizeof(desktopName), &size) || wcscmp(desktopName, L"Default") != 0)
            return ERROR_INVALID_FUNCTION;
        const auto elevation = ProcessElevation(GetCurrentProcessId());
        if (!elevation.known || elevation.elevated) return ERROR_ACCESS_DENIED;
        MessageObservationTests(L"Default", true);
        return failures ? 1 : 0;
    }
#endif
    if (argc == 2 && wcscmp(argv[1], L"--token-inventory") == 0) return TokenInventory();
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
#ifdef CAPSLANG_ENGINE_INTEGRATION
    if (argc == 5 && wcscmp(argv[1], L"--ipc-client") == 0) {
        return IpcClientMain(reinterpret_cast<HANDLE>(wcstoull(argv[2], nullptr, 10)),
            reinterpret_cast<HANDLE>(wcstoull(argv[3], nullptr, 10)),
            reinterpret_cast<HANDLE>(wcstoull(argv[4], nullptr, 10)));
    }
#endif
    if (argc == 5 && wcscmp(argv[1], L"--fixture") == 0) {
        return FixtureMain(reinterpret_cast<HANDLE>(wcstoull(argv[2], nullptr, 10)),
            reinterpret_cast<HANDLE>(wcstoull(argv[3], nullptr, 10)),
            reinterpret_cast<HANDLE>(wcstoull(argv[4], nullptr, 10)));
    }
#ifdef CAPSLANG_ENGINE_INTEGRATION
    // Read only MWB's own routing-window metadata on the user's desktop before
    // creating the test desktop. No hooks/input/layout changes on that desktop.
    MwbObserver observer;
    const auto mwb = observer.Read();
    std::printf("MWB metadata (NOT activity acceptance): applications=%u helpers=%u supported=%d dots=%u visible=%d candidate=%u error=%lu\n",
        mwb.applications, mwb.helpers, mwb.supportedBinary, mwb.dots, mwb.dotVisible, static_cast<unsigned>(mwb.route), mwb.error);
#endif
    const HDESK original = GetThreadDesktop(GetCurrentThreadId());
    const std::wstring name = L"CapsLangTests-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64());
    // No DESKTOP_SWITCHDESKTOP: even this handle cannot activate the test desktop.
    // Allow the low-integrity test child to JOIN this disposable desktop.
    // Its medium/high target windows retain their own UIPI protection. The
    // user's Default desktop and existing objects are never relabeled.
    const FixtureSecurity fixtureSecurity;
    if (!fixtureSecurity.descriptor) return 17;
    SECURITY_ATTRIBUTES security{sizeof(security), fixtureSecurity.descriptor, FALSE};
    const HDESK desktop = CreateDesktopW(name.c_str(), nullptr, nullptr, 0,
        DESKTOP_CREATEWINDOW | DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS | DESKTOP_ENUMERATE
#if defined(CAPSLANG_ENGINE_INTEGRATION) || defined(CAPSLANG_MESSAGE_PROBE)
        | DESKTOP_HOOKCONTROL
#endif
        , &security);
    if (!desktop || !SetThreadDesktop(desktop)) {
        std::fprintf(stderr, "Cannot isolate tests; refusing to run: %lu\n", GetLastError());
        if (desktop) CloseDesktop(desktop);
        return 2;
    }
    const HRESULT com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (SUCCEEDED(com) && FindLayout(kEnglish) && FindLayout(kRussian)) {
#ifdef CAPSLANG_ENGINE_INTEGRATION
        // Diagnostic A/B only: defaults retain the full regression suite.
        // Does a prior TSF manager on the harness STA affect the worker STA?
        if (!(argc == 2 && wcscmp(argv[1], L"--engine-only") == 0)) Tests(name);
#else
        Tests(name);
#endif
#ifdef CAPSLANG_ENGINE_INTEGRATION
        EngineTests(name);
#endif
#ifdef CAPSLANG_MESSAGE_PROBE
        MessageObservationTests(name);
#endif
    }
    else Check(false, "COM and installed EN/RU required; no layouts are installed by test");
    if (SUCCEEDED(com)) CoUninitialize();
    if (SetThreadDesktop(original)) CloseDesktop(desktop);
    std::printf("Windows layout integration: %u checks, %u failures; no input desktop switch.\n", checks, failures);
    return failures ? 1 : 0;
}
