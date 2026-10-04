#include "system_layout.hpp"
#include "../app/paths.hpp"
#include "../app/install_store.hpp"
#include <sddl.h>
#include <wtsapi32.h>
#include <objbase.h>
#include <atomic>

namespace capslang::system_layout {
namespace {
constexpr wchar_t kService[] = L"CapsLangLayout";
constexpr wchar_t kDescription[] = L"CapsLang local layout access v1; no networking";
struct Handle {
    HANDLE h = nullptr;
    ~Handle() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
};
struct ServiceHandle {
    SC_HANDLE h = nullptr;
    ~ServiceHandle() { if (h) CloseServiceHandle(h); }
};
std::wstring Sid(HANDLE token) {
    DWORD size = 0; GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    if (!size || size > 65536) return {};
    std::vector<BYTE> bytes(size);
    if (!GetTokenInformation(token, TokenUser, bytes.data(), size, &size)) return {};
    LPWSTR text = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(bytes.data())->User.Sid, &text)) return {};
    const std::wstring result(text); LocalFree(text); return result;
}
std::wstring Owner() {
    DWORD error = 0;
    const auto exe = app::InstalledExecutable(error);
    if (exe.empty() || !app::ProtectedExecutable(exe, error)) return {};
    std::vector<BYTE> bytes;
    if (!app::install::ReadProtected(exe.substr(0, exe.find_last_of(L'\\')) + L"\\owner.bin", bytes, error) ||
        bytes.size() % 2 || bytes.size() > 512) return {};
    std::wstring value(bytes.size()/2, L'\0'); memcpy(value.data(), bytes.data(), bytes.size());
    const std::wstring prefix = L"CapsLang protected installation v1\n";
    if (value.rfind(prefix, 0) != 0) return {};
    value.erase(0, prefix.size());
    PSID parsed = nullptr;
    if (value.find(L'\0') != std::wstring::npos || !ConvertStringSidToSidW(value.c_str(), &parsed)) return {};
    const bool valid = IsValidSid(parsed) && !IsWellKnownSid(parsed, WinLocalSystemSid);
    LocalFree(parsed); return valid ? value : std::wstring{};
}
std::wstring SessionUser(DWORD session) {
    Handle token;
    if (!session || session == 0xffffffff || !WTSQueryUserToken(session, &token.h)) return {};
    return Sid(token.h); // Token never leaves this scope and is never used to execute code.
}
bool Privilege(const wchar_t* name) {
    Handle token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token.h)) return false;
    TOKEN_PRIVILEGES privileges{}; privileges.PrivilegeCount = 1;
    if (!LookupPrivilegeValueW(nullptr, name, &privileges.Privileges[0].Luid)) return false;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    return AdjustTokenPrivileges(token.h, FALSE, &privileges, 0, nullptr, nullptr) && GetLastError() == 0;
}
bool NormalDesktop(DWORD session) {
    // Fail closed during lock, disconnect, console transfer and secure UAC.
    if (WTSGetActiveConsoleSessionId() != session) return false;
    LPWSTR raw = nullptr; DWORD size = 0;
    if (!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session, WTSSessionInfoEx, &raw, &size)) return false;
    const auto info = reinterpret_cast<WTSINFOEXW*>(raw);
    const bool unlocked = size >= sizeof(WTSINFOEXW) && info->Level == 1 &&
        info->Data.WTSInfoExLevel1.SessionState == WTSActive &&
        info->Data.WTSInfoExLevel1.SessionFlags == WTS_SESSIONSTATE_UNLOCK;
    WTSFreeMemory(raw);
    if (!unlocked) return false;
    HDESK desktop = OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS);
    if (!desktop) return false;
    wchar_t name[64]{}; DWORD needed = 0;
    const bool normal = GetUserObjectInformationW(desktop, UOI_NAME, name, sizeof(name), &needed) &&
        wcscmp(name, L"Default") == 0;
    CloseDesktop(desktop); return normal;
}
Response Execute(const Request& request, DWORD session, const std::wstring& owner) {
    Response result; result.id = request.id; result.session = session;
    if (!Valid(request)) { result.error = ERROR_INVALID_DATA; return result; }
    if (SessionUser(session) != owner || !NormalDesktop(session)) {
        result.locked = 1; result.error = ERROR_NOT_READY; return result;
    }
    const auto target = CaptureLayoutTarget();
    if (!TargetStillValid(target)) { result.error = ERROR_INVALID_WINDOW_HANDLE; return result; }
    DWORD targetSession = 0;
    if (!ProcessIdToSessionId(target.processId, &targetSession) || targetSession != session) {
        result.error = ERROR_ACCESS_DENIED; return result;
    }
    const auto initial = TargetLanguage(target);
    result.actual = IsSupportedLanguage(initial) ? initial : 0;
    if (request.operation == Operation::Observe) return result;
    const auto layout = FindLayout(static_cast<LANGID>(request.language));
    if (!layout) { result.error = ERROR_NOT_SUPPORTED; return result; }
    const HRESULT com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(com)) { result.error = static_cast<DWORD>(com); return result; }
    {
        LayoutApplier applier;
        // Recheck the security desktop after COM initialization, before posting.
        if (!NormalDesktop(session) || GetForegroundWindow() != target.foreground) result.error = ERROR_RETRY;
        else {
            const auto applied = applier.Request(target, layout);
            result.changeHr = applied.changeLanguage; result.profileHr = applied.activateProfile;
            result.error = applied.postError;
            if (!result.error && FAILED(applied.changeLanguage)) result.error = static_cast<DWORD>(applied.changeLanguage);
            if (!result.error && FAILED(applied.activateProfile)) result.error = static_cast<DWORD>(applied.activateProfile);
            const auto deadline = GetTickCount64() + 300;
            while (!result.error && TargetLanguage(target) != request.language && GetTickCount64() < deadline) {
                MSG message{};
                while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
                    TranslateMessage(&message); DispatchMessageW(&message);
                }
                MsgWaitForMultipleObjects(0, nullptr, FALSE, 10, QS_ALLINPUT);
            }
            const auto actual = TargetLanguage(target);
            result.actual = IsSupportedLanguage(actual) ? actual : 0;
            if (!result.error && (GetForegroundWindow() != target.foreground || !NormalDesktop(session))) result.error = ERROR_RETRY;
            if (!result.error && result.actual != request.language) result.error = ERROR_TIMEOUT;
        }
    }
    CoUninitialize(); return result;
}
bool ServiceSafe(SC_HANDLE service, DWORD& error) {
    DWORD bytes = 0;
    QueryServiceConfigW(service, nullptr, 0, &bytes);
    if (!bytes || bytes > 65536) { error = ERROR_INVALID_DATA; return false; }
    std::vector<BYTE> buffer(bytes);
    auto config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());
    const auto exe = app::InstalledExecutable(error);
    const auto command = L"\"" + exe + L"\" --layout-service";
    if (exe.empty() || !QueryServiceConfigW(service, config, bytes, &bytes) ||
        config->dwServiceType != SERVICE_WIN32_OWN_PROCESS || config->dwStartType != SERVICE_AUTO_START ||
        wcscmp(config->lpBinaryPathName, command.c_str()) ||
        _wcsicmp(config->lpServiceStartName, L"LocalSystem") ||
        (config->lpDependencies && *config->lpDependencies)) { error = ERROR_ACCESS_DENIED; return false; }
    QueryServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, nullptr, 0, &bytes);
    if (!bytes || bytes > 65536) { error = ERROR_INVALID_DATA; return false; }
    buffer.resize(bytes);
    if (!QueryServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, buffer.data(), bytes, &bytes)) {
        error = GetLastError(); return false;
    }
    const auto description = reinterpret_cast<SERVICE_DESCRIPTIONW*>(buffer.data());
    if (!description->lpDescription || wcscmp(description->lpDescription, kDescription)) {
        error = ERROR_ACCESS_DENIED; return false;
    }
    QueryServiceObjectSecurity(service, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, nullptr, 0, &bytes);
    if (!bytes || bytes > 65536) { error = ERROR_INVALID_DATA; return false; }
    buffer.resize(bytes);
    auto descriptor = reinterpret_cast<PSECURITY_DESCRIPTOR>(buffer.data());
    if (!QueryServiceObjectSecurity(service, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, descriptor, bytes, &bytes)) {
        error = GetLastError(); return false;
    }
    PSID owner = nullptr; PACL acl = nullptr; BOOL present = FALSE, defaulted = FALSE;
    auto trusted = [](PSID sid) { return sid && (IsWellKnownSid(sid, WinLocalSystemSid) || IsWellKnownSid(sid, WinBuiltinAdministratorsSid)); };
    if (!GetSecurityDescriptorOwner(descriptor, &owner, &defaulted) || !trusted(owner) ||
        !GetSecurityDescriptorDacl(descriptor, &present, &acl, &defaulted) || !present || !acl) {
        error = ERROR_ACCESS_DENIED; return false;
    }
    const DWORD writes = SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_STOP | SERVICE_PAUSE_CONTINUE |
        SERVICE_USER_DEFINED_CONTROL | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL;
    for (DWORD i = 0; i < acl->AceCount; ++i) {
        void* raw = nullptr;
        if (!GetAce(acl, i, &raw)) { error = ERROR_INVALID_ACL; return false; }
        const auto header = static_cast<ACE_HEADER*>(raw);
        if (header->AceFlags & INHERIT_ONLY_ACE || header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) { error = ERROR_ACCESS_DENIED; return false; }
        const auto ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
        if ((ace->Mask & writes) && !trusted(&ace->SidStart)) { error = ERROR_ACCESS_DENIED; return false; }
    }
    error = 0; return true;
}
bool Open(ServiceHandle& manager, ServiceHandle& service, DWORD access, bool& exists, DWORD& error) {
    exists = false;
    manager.h = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager.h) { error = GetLastError(); return false; }
    service.h = OpenServiceW(manager.h, kService, access | SERVICE_QUERY_CONFIG | READ_CONTROL);
    if (!service.h) { error = GetLastError(); if (error == ERROR_SERVICE_DOES_NOT_EXIST) { error = 0; return true; } return false; }
    exists = true; return ServiceSafe(service.h, error);
}
SERVICE_STATUS_HANDLE statusHandle = nullptr;
HANDLE stopEvent = nullptr;
void Status(DWORD state, DWORD error = 0) {
    SERVICE_STATUS status{};
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS; status.dwCurrentState = state;
    status.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
    status.dwWin32ExitCode = error;
    if (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING) { status.dwCheckPoint = 1; status.dwWaitHint = 5000; }
    SetServiceStatus(statusHandle, &status);
}
DWORD WINAPI Control(DWORD code, DWORD, void*, void*) {
    if (code == SERVICE_CONTROL_STOP || code == SERVICE_CONTROL_SHUTDOWN) {
        SetEvent(stopEvent); return NO_ERROR;
    }
    return code == SERVICE_CONTROL_INTERROGATE ? NO_ERROR : ERROR_CALL_NOT_IMPLEMENTED;
}
bool Spawn(DWORD session, HANDLE job, HANDLE& process) {
    Handle own, token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &own.h) ||
        !DuplicateTokenEx(own.h, MAXIMUM_ALLOWED, nullptr, SecurityImpersonation, TokenPrimary, &token.h) ||
        !SetTokenInformation(token.h, TokenSessionId, &session, sizeof(session))) return false;
    const auto exe = app::ExecutablePath();
    auto command = L"\"" + exe + L"\" --layout-worker";
    STARTUPINFOW startup{}; startup.cb = sizeof(startup); wchar_t desktop[] = L"winsta0\\default"; startup.lpDesktop = desktop;
    PROCESS_INFORMATION child{};
    if (!CreateProcessAsUserW(token.h, exe.c_str(), command.data(), nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, nullptr, &startup, &child)) return false;
    const bool assigned = AssignProcessToJobObject(job, child.hProcess) && ResumeThread(child.hThread) != DWORD(-1);
    if (!assigned) { TerminateProcess(child.hProcess, ERROR_PROCESS_ABORTED); CloseHandle(child.hProcess); }
    else process = child.hProcess;
    CloseHandle(child.hThread); return assigned;
}
void WINAPI RunService(DWORD, LPWSTR*) {
    Handle stop; stop.h = CreateEventW(nullptr, TRUE, FALSE, nullptr); stopEvent = stop.h;
    statusHandle = RegisterServiceCtrlHandlerExW(kService, Control, nullptr);
    if (!statusHandle) return;
    Status(SERVICE_START_PENDING);
    const auto owner = Owner();
    Handle job; job.h = CreateJobObjectW(nullptr, nullptr);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!stop.h || owner.empty() || !job.h || !SetInformationJobObject(job.h, JobObjectExtendedLimitInformation, &limits, sizeof(limits)) ||
        !Privilege(SE_TCB_NAME) || !Privilege(SE_ASSIGNPRIMARYTOKEN_NAME) || !Privilege(SE_INCREASE_QUOTA_NAME)) {
        Status(SERVICE_STOPPED, ERROR_ACCESS_DENIED); return;
    }
    Status(SERVICE_RUNNING);
    Handle child; DWORD childSession = 0; ULONGLONG nextLaunch = 0;
    while (WaitForSingleObject(stop.h, 250) == WAIT_TIMEOUT) {
        const DWORD session = WTSGetActiveConsoleSessionId();
        const bool eligible = SessionUser(session) == owner;
        if (child.h && (session != childSession || !eligible || WaitForSingleObject(child.h, 0) == WAIT_OBJECT_0)) {
            // Only the process this service created, held by its original handle.
            if (WaitForSingleObject(child.h, 0) != WAIT_OBJECT_0) TerminateProcess(child.h, ERROR_OPERATION_ABORTED);
            WaitForSingleObject(child.h, 3000); CloseHandle(child.h); child.h = nullptr;
            nextLaunch = GetTickCount64() + 1000;
        }
        if (!child.h && eligible && GetTickCount64() >= nextLaunch) {
            childSession = session; Spawn(session, job.h, child.h);
            nextLaunch = GetTickCount64() + 1000;
        }
    }
    Status(SERVICE_STOP_PENDING);
    if (child.h) { TerminateProcess(child.h, ERROR_OPERATION_ABORTED); WaitForSingleObject(child.h, 3000); }
    // Close the kill-on-close job before reporting STOPPED (image replacement).
    CloseHandle(job.h); job.h = nullptr;
    Status(SERVICE_STOPPED);
}
} // namespace

bool IsSystem() { Handle token; return OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.h) && Sid(token.h) == L"S-1-5-18"; }
ipc::Endpoint Endpoint(const std::wstring& userSid, DWORD session) {
    ipc::Endpoint result; PSID sid = nullptr;
    if (!session || session == 0xffffffff || userSid.find(L'\0') != std::wstring::npos ||
        !ConvertStringSidToSidW(userSid.c_str(), &sid)) { result.error = ERROR_INVALID_PARAMETER; return result; }
    const bool valid = IsValidSid(sid) && !IsWellKnownSid(sid, WinLocalSystemSid); LocalFree(sid);
    if (!valid) { result.error = ERROR_INVALID_SID; return result; }
    result.sid = userSid; result.session = session; result.serverSid = L"S-1-5-18";
    result.name = L"\\\\.\\pipe\\CapsLang.layout-v1." + std::to_wstring(session) + L"." + userSid;
    return result;
}
bool Call(const std::wstring& exe, const Request& request, Response& response, DWORD& error) {
    response = {}; error = 0;
    if (!Valid(request) || !app::ProtectedExecutable(exe, error)) { if (!error) error = ERROR_INVALID_PARAMETER; return false; }
    const auto current = ipc::Endpoint::Current();
    auto endpoint = Endpoint(current.sid, current.session);
    Response incoming;
    if (!ipc::Exchange(endpoint, exe, true, &request, sizeof(request), &incoming, sizeof(incoming), error)) return false;
    if (!Valid(incoming, request.id, current.session)) { error = ERROR_INVALID_DATA; return false; }
    response = incoming; error = incoming.error; return !error;
}
DWORD WorkerMain() {
    DWORD error = 0, session = 0;
    if (!IsSystem() || !app::ProtectedExecutable(app::ExecutablePath(), error) ||
        !ProcessIdToSessionId(GetCurrentProcessId(), &session) || !session || !Privilege(SE_TCB_NAME)) return ERROR_ACCESS_DENIED;
    const auto owner = Owner();
    if (owner.empty() || SessionUser(session) != owner) return ERROR_ACCESS_DENIED;
    auto endpoint = Endpoint(owner, session); endpoint.clientImage = app::ExecutablePath(); endpoint.requireClientElevation = true;
    std::atomic<ULONGLONG> executing{0};
    ipc::MessageServer server(endpoint, sizeof(Request), sizeof(Response), [&](const void* input, void* output) {
        struct Guard {
            std::atomic<ULONGLONG>& value;
            explicit Guard(std::atomic<ULONGLONG>& v) : value(v) { value = GetTickCount64(); }
            ~Guard() { value = 0; }
        } guard(executing);
        Request request; memcpy(&request, input, sizeof(request));
        const auto result = Execute(request, session, owner); memcpy(output, &result, sizeof(result));
    });
    if (!server.Start()) return server.Error();
    while (WTSGetActiveConsoleSessionId() == session && SessionUser(session) == owner) {
        const auto started = executing.load();
        // TSF is external COM code and can block. Sacrifice only this owned
        // stateless worker; the service recreates it, never the user's window.
        if (started && GetTickCount64() - started >= 2000) TerminateProcess(GetCurrentProcess(), ERROR_TIMEOUT);
        Sleep(100);
    }
    server.Stop(); return 0;
}
DWORD ServiceMain() {
    DWORD error = 0;
    if (!IsSystem() || !app::ProtectedExecutable(app::ExecutablePath(), error)) return ERROR_ACCESS_DENIED;
    SERVICE_TABLE_ENTRYW table[]{{const_cast<LPWSTR>(kService), RunService}, {nullptr, nullptr}};
    return StartServiceCtrlDispatcherW(table) ? 0 : GetLastError();
}
bool Installed(bool& exists, DWORD& error) { ServiceHandle manager, service; return Open(manager, service, SERVICE_QUERY_STATUS, exists, error); }
bool Install(DWORD& error) {
    bool exists = false; if (!Installed(exists, error)) return false;
    if (exists) return true;
    const auto exe = app::InstalledExecutable(error);
    if (exe.empty() || !app::ProtectedExecutable(exe, error)) return false;
    ServiceHandle manager, service; manager.h = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!manager.h) { error = GetLastError(); return false; }
    const auto command = L"\"" + exe + L"\" --layout-service";
    service.h = CreateServiceW(manager.h, kService, L"CapsLang Local Layout", SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, command.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!service.h) { error = GetLastError(); return false; }
    PSECURITY_DESCRIPTOR sd = nullptr;
    bool ok = ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;CCLCRC;;;BU)", SDDL_REVISION_1, &sd, nullptr) &&
        SetServiceObjectSecurity(service.h, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, sd);
    error = ok ? 0 : GetLastError(); if (sd) LocalFree(sd);
    SERVICE_DESCRIPTIONW description{const_cast<LPWSTR>(kDescription)};
    SC_ACTION actions[]{{SC_ACTION_RESTART, 1000}, {SC_ACTION_RESTART, 5000}, {SC_ACTION_RESTART, 30000}};
    SERVICE_FAILURE_ACTIONSW recovery{86400, nullptr, nullptr, 3, actions};
    if (ok) { ok = ChangeServiceConfig2W(service.h, SERVICE_CONFIG_DESCRIPTION, &description) &&
        ChangeServiceConfig2W(service.h, SERVICE_CONFIG_FAILURE_ACTIONS, &recovery); error = ok ? 0 : GetLastError(); }
    if (!ok) DeleteService(service.h); // Only the service just created by this call.
    return ok;
}
bool Stop(DWORD& error) {
    ServiceHandle manager, service; bool exists = false;
    if (!Open(manager, service, SERVICE_STOP | SERVICE_QUERY_STATUS, exists, error) || !exists) return !error;
    SERVICE_STATUS status{};
    if (!QueryServiceStatus(service.h, &status)) { error = GetLastError(); return false; }
    if (status.dwCurrentState != SERVICE_STOP_PENDING && status.dwCurrentState != SERVICE_STOPPED &&
        !ControlService(service.h, SERVICE_CONTROL_STOP, &status) && GetLastError() != ERROR_SERVICE_NOT_ACTIVE) {
        error = GetLastError(); return false;
    }
    const auto deadline = GetTickCount64() + 10000;
    do {
        if (!QueryServiceStatus(service.h, &status)) { error = GetLastError(); return false; }
        if (status.dwCurrentState == SERVICE_STOPPED) { error = 0; return true; }
        Sleep(50);
    } while (GetTickCount64() < deadline);
    error = ERROR_TIMEOUT; return false;
}
bool Remove(DWORD& error) {
    if (!Stop(error)) return false;
    ServiceHandle manager, service; bool exists = false;
    if (!Open(manager, service, DELETE, exists, error) || !exists) return !error;
    if (!DeleteService(service.h)) { error = GetLastError(); return false; }
    error = 0; return true;
}
bool Start(DWORD& error) {
    ServiceHandle manager, service; bool exists = false;
    if (!Open(manager, service, SERVICE_START | SERVICE_QUERY_STATUS, exists, error)) return false;
    if (!exists) { error = ERROR_SERVICE_DOES_NOT_EXIST; return false; }
    if (!StartServiceW(service.h, 0, nullptr) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) { error = GetLastError(); return false; }
    error = 0; return true;
}
} // namespace capslang::system_layout
