#include "tasks.hpp"
#include "../runtime/local_ipc.hpp"
#include "paths.hpp"
#include <sddl.h>

namespace capslang::app {
namespace {
// TASK_RUN_FLAGS is absent from the pinned MinGW header. SDK values:
// https://learn.microsoft.com/windows/win32/api/taskschd/ne-taskschd-task_run_flags
constexpr LONG kUseSessionId = 0x4, kUserSid = 0x8;
template <class T> struct Com {
    T *value = nullptr;
    ~Com() {
        if (value)
            value->Release();
    }
    T *operator->() const { return value; }
    T **Out() { return &value; }
};
struct Bstr {
    BSTR value = nullptr;
    explicit Bstr(const std::wstring &text)
        : value(SysAllocStringLen(text.data(), static_cast<UINT>(text.size()))) {}
    ~Bstr() { SysFreeString(value); }
    operator BSTR() const { return value; }
};
struct Variant {
    VARIANT value{};
    Variant() { VariantInit(&value); }
    explicit Variant(const std::wstring &text) : Variant() {
        value.vt = VT_BSTR;
        value.bstrVal = SysAllocStringLen(text.data(), static_cast<UINT>(text.size()));
    }
    ~Variant() { VariantClear(&value); }
};
bool Same(BSTR value, const std::wstring &expected) {
    return value && SysStringLen(value) == expected.size() && expected == value;
}
bool SameAccount(BSTR value, const std::wstring &sid) {
    if (!value || !SysStringLen(value) || SysStringLen(value) > 1024)
        return false;
    PSID expected = nullptr, actual = nullptr;
    if (!ConvertStringSidToSidW(sid.c_str(), &expected))
        return false;
    if (ConvertStringSidToSidW(value, &actual)) {
        const bool equal = EqualSid(expected, actual) != FALSE;
        LocalFree(actual);
        LocalFree(expected);
        return equal;
    }
    // Task Scheduler normalizes SID principal values to account names. Compare
    // resolved SIDs, not names, and never accept an unresolvable principal.
    DWORD bytes = 0, domainSize = 0;
    SID_NAME_USE use = SidTypeUnknown;
    LookupAccountNameW(nullptr, value, nullptr, &bytes, nullptr, &domainSize, &use);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || !bytes || bytes > 65536 ||
        domainSize > 1024) {
        LocalFree(expected);
        return false;
    }
    std::vector<BYTE> resolved(bytes);
    std::vector<wchar_t> domain(domainSize ? domainSize : 1);
    const bool equal = LookupAccountNameW(nullptr, value, resolved.data(), &bytes, domain.data(),
                                          &domainSize, &use) &&
                       use == SidTypeUser && EqualSid(expected, resolved.data());
    LocalFree(expected);
    return equal;
}
bool SidValid(const std::wstring &sid) {
    PSID parsed = nullptr;
    const bool ok =
        !sid.empty() && ConvertStringSidToSidW(sid.c_str(), &parsed) && IsValidSid(parsed);
    if (parsed)
        LocalFree(parsed);
    return ok;
}
bool Administrator() {
    const auto elevation = ProcessElevation(GetCurrentProcessId());
    return elevation.known && elevation.elevated;
}
bool Absent(HRESULT hr) {
    return hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) ||
           hr == HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);
}
bool ValidPath(const std::wstring &path) {
    return path.size() > 3 && path.size() < 32000 && path[1] == L':' && path[2] == L'\\' &&
           path.find_first_of(L"\r\n\"%$") == std::wstring::npos &&
           path.find(L"..") == std::wstring::npos;
}
} // namespace
const wchar_t *TaskArgument(TaskRole role) {
    return role == TaskRole::Engine ? L"--engine" : L"--background";
}
std::wstring TaskName(TaskRole role, const std::wstring &sid) {
    return (role == TaskRole::Engine ? L"CapsLang Engine " : L"CapsLang Broker ") + sid;
}
std::wstring TaskSecurity(const std::wstring &sid) {
    return SidValid(sid) ? L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;" + sid + L")"
                         : std::wstring{};
}
HRESULT BuildTaskDefinition(ITaskService *service, const std::wstring &executable,
                            const std::wstring &sid, TaskRole role, ITaskDefinition **output) {
    if (!output)
        return E_POINTER;
    *output = nullptr;
    if (!service || !SidValid(sid) || !ValidPath(executable))
        return E_INVALIDARG;
    Com<ITaskDefinition> task;
    HRESULT hr = service->NewTask(0, task.Out());
    if (FAILED(hr))
        return hr;
    Com<IPrincipal> principal;
    Com<ITaskSettings> settings;
    Com<IRegistrationInfo> info;
    Com<ITriggerCollection> triggers;
    Com<ITrigger> trigger;
    Com<ILogonTrigger> logon;
    Com<IActionCollection> actions;
    Com<IAction> action;
    Com<IExecAction> execute;
    Bstr user(sid), id(L"CapsLangUser"), source(L"CapsLang native user installer v1"),
        description(
            L"CapsLang interactive user session; no stored password; fixed protected executable."),
        command(executable), args(TaskArgument(role)), zero(L"PT0S"), minute(L"PT1M");
    if (FAILED(hr = task->get_Principal(principal.Out())) || FAILED(hr = principal->put_Id(id)) ||
        FAILED(hr = principal->put_UserId(user)) ||
        FAILED(hr = principal->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN)) ||
        FAILED(hr = principal->put_RunLevel(role == TaskRole::Engine ? TASK_RUNLEVEL_HIGHEST
                                                                     : TASK_RUNLEVEL_LUA)) ||
        FAILED(hr = task->get_Settings(settings.Out())) ||
        FAILED(hr = settings->put_Enabled(VARIANT_TRUE)) ||
        FAILED(hr = settings->put_AllowDemandStart(VARIANT_TRUE)) ||
        FAILED(hr = settings->put_StartWhenAvailable(VARIANT_TRUE)) ||
        FAILED(hr = settings->put_DisallowStartIfOnBatteries(VARIANT_FALSE)) ||
        FAILED(hr = settings->put_StopIfGoingOnBatteries(VARIANT_FALSE)) ||
        FAILED(hr = settings->put_RunOnlyIfIdle(VARIANT_FALSE)) ||
        FAILED(hr = settings->put_RunOnlyIfNetworkAvailable(VARIANT_FALSE)) ||
        FAILED(hr = settings->put_WakeToRun(VARIANT_FALSE)) ||
        FAILED(hr = settings->put_ExecutionTimeLimit(zero)) ||
        FAILED(hr = settings->put_MultipleInstances(TASK_INSTANCES_IGNORE_NEW)) ||
        FAILED(hr = settings->put_RestartInterval(minute)) ||
        FAILED(hr = settings->put_RestartCount(3)) ||
        FAILED(hr = task->get_RegistrationInfo(info.Out())) ||
        FAILED(hr = info->put_Source(source)) || FAILED(hr = info->put_Description(description)) ||
        FAILED(hr = task->get_Triggers(triggers.Out())) ||
        FAILED(hr = triggers->Create(TASK_TRIGGER_LOGON, trigger.Out())) ||
        FAILED(hr = trigger->QueryInterface(IID_ILogonTrigger,
                                            reinterpret_cast<void **>(logon.Out()))) ||
        FAILED(hr = logon->put_UserId(user)) || FAILED(hr = task->get_Actions(actions.Out())) ||
        FAILED(hr = actions->put_Context(id)) ||
        FAILED(hr = actions->Create(TASK_ACTION_EXEC, action.Out())) ||
        FAILED(hr = action->QueryInterface(IID_IExecAction,
                                           reinterpret_cast<void **>(execute.Out()))) ||
        FAILED(hr = execute->put_Path(command)) || FAILED(hr = execute->put_Arguments(args)))
        return hr;
    *output = task.value;
    task.value = nullptr;
    return S_OK;
}
bool MatchesTaskDefinition(ITaskDefinition *task, const std::wstring &executable,
                           const std::wstring &sid, TaskRole role) {
    if (!task || !SidValid(sid) || !ValidPath(executable))
        return false;
    Com<IPrincipal> principal;
    Com<IActionCollection> actions;
    Com<IAction> action;
    Com<IExecAction> execute;
    Com<IRegistrationInfo> info;
    TASK_LOGON_TYPE logon = TASK_LOGON_NONE;
    TASK_RUNLEVEL_TYPE level = TASK_RUNLEVEL_LUA;
    LONG count = 0;
    if (FAILED(task->get_Principal(principal.Out())) || FAILED(principal->get_LogonType(&logon)) ||
        logon != TASK_LOGON_INTERACTIVE_TOKEN || FAILED(principal->get_RunLevel(&level)) ||
        level != (role == TaskRole::Engine ? TASK_RUNLEVEL_HIGHEST : TASK_RUNLEVEL_LUA))
        return false;
    BSTR user = nullptr;
    const bool sameUser = SUCCEEDED(principal->get_UserId(&user)) && SameAccount(user, sid);
    SysFreeString(user);
    if (!sameUser)
        return false;
    if (FAILED(task->get_RegistrationInfo(info.Out())))
        return false;
    BSTR source = nullptr;
    const bool marked =
        SUCCEEDED(info->get_Source(&source)) && Same(source, L"CapsLang native user installer v1");
    SysFreeString(source);
    if (!marked)
        return false;
    if (FAILED(task->get_Actions(actions.Out())) || FAILED(actions->get_Count(&count)) ||
        count != 1 || FAILED(actions->get_Item(1, action.Out())) ||
        FAILED(action->QueryInterface(IID_IExecAction, reinterpret_cast<void **>(execute.Out()))))
        return false;
    BSTR path = nullptr, args = nullptr, working = nullptr;
    const bool fixed = SUCCEEDED(execute->get_Path(&path)) && Same(path, executable) &&
                       SUCCEEDED(execute->get_Arguments(&args)) && Same(args, TaskArgument(role)) &&
                       SUCCEEDED(execute->get_WorkingDirectory(&working)) &&
                       (!working || SysStringLen(working) == 0);
    SysFreeString(path);
    SysFreeString(args);
    SysFreeString(working);
    return fixed;
}
bool SafeTaskSecurity(const std::wstring &sddl, const std::wstring &sid) {
    if (!SidValid(sid))
        return false;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1,
                                                              &descriptor, nullptr))
        return false;
    PSID owner = nullptr;
    BOOL defaulted = FALSE, present = FALSE;
    PACL dacl = nullptr;
    bool ok = GetSecurityDescriptorOwner(descriptor, &owner, &defaulted) && owner &&
              (IsWellKnownSid(owner, WinBuiltinAdministratorsSid) ||
               IsWellKnownSid(owner, WinLocalSystemSid)) &&
              GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted) && present && dacl;
    PSID user = nullptr;
    ConvertStringSidToSidW(sid.c_str(), &user);
    bool allowedUser = false;
    const DWORD write = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES |
                        FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE |
                        GENERIC_ALL;
    if (ok)
        for (DWORD i = 0; i < dacl->AceCount; ++i) {
            void *data = nullptr;
            if (!GetAce(dacl, i, &data)) {
                ok = false;
                break;
            }
            const auto *header = static_cast<ACE_HEADER *>(data);
            if (header->AceFlags & INHERIT_ONLY_ACE)
                continue;
            if (header->AceType == ACCESS_DENIED_ACE_TYPE)
                continue;
            if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) {
                ok = false;
                break;
            }
            const auto *ace = static_cast<ACCESS_ALLOWED_ACE *>(data);
            auto *trustee = const_cast<DWORD *>(&ace->SidStart);
            if ((ace->Mask & write) && !IsWellKnownSid(trustee, WinBuiltinAdministratorsSid) &&
                !IsWellKnownSid(trustee, WinLocalSystemSid)) {
                ok = false;
                break;
            }
            if (user && EqualSid(trustee, user) && (ace->Mask & FILE_READ_DATA) &&
                (ace->Mask & FILE_EXECUTE))
                allowedUser = true;
        }
    if (user)
        LocalFree(user);
    LocalFree(descriptor);
    return ok && allowedUser;
}
Tasks::Tasks() = default;
Tasks::~Tasks() {
    if (root_)
        root_->Release();
    if (service_)
        service_->Release();
}
HRESULT Tasks::Open() {
    if (root_)
        return S_OK;
    HRESULT hr;
    if (!service_ &&
        FAILED(hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
                                     IID_ITaskService, reinterpret_cast<void **>(&service_))))
        return hr;
    Variant empty;
    if (FAILED(hr = service_->Connect(empty.value, empty.value, empty.value, empty.value)))
        return hr;
    return service_->GetFolder(Bstr(L"\\"), &root_);
}
HRESULT Tasks::Read(TaskRole role, const std::wstring &executable, const std::wstring &sid,
                    bool &exists, std::wstring &xml, std::wstring &security) {
    exists = false;
    xml.clear();
    security.clear();
    DWORD pathError = 0;
    const auto fixedPath = InstalledExecutable(pathError);
    if (fixedPath.empty() || executable != fixedPath || !SidValid(sid) ||
        (role != TaskRole::Engine && role != TaskRole::Broker))
        return E_INVALIDARG;
    HRESULT hr = Open();
    if (FAILED(hr))
        return hr;
    Com<IRegisteredTask> task;
    hr = root_->GetTask(Bstr(TaskName(role, sid)), task.Out());
    if (Absent(hr))
        return S_OK;
    if (FAILED(hr))
        return hr;
    Com<ITaskDefinition> definition;
    if (FAILED(hr = task->get_Definition(definition.Out())))
        return hr;
    if (!MatchesTaskDefinition(definition.value, executable, sid, role))
        return HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS);
    BSTR descriptor = nullptr, text = nullptr;
    hr = task->GetSecurityDescriptor(OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                     &descriptor);
    if (SUCCEEDED(hr))
        security.assign(descriptor ? descriptor : L"");
    SysFreeString(descriptor);
    if (FAILED(hr))
        return hr;
    if (!SafeTaskSecurity(security, sid))
        return E_ACCESSDENIED;
    hr = task->get_Xml(&text);
    if (SUCCEEDED(hr))
        xml.assign(text ? text : L"");
    SysFreeString(text);
    if (FAILED(hr))
        return hr;
    if (xml.empty() || xml.size() > 65536)
        return E_INVALIDARG;
    exists = true;
    return S_OK;
}
HRESULT Tasks::Register(TaskRole role, const std::wstring &executable, const std::wstring &sid) {
    if (!Administrator())
        return E_ACCESSDENIED;
    DWORD error = 0;
    if (!ProtectedExecutable(executable, error))
        return HRESULT_FROM_WIN32(error);
    bool exists = false;
    std::wstring xml, security;
    HRESULT hr = Read(role, executable, sid, exists, xml, security);
    if (FAILED(hr))
        return hr;
    Com<ITaskDefinition> definition;
    if (FAILED(hr = BuildTaskDefinition(service_, executable, sid, role, definition.Out())))
        return hr;
    Variant user(sid), empty, descriptor(TaskSecurity(sid));
    Com<IRegisteredTask> task;
    return root_->RegisterTaskDefinition(
        Bstr(TaskName(role, sid)), definition.value,
        (exists ? TASK_UPDATE : TASK_CREATE) | TASK_DONT_ADD_PRINCIPAL_ACE, user.value, empty.value,
        TASK_LOGON_INTERACTIVE_TOKEN, descriptor.value, task.Out());
}
HRESULT Tasks::Start(TaskRole role, const std::wstring &executable, const std::wstring &sid,
                     DWORD session) {
    if (!session || session > LONG_MAX)
        return E_INVALIDARG;
    DWORD error = 0;
    if (!ProtectedExecutable(executable, error))
        return HRESULT_FROM_WIN32(error);
    bool exists = false;
    std::wstring xml, security;
    HRESULT hr = Read(role, executable, sid, exists, xml, security);
    if (FAILED(hr))
        return hr;
    if (!exists)
        return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
    Com<IRegisteredTask> task;
    if (FAILED(hr = root_->GetTask(Bstr(TaskName(role, sid)), task.Out())))
        return hr;
    VARIANT_BOOL enabled = VARIANT_FALSE;
    if (FAILED(hr = task->get_Enabled(&enabled)))
        return hr;
    if (!enabled)
        return HRESULT_FROM_WIN32(ERROR_SERVICE_DISABLED);
    Com<IRunningTask> running;
    Variant empty;
    if (!Administrator()) {
        const auto current = ipc::Endpoint::Current();
        if (current.error || current.sid != sid || current.session != session)
            return E_ACCESSDENIED;
        // The fixed task's read/execute ACL permits normal startup without
        // another UAC prompt. RunEx's explicit session override requires an
        // administrator, so ordinary callers use their current session.
        return task->Run(empty.value, running.Out());
    }
    return task->RunEx(empty.value, kUseSessionId | kUserSid, static_cast<LONG>(session), Bstr(sid),
                       running.Out());
}
HRESULT Tasks::Remove(TaskRole role, const std::wstring &executable, const std::wstring &sid) {
    if (!Administrator())
        return E_ACCESSDENIED;
    bool exists = false;
    std::wstring xml, security;
    HRESULT hr = Read(role, executable, sid, exists, xml, security);
    if (FAILED(hr) || !exists)
        return hr;
    return root_->DeleteTask(Bstr(TaskName(role, sid)), 0);
}
HRESULT Tasks::Restore(TaskRole role, const std::wstring &executable, const std::wstring &sid,
                       const std::wstring &xml, const std::wstring &security) {
    if (!Administrator())
        return E_ACCESSDENIED;
    if (xml.empty())
        return Remove(role, executable, sid);
    DWORD error = 0;
    if (!ProtectedExecutable(executable, error))
        return HRESULT_FROM_WIN32(error);
    if (xml.size() > 65536 || !SafeTaskSecurity(security, sid))
        return E_INVALIDARG;
    bool exists = false;
    std::wstring current, acl;
    HRESULT hr = Read(role, executable, sid, exists, current, acl);
    if (FAILED(hr))
        return hr;
    Com<ITaskDefinition> definition;
    if (FAILED(hr = service_->NewTask(0, definition.Out())) ||
        FAILED(hr = definition->put_XmlText(Bstr(xml))))
        return hr;
    if (!MatchesTaskDefinition(definition.value, executable, sid, role))
        return E_ACCESSDENIED;
    Variant user(sid), empty, descriptor(security);
    Com<IRegisteredTask> task;
    return root_->RegisterTaskDefinition(
        Bstr(TaskName(role, sid)), definition.value,
        (exists ? TASK_UPDATE : TASK_CREATE) | TASK_DONT_ADD_PRINCIPAL_ACE, user.value, empty.value,
        TASK_LOGON_INTERACTIVE_TOKEN, descriptor.value, task.Out());
}
} // namespace capslang::app
