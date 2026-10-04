#include "../src/app/broker.hpp"
#include "../src/app/firewall.hpp"
#include "../src/app/install_store.hpp"
#include "../src/app/installer.hpp"
#include "../src/app/paths.hpp"
#include "../src/app/tasks.hpp"
#include "../src/platform/private_store.hpp"
#include <atomic>
#include <bcrypt.h>
#include <cstdio>

using namespace capslang;
using namespace capslang::app;
namespace {
unsigned checks = 0, failures = 0;
void Check(bool yes, const char *name) {
    ++checks;
    if (!yes) {
        ++failures;
        std::printf("FAIL %s error=%lu\n", name, GetLastError());
    }
}
template <class P> bool Until(P predicate) {
    const auto end = GetTickCount64() + 6000;
    do {
        if (predicate())
            return true;
        Sleep(10);
    } while (GetTickCount64() < end);
    return predicate();
}
struct Scratch {
    std::wstring path;
    Scratch() {
        wchar_t temp[32768]{};
        BYTE nonce[16]{};
        if (!GetTempPathW(ARRAYSIZE(temp), temp) ||
            BCryptGenRandom(nullptr, nonce, sizeof(nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG))
            return;
        std::wstring root = std::wstring(temp) + L"CapsLang-app-test-";
        for (BYTE v : nonce) {
            root += L"0123456789abcdef"[v >> 4];
            root += L"0123456789abcdef"[v & 15];
        }
        if (CreateDirectoryW(root.c_str(), nullptr))
            path = root;
    }
    ~Scratch() {
        if (path.empty())
            return;
        DWORD error = 0;
        net::Identity identity;
        if (identity.Load(path + L"\\identity.dat", error))
            Check(identity.Erase(error), "fixture key removed");
        net::RemovePair(path + L"\\pair.dat", error);
        DeleteFileW((path + L"\\capslang.log").c_str());
        DeleteFileW((path + L"\\capslang.log.1").c_str());
        Check(RemoveDirectoryW(path.c_str()) != FALSE,
              "fixture removed without recursive deletion");
    }
};
void Codec() {
    ControlRequest r;
    r.id = 1;
    Check(Valid(r), "status request valid");
    for (Command c : {Command::Status, Command::Show, Command::Refresh, Command::Stop,
                      Command::Pairing, Command::Unpair}) {
        r.command = c;
        Check(Valid(r), "fixed command accepted");
        r.text[0] = 'x';
        Check(!Valid(r), "fixed command refuses payload");
        r.text[0] = 0;
    }
    r = {};
    r.id = 1;
    r.magic ^= 1;
    Check(!Valid(r), "bad magic");
    r = {};
    r.id = 1;
    r.version++;
    Check(!Valid(r), "bad version");
    r = {};
    Check(!Valid(r), "missing id");
    r.id = 1;
    r.reserved = 1;
    Check(!Valid(r), "reserved fields");
    r = {};
    r.id = 1;
    r.command = static_cast<Command>(999);
    Check(!Valid(r), "no arbitrary command");
    r.command = Command::Invite;
    r.port = 42519;
    strcpy_s(r.text, "4ERK-PC");
    Check(Valid(r), "invite host and port");
    r.port = 65536;
    Check(!Valid(r), "port overflow");
    r.port = 443;
    Check(!Valid(r), "privileged port");
    r.port = 42519;
    r.text[30] = 'x';
    Check(!Valid(r), "nonzero tail rejected");
    memset(r.text, 'a', sizeof(r.text));
    Check(!Valid(r), "unterminated text rejected");
    r = {};
    r.id = 1;
    r.command = Command::Join;
    strcpy_s(r.text, "not a code");
    Check(!Valid(r), "malformed join proof");
    r = {};
    r.id = 1;
    r.command = Command::Confirm;
    r.ticket = 1;
    r.peer[0] = 1;
    r.allow = 1;
    Check(Valid(r), "exact peer approval");
    r.ticket = 0;
    Check(!Valid(r), "no approval without ticket");
    r.ticket = 1;
    r.allow = 2;
    Check(!Valid(r), "unknown confirmation rejected");
    PublicStatus status;
    status.sampled = 100;
    const auto json = StatusJson(status, 200);
    Check(json.find("\"fresh\":true") != std::string::npos, "freshness explicit");
    Check(StatusJson(status, 4000).find("\"fresh\":false") != std::string::npos,
          "stale not represented as live");
    Check(StatusJson(status, 90).find("\"fresh\":false") != std::string::npos,
          "future timestamp rejected");
    Check(json.find("invitation") == std::string::npos &&
              json.find("secret") == std::string::npos && json.find("window") == std::string::npos,
          "diagnostic allowlist excludes secret and window data");
    DWORD error = 0;
    Check(!ProtectedExecutable(ExecutablePath(), error) && error == ERROR_ACCESS_DENIED,
          "unprotected developer executable cannot become privileged engine");
}
void InstallationRecords() {
    install::Record record;
    record.sid = ipc::Endpoint::Current().sid;
    record.after[0] = 1;
    std::vector<BYTE> bytes;
    install::Record decoded;
    Check(install::Encode(record, bytes) && install::Decode(bytes, decoded) &&
              decoded.sid == record.sid && decoded.after == record.after,
          "durable installation journal roundtrip");
    for (size_t i = 0; i < bytes.size(); ++i) {
        auto corrupt = bytes;
        corrupt[i] ^= 1;
        Check(!install::Decode(corrupt, decoded), "every single-byte journal corruption refused");
    }
    for (size_t length : {size_t(0), size_t(4), bytes.size() - 1}) {
        auto shortRecord = bytes;
        shortRecord.resize(length);
        Check(!install::Decode(shortRecord, decoded), "partial durable journal refused");
    }
    auto extra = bytes;
    extra.push_back(0);
    Check(!install::Decode(extra, decoded), "journal trailing data refused");
    record.phase = static_cast<install::Phase>(900);
    Check(!install::Encode(record, bytes), "unknown installation phase refused");
    record.phase = install::Phase::Prepared;
    record.hadExecutable = true;
    Check(!install::Encode(record, bytes), "rollback requires prior executable digest");
    record.before[0] = 2;
    record.engineXml = L"owned fixture";
    Check(!install::Encode(record, bytes), "task snapshot requires ACL");
    record.engineSecurity = L"owned ACL";
    Check(install::Encode(record, bytes) && install::Decode(bytes, decoded) &&
              decoded.before == record.before,
          "previous executable and owned task metadata preserved");
    if (!ProcessElevation(GetCurrentProcessId()).elevated)
        Check(AdminInstall(AdminAction::Install) == ERROR_ACCESS_DENIED,
              "ordinary code cannot enter administrative installation");
    const HRESULT initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    Check(SUCCEEDED(initialized), "COM initialized for in-memory firewall definition");
    if (SUCCEEDED(initialized)) {
        DWORD error = 0;
        const auto executable = InstalledExecutable(error);
        INetFwRule *rule = nullptr;
        const auto hr = BuildFirewallRule(executable, record.sid, &rule);
        Check(SUCCEEDED(hr) && rule, "firewall definition built without registration");
        if (rule) {
            Check(MatchesFirewallRule(rule, executable, record.sid),
                  "firewall exact executable, TCP port, LocalSubnet, all profiles, no edge "
                  "traversal");
            BSTR all = SysAllocString(L"*");
            rule->put_RemoteAddresses(all);
            SysFreeString(all);
            Check(!MatchesFirewallRule(rule, executable, record.sid),
                  "broad remote-address rule cannot be adopted");
            rule->Release();
        }
        CoUninitialize();
    }
}
void TaskDefinitions() {
    const auto endpoint = ipc::Endpoint::Current();
    const auto sid = endpoint.sid;
    const auto acl = TaskSecurity(sid);
    Check(!acl.empty() && SafeTaskSecurity(acl, sid),
          "task ACL: Administrators owner, user read+execute only");
    Check(!SafeTaskSecurity(L"O:" + sid + L"D:(A;;FA;;;BA)(A;;FRFX;;;" + sid + L")", sid),
          "task cannot be owned by ordinary user");
    Check(!SafeTaskSecurity(L"O:BAD:(A;;FA;;;BA)(A;;FA;;;" + sid + L")", sid),
          "user cannot modify high task");
    Check(!SafeTaskSecurity(L"O:BAD:(A;;FA;;;BA)(A;;FA;;;WD)(A;;FRFX;;;" + sid + L")", sid),
          "world write task refused");
    Check(!SafeTaskSecurity(L"O:BAD:(A;;FA;;;BA)", sid), "user must be able to run installed task");
    const HRESULT initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    Check(SUCCEEDED(initialized), "COM initialized for in-memory native task definition");
    if (FAILED(initialized))
        return;
    ITaskService *service = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_ITaskService, reinterpret_cast<void **>(&service));
    Check(SUCCEEDED(hr), "native scheduler service object");
    if (service) {
        VARIANT empty{};
        VariantInit(&empty);
        hr = service->Connect(empty, empty, empty, empty);
        Check(SUCCEEDED(hr), "read-only scheduler connection");
        for (auto role : {TaskRole::Engine, TaskRole::Broker}) {
            ITaskDefinition *task = nullptr;
            const std::wstring path = L"C:\\Program Files\\CapsLang\\CapsLang.exe";
            hr = BuildTaskDefinition(service, path, sid, role, &task);
            Check(SUCCEEDED(hr) && task, "native fixed task definition built without registration");
            if (!task)
                continue;
            Check(MatchesTaskDefinition(task, path, sid, role),
                  "definition matches exact protected path, SID and role");
            Check(!MatchesTaskDefinition(task, path, sid,
                                         role == TaskRole::Engine ? TaskRole::Broker
                                                                  : TaskRole::Engine),
                  "cross-role privilege confusion rejected");
            Check(!MatchesTaskDefinition(task, L"C:\\other.exe", sid, role),
                  "foreign binary definition rejected");
            ITaskSettings *settings = nullptr;
            task->get_Settings(&settings);
            VARIANT_BOOL battery = VARIANT_TRUE, stop = VARIANT_TRUE;
            BSTR time = nullptr;
            Check(settings && SUCCEEDED(settings->get_DisallowStartIfOnBatteries(&battery)) &&
                      !battery && SUCCEEDED(settings->get_StopIfGoingOnBatteries(&stop)) && !stop &&
                      SUCCEEDED(settings->get_ExecutionTimeLimit(&time)) && time &&
                      wcscmp(time, L"PT0S") == 0,
                  "battery-safe and no runtime limit");
            SysFreeString(time);
            if (settings)
                settings->Release();
            IPrincipal *principal = nullptr;
            task->get_Principal(&principal);
            TASK_RUNLEVEL_TYPE level = TASK_RUNLEVEL_LUA;
            TASK_LOGON_TYPE logon = TASK_LOGON_NONE;
            Check(principal && SUCCEEDED(principal->get_RunLevel(&level)) &&
                      level ==
                          (role == TaskRole::Engine ? TASK_RUNLEVEL_HIGHEST : TASK_RUNLEVEL_LUA) &&
                      SUCCEEDED(principal->get_LogonType(&logon)) &&
                      logon == TASK_LOGON_INTERACTIVE_TOKEN,
                  "interactive SID, correct elevation, no password or SYSTEM");
            if (principal)
                principal->Release();
            BSTR xml = nullptr;
            task->get_XmlText(&xml);
            Check(xml && wcsstr(xml, L"$(Arg") == nullptr,
                  "no parameter substitution in task action");
            SysFreeString(xml);
            IRegistrationInfo *info = nullptr;
            task->get_RegistrationInfo(&info);
            if (info) {
                BSTR source = SysAllocString(L"foreign");
                info->put_Source(source);
                SysFreeString(source);
                info->Release();
            }
            Check(!MatchesTaskDefinition(task, path, sid, role), "unmarked task cannot be adopted");
            task->Release();
        }
        ITaskDefinition *invalid = nullptr;
        Check(FAILED(BuildTaskDefinition(service, L"C:\\Users\\$(Arg0).exe", sid, TaskRole::Engine,
                                         &invalid)),
              "task macros refused before definition creation");
        service->Release();
    }
    CoUninitialize();
}
void Lifecycle() {
    Scratch scratch;
    Check(!scratch.path.empty(), "unique app fixture directory");
    if (scratch.path.empty())
        return;
    std::atomic<unsigned> refreshes{0}, stops{0};
    BrokerDependencies deps{[](ipc::Response &out, DWORD &error) {
                                out = {};
                                out.engineEpoch = 1;
                                out.target = out.actual = 0x409;
                                out.apply = 2;
                                out.flags = ipc::HookRegistered | ipc::HookResponsive;
                                error = 0;
                                return true;
                            },
                            [&refreshes, &stops](ipc::Operation operation, DWORD &error) {
                                if (operation == ipc::Operation::Stop) {
                                    ++stops;
                                    error = 0;
                                    return true;
                                }
                                if (operation != ipc::Operation::RefreshHook) {
                                    error = ERROR_ACCESS_DENIED;
                                    return false;
                                }
                                ++refreshes;
                                error = 0;
                                return true;
                            },
                            {[](sync::LocalState &value) {
                                 value = {{1, 0, 0, core::Language::English, {}, false},
                                          core::Language::English,
                                          core::ApplyState::Applied,
                                          false};
                                 return true;
                             },
                             [](const sync::ApplyCommand &) { return false; },
                             {}}};
    const auto endpoint =
        ipc::Endpoint::Current(L"app-test-" + std::to_wstring(GetCurrentProcessId()));
    Broker broker(scratch.path, deps, endpoint);
    if (ProcessElevation(GetCurrentProcessId()).elevated) {
        Check(!broker.Start() && broker.Error() == ERROR_ACCESS_DENIED,
              "ordinary broker refuses elevated token");
        return;
    }
    Check(broker.Start() && broker.Start(), "broker starts idempotently");
    Check(Until([&] {
              const auto s = broker.Snapshot();
              return s.status.sampled &&
                     s.status.networkPhase == static_cast<unsigned>(net::NetworkPhase::Unpaired);
          }),
          "cache populated independently of UI");
    Broker duplicate(scratch.path, deps, endpoint);
    Check(!duplicate.Start(), "second broker cannot own same endpoint");
    ControlRequest request;
    request.id = 1;
    ControlResponse response;
    DWORD error = 0;
    Check(ControlCall(ExecutablePath(), request, response, error, endpoint) && !response.error &&
              !response.status.engineError,
          "real authenticated local control status");
    Check(!response.invitation[0] && !response.ticket && net::EqualPin(response.local, {}),
          "public status no pairing fields");
    Check(!ControlCall(L"C:\\wrong.exe", request, response, error, endpoint) &&
              error == ERROR_ACCESS_DENIED,
          "control refuses foreign executable");
    request.command = Command::Show;
    ++request.id;
    Check(ControlCall(ExecutablePath(), request, response, error, endpoint) && !response.error,
          "second launch requests primary UI");
    Check(broker.TakeShowRequest() && !broker.TakeShowRequest(), "show request consumed once");
    request.command = Command::Refresh;
    ++request.id;
    Check(broker.Submit(request, error), "refresh queued outside IPC callback");
    Check(Until([&] { return refreshes == 1; }), "fixed command executed once");
    request.command = Command::Pairing;
    ++request.id;
    Check(ControlCall(ExecutablePath(), request, response, error, endpoint) && !response.error &&
              !net::EqualPin(response.local, {}),
          "explicit pairing view contains public local pin");
    request = {};
    request.id = 7;
    request.command = static_cast<Command>(900);
    Check(ipc::Exchange(endpoint, ExecutablePath(), false, &request, sizeof(request), &response,
                        sizeof(response), error) &&
              response.error == ERROR_INVALID_DATA,
          "server rejects malformed control before dispatch");
    request = {};
    request.id = 8;
    request.command = Command::Unpair;
    Check(broker.Submit(request, error), "unpair accepted even already unpaired");
    Check(Until([&] { return !broker.Snapshot().status.commandError; }), "no hidden unpair error");
    const auto json = StatusJson(broker.Snapshot().status, GetTickCount64());
    std::wstring exported;
    Check(ExportDiagnosis(scratch.path, json, exported, error),
          "diagnosis writes exclusively new fixed-name file");
    if (!exported.empty())
        Check(DeleteFileW(exported.c_str()) != FALSE, "exact owned diagnostic fixture removed");
    broker.Stop();
    Check(WaitForSingleObject(broker.Stopped(), 0) == WAIT_OBJECT_0, "broker completion signaled");
    Check(stops == 0, "broker teardown alone does not stop independent engine");
    Check(broker.Start() && Until([&] { return !broker.Snapshot().error; }),
          "broker restarts after complete stop");
    request = {};
    request.id = 9;
    request.command = Command::Stop;
    Check(broker.Submit(request, error), "stop request queued");
    Check(WaitForSingleObject(broker.Stopped(), 3000) == WAIT_OBJECT_0,
          "normal stop ends network without UI or hook wait");
    Check(stops == 1, "explicit app stop also stops engine exactly once");
    broker.Stop();
    broker.Stop();
}
} // namespace
int main() {
    Codec();
    InstallationRecords();
    TaskDefinitions();
    Lifecycle();
    std::printf("Application: %u checks, %u failures; model engine, isolated files, no "
                "hooks/autostart/firewall changes.\n",
                checks, failures);
    return failures ? 1 : 0;
}
