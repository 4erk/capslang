#include "installer.hpp"
#include "../runtime/engine_client.hpp"
#include "control.hpp"
#include "firewall.hpp"
#include "install_store.hpp"
#include "tasks.hpp"
#include <bcrypt.h>
#include <shellapi.h>

namespace capslang::app {
namespace {
struct ComApartment {
    HRESULT result = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    ~ComApartment() {
        if (SUCCEEDED(result))
            CoUninitialize();
    }
};
struct Handle {
    HANDLE value = INVALID_HANDLE_VALUE;
    explicit Handle(HANDLE v = INVALID_HANDLE_VALUE) : value(v) {}
    ~Handle() {
        if (value && value != INVALID_HANDLE_VALUE)
            CloseHandle(value);
    }
    Handle(const Handle &) = delete;
};
bool Missing(DWORD error) { return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND; }
bool Exists(const std::wstring &path) {
    return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}
// Scheduler may return a success-severity warning for partially registered
// triggers. Only full S_OK is sufficient for a durable logon installation.
DWORD Hr(HRESULT hr) { return hr == S_OK ? 0 : static_cast<DWORD>(hr); }
std::wstring Root(const std::wstring &exe) { return exe.substr(0, exe.find_last_of(L'\\')); }
bool SameFile(const std::wstring &path, const install::Hash &hash, DWORD &error) {
    install::Hash actual{};
    if (!ProtectedPath(path, false, error) || !install::FileHash(path, actual, error))
        return false;
    if (actual != hash) {
        error = ERROR_CRC;
        return false;
    }
    return true;
}
bool StopOwnedSaver(const std::wstring &executable, DWORD &error) {
    // Leave the separately installed old Guard alone. Stop only our own
    // embedded parent; its watchdog restores the lease if the desktop is busy.
    HWND saver = FindWindowW(L"CapsLang.MwbSaverGuard", nullptr);
    if (saver) {
        DWORD pid = 0;
        GetWindowThreadProcessId(saver, &pid);
        Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid));
        wchar_t path[32768]{};
        DWORD length = ARRAYSIZE(path);
        if (process.value && process.value != INVALID_HANDLE_VALUE &&
            QueryFullProcessImageNameW(process.value, 0, path, &length) &&
            _wcsicmp(path, executable.c_str()) == 0) {
            if (!PostMessageW(saver, WM_APP + 30, 0, 0) ||
                WaitForSingleObject(process.value, 5000) != WAIT_OBJECT_0) {
                error = ERROR_TIMEOUT;
                return false;
            }
        }
    }
    error = 0;
    return true;
}
bool StopManaged(const std::wstring &executable, DWORD &error) {
    ControlRequest control;
    control.id = GetTickCount64() + 1;
    control.command = Command::Stop;
    ControlResponse status;
    const bool broker = ControlCall(executable, control, status, error);
    if ((broker && status.error) || (!broker && !Missing(error) && error != ERROR_BROKEN_PIPE &&
                                     error != ERROR_PIPE_NOT_CONNECTED)) {
        if (broker)
            error = status.error;
        return false;
    }
    if (!broker) {
        ipc::Request stop;
        stop.id = GetTickCount64() + 1;
        stop.operation = ipc::Operation::Stop;
        ipc::Response response;
        if (!ipc::Call(ipc::Endpoint::Current(), executable, true, stop, response, error) &&
            !Missing(error) && error != ERROR_BROKEN_PIPE && error != ERROR_PIPE_NOT_CONNECTED)
            return false;
    }
    const auto deadline = GetTickCount64() + 10000;
    do {
        control.command = Command::Status;
        control.id++;
        DWORD brokerError = 0, engineError = 0;
        const bool b = ControlCall(executable, control, status, brokerError);
        ipc::Request query;
        query.id = control.id;
        ipc::Response response;
        const bool e =
            ipc::Call(ipc::Endpoint::Current(), executable, true, query, response, engineError);
        // The broker maintains the Guard. Stop it first so maintenance cannot
        // respawn the Guard while the installed image is being replaced.
        if (!b && !e && Missing(brokerError) && Missing(engineError))
            return StopOwnedSaver(executable, error);
        if ((!b && brokerError == ERROR_ACCESS_DENIED) ||
            (!e && engineError == ERROR_ACCESS_DENIED)) {
            error = ERROR_ACCESS_DENIED;
            return false;
        }
        Sleep(50);
    } while (GetTickCount64() < deadline);
    error = ERROR_TIMEOUT;
    return false;
}
bool ArchiveInstalled(const std::wstring &executable, DWORD &error) {
    if (!Exists(executable)) {
        error = 0;
        return true;
    }
    if (!ProtectedExecutable(executable, error))
        return false;
    install::Hash hash{};
    if (!install::FileHash(executable, hash, error))
        return false;
    BYTE nonce[8]{};
    if (BCryptGenRandom(nullptr, nonce, sizeof(nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG)) {
        error = ERROR_GEN_FAILURE;
        return false;
    }
    auto path = Root(executable) + L"\\retired-" + install::Hex(hash) + L"-";
    for (BYTE b : nonce) {
        path += L"0123456789abcdef"[b >> 4];
        path += L"0123456789abcdef"[b & 15];
    }
    path += L".disabled";
    if (!MoveFileExW(executable.c_str(), path.c_str(), MOVEFILE_WRITE_THROUGH)) {
        error = GetLastError();
        return false;
    }
    error = 0;
    return true;
}
bool StartRoles(Tasks &tasks, const std::wstring &executable, const ipc::Endpoint &user,
                DWORD &error) {
    if ((error = Hr(tasks.Start(TaskRole::Engine, executable, user.sid, user.session))))
        return false;
    EngineClient engine(executable);
    ipc::Response response;
    const auto deadline = GetTickCount64() + 12000;
    bool healthy = false;
    do {
        if (engine.Read(response) && (response.flags & 7U) == 7U && !response.hookError) {
            healthy = true;
            break;
        }
        Sleep(100);
    } while (GetTickCount64() < deadline);
    if (!healthy) {
        error = engine.Error() ? engine.Error() : ERROR_NOT_READY;
        return false;
    }
    if ((error = Hr(tasks.Start(TaskRole::Broker, executable, user.sid, user.session))))
        return false;
    ControlRequest query;
    query.id = 1;
    ControlResponse state;
    const auto brokerDeadline = GetTickCount64() + 12000;
    do {
        query.id++;
        if (ControlCall(executable, query, state, error) && !state.error &&
            !state.status.engineError && state.status.sampled &&
            GetTickCount64() - state.status.sampled < 3000 &&
            (state.status.engine.flags & 7U) == 7U &&
            state.status.networkPhase != static_cast<DWORD>(net::NetworkPhase::Starting) &&
            state.status.networkPhase != static_cast<DWORD>(net::NetworkPhase::Error) &&
            state.status.networkPhase != static_cast<DWORD>(net::NetworkPhase::Stopped)) {
            error = 0;
            return true;
        }
        Sleep(100);
    } while (GetTickCount64() < brokerDeadline);
    if (!error)
        error = ERROR_NOT_READY;
    return false;
}
bool RollBack(Tasks &tasks, const std::wstring &executable, const ipc::Endpoint &user,
              install::Record &record, DWORD &error) {
    const auto root = Root(executable);
    if (!StopManaged(executable, error))
        return false;
    if (record.hadExecutable) {
        const auto backup = root + L"\\rollback-" + install::Hex(record.before) + L".exe";
        if (!SameFile(backup, record.before, error))
            return false;
        install::Hash current{};
        if (!Exists(executable) || !install::FileHash(executable, current, error) ||
            current != record.before) {
            if (!ArchiveInstalled(executable, error))
                return false;
            install::Hash copied{};
            if (!install::CopyProtected(backup, executable, copied, error) ||
                copied != record.before)
                return false;
        }
    }
    // Restore/remove only definitions captured after ownership+ACL validation.
    if ((error = Hr(tasks.Restore(TaskRole::Engine, executable, user.sid, record.engineXml,
                                  record.engineSecurity))) ||
        (error = Hr(tasks.Restore(TaskRole::Broker, executable, user.sid, record.brokerXml,
                                  record.brokerSecurity))))
        return false;
    if (!record.hadRule && (error = Hr(RemoveFirewallRule(executable, user.sid))))
        return false;
    if (!record.hadExecutable && !ArchiveInstalled(executable, error))
        return false;
    record.phase = install::Phase::RolledBack;
    if (!install::SaveRecord(root, record, error))
        return false;
    if (record.hadExecutable && !record.engineXml.empty() && !record.brokerXml.empty())
        return StartRoles(tasks, executable, user, error);
    error = 0;
    return true;
}
bool Owner(const std::wstring &root, const ipc::Endpoint &user, DWORD &error) {
    const auto path = root + L"\\owner.bin";
    std::vector<BYTE> bytes;
    const auto text = L"CapsLang protected installation v1\n" + user.sid;
    const auto *begin = reinterpret_cast<const BYTE *>(text.data());
    const std::vector<BYTE> expected(begin, begin + text.size() * sizeof(wchar_t));
    if (Exists(path))
        return install::ReadProtected(path, bytes, error) &&
               (bytes == expected || (error = ERROR_ACCESS_DENIED, false));
    // Never adopt somebody else's populated Program Files directory.
    WIN32_FIND_DATAW entry{};
    HANDLE find = FindFirstFileW((root + L"\\*").c_str(), &entry);
    bool empty = true;
    if (find != INVALID_HANDLE_VALUE) {
        do {
            if (wcscmp(entry.cFileName, L".") && wcscmp(entry.cFileName, L".."))
                empty = false;
        } while (FindNextFileW(find, &entry));
        FindClose(find);
    }
    if (!empty) {
        error = ERROR_ALREADY_EXISTS;
        return false;
    }
    return install::WriteProtected(path, expected, false, error);
}
DWORD ElevatedChild(AdminAction action) {
    const auto executable = ExecutablePath();
    const wchar_t *args = action == AdminAction::Install  ? L"--admin-install"
                          : action == AdminAction::Revert ? L"--admin-revert"
                                                          : L"--admin-uninstall";
    SHELLEXECUTEINFOW execute{};
    execute.cbSize = sizeof(execute);
    execute.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    execute.lpVerb = L"runas";
    execute.lpFile = executable.c_str();
    execute.lpParameters = args;
    execute.nShow = SW_HIDE;
    if (!ShellExecuteExW(&execute))
        return GetLastError();
    Handle process(execute.hProcess);
    const auto deadline = GetTickCount64() + 120000;
    while (WaitForSingleObject(process.value, 250) == WAIT_TIMEOUT) {
        MSG msg{};
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        if (GetTickCount64() > deadline)
            return ERROR_IO_PENDING;
    }
    DWORD code = 0;
    return GetExitCodeProcess(process.value, &code) ? code : GetLastError();
}
} // namespace
DWORD AdminInstall(AdminAction action) {
    const auto elevation = ProcessElevation(GetCurrentProcessId());
    if (!elevation.known || !elevation.elevated)
        return ERROR_ACCESS_DENIED;
    const auto user = ipc::Endpoint::Current();
    if (user.error || !user.session)
        return ERROR_ACCESS_DENIED;
    ComApartment apartment;
    if (FAILED(apartment.result))
        return static_cast<DWORD>(apartment.result);
    DWORD error = 0;
    const auto executable = InstalledExecutable(error);
    if (executable.empty())
        return error;
    const auto root = Root(executable);
    if (action != AdminAction::Install && !Exists(root))
        return 0;
    if (!install::CreateRoot(root, error) || !Owner(root, user, error))
        return error;
    // No named mutex can be pre-created by a lower-privileged process: this
    // exclusive lock lives inside the already authenticated protected root.
    const auto lockPath = root + L"\\install.lock";
    if (!Exists(lockPath) && !install::WriteProtected(lockPath, {0}, false, error))
        return error;
    if (!ProtectedPath(lockPath, false, error))
        return error;
    Handle lock(CreateFileW(lockPath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                            OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (lock.value == INVALID_HANDLE_VALUE)
        return GetLastError();
    Tasks tasks;
    install::Record previous;
    const bool journal = install::LoadRecord(root, previous, error);
    if (!journal && !Missing(error))
        return error;
    if (journal && previous.sid != user.sid)
        return ERROR_ACCESS_DENIED;
    if (journal && (previous.phase == install::Phase::Prepared ||
                    previous.phase == install::Phase::Applying)) {
        if (!RollBack(tasks, executable, user, previous, error))
            return error;
    }
    if (action == AdminAction::Revert) {
        if (!journal)
            return ERROR_NOT_FOUND;
        return RollBack(tasks, executable, user, previous, error) ? 0 : error;
    }
    if (action == AdminAction::Uninstall) {
        if (!StopManaged(executable, error))
            return error;
        if ((error = Hr(tasks.Remove(TaskRole::Engine, executable, user.sid))) ||
            (error = Hr(tasks.Remove(TaskRole::Broker, executable, user.sid))) ||
            (error = Hr(RemoveFirewallRule(executable, user.sid))))
            return error;
        if (!ArchiveInstalled(executable, error))
            return error;
        if (journal) {
            previous.phase = install::Phase::Removed;
            if (!install::SaveRecord(root, previous, error))
                return error;
        }
        return 0;
    }
    // The ordinary coordinator is responsible for stopping user-owned 1.0.0.
    // Elevated code never executes or overwrites that profile binary.
    if (FindWindowW(L"CapsLang.Reliable.HiddenWindow.1", nullptr))
        return ERROR_BUSY;
    install::Record record;
    record.sid = user.sid;
    record.hadExecutable = Exists(executable);
    bool existed = false;
    if ((error = Hr(tasks.Read(TaskRole::Engine, executable, user.sid, existed, record.engineXml,
                               record.engineSecurity))) ||
        (error = Hr(tasks.Read(TaskRole::Broker, executable, user.sid, existed, record.brokerXml,
                               record.brokerSecurity))) ||
        (error = Hr(ReadFirewallRule(executable, user.sid, record.hadRule))))
        return error;
    if (record.hadExecutable) {
        if (!ProtectedExecutable(executable, error) ||
            !install::FileHash(executable, record.before, error))
            return error;
        install::Hash copied{};
        if (!install::CopyProtected(executable,
                                    root + L"\\rollback-" + install::Hex(record.before) + L".exe",
                                    copied, error))
            return error;
    }
    const auto source = ExecutablePath();
    if (!install::FileHash(source, record.after, error))
        return error;
    const auto candidate = root + L"\\candidate-" + install::Hex(record.after) + L".exe";
    install::Hash copied{};
    if (!install::CopyProtected(source, candidate, copied, error) || copied != record.after)
        return error ? error : ERROR_CRC;
    if (!install::SaveRecord(root, record, error))
        return error;
    auto apply = [&]() {
        record.phase = install::Phase::Applying;
        if (!install::SaveRecord(root, record, error) || !StopManaged(executable, error))
            return false;
        if (!ArchiveInstalled(executable, error))
            return false;
        if (!install::CopyProtected(candidate, executable, copied, error) ||
            copied != record.after) {
            if (!error)
                error = ERROR_CRC;
            return false;
        }
        if ((error = Hr(tasks.Register(TaskRole::Engine, executable, user.sid))) ||
            (error = Hr(tasks.Register(TaskRole::Broker, executable, user.sid))) ||
            (error = Hr(EnsureFirewallRule(executable, user.sid))) ||
            !StartRoles(tasks, executable, user, error))
            return false;
        record.phase = install::Phase::Committed;
        return install::SaveRecord(root, record, error);
    };
    if (apply())
        return 0;
    const DWORD cause = error ? error : ERROR_GEN_FAILURE;
    DWORD rollbackError = 0;
    if (!RollBack(tasks, executable, user, record, rollbackError))
        return rollbackError ? rollbackError : ERROR_GEN_FAILURE;
    return cause;
}
DWORD UserInstall(UserAction action) {
    const auto elevation = ProcessElevation(GetCurrentProcessId());
    if (!elevation.known || elevation.elevated)
        return ERROR_ACCESS_DENIED;
    if (action == UserAction::Install) {
        DWORD error = PrepareMigration();
        if (error) {
            AbortMigration();
            return error;
        }
        error = ElevatedChild(AdminAction::Install);
        if (error) {
            if (error != ERROR_IO_PENDING)
                AbortMigration();
            return error;
        }
        error = CompleteMigration();
        if (error) {
            const auto reverted = ElevatedChild(AdminAction::Revert);
            if (!reverted)
                AbortMigration();
            return error;
        }
        return 0;
    }
    if (action == UserAction::Rollback || action == UserAction::RestoreLegacy) {
        const auto ready = CheckRestoreAvailable(action == UserAction::RestoreLegacy);
        if (ready)
            return ready;
    }
    const DWORD error = ElevatedChild(AdminAction::Uninstall);
    if (error)
        return error;
    return action == UserAction::Rollback        ? RestorePreviousUserVersion(false)
           : action == UserAction::RestoreLegacy ? RestorePreviousUserVersion(true)
                                                 : 0;
}
DWORD RestartInstalled() {
    ComApartment apartment;
    if (FAILED(apartment.result))
        return static_cast<DWORD>(apartment.result);
    DWORD error = 0;
    const auto executable = InstalledExecutable(error);
    const auto user = ipc::Endpoint::Current();
    if (user.error || !user.session)
        return ERROR_ACCESS_DENIED;
    if (executable.empty() || !ProtectedExecutable(executable, error))
        return error;
    if (!StopManaged(executable, error))
        return error;
    Tasks tasks;
    return StartRoles(tasks, executable, user, error) ? 0 : error;
}
DWORD EnsureInstalledEngine() {
    ComApartment apartment;
    if (FAILED(apartment.result))
        return static_cast<DWORD>(apartment.result);
    DWORD error = 0;
    const auto executable = InstalledExecutable(error);
    const auto user = ipc::Endpoint::Current();
    if (user.error || !user.session)
        return ERROR_ACCESS_DENIED;
    if (executable.empty() || !ProtectedExecutable(executable, error))
        return error;
    EngineClient engine(executable);
    ipc::Response status;
    Tasks tasks;
    const auto deadline = GetTickCount64() + 12000;
    ULONGLONG nextStart = 0;
    do {
        if (engine.Read(status))
            return 0;
        const DWORD cause = engine.Error();
        // Logon triggers can run in either order. An acquired pipe with an
        // engine still initializing is not a failed installation. Wait for
        // readiness, never turn a normal startup race into a one-minute outage.
        if (Missing(cause) && GetTickCount64() >= nextStart) {
            error = Hr(tasks.Start(TaskRole::Engine, executable, user.sid, user.session));
            if (error)
                return error;
            nextStart = GetTickCount64() + 1000;
        } else if (!Missing(cause) && cause != ERROR_NOT_READY && cause != ERROR_PIPE_BUSY &&
                   cause != ERROR_BROKEN_PIPE && cause != ERROR_PIPE_NOT_CONNECTED &&
                   cause != ERROR_TIMEOUT)
            return cause;
        Sleep(50);
    } while (GetTickCount64() < deadline);
    return ERROR_TIMEOUT;
}
} // namespace capslang::app
