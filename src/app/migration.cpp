#include "../platform/private_store.hpp"
#include "control.hpp"
#include "install_store.hpp"
#include "installer.hpp"
#include <shlobj.h>
#include <tlhelp32.h>

namespace capslang::app {
namespace {
constexpr wchar_t kRun[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
constexpr DWORD HadRun = 1, HadExe = 2, Pending = 4, WasRunning = 8, HadLegacy = 16,
                LegacyRunning = 32;
struct Migration {
    DWORD flags = 0;
    install::Hash hash{};
};
bool Ordinary() {
    const auto e = ProcessElevation(GetCurrentProcessId());
    return e.known && !e.elevated;
}
bool Exists(const std::wstring &path) {
    return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}
std::wstring OldExe(const std::wstring &root) { return root + L"\\CapsLang.exe"; }
std::wstring Backup(const std::wstring &root) { return root + L"\\CapsLang-1.0.0.rollback.exe"; }
std::wstring ExpectedRun(const std::wstring &root) {
    return L"\"" + OldExe(root) + L"\" --background";
}
bool ReadRun(std::wstring &command, bool &present, DWORD &error) {
    present = false;
    command.clear();
    DWORD bytes = 0, type = 0;
    LONG result =
        RegGetValueW(HKEY_CURRENT_USER, kRun, L"CapsLang", RRF_RT_REG_SZ, &type, nullptr, &bytes);
    if (result == ERROR_FILE_NOT_FOUND) {
        error = 0;
        return true;
    }
    if (result != ERROR_SUCCESS) {
        error = result;
        return false;
    }
    if (bytes < sizeof(wchar_t) || bytes > 32768 || bytes % sizeof(wchar_t)) {
        error = ERROR_INVALID_DATA;
        return false;
    }
    std::vector<wchar_t> value(bytes / sizeof(wchar_t));
    result = RegGetValueW(HKEY_CURRENT_USER, kRun, L"CapsLang", RRF_RT_REG_SZ, &type, value.data(),
                          &bytes);
    if (result != ERROR_SUCCESS) {
        error = result;
        return false;
    }
    if (value.back() != 0) {
        error = ERROR_INVALID_DATA;
        return false;
    }
    command = value.data();
    present = true;
    error = 0;
    return true;
}
bool RunWrite(const std::wstring &value, DWORD &error) {
    HKEY key = nullptr;
    LONG result = RegCreateKeyExW(HKEY_CURRENT_USER, kRun, 0, nullptr, 0, KEY_SET_VALUE, nullptr,
                                  &key, nullptr);
    if (result != ERROR_SUCCESS) {
        error = result;
        return false;
    }
    result =
        RegSetValueExW(key, L"CapsLang", 0, REG_SZ, reinterpret_cast<const BYTE *>(value.c_str()),
                       static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(key);
    error = result;
    return !error;
}
bool Save(const std::wstring &root, const Migration &value, DWORD &error) {
    std::vector<BYTE> bytes{'C', 'L', 'M', 1};
    for (unsigned i = 0; i < 4; ++i)
        bytes.push_back(static_cast<BYTE>(value.flags >> (8 * i)));
    bytes.insert(bytes.end(), value.hash.begin(), value.hash.end());
    return SavePrivateData(root + L"\\migration.dat", bytes, true, error);
}
bool Load(const std::wstring &root, Migration &value, DWORD &error) {
    std::vector<BYTE> bytes;
    if (!LoadPrivateData(root + L"\\migration.dat", bytes, error))
        return false;
    if (bytes.size() != 40 || bytes[0] != 'C' || bytes[1] != 'L' || bytes[2] != 'M' ||
        bytes[3] != 1) {
        error = ERROR_INVALID_DATA;
        return false;
    }
    value = {};
    for (unsigned i = 0; i < 4; ++i)
        value.flags |= static_cast<DWORD>(bytes[4 + i]) << (8 * i);
    if (value.flags & ~63U) {
        error = ERROR_INVALID_DATA;
        return false;
    }
    memcpy(value.hash.data(), bytes.data() + 8, 32);
    error = 0;
    return true;
}
bool Launch(const std::wstring &path, const wchar_t *args, DWORD &error) {
    std::wstring line = L"\"" + path + L"\" " + args;
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(path.c_str(), line.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &startup, &process)) {
        error = GetLastError();
        return false;
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    error = 0;
    return true;
}
bool OldWindow(const std::wstring &root, HWND &window, HANDLE &process, DWORD &error) {
    window = FindWindowW(L"CapsLang.Reliable.HiddenWindow.1", nullptr);
    process = nullptr;
    if (!window) {
        error = 0;
        return true;
    }
    DWORD pid = 0;
    GetWindowThreadProcessId(window, &pid);
    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
    if (!process) {
        error = GetLastError();
        return false;
    }
    wchar_t path[32768]{};
    DWORD bytes = ARRAYSIZE(path), session = 0, current = 0;
    const bool match = QueryFullProcessImageNameW(process, 0, path, &bytes) &&
                       _wcsicmp(path, OldExe(root).c_str()) == 0 &&
                       ProcessIdToSessionId(pid, &session) &&
                       ProcessIdToSessionId(GetCurrentProcessId(), &current) && current == session;
    if (!match) {
        CloseHandle(process);
        process = nullptr;
        error = ERROR_ACCESS_DENIED;
        return false;
    }
    error = 0;
    return true;
}
bool Version100(const std::wstring &path) {
    DWORD ignored = 0;
    const DWORD count = GetFileVersionInfoSizeW(path.c_str(), &ignored);
    if (!count || count > 65536)
        return false;
    std::vector<BYTE> data(count);
    if (!GetFileVersionInfoW(path.c_str(), 0, count, data.data()))
        return false;
    VS_FIXEDFILEINFO *info = nullptr;
    UINT bytes = 0;
    return VerQueryValueW(data.data(), L"\\", reinterpret_cast<void **>(&info), &bytes) &&
           bytes >= sizeof(*info) && info->dwSignature == 0xfeef04bd &&
           info->dwFileVersionMS == 0x00010000 && info->dwFileVersionLS == 0;
}
} // namespace
std::wstring LegacyPath(DWORD &error) {
    PWSTR startup = nullptr;
    const HRESULT hr = SHGetKnownFolderPath(FOLDERID_Startup, 0, nullptr, &startup);
    if (FAILED(hr)) {
        error = static_cast<DWORD>(hr);
        return {};
    }
    std::wstring path = std::wstring(startup) + L"\\capslang-win-space.exe";
    CoTaskMemFree(startup);
    error = 0;
    return path;
}
bool LegacyProcesses(const std::wstring &path, bool stop, bool &running, DWORD &error) {
    running = false;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        error = GetLastError();
        return false;
    }
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    bool ok = true;
    if (Process32FirstW(snapshot, &entry))
        do {
            if (_wcsicmp(entry.szExeFile, L"capslang-win-space.exe"))
                continue;
            HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE |
                                             (stop ? PROCESS_TERMINATE : 0),
                                         FALSE, entry.th32ProcessID);
            if (!process) {
                error = GetLastError();
                ok = false;
                break;
            }
            wchar_t candidate[32768]{};
            DWORD size = ARRAYSIZE(candidate);
            const bool match = QueryFullProcessImageNameW(process, 0, candidate, &size) &&
                               !_wcsicmp(candidate, path.c_str());
            if (match) {
                running = true;
                if (stop) {
                    HANDLE threads = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                    THREADENTRY32 thread{};
                    thread.dwSize = sizeof(thread);
                    if (threads != INVALID_HANDLE_VALUE) {
                        if (Thread32First(threads, &thread))
                            do {
                                if (thread.th32OwnerProcessID == entry.th32ProcessID)
                                    PostThreadMessageW(thread.th32ThreadID, WM_HOTKEY, 0x21,
                                                       MAKELPARAM(MOD_ALT | MOD_CONTROL, 'L'));
                            } while (Thread32Next(threads, &thread));
                        CloseHandle(threads);
                    }
                    if (WaitForSingleObject(process, 2000) != WAIT_OBJECT_0 &&
                        (!TerminateProcess(process, 0) ||
                         WaitForSingleObject(process, 2000) != WAIT_OBJECT_0)) {
                        error = GetLastError();
                        if (!error)
                            error = ERROR_TIMEOUT;
                        ok = false;
                    }
                }
            }
            CloseHandle(process);
            if (!ok)
                break;
        } while (Process32NextW(snapshot, &entry));
    CloseHandle(snapshot);
    if (ok)
        error = 0;
    return ok;
}
bool NoManagedEngine(DWORD &error) {
    const auto installed = InstalledExecutable(error);
    if (installed.empty())
        return false;
    ipc::Request query;
    query.id = 1;
    ipc::Response response;
    if (ipc::Call(ipc::Endpoint::Current(), installed, true, query, response, error)) {
        error = ERROR_BUSY;
        return false;
    }
    if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND)
        return false;
    ControlRequest control;
    control.id = 1;
    ControlResponse state;
    if (ControlCall(installed, control, state, error)) {
        error = ERROR_BUSY;
        return false;
    }
    if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND)
        return false;
    error = 0;
    return true;
}
DWORD PrepareMigration() {
    if (!Ordinary())
        return ERROR_ACCESS_DENIED;
    DWORD error = 0;
    const auto root = DataDirectory(error);
    if (root.empty())
        return error;
    std::wstring run;
    bool present = false;
    if (!ReadRun(run, present, error))
        return error;
    if (present && _wcsicmp(run.c_str(), ExpectedRun(root).c_str()))
        return ERROR_ALREADY_EXISTS;
    const auto legacy = LegacyPath(error);
    if (legacy.empty())
        return error;
    if (Exists(legacy) && Exists(legacy + L".disabled"))
        return ERROR_ALREADY_EXISTS;
    bool legacyRunning = false;
    if (!LegacyProcesses(legacy, false, legacyRunning, error))
        return error;
    Migration value;
    if (!Load(root, value, error)) {
        if (error != ERROR_FILE_NOT_FOUND)
            return error;
        if (present)
            value.flags |= HadRun;
        if (Exists(OldExe(root))) {
            if (!Version100(OldExe(root)))
                return ERROR_REVISION_MISMATCH;
            if (!install::FileHash(OldExe(root), value.hash, error))
                return error;
            if (!Exists(Backup(root)) &&
                !CopyFileW(OldExe(root).c_str(), Backup(root).c_str(), TRUE))
                return GetLastError();
            install::Hash copy{};
            if (!install::FileHash(Backup(root), copy, error) || copy != value.hash)
                return ERROR_CRC;
            value.flags |= HadExe;
        } else if (present)
            return ERROR_FILE_NOT_FOUND;
    }
    HWND window = nullptr;
    HANDLE process = nullptr;
    if (!OldWindow(root, window, process, error))
        return error;
    // A retry after interruption must retain the original running-state
    // snapshot, even though the first attempt already stopped 1.0.0.
    if (!(value.flags & Pending))
        value.flags &= ~(WasRunning | HadLegacy | LegacyRunning);
    value.flags |= Pending;
    if (window)
        value.flags |= WasRunning;
    if (Exists(legacy))
        value.flags |= HadLegacy;
    if (legacyRunning)
        value.flags |= LegacyRunning;
    if (!Save(root, value, error)) {
        if (process)
            CloseHandle(process);
        return error;
    }
    if (legacyRunning && !LegacyProcesses(legacy, true, legacyRunning, error)) {
        if (process)
            CloseHandle(process);
        return error;
    }
    if (window) {
        const bool sent = PostMessageW(window, WM_APP + 5, 0, 0) != FALSE;
        const DWORD wait = sent ? WaitForSingleObject(process, 5000) : WAIT_FAILED;
        CloseHandle(process);
        if (!sent)
            return GetLastError();
        if (wait != WAIT_OBJECT_0)
            return ERROR_TIMEOUT;
    }
    return 0;
}
DWORD CompleteMigration() {
    if (!Ordinary())
        return ERROR_ACCESS_DENIED;
    DWORD error = 0;
    const auto root = DataDirectory(error);
    if (root.empty())
        return error;
    Migration value;
    if (!Load(root, value, error))
        return error == ERROR_FILE_NOT_FOUND ? 0 : error;
    if (!(value.flags & Pending))
        return 0;
    const auto executable = InstalledExecutable(error);
    if (executable.empty())
        return error;
    install::Record receipt;
    const auto directory = executable.substr(0, executable.find_last_of(L'\\'));
    if (!install::LoadRecord(directory, receipt, error) ||
        receipt.phase != install::Phase::Committed || receipt.sid != ipc::Endpoint::Current().sid)
        return error ? error : ERROR_NOT_READY;
    ControlRequest request;
    request.id = 1;
    ControlResponse state;
    if (!ControlCall(executable, request, state, error) || state.error ||
        state.status.engineError || (state.status.engine.flags & 7U) != 7U)
        return error ? error : ERROR_NOT_READY;
    const auto legacy = LegacyPath(error);
    if (legacy.empty())
        return error;
    if ((value.flags & HadLegacy) && Exists(legacy) &&
        !MoveFileExW(legacy.c_str(), (legacy + L".disabled").c_str(), MOVEFILE_WRITE_THROUGH))
        return GetLastError();
    std::wstring run;
    bool present = false;
    if (!ReadRun(run, present, error))
        return error;
    if (present) {
        if (_wcsicmp(run.c_str(), ExpectedRun(root).c_str()))
            return ERROR_REVISION_MISMATCH;
        HKEY key = nullptr;
        LONG result = RegOpenKeyExW(HKEY_CURRENT_USER, kRun, 0, KEY_SET_VALUE, &key);
        if (result != ERROR_SUCCESS)
            return result;
        result = RegDeleteValueW(key, L"CapsLang");
        RegCloseKey(key);
        if (result != ERROR_SUCCESS && result != ERROR_FILE_NOT_FOUND)
            return result;
    }
    value.flags &= ~(Pending | WasRunning | LegacyRunning);
    return Save(root, value, error) ? 0 : error;
}
DWORD AbortMigration() {
    if (!Ordinary())
        return ERROR_ACCESS_DENIED;
    DWORD error = 0;
    const auto root = DataDirectory(error);
    if (root.empty())
        return error;
    Migration value;
    if (!Load(root, value, error))
        return error == ERROR_FILE_NOT_FOUND ? 0 : error;
    if (!(value.flags & Pending))
        return 0;
    if (!NoManagedEngine(error))
        return error;
    if (value.flags & HadLegacy) {
        const auto legacy = LegacyPath(error);
        if (legacy.empty())
            return error;
        if (!Exists(legacy) &&
            !MoveFileExW((legacy + L".disabled").c_str(), legacy.c_str(), MOVEFILE_WRITE_THROUGH))
            return GetLastError();
        bool running = false;
        if ((value.flags & LegacyRunning) && (!LegacyProcesses(legacy, false, running, error) ||
                                              (!running && !Launch(legacy, L"", error))))
            return error;
    }
    if (value.flags & WasRunning) {
        HWND window = nullptr;
        HANDLE process = nullptr;
        if (!OldWindow(root, window, process, error))
            return error;
        if (process)
            CloseHandle(process);
        if (!window && !Launch(OldExe(root), L"--background", error))
            return error;
    }
    value.flags &= ~(Pending | WasRunning | LegacyRunning);
    return Save(root, value, error) ? 0 : error;
}
DWORD RestorePreviousUserVersion(bool legacy) {
    if (!Ordinary())
        return ERROR_ACCESS_DENIED;
    DWORD error = 0;
    const auto root = DataDirectory(error);
    if (root.empty())
        return error;
    if (!NoManagedEngine(error))
        return error;
    if (legacy) {
        const auto active = LegacyPath(error);
        if (active.empty())
            return error;
        if (!Exists(active) &&
            !MoveFileExW((active + L".disabled").c_str(), active.c_str(), MOVEFILE_WRITE_THROUGH))
            return GetLastError();
        bool running = false;
        if (!LegacyProcesses(active, false, running, error))
            return error;
        return running || Launch(active, L"", error) ? 0 : error;
    }
    Migration value;
    if (!Load(root, value, error))
        return error;
    if (!(value.flags & HadExe))
        return ERROR_NOT_FOUND;
    install::Hash hash{};
    if (!install::FileHash(Backup(root), hash, error) || hash != value.hash)
        return ERROR_CRC;
    if (Exists(OldExe(root))) {
        install::Hash existing{};
        if (!install::FileHash(OldExe(root), existing, error) || existing != value.hash)
            return ERROR_FILE_EXISTS;
    } else if (!CopyFileW(Backup(root).c_str(), OldExe(root).c_str(), TRUE))
        return GetLastError();
    if (value.flags & HadRun) {
        std::wstring run;
        bool present = false;
        if (!ReadRun(run, present, error))
            return error;
        if (present && _wcsicmp(run.c_str(), ExpectedRun(root).c_str()))
            return ERROR_ALREADY_EXISTS;
        if (!RunWrite(ExpectedRun(root), error))
            return error;
    }
    HWND window = nullptr;
    HANDLE process = nullptr;
    if (!OldWindow(root, window, process, error))
        return error;
    if (process)
        CloseHandle(process);
    return window || Launch(OldExe(root), L"--background", error) ? 0 : error;
}
DWORD CheckRestoreAvailable(bool legacy) {
    if (!Ordinary())
        return ERROR_ACCESS_DENIED;
    DWORD error = 0;
    if (legacy) {
        const auto path = LegacyPath(error);
        if (path.empty())
            return error;
        return Exists(path) || Exists(path + L".disabled") ? 0 : ERROR_FILE_NOT_FOUND;
    }
    const auto root = DataDirectory(error);
    if (root.empty())
        return error;
    Migration value;
    if (!Load(root, value, error))
        return error;
    if (!(value.flags & HadExe))
        return ERROR_NOT_FOUND;
    install::Hash hash{};
    if (!install::FileHash(Backup(root), hash, error))
        return error;
    if (hash != value.hash)
        return ERROR_CRC;
    if (Exists(OldExe(root))) {
        if (!install::FileHash(OldExe(root), hash, error))
            return error;
        if (hash != value.hash)
            return ERROR_FILE_EXISTS;
    }
    return 0;
}
} // namespace capslang::app
