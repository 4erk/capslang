#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _WIN32_WINNT 0x0A00
#define WINVER 0x0A00

#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <strsafe.h>
#include <tlhelp32.h>
#include <wtsapi32.h>

#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cwchar>
#include <string>
#include <vector>

namespace {

constexpr wchar_t kAppName[] = L"CapsLang";
constexpr wchar_t kVersion[] = L"1.0.0";
constexpr wchar_t kWindowClass[] = L"CapsLang.Reliable.HiddenWindow.1";
constexpr wchar_t kWindowTitle[] = L"CapsLang reliable background engine";
constexpr wchar_t kMutexName[] = L"Local\\CapsLang.Reliable.Singleton.1";
constexpr wchar_t kRunValueName[] = L"CapsLang";

constexpr UINT WM_APP_SWITCH_LANGUAGE = WM_APP + 1;
constexpr UINT WM_APP_SHOW_MENU = WM_APP + 2;
constexpr UINT WM_APP_RESTART_HOOK = WM_APP + 3;
constexpr UINT WM_APP_HOOK_STATE = WM_APP + 4;
constexpr UINT WM_APP_SHUTDOWN = WM_APP + 5;
constexpr UINT WM_APP_BEGIN_UNINSTALL = WM_APP + 6;
constexpr UINT WM_APP_SIMULATE_HOOK_LOSS = WM_APP + 7;
constexpr UINT WM_APP_DROP_HOOK = WM_APP + 8;

constexpr UINT_PTR TIMER_LAYOUT = 1;
constexpr UINT_PTR TIMER_HEALTH = 2;
constexpr UINT_PTR TIMER_PROBE_CHECK = 3;
constexpr UINT_PTR TIMER_FALLBACK_REHOOK = 4;
constexpr UINT_PTR TIMER_HOOK_RETRY = 5;
constexpr int HOTKEY_PROBE_ID = 0xCA51;

constexpr ULONG_PTR kInjectedMarker =
    sizeof(ULONG_PTR) == 8 ? static_cast<ULONG_PTR>(0x434150534C414E47ULL)
                           : static_cast<ULONG_PTR>(0x43415053UL);
constexpr ULONG_PTR kProbeMarker =
    sizeof(ULONG_PTR) == 8 ? static_cast<ULONG_PTR>(0x4341505350524F42ULL)
                           : static_cast<ULONG_PTR>(0x50524F42UL);

enum class HookReason : WPARAM {
    Initial = 0,
    Watchdog = 1,
    UserRestart = 2,
    SessionResume = 3,
    Retry = 4,
    PeriodicFallback = 5,
};

struct KeyOutcome {
    bool swallow = false;
    bool switchLanguage = false;
    bool probeSeen = false;
};

class CapsKeyState {
public:
    KeyOutcome Handle(DWORD vkCode, WPARAM message, bool shiftDown, ULONG_PTR extraInfo) {
        if (vkCode == VK_F24 && extraInfo == kProbeMarker) {
            return {true, false, true};
        }
        if (vkCode != VK_CAPITAL) {
            return {};
        }

        const bool isDown = message == WM_KEYDOWN || message == WM_SYSKEYDOWN;
        const bool isUp = message == WM_KEYUP || message == WM_SYSKEYUP;
        if (!isDown && !isUp) {
            return {};
        }

        if (isDown) {
            if (!down_) {
                down_ = true;
                passThrough_ = shiftDown;
                return {!passThrough_, !passThrough_, false};
            }
            return {!passThrough_, false, false};
        }

        const bool pass = down_ && passThrough_;
        down_ = false;
        passThrough_ = false;
        return {!pass, false, false};
    }

    void Reset() {
        down_ = false;
        passThrough_ = false;
    }

private:
    bool down_ = false;
    bool passThrough_ = false;
};

std::atomic<ULONG_PTR> g_mainWindow{0};
std::atomic<bool> g_hookInstalled{false};
std::atomic<ULONGLONG> g_lastProbeSeen{0};
std::atomic<ULONGLONG> g_lastRecoveryFileTime{0};
std::atomic<unsigned long> g_recoveryCount{0};
std::atomic<DWORD> g_hookThreadId{0};

CapsKeyState g_keyState;
SRWLOCK g_logLock = SRWLOCK_INIT;
std::wstring g_appDir;
std::wstring g_logPath;
HANDLE g_instanceMutex = nullptr;
HANDLE g_hookReadyEvent = nullptr;
HANDLE g_hookThread = nullptr;
bool g_probeHotkeyRegistered = false;
ULONGLONG g_lastProbeSent = 0;
unsigned g_hookRetryDelayMs = 1000;

std::wstring JoinPath(const std::wstring& left, const std::wstring& right) {
    if (left.empty()) return right;
    if (left.back() == L'\\' || left.back() == L'/') return left + right;
    return left + L"\\" + right;
}

std::wstring GetKnownFolder(REFKNOWNFOLDERID id) {
    PWSTR raw = nullptr;
    std::wstring result;
    if (SUCCEEDED(SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, nullptr, &raw)) && raw) {
        result = raw;
    }
    CoTaskMemFree(raw);
    return result;
}

std::wstring CurrentExecutablePath() {
    std::vector<wchar_t> buffer(32768);
    const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    return length ? std::wstring(buffer.data(), length) : std::wstring();
}

std::wstring InstalledExecutablePath() {
    return JoinPath(g_appDir, L"CapsLang.exe");
}

std::wstring LegacyExecutablePath() {
    return JoinPath(GetKnownFolder(FOLDERID_Startup), L"capslang-win-space.exe");
}

std::wstring DisabledLegacyPath() {
    return LegacyExecutablePath() + L".disabled";
}

bool FileExists(const std::wstring& path) {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
}

bool DirectoryExists(const std::wstring& path) {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY);
}

bool EnsureDirectory(const std::wstring& path) {
    if (DirectoryExists(path)) return true;
    const int result = SHCreateDirectoryExW(nullptr, path.c_str(), nullptr);
    return result == ERROR_SUCCESS || result == ERROR_ALREADY_EXISTS;
}

void RotateLogsIfNeeded() {
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (!GetFileAttributesExW(g_logPath.c_str(), GetFileExInfoStandard, &data)) return;
    ULARGE_INTEGER size{};
    size.HighPart = data.nFileSizeHigh;
    size.LowPart = data.nFileSizeLow;
    if (size.QuadPart < 256 * 1024) return;

    const std::wstring log1 = g_logPath + L".1";
    const std::wstring log2 = g_logPath + L".2";
    const std::wstring log3 = g_logPath + L".3";
    DeleteFileW(log3.c_str());
    MoveFileExW(log2.c_str(), log3.c_str(), MOVEFILE_REPLACE_EXISTING);
    MoveFileExW(log1.c_str(), log2.c_str(), MOVEFILE_REPLACE_EXISTING);
    MoveFileExW(g_logPath.c_str(), log1.c_str(), MOVEFILE_REPLACE_EXISTING);
}

void Log(const wchar_t* format, ...) {
    if (g_logPath.empty()) return;
    AcquireSRWLockExclusive(&g_logLock);
    EnsureDirectory(g_appDir);
    RotateLogsIfNeeded();

    wchar_t message[1536]{};
    va_list args;
    va_start(args, format);
    StringCchVPrintfW(message, ARRAYSIZE(message), format, args);
    va_end(args);

    SYSTEMTIME now{};
    GetLocalTime(&now);
    wchar_t line[1800]{};
    StringCchPrintfW(line, ARRAYSIZE(line),
                     L"%04u-%02u-%02u %02u:%02u:%02u.%03u [%lu] %s\r\n",
                     now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute,
                     now.wSecond, now.wMilliseconds, GetCurrentThreadId(), message);

    const int utf8Length = WideCharToMultiByte(CP_UTF8, 0, line, -1, nullptr, 0, nullptr, nullptr);
    if (utf8Length > 1) {
        std::vector<char> utf8(static_cast<size_t>(utf8Length));
        WideCharToMultiByte(CP_UTF8, 0, line, -1, utf8.data(), utf8Length, nullptr, nullptr);
        HANDLE file = CreateFileW(g_logPath.c_str(), FILE_APPEND_DATA,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                  nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            WriteFile(file, utf8.data(), static_cast<DWORD>(utf8Length - 1), &written, nullptr);
            CloseHandle(file);
        }
    }
    ReleaseSRWLockExclusive(&g_logLock);
}

ULONGLONG CurrentFileTimeValue() {
    FILETIME ft{};
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER value{};
    value.LowPart = ft.dwLowDateTime;
    value.HighPart = ft.dwHighDateTime;
    return value.QuadPart;
}

std::wstring FormatWin32Error(DWORD error) {
    wchar_t* raw = nullptr;
    const DWORD length = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                                            FORMAT_MESSAGE_FROM_SYSTEM |
                                            FORMAT_MESSAGE_IGNORE_INSERTS,
                                        nullptr, error, 0,
                                        reinterpret_cast<wchar_t*>(&raw), 0, nullptr);
    std::wstring result = length && raw ? std::wstring(raw, length) : L"unknown error";
    LocalFree(raw);
    while (!result.empty() && (result.back() == L'\r' || result.back() == L'\n' || result.back() == L' ')) {
        result.pop_back();
    }
    return result;
}

HWND FindEngineWindow() {
    return FindWindowExW(HWND_MESSAGE, nullptr, kWindowClass, kWindowTitle);
}

bool SamePath(const std::wstring& first, const std::wstring& second) {
    return _wcsicmp(first.c_str(), second.c_str()) == 0;
}

bool Launch(const std::wstring& executable, const std::wstring& arguments = L"") {
    std::wstring command = L"\"" + executable + L"\"";
    if (!arguments.empty()) command += L" " + arguments;
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    const BOOL ok = CreateProcessW(executable.c_str(), mutableCommand.data(), nullptr, nullptr,
                                   FALSE, CREATE_UNICODE_ENVIRONMENT, nullptr, nullptr,
                                   &startup, &process);
    if (ok) {
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        return true;
    }
    Log(L"CreateProcess failed for %s: %lu (%s)", executable.c_str(), GetLastError(),
        FormatWin32Error(GetLastError()).c_str());
    return false;
}

bool SetRunRegistration() {
    HKEY key = nullptr;
    const LONG openResult = RegCreateKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, nullptr, 0,
        KEY_SET_VALUE, nullptr, &key, nullptr);
    if (openResult != ERROR_SUCCESS) {
        Log(L"Cannot open HKCU Run: %ld", openResult);
        return false;
    }
    const std::wstring command = L"\"" + InstalledExecutablePath() + L"\" --background";
    const LONG result = RegSetValueExW(key, kRunValueName, 0, REG_SZ,
        reinterpret_cast<const BYTE*>(command.c_str()),
        static_cast<DWORD>((command.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(key);
    if (result != ERROR_SUCCESS) Log(L"Cannot write HKCU Run: %ld", result);
    return result == ERROR_SUCCESS;
}

bool RemoveRunRegistration() {
    HKEY key = nullptr;
    const LONG openResult = RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &key);
    if (openResult == ERROR_FILE_NOT_FOUND) return true;
    if (openResult != ERROR_SUCCESS) return false;
    const LONG result = RegDeleteValueW(key, kRunValueName);
    RegCloseKey(key);
    return result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND;
}

bool IsRunRegistrationPresent() {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) {
        return false;
    }
    wchar_t value[32768]{};
    DWORD type = 0;
    DWORD size = sizeof(value);
    const LONG result = RegQueryValueExW(key, kRunValueName, nullptr, &type,
                                         reinterpret_cast<BYTE*>(value), &size);
    RegCloseKey(key);
    return result == ERROR_SUCCESS && type == REG_SZ;
}

std::vector<DWORD> ThreadsForProcess(DWORD processId) {
    std::vector<DWORD> result;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return result;
    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    if (Thread32First(snapshot, &entry)) {
        do {
            if (entry.th32OwnerProcessID == processId) result.push_back(entry.th32ThreadID);
        } while (Thread32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return result;
}

bool StopLegacyProcess() {
    const std::wstring legacyPath = LegacyExecutablePath();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;

    bool allStopped = true;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE |
                                             PROCESS_TERMINATE,
                                         FALSE, entry.th32ProcessID);
            if (!process) continue;
            wchar_t path[32768]{};
            DWORD length = ARRAYSIZE(path);
            const bool match = QueryFullProcessImageNameW(process, 0, path, &length) &&
                               SamePath(path, legacyPath);
            if (match) {
                Log(L"Stopping legacy process PID %lu", entry.th32ProcessID);
                for (DWORD threadId : ThreadsForProcess(entry.th32ProcessID)) {
                    PostThreadMessageW(threadId, WM_HOTKEY, 0x21, MAKELPARAM(MOD_ALT | MOD_CONTROL, 'L'));
                }
                if (WaitForSingleObject(process, 2000) == WAIT_TIMEOUT) {
                    Log(L"Legacy process did not stop gracefully; terminating exact-path process");
                    if (!TerminateProcess(process, 0) || WaitForSingleObject(process, 2000) == WAIT_TIMEOUT) {
                        allStopped = false;
                    }
                }
            }
            CloseHandle(process);
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return allStopped;
}

bool DisableLegacyExecutable() {
    const std::wstring source = LegacyExecutablePath();
    if (!FileExists(source)) return true;
    std::wstring target = DisabledLegacyPath();
    if (FileExists(target)) {
        SYSTEMTIME now{};
        GetLocalTime(&now);
        wchar_t suffix[64]{};
        StringCchPrintfW(suffix, ARRAYSIZE(suffix), L".%04u%02u%02u-%02u%02u%02u",
                         now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond);
        target += suffix;
    }
    if (!MoveFileExW(source.c_str(), target.c_str(), MOVEFILE_WRITE_THROUGH)) {
        Log(L"Cannot disable legacy executable: %lu (%s)", GetLastError(),
            FormatWin32Error(GetLastError()).c_str());
        return false;
    }
    Log(L"Legacy executable preserved as %s", target.c_str());
    return true;
}

bool RestoreLegacyExecutable(bool launchAfterRestore) {
    const std::wstring disabled = DisabledLegacyPath();
    const std::wstring active = LegacyExecutablePath();
    if (!FileExists(disabled)) return false;
    if (FileExists(active)) return false;
    if (!MoveFileExW(disabled.c_str(), active.c_str(), MOVEFILE_WRITE_THROUGH)) return false;
    if (launchAfterRestore) Launch(active);
    return true;
}

bool StopEngineAndWait() {
    HWND window = FindEngineWindow();
    if (!window) return true;
    HANDLE mutex = OpenMutexW(SYNCHRONIZE, FALSE, kMutexName);
    PostMessageW(window, WM_APP_SHUTDOWN, 0, 0);
    bool stopped = true;
    if (mutex) {
        const DWORD waitResult = WaitForSingleObject(mutex, 5000);
        stopped = waitResult == WAIT_OBJECT_0 || waitResult == WAIT_ABANDONED;
        if (waitResult == WAIT_OBJECT_0) ReleaseMutex(mutex);
        CloseHandle(mutex);
    } else {
        Sleep(500);
    }
    return stopped;
}

int ShowTask(const wchar_t* title, const wchar_t* instruction, const wchar_t* content,
             const std::vector<TASKDIALOG_BUTTON>& buttons, TASKDIALOG_COMMON_BUTTON_FLAGS common) {
    TASKDIALOGCONFIG config{};
    config.cbSize = sizeof(config);
    config.hInstance = GetModuleHandleW(nullptr);
    config.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_SIZE_TO_CONTENT;
    config.dwCommonButtons = common;
    config.pszWindowTitle = title;
    config.pszMainInstruction = instruction;
    config.pszContent = content;
    config.cButtons = static_cast<UINT>(buttons.size());
    config.pButtons = buttons.empty() ? nullptr : buttons.data();
    config.pszMainIcon = TD_INFORMATION_ICON;
    int pressed = IDCANCEL;
    if (FAILED(TaskDialogIndirect(&config, &pressed, nullptr, nullptr))) {
        MessageBoxW(nullptr, content, title, MB_OK | MB_ICONINFORMATION);
    }
    return pressed;
}

bool CopySelfToInstalledPath() {
    EnsureDirectory(g_appDir);
    const std::wstring source = CurrentExecutablePath();
    const std::wstring installed = InstalledExecutablePath();
    if (SamePath(source, installed)) return true;
    const std::wstring temporary = installed + L".new";
    DeleteFileW(temporary.c_str());
    if (!CopyFileW(source.c_str(), temporary.c_str(), FALSE)) {
        Log(L"Copy to install staging failed: %lu (%s)", GetLastError(),
            FormatWin32Error(GetLastError()).c_str());
        return false;
    }
    if (!MoveFileExW(temporary.c_str(), installed.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        Log(L"Install replacement failed: %lu (%s)", GetLastError(),
            FormatWin32Error(GetLastError()).c_str());
        DeleteFileW(temporary.c_str());
        return false;
    }
    return true;
}

bool InstallApplication(bool showResult) {
    EnsureDirectory(g_appDir);
    Log(L"Installation requested from %s", CurrentExecutablePath().c_str());
    if (!StopEngineAndWait()) {
        MessageBoxW(nullptr, L"Не удалось остановить уже запущенный CapsLang.", kAppName,
                    MB_OK | MB_ICONERROR);
        return false;
    }
    if (!CopySelfToInstalledPath()) {
        MessageBoxW(nullptr, L"Не удалось скопировать CapsLang в профиль пользователя.",
                    kAppName, MB_OK | MB_ICONERROR);
        return false;
    }
    if (!StopLegacyProcess() || !DisableLegacyExecutable()) {
        DeleteFileW(InstalledExecutablePath().c_str());
        MessageBoxW(nullptr,
                    L"Не удалось безопасно отключить старый CapsLang. Установка отменена.",
                    kAppName, MB_OK | MB_ICONERROR);
        return false;
    }
    if (!SetRunRegistration()) {
        RestoreLegacyExecutable(true);
        DeleteFileW(InstalledExecutablePath().c_str());
        MessageBoxW(nullptr, L"Не удалось установить CapsLang в профиль пользователя.",
                    kAppName, MB_OK | MB_ICONERROR);
        return false;
    }
    if (!Launch(InstalledExecutablePath(), L"--background")) {
        RemoveRunRegistration();
        RestoreLegacyExecutable(true);
        DeleteFileW(InstalledExecutablePath().c_str());
        MessageBoxW(nullptr, L"CapsLang установлен, но не смог запуститься.",
                    kAppName, MB_OK | MB_ICONWARNING);
        return false;
    }
    Log(L"Installation completed");
    if (showResult) {
        MessageBoxW(nullptr,
                    L"CapsLang установлен и запущен. Старый EXE сохранён с расширением .disabled.",
                    kAppName, MB_OK | MB_ICONINFORMATION);
    }
    return true;
}

LANGID CurrentLanguageId() {
    HWND foreground = GetForegroundWindow();
    DWORD threadId = foreground ? GetWindowThreadProcessId(foreground, nullptr) : 0;
    HKL layout = GetKeyboardLayout(threadId);
    return LOWORD(reinterpret_cast<ULONG_PTR>(layout));
}

const wchar_t* LanguageName(LANGID language) {
    if (language == 0x0409) return L"English (US)";
    if (language == 0x0419) return L"Русский";
    return L"другая раскладка";
}

bool SendMarkedKey(WORD key, bool keyUp, ULONG_PTR marker) {
    INPUT input{};
    input.type = INPUT_KEYBOARD;
    input.ki.wVk = key;
    input.ki.dwFlags = keyUp ? KEYEVENTF_KEYUP : 0;
    input.ki.dwExtraInfo = marker;
    return SendInput(1, &input, sizeof(input)) == 1;
}

void SwitchLanguage() {
    INPUT inputs[4]{};
    const WORD keys[4] = {VK_LWIN, VK_SPACE, VK_SPACE, VK_LWIN};
    for (int index = 0; index < 4; ++index) {
        inputs[index].type = INPUT_KEYBOARD;
        inputs[index].ki.wVk = keys[index];
        inputs[index].ki.dwExtraInfo = kInjectedMarker;
        if (index >= 2) inputs[index].ki.dwFlags = KEYEVENTF_KEYUP;
    }
    const UINT sent = SendInput(ARRAYSIZE(inputs), inputs, sizeof(INPUT));
    if (sent != ARRAYSIZE(inputs)) {
        const DWORD error = GetLastError();
        Log(L"SendInput Win+Space incomplete: %u/4, error %lu (%s)", sent, error,
            FormatWin32Error(error).c_str());
        SendMarkedKey(VK_SPACE, true, kInjectedMarker);
        SendMarkedKey(VK_LWIN, true, kInjectedMarker);
    }
}

void SynchronizeScrollLock() {
    const LANGID language = CurrentLanguageId();
    if (language != 0x0409 && language != 0x0419) return;
    const bool desired = language == 0x0419;
    const bool current = (GetKeyState(VK_SCROLL) & 1) != 0;
    if (desired == current) return;
    if (!SendMarkedKey(VK_SCROLL, false, kInjectedMarker) ||
        !SendMarkedKey(VK_SCROLL, true, kInjectedMarker)) {
        Log(L"Failed to synchronize Scroll Lock LED: %lu", GetLastError());
    }
}

const wchar_t* HookReasonName(HookReason reason) {
    switch (reason) {
        case HookReason::Initial: return L"initial";
        case HookReason::Watchdog: return L"watchdog";
        case HookReason::UserRestart: return L"user restart";
        case HookReason::SessionResume: return L"session/resume";
        case HookReason::Retry: return L"retry";
        case HookReason::PeriodicFallback: return L"periodic fallback";
    }
    return L"unknown";
}

LRESULT CALLBACK LowLevelKeyboardProc(int code, WPARAM wParam, LPARAM lParam) {
    if (code < 0) return CallNextHookEx(nullptr, code, wParam, lParam);
    const auto* data = reinterpret_cast<KBDLLHOOKSTRUCT*>(lParam);
    const bool shiftDown = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
    const KeyOutcome outcome = g_keyState.Handle(data->vkCode, wParam, shiftDown, data->dwExtraInfo);
    if (outcome.probeSeen) g_lastProbeSeen.store(GetTickCount64(), std::memory_order_release);
    if (outcome.switchLanguage) {
        HWND window = reinterpret_cast<HWND>(g_mainWindow.load(std::memory_order_acquire));
        if (window) PostMessageW(window, WM_APP_SWITCH_LANGUAGE, 0, 0);
    }
    if (outcome.swallow) return 1;
    return CallNextHookEx(nullptr, code, wParam, lParam);
}

DWORD WINAPI HookThreadMain(void*) {
    const DWORD threadId = GetCurrentThreadId();
    g_hookThreadId.store(threadId, std::memory_order_release);
    MSG message{};
    PeekMessageW(&message, nullptr, WM_USER, WM_USER, PM_NOREMOVE);

    HHOOK hook = nullptr;
    auto installHook = [&](HookReason reason) {
        if (hook) {
            UnhookWindowsHookEx(hook);
            hook = nullptr;
        }
        g_keyState.Reset();
        hook = SetWindowsHookExW(WH_KEYBOARD_LL, LowLevelKeyboardProc,
                                 GetModuleHandleW(nullptr), 0);
        const bool installed = hook != nullptr;
        g_hookInstalled.store(installed, std::memory_order_release);
        if (installed) {
            g_lastProbeSeen.store(GetTickCount64(), std::memory_order_release);
            if (reason != HookReason::Initial) {
                g_recoveryCount.fetch_add(1, std::memory_order_relaxed);
                g_lastRecoveryFileTime.store(CurrentFileTimeValue(), std::memory_order_release);
            }
            Log(L"Keyboard hook installed (%s)", HookReasonName(reason));
        } else {
            const DWORD error = GetLastError();
            Log(L"SetWindowsHookEx failed (%s): %lu (%s)", HookReasonName(reason), error,
                FormatWin32Error(error).c_str());
        }
        HWND window = reinterpret_cast<HWND>(g_mainWindow.load(std::memory_order_acquire));
        if (window) PostMessageW(window, WM_APP_HOOK_STATE, installed ? 1 : 0, 0);
    };

    installHook(HookReason::Initial);
    SetEvent(g_hookReadyEvent);
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        if (message.message == WM_APP_RESTART_HOOK) {
            installHook(static_cast<HookReason>(message.wParam));
        } else if (message.message == WM_APP_DROP_HOOK) {
            if (hook) {
                UnhookWindowsHookEx(hook);
                hook = nullptr;
            }
            g_keyState.Reset();
            g_hookInstalled.store(false, std::memory_order_release);
            Log(L"Keyboard hook silently removed for recovery diagnostic");
        } else {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    if (hook) UnhookWindowsHookEx(hook);
    g_hookInstalled.store(false, std::memory_order_release);
    g_hookThreadId.store(0, std::memory_order_release);
    Log(L"Hook thread stopped");
    return 0;
}

void RequestHookReinstall(HookReason reason) {
    const DWORD threadId = g_hookThreadId.load(std::memory_order_acquire);
    if (!threadId || !PostThreadMessageW(threadId, WM_APP_RESTART_HOOK,
                                          static_cast<WPARAM>(reason), 0)) {
        Log(L"Cannot request hook reinstall (%s): %lu", HookReasonName(reason), GetLastError());
    }
}

void SendHealthProbe(HWND window) {
    INPUT inputs[2]{};
    inputs[0].type = INPUT_KEYBOARD;
    inputs[0].ki.wVk = VK_F24;
    inputs[0].ki.dwExtraInfo = kProbeMarker;
    inputs[1] = inputs[0];
    inputs[1].ki.dwFlags = KEYEVENTF_KEYUP;
    g_lastProbeSent = GetTickCount64();
    const UINT sent = SendInput(ARRAYSIZE(inputs), inputs, sizeof(INPUT));
    if (sent == ARRAYSIZE(inputs)) {
        SetTimer(window, TIMER_PROBE_CHECK, 1000, nullptr);
    } else {
        Log(L"Health probe SendInput failed: %u/2, error %lu", sent, GetLastError());
    }
}

std::wstring FormatStatus() {
    wchar_t status[2048]{};
    const LANGID language = CurrentLanguageId();
    const bool hook = g_hookInstalled.load(std::memory_order_acquire);
    const unsigned long recoveries = g_recoveryCount.load(std::memory_order_relaxed);
    std::wstring recoveryText = L"ещё не требовалось";
    const ULONGLONG fileTimeValue = g_lastRecoveryFileTime.load(std::memory_order_acquire);
    if (fileTimeValue) {
        ULARGE_INTEGER value{};
        value.QuadPart = fileTimeValue;
        FILETIME utc{value.LowPart, value.HighPart};
        FILETIME local{};
        SYSTEMTIME time{};
        if (FileTimeToLocalFileTime(&utc, &local) && FileTimeToSystemTime(&local, &time)) {
            wchar_t formatted[128]{};
            StringCchPrintfW(formatted, ARRAYSIZE(formatted), L"%02u.%02u.%04u %02u:%02u:%02u",
                             time.wDay, time.wMonth, time.wYear, time.wHour, time.wMinute, time.wSecond);
            recoveryText = formatted;
        }
    }
    StringCchPrintfW(status, ARRAYSIZE(status),
        L"Версия: %s\nЯзык: %s (0x%04X)\nKeyboard hook: %s\n"
        L"Самовосстановлений: %lu\nПоследнее восстановление: %s\n"
        L"Автозапуск: %s\nЖурнал: %s",
        kVersion, LanguageName(language), language, hook ? L"работает" : L"восстанавливается",
        recoveries, recoveryText.c_str(), IsRunRegistrationPresent() ? L"включён" : L"выключен",
        g_logPath.c_str());
    return status;
}

void BeginSelfRemoval(bool restoreLegacy) {
    wchar_t tempDirectory[MAX_PATH]{};
    GetTempPathW(ARRAYSIZE(tempDirectory), tempDirectory);
    wchar_t helperName[128]{};
    StringCchPrintfW(helperName, ARRAYSIZE(helperName), L"CapsLang-uninstall-%lu.exe", GetCurrentProcessId());
    const std::wstring helperPath = JoinPath(tempDirectory, helperName);
    if (!CopyFileW(CurrentExecutablePath().c_str(), helperPath.c_str(), FALSE)) {
        MessageBoxW(nullptr, L"Не удалось подготовить удаление CapsLang.", kAppName,
                    MB_OK | MB_ICONERROR);
        return;
    }
    wchar_t arguments[160]{};
    StringCchPrintfW(arguments, ARRAYSIZE(arguments), L"--finish-uninstall %lu%s",
                     GetCurrentProcessId(), restoreLegacy ? L" --restore-legacy" : L"");
    if (!Launch(helperPath, arguments)) {
        DeleteFileW(helperPath.c_str());
        MessageBoxW(nullptr, L"Не удалось запустить удаление CapsLang.", kAppName,
                    MB_OK | MB_ICONERROR);
        return;
    }
    RemoveRunRegistration();
    Log(L"Uninstall initiated; restore legacy=%d", restoreLegacy ? 1 : 0);
    PostQuitMessage(0);
}

void ShowManagementWindow(HWND window) {
    const std::wstring status = FormatStatus();
    std::vector<TASKDIALOG_BUTTON> buttons;
    buttons.push_back({301, L"Перезапустить hook"});
    if (FileExists(DisabledLegacyPath()) && !FileExists(LegacyExecutablePath())) {
        buttons.push_back({302, L"Восстановить старую версию"});
    }
    buttons.push_back({303, L"Удалить новую версию"});
    const int result = ShowTask(kAppName, L"CapsLang работает в фоне", status.c_str(),
                                buttons, TDCBF_CLOSE_BUTTON);
    if (result == 301) {
        RequestHookReinstall(HookReason::UserRestart);
        MessageBoxW(window, L"Keyboard hook перезапущен.", kAppName, MB_OK | MB_ICONINFORMATION);
    } else if (result == 302) {
        if (MessageBoxW(window,
            L"Удалить новую версию и снова включить старый CapsLang?",
            kAppName, MB_YESNO | MB_ICONWARNING) == IDYES) {
            BeginSelfRemoval(true);
        }
    } else if (result == 303) {
        if (MessageBoxW(window,
            L"Удалить новую версию? Старый EXE останется отключённым.",
            kAppName, MB_YESNO | MB_ICONQUESTION) == IDYES) {
            BeginSelfRemoval(false);
        }
    }
}

LRESULT CALLBACK MainWindowProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_APP_SWITCH_LANGUAGE:
            SwitchLanguage();
            return 0;
        case WM_APP_SHOW_MENU:
            ShowManagementWindow(window);
            return 0;
        case WM_APP_RESTART_HOOK:
            RequestHookReinstall(HookReason::UserRestart);
            return 0;
        case WM_APP_HOOK_STATE:
            if (wParam) {
                KillTimer(window, TIMER_HOOK_RETRY);
                g_hookRetryDelayMs = 1000;
            } else {
                SetTimer(window, TIMER_HOOK_RETRY, g_hookRetryDelayMs, nullptr);
                const unsigned doubled = g_hookRetryDelayMs * 2;
                g_hookRetryDelayMs = doubled < 30000U ? doubled : 30000U;
            }
            return 0;
        case WM_APP_SHUTDOWN:
            PostQuitMessage(0);
            return 0;
        case WM_APP_BEGIN_UNINSTALL:
            BeginSelfRemoval(wParam != 0);
            return 0;
        case WM_APP_SIMULATE_HOOK_LOSS: {
            const DWORD hookThreadId = g_hookThreadId.load(std::memory_order_acquire);
            if (hookThreadId) PostThreadMessageW(hookThreadId, WM_APP_DROP_HOOK, 0, 0);
            return 0;
        }
        case WM_TIMER:
            if (wParam == TIMER_LAYOUT) {
                SynchronizeScrollLock();
            } else if (wParam == TIMER_HEALTH) {
                SendHealthProbe(window);
            } else if (wParam == TIMER_PROBE_CHECK) {
                KillTimer(window, TIMER_PROBE_CHECK);
                if (g_lastProbeSeen.load(std::memory_order_acquire) < g_lastProbeSent) {
                    Log(L"Watchdog detected missing keyboard hook heartbeat");
                    RequestHookReinstall(HookReason::Watchdog);
                }
            } else if (wParam == TIMER_FALLBACK_REHOOK) {
                RequestHookReinstall(HookReason::PeriodicFallback);
            } else if (wParam == TIMER_HOOK_RETRY) {
                KillTimer(window, TIMER_HOOK_RETRY);
                RequestHookReinstall(HookReason::Retry);
            }
            return 0;
        case WM_HOTKEY:
            if (wParam == HOTKEY_PROBE_ID &&
                g_lastProbeSeen.load(std::memory_order_acquire) < g_lastProbeSent) {
                Log(L"Watchdog F24 safety hotkey received; reinstalling hook");
                RequestHookReinstall(HookReason::Watchdog);
            }
            return 0;
        case WM_POWERBROADCAST:
            if (wParam == PBT_APMRESUMEAUTOMATIC || wParam == PBT_APMRESUMESUSPEND) {
                Log(L"Power resume detected");
                RequestHookReinstall(HookReason::SessionResume);
            }
            return TRUE;
        case WM_WTSSESSION_CHANGE:
            if (wParam == WTS_SESSION_UNLOCK || wParam == WTS_SESSION_LOGON ||
                wParam == WTS_REMOTE_CONNECT || wParam == WTS_CONSOLE_CONNECT) {
                Log(L"Session event %llu detected", static_cast<unsigned long long>(wParam));
                RequestHookReinstall(HookReason::SessionResume);
            }
            return 0;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        default:
            return DefWindowProcW(window, message, wParam, lParam);
    }
}

int RunEngine(bool showMenu) {
    g_instanceMutex = CreateMutexW(nullptr, TRUE, kMutexName);
    if (!g_instanceMutex) return 2;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(g_instanceMutex);
        g_instanceMutex = nullptr;
        HWND existing = FindEngineWindow();
        if (existing && showMenu) PostMessageW(existing, WM_APP_SHOW_MENU, 0, 0);
        return 0;
    }

    WNDCLASSEXW windowClass{};
    windowClass.cbSize = sizeof(windowClass);
    windowClass.lpfnWndProc = MainWindowProc;
    windowClass.hInstance = GetModuleHandleW(nullptr);
    windowClass.lpszClassName = kWindowClass;
    if (!RegisterClassExW(&windowClass) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        return 3;
    }
    HWND window = CreateWindowExW(0, kWindowClass, kWindowTitle, 0, 0, 0, 0, 0,
                                  HWND_MESSAGE, nullptr, GetModuleHandleW(nullptr), nullptr);
    if (!window) return 4;
    g_mainWindow.store(reinterpret_cast<ULONG_PTR>(window), std::memory_order_release);

    WTSRegisterSessionNotification(window, NOTIFY_FOR_THIS_SESSION);
    g_probeHotkeyRegistered = RegisterHotKey(window, HOTKEY_PROBE_ID, MOD_NOREPEAT, VK_F24) != FALSE;
    if (!g_probeHotkeyRegistered) {
        Log(L"F24 watchdog hotkey unavailable; using 30-second periodic hook renewal");
        SetTimer(window, TIMER_FALLBACK_REHOOK, 30000, nullptr);
    }
    SetTimer(window, TIMER_LAYOUT, 500, nullptr);
    if (g_probeHotkeyRegistered) SetTimer(window, TIMER_HEALTH, 10000, nullptr);

    g_hookReadyEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_hookThread = CreateThread(nullptr, 0, HookThreadMain, nullptr, 0, nullptr);
    if (!g_hookThread || WaitForSingleObject(g_hookReadyEvent, 5000) != WAIT_OBJECT_0) {
        Log(L"Hook thread failed to initialize");
        MessageBoxW(nullptr, L"Не удалось запустить keyboard hook.", kAppName,
                    MB_OK | MB_ICONERROR);
    }

    Log(L"CapsLang %s started; watchdog hotkey=%d", kVersion,
        g_probeHotkeyRegistered ? 1 : 0);
    if (showMenu) PostMessageW(window, WM_APP_SHOW_MENU, 0, 0);

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

    KillTimer(window, TIMER_LAYOUT);
    KillTimer(window, TIMER_HEALTH);
    KillTimer(window, TIMER_PROBE_CHECK);
    KillTimer(window, TIMER_FALLBACK_REHOOK);
    KillTimer(window, TIMER_HOOK_RETRY);
    if (g_probeHotkeyRegistered) UnregisterHotKey(window, HOTKEY_PROBE_ID);
    WTSUnRegisterSessionNotification(window);
    const DWORD hookThreadId = g_hookThreadId.load(std::memory_order_acquire);
    if (hookThreadId) PostThreadMessageW(hookThreadId, WM_QUIT, 0, 0);
    if (g_hookThread) {
        WaitForSingleObject(g_hookThread, 5000);
        CloseHandle(g_hookThread);
        g_hookThread = nullptr;
    }
    if (g_hookReadyEvent) {
        CloseHandle(g_hookReadyEvent);
        g_hookReadyEvent = nullptr;
    }
    g_mainWindow.store(0, std::memory_order_release);
    DestroyWindow(window);
    if (g_instanceMutex) {
        ReleaseMutex(g_instanceMutex);
        CloseHandle(g_instanceMutex);
        g_instanceMutex = nullptr;
    }
    Log(L"CapsLang stopped");
    return 0;
}

int FinishUninstall(DWORD parentProcessId, bool restoreLegacy) {
    HANDLE parent = OpenProcess(SYNCHRONIZE, FALSE, parentProcessId);
    if (parent) {
        WaitForSingleObject(parent, 10000);
        CloseHandle(parent);
    } else {
        Sleep(1000);
    }
    RemoveRunRegistration();
    DeleteFileW(InstalledExecutablePath().c_str());
    DeleteFileW((g_logPath + L".3").c_str());
    DeleteFileW((g_logPath + L".2").c_str());
    DeleteFileW((g_logPath + L".1").c_str());
    DeleteFileW(g_logPath.c_str());
    DeleteFileW(JoinPath(g_appDir, L"CapsLang.exe.new").c_str());
    RemoveDirectoryW(g_appDir.c_str());
    if (restoreLegacy) RestoreLegacyExecutable(true);
    MoveFileExW(CurrentExecutablePath().c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
    return 0;
}

std::vector<std::wstring> CommandLineArguments() {
    int count = 0;
    LPWSTR* raw = CommandLineToArgvW(GetCommandLineW(), &count);
    std::vector<std::wstring> result;
    if (raw) {
        for (int index = 1; index < count; ++index) result.emplace_back(raw[index]);
        LocalFree(raw);
    }
    return result;
}

bool HasArgument(const std::vector<std::wstring>& arguments, const wchar_t* expected) {
    for (const std::wstring& argument : arguments) {
        if (_wcsicmp(argument.c_str(), expected) == 0) return true;
    }
    return false;
}

} // namespace

#ifdef CAPSLANG_TEST

#include <cstdio>

int main() {
    int failures = 0;
    auto check = [&](bool condition, const char* name) {
        if (!condition) {
            std::fprintf(stderr, "FAIL: %s\n", name);
            ++failures;
        }
    };

    CapsKeyState state;
    KeyOutcome result = state.Handle(VK_CAPITAL, WM_KEYDOWN, false, 0);
    check(result.swallow && result.switchLanguage, "plain down switches and swallows");
    result = state.Handle(VK_CAPITAL, WM_KEYDOWN, false, 0);
    check(result.swallow && !result.switchLanguage, "repeat is swallowed without switch");
    result = state.Handle(VK_CAPITAL, WM_KEYUP, false, 0);
    check(result.swallow && !result.switchLanguage, "plain up swallowed");

    result = state.Handle(VK_CAPITAL, WM_KEYDOWN, true, 0);
    check(!result.swallow && !result.switchLanguage, "shift down passes");
    result = state.Handle(VK_CAPITAL, WM_KEYDOWN, true, 0);
    check(!result.swallow && !result.switchLanguage, "shift repeat passes");
    result = state.Handle(VK_CAPITAL, WM_KEYUP, false, 0);
    check(!result.swallow && !result.switchLanguage, "shift mode up passes even if shift released first");

    result = state.Handle(VK_F24, WM_KEYDOWN, false, kProbeMarker);
    check(result.swallow && result.probeSeen, "watchdog probe recognized");
    result = state.Handle('A', WM_KEYDOWN, false, 0);
    check(!result.swallow && !result.switchLanguage && !result.probeSeen, "unrelated key passes");

    state.Handle(VK_CAPITAL, WM_KEYDOWN, false, 0);
    state.Reset();
    result = state.Handle(VK_CAPITAL, WM_KEYDOWN, false, 0);
    check(result.switchLanguage, "reset clears held state");

    if (failures == 0) std::puts("All CapsLang state-machine tests passed.");
    return failures == 0 ? 0 : 1;
}

#else

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    g_appDir = JoinPath(GetKnownFolder(FOLDERID_LocalAppData), L"CapsLang");
    g_logPath = JoinPath(g_appDir, L"capslang.log");
    const std::vector<std::wstring> arguments = CommandLineArguments();

    if (HasArgument(arguments, L"--finish-uninstall")) {
        DWORD parentProcessId = 0;
        for (size_t index = 0; index + 1 < arguments.size(); ++index) {
            if (_wcsicmp(arguments[index].c_str(), L"--finish-uninstall") == 0) {
                parentProcessId = wcstoul(arguments[index + 1].c_str(), nullptr, 10);
                break;
            }
        }
        const int result = FinishUninstall(parentProcessId,
                                            HasArgument(arguments, L"--restore-legacy"));
        CoUninitialize();
        return result;
    }

    if (HasArgument(arguments, L"--install")) {
        const int result = InstallApplication(false) ? 0 : 1;
        CoUninitialize();
        return result;
    }

    if (HasArgument(arguments, L"--uninstall") ||
        HasArgument(arguments, L"--restore-legacy")) {
        const bool restore = HasArgument(arguments, L"--restore-legacy");
        HWND engine = FindEngineWindow();
        if (engine) {
            PostMessageW(engine, WM_APP_BEGIN_UNINSTALL, restore ? 1 : 0, 0);
            CoUninitialize();
            return 0;
        }
        RemoveRunRegistration();
        if (SamePath(CurrentExecutablePath(), InstalledExecutablePath())) {
            BeginSelfRemoval(restore);
            CoUninitialize();
            return 0;
        }
        DeleteFileW(InstalledExecutablePath().c_str());
        if (restore) RestoreLegacyExecutable(true);
        CoUninitialize();
        return 0;
    }

    HWND existing = FindEngineWindow();
    if (HasArgument(arguments, L"--test-drop-hook")) {
        if (existing) {
            PostMessageW(existing, WM_APP_SIMULATE_HOOK_LOSS, 0, 0);
            CoUninitialize();
            return 0;
        }
        CoUninitialize();
        return 1;
    }
    if (HasArgument(arguments, L"--stop")) {
        if (existing) PostMessageW(existing, WM_APP_SHUTDOWN, 0, 0);
        CoUninitialize();
        return existing ? 0 : 1;
    }
    if (HasArgument(arguments, L"--status")) {
        if (existing) {
            PostMessageW(existing, WM_APP_SHOW_MENU, 0, 0);
            CoUninitialize();
            return 0;
        }
        MessageBoxW(nullptr, L"CapsLang сейчас не запущен.", kAppName, MB_OK | MB_ICONWARNING);
        CoUninitialize();
        return 1;
    }
    if (HasArgument(arguments, L"--restart")) {
        if (existing) {
            PostMessageW(existing, WM_APP_RESTART_HOOK, 0, 0);
            CoUninitialize();
            return 0;
        }
        const bool launched = FileExists(InstalledExecutablePath()) &&
                              Launch(InstalledExecutablePath(), L"--background");
        CoUninitialize();
        return launched ? 0 : 1;
    }

    const bool background = HasArgument(arguments, L"--background");
    const bool runOnce = HasArgument(arguments, L"--run-once");
    if (existing) {
        if (!background && !runOnce) PostMessageW(existing, WM_APP_SHOW_MENU, 0, 0);
        CoUninitialize();
        return 0;
    }

    const bool currentIsInstalled = SamePath(CurrentExecutablePath(), InstalledExecutablePath());
    if (!background && !runOnce && !currentIsInstalled) {
        const std::vector<TASKDIALOG_BUTTON> buttons = {
            {201, L"Установить"},
            {202, L"Запустить один раз"},
        };
        const int choice = ShowTask(kAppName, L"Переключение языка по CapsLock",
            L"CapsLock переключает English ↔ Русский, Shift+CapsLock оставляет обычный Caps Lock.",
            buttons, TDCBF_CANCEL_BUTTON);
        if (choice == 201) {
            const int result = InstallApplication(true) ? 0 : 1;
            CoUninitialize();
            return result;
        }
        if (choice != 202) {
            CoUninitialize();
            return 0;
        }
    }

    const int result = RunEngine(!background && !runOnce && currentIsInstalled);
    CoUninitialize();
    return result;
}

#endif
