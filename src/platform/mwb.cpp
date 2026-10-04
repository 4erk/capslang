#include "mwb.hpp"
#include "../core/json_bool.hpp"
#include <wtsapi32.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <vector>

namespace capslang {
namespace {
bool SupportedBinary(DWORD pid, DWORD& error) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) { error = GetLastError(); return false; }
    wchar_t path[32768]{};
    DWORD length = ARRAYSIZE(path);
    const bool gotPath = QueryFullProcessImageNameW(process, 0, path, &length) != FALSE;
    error = gotPath ? 0 : GetLastError();
    CloseHandle(process);
    if (!gotPath) return false;
    const DWORD size = GetFileVersionInfoSizeW(path, nullptr);
    if (!size || size > 1024 * 1024) { error = ERROR_REVISION_MISMATCH; return false; }
    std::vector<BYTE> version(size);
    VS_FIXEDFILEINFO* info = nullptr;
    UINT bytes = 0;
    if (!GetFileVersionInfoW(path, 0, size, version.data()) ||
        !VerQueryValueW(version.data(), L"\\", reinterpret_cast<void**>(&info), &bytes) ||
        bytes < sizeof(*info) || info->dwSignature != 0xfeef04bd ||
        info->dwFileVersionMS != MAKELONG(101, 0) || info->dwFileVersionLS != MAKELONG(0, 2362)) {
        error = ERROR_REVISION_MISMATCH; return false;
    }
    WINTRUST_FILE_INFO file{};
    file.cbStruct = sizeof(file); file.pcwszFilePath = path;
    WINTRUST_DATA trust{};
    trust.cbStruct = sizeof(trust); trust.dwUIChoice = WTD_UI_NONE;
    trust.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust.dwUnionChoice = WTD_CHOICE_FILE; trust.pFile = &file;
    trust.dwStateAction = WTD_STATEACTION_VERIFY;
    // Read-only local validation; this observer must never access the network.
    trust.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG result = WinVerifyTrust(reinterpret_cast<HWND>(INVALID_HANDLE_VALUE), &policy, &trust);
    bool microsoft = false;
    if (result == ERROR_SUCCESS) {
        auto* provider = WTHelperProvDataFromStateData(trust.hWVTStateData);
        auto* signer = provider ? WTHelperGetProvSignerFromChain(provider, 0, FALSE, 0) : nullptr;
        auto* cert = signer ? WTHelperGetProvCertFromChain(signer, 0) : nullptr;
        wchar_t name[256]{};
        if (cert && CertGetNameStringW(cert->pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr,
                                      name, ARRAYSIZE(name))) {
            microsoft = wcscmp(name, L"Microsoft Corporation") == 0;
        }
    }
    trust.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(reinterpret_cast<HWND>(INVALID_HANDLE_VALUE), &policy, &trust);
    error = microsoft ? 0 : (result ? static_cast<DWORD>(result) : static_cast<DWORD>(TRUST_E_SUBJECT_NOT_TRUSTED));
    return microsoft;
}
struct Windows { DWORD pid; unsigned dots = 0; bool visible = false; HWND window = nullptr; };
BOOL CALLBACK Dot(HWND window, LPARAM param) {
    auto& result = *reinterpret_cast<Windows*>(param);
    DWORD pid = 0;
    GetWindowThreadProcessId(window, &pid);
    if (pid != result.pid) return TRUE;
    // No GetWindowText: window titles/content are neither read nor logged.
    RECT rect{};
    wchar_t className[128]{};
    const auto style = GetWindowLongPtrW(window, GWL_EXSTYLE);
    if (GetWindowRect(window, &rect) && rect.right - rect.left == 4 && rect.bottom - rect.top == 4 &&
        (style & WS_EX_LAYERED) && (style & WS_EX_TOPMOST) &&
        GetClassNameW(window, className, ARRAYSIZE(className)) &&
        wcsncmp(className, L"WindowsForms10.", 15) == 0) {
        ++result.dots; result.visible = IsWindowVisible(window) != FALSE; result.window = window;
    }
    return TRUE;
}
}
MwbSettings ReadMwbSettings(const std::wstring& path) {
    MwbSettings result;
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) { result.error = GetLastError(); return result; }
    BY_HANDLE_FILE_INFORMATION before{}, after{};
    if (!GetFileInformationByHandle(file, &before)) {
        result.error = GetLastError(); CloseHandle(file); return result;
    }
    if (before.nFileSizeHigh || !before.nFileSizeLow || before.nFileSizeLow > 1024 * 1024 ||
        (before.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
        result.error = ERROR_INVALID_DATA; CloseHandle(file); return result;
    }
    std::string text(before.nFileSizeLow, '\0'); DWORD read = 0;
    const bool ok = ReadFile(file, text.data(), static_cast<DWORD>(text.size()), &read, nullptr) &&
        read == text.size() && GetFileInformationByHandle(file, &after) &&
        before.nFileSizeLow == after.nFileSizeLow && before.nFileSizeHigh == after.nFileSizeHigh &&
        CompareFileTime(&before.ftLastWriteTime, &after.ftLastWriteTime) == 0;
    CloseHandle(file);
    if (ok) {
        const auto maintenance = core::ReadSettingBool(text, "BlockScreenSaverOnOtherMachines");
        const auto hide = core::ReadSettingBool(text, "HideMouseAtScreenEdge");
        const auto relative = core::ReadSettingBool(text, "MoveMouseRelatively");
        result.known = maintenance != core::JsonBool::Unknown && hide != core::JsonBool::Unknown &&
            relative != core::JsonBool::Unknown;
        if (result.known) {
            result.maintenanceInput = maintenance == core::JsonBool::True;
            result.hideCursor = hide == core::JsonBool::True;
            result.relativeMouse = relative == core::JsonBool::True;
        }
    }
    SecureZeroMemory(text.data(), text.size());
    result.error = result.known ? ERROR_SUCCESS : ERROR_INVALID_DATA;
    return result;
}
MwbEvidence MwbObserver::Read() {
    const auto now = GetTickCount64();
    if (now >= nextSettings_) {
        nextSettings_ = now + 1000;
        wchar_t root[32768]{};
        const DWORD length = GetEnvironmentVariableW(L"LOCALAPPDATA", root, ARRAYSIZE(root));
        if (!length || length >= ARRAYSIZE(root)) { settings_ = {}; settings_.error = ERROR_PATH_NOT_FOUND; }
        else settings_ = ReadMwbSettings(std::wstring(root) + L"\\Microsoft\\PowerToys\\MouseWithoutBorders\\settings.json");
    }
    if (now >= nextDiscovery_) {
        nextDiscovery_ = now + 5000; helperPid_ = 0; discovered_ = {};
        DWORD session = 0;
        ProcessIdToSessionId(GetCurrentProcessId(), &session);
        WTS_PROCESS_INFOW* entries = nullptr;
        DWORD count = 0;
        // ProcessIdToSessionId fails for high-integrity PowerToys from a normal
        // client. WTS supplies session IDs without misreporting access denial
        // as "MWB is stopped". Signature/path verification still fails closed.
        if (!WTSEnumerateProcessesW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &entries, &count)) {
            discovered_.error = GetLastError(); return discovered_;
        }
        for (DWORD index = 0; index < count; ++index) {
            const auto& entry = entries[index];
            if (session != entry.SessionId || !entry.pProcessName) continue;
            if (_wcsicmp(entry.pProcessName, L"PowerToys.MouseWithoutBorders.exe") == 0) ++discovered_.applications;
            if (_wcsicmp(entry.pProcessName, L"PowerToys.MouseWithoutBordersHelper.exe") == 0) {
                ++discovered_.helpers;
                if (SupportedBinary(entry.ProcessId, discovered_.error)) {
                    helperPid_ = entry.ProcessId; discovered_.supportedBinary = true;
                }
            }
        }
        WTSFreeMemory(entries);
    }
    auto result = discovered_;
    result.settings = settings_; result.helperPid = helperPid_;
    if (!result.applications || result.helpers != 1 || !helperPid_ || !result.supportedBinary) return result;
    Windows windows{helperPid_};
    if (!EnumWindows(Dot, reinterpret_cast<LPARAM>(&windows))) { result.error = GetLastError(); return result; }
    result.dots = windows.dots; result.dotVisible = windows.visible;
    result.dotWindow = windows.dots == 1 ? windows.window : nullptr;
    if (windows.dots == 1) result.route = windows.visible ? MwbRoute::RemoteCandidate : MwbRoute::LocalCandidate;
    return result;
}
} // namespace capslang
