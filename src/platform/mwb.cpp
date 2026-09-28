#include "mwb.hpp"
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
struct Windows { DWORD pid; unsigned dots = 0; bool visible = false; };
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
        ++result.dots; result.visible = IsWindowVisible(window) != FALSE;
    }
    return TRUE;
}
}
MwbEvidence MwbObserver::Read() {
    const auto now = GetTickCount64();
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
    if (!result.applications || result.helpers != 1 || !helperPid_ || !result.supportedBinary) return result;
    Windows windows{helperPid_};
    if (!EnumWindows(Dot, reinterpret_cast<LPARAM>(&windows))) { result.error = GetLastError(); return result; }
    result.dots = windows.dots; result.dotVisible = windows.visible;
    if (windows.dots == 1) result.route = windows.visible ? MwbRoute::RemoteCandidate : MwbRoute::LocalCandidate;
    return result;
}
} // namespace capslang
