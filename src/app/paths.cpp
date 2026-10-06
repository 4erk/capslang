#include "paths.hpp"
#include <aclapi.h>
#include <bcrypt.h>
#include <sddl.h>
#include <shlobj.h>

namespace capslang::app {
namespace {
std::wstring Folder(REFKNOWNFOLDERID id, DWORD &error) {
    PWSTR value = nullptr;
    const HRESULT result = SHGetKnownFolderPath(id, KF_FLAG_DONT_VERIFY, nullptr, &value);
    if (FAILED(result)) {
        error = static_cast<DWORD>(result);
        return {};
    }
    std::wstring path = value;
    CoTaskMemFree(value);
    error = 0;
    return path;
}
bool TrustedSid(PSID sid) {
    if (!IsValidSid(sid))
        return false;
    if (IsWellKnownSid(sid, WinBuiltinAdministratorsSid) || IsWellKnownSid(sid, WinLocalSystemSid))
        return true;
    PSID installer = nullptr;
    const bool parsed =
        ConvertStringSidToSidW(L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
                               &installer) != FALSE;
    const bool yes = parsed && EqualSid(sid, installer);
    if (installer)
        LocalFree(installer);
    return yes;
}
bool ProtectedObject(const std::wstring &path, bool directory, DWORD &error) {
    HANDLE handle = CreateFileW(
        path.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | (directory ? FILE_FLAG_BACKUP_SEMANTICS : 0), nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        error = GetLastError();
        return false;
    }
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(handle, &info) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        (((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory)) {
        CloseHandle(handle);
        error = ERROR_ACCESS_DENIED;
        return false;
    }
    PSID owner = nullptr;
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR security = nullptr;
    error = GetSecurityInfo(handle, SE_FILE_OBJECT,
                            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr,
                            &dacl, nullptr, &security);
    CloseHandle(handle);
    if (error)
        return false;
    bool ok = owner && TrustedSid(owner) && dacl;
    const DWORD writes = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
                         FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER |
                         FILE_DELETE_CHILD | GENERIC_WRITE | GENERIC_ALL;
    if (ok)
        for (DWORD i = 0; i < dacl->AceCount; ++i) {
            void *data = nullptr;
            if (!GetAce(dacl, i, &data)) {
                ok = false;
                break;
            }
            const auto *header = static_cast<const ACE_HEADER *>(data);
            if (header->AceFlags & INHERIT_ONLY_ACE)
                continue;
            if (header->AceType == ACCESS_DENIED_ACE_TYPE)
                continue;
            if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) {
                ok = false;
                break;
            }
            const auto *ace = static_cast<const ACCESS_ALLOWED_ACE *>(data);
            if ((ace->Mask & writes) && !TrustedSid(const_cast<DWORD *>(&ace->SidStart))) {
                ok = false;
                break;
            }
        }
    LocalFree(security);
    error = ok ? 0 : ERROR_ACCESS_DENIED;
    return ok;
}
} // namespace
bool ProtectedPath(const std::wstring &path, bool directory, DWORD &error) {
    return ProtectedObject(path, directory, error);
}
std::wstring ExecutablePath() {
    wchar_t path[32768]{};
    const DWORD size = GetModuleFileNameW(nullptr, path, ARRAYSIZE(path));
    return size && size < ARRAYSIZE(path) ? std::wstring(path, size) : std::wstring{};
}
std::wstring DataDirectory(DWORD &error) {
    auto root = Folder(FOLDERID_LocalAppData, error);
    if (root.empty())
        return {};
    root += L"\\CapsLang";
    if (!CreateDirectoryW(root.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) {
        error = GetLastError();
        return {};
    }
    error = 0;
    return root;
}
std::wstring InstalledExecutable(DWORD &error) {
#ifndef _WIN64
    // FOLDERID_ProgramFilesX64 is explicitly unsupported in a WOW64 process.
    // Read the machine-owned 64-bit registry view, never an inherited env var.
    wchar_t native[32768]{};
    DWORD bytes = sizeof(native);
    error = RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
        L"ProgramFilesDir", RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY, nullptr, native, &bytes);
    if (error || bytes < 2 * sizeof(wchar_t) || bytes > sizeof(native) || native[bytes / sizeof(wchar_t) - 1]) {
        if (!error) error = ERROR_INVALID_DATA;
        return {};
    }
    const std::wstring root(native);
#else
    const auto root = Folder(FOLDERID_ProgramFiles, error);
#endif
    return root.empty() ? std::wstring{} : root + L"\\CapsLang\\CapsLang.exe";
}
bool ProtectedExecutable(const std::wstring &path, DWORD &error) {
    const auto expected = InstalledExecutable(error);
    if (expected.empty() || _wcsicmp(expected.c_str(), path.c_str())) {
        error = ERROR_ACCESS_DENIED;
        return false;
    }
    const auto folder = expected.substr(0, expected.find_last_of(L'\\'));
    const auto parent = folder.substr(0, folder.find_last_of(L'\\'));
    return ProtectedObject(parent, true, error) && ProtectedObject(folder, true, error) &&
           ProtectedObject(path, false, error);
}
bool StartSelf(const wchar_t *args, DWORD &error) {
    const auto path = ExecutablePath();
    if (path.empty()) {
        error = ERROR_BAD_PATHNAME;
        return false;
    }
    std::wstring command = L"\"" + path + L"\" " + args;
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION child{};
    if (!CreateProcessW(path.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &startup, &child)) {
        error = GetLastError();
        return false;
    }
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);
    error = 0;
    return true;
}
bool ExportDiagnosis(const std::wstring &directory, const std::string &json, std::wstring &path,
                     DWORD &error) {
    path.clear();
    BYTE random[8]{};
    if (directory.empty() || json.size() > 16384 ||
        BCryptGenRandom(nullptr, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG)) {
        error = ERROR_INVALID_PARAMETER;
        return false;
    }
    auto selected = directory + L"\\diagnostics-";
    for (BYTE value : random) {
        selected += L"0123456789abcdef"[value >> 4];
        selected += L"0123456789abcdef"[value & 15];
    }
    selected += L".json";
    HANDLE file = CreateFileW(selected.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        error = GetLastError();
        return false;
    }
    DWORD written = 0;
    const bool ok =
        WriteFile(file, json.data(), static_cast<DWORD>(json.size()), &written, nullptr) &&
        written == json.size() && FlushFileBuffers(file);
    error = ok ? 0 : GetLastError();
    CloseHandle(file);
    if (ok)
        path = selected;
    else if (!error)
        error = ERROR_WRITE_FAULT;
    return ok;
}
} // namespace capslang::app
