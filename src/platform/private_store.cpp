#include "private_store.hpp"
#include <wincrypt.h>
#include <bcrypt.h>
#include <sddl.h>

namespace capslang {
namespace {
constexpr DWORD kMaximum = 65536;
constexpr BYTE kDomain[] = "CapsLang private data v1";
void Clear(std::vector<BYTE>& data) {
    if (!data.empty()) SecureZeroMemory(data.data(), data.size());
    data.clear();
}
struct Security {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    Security() {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return;
        DWORD bytes = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &bytes);
        std::vector<BYTE> storage(bytes);
        wchar_t* sid = nullptr;
        if (bytes && GetTokenInformation(token, TokenUser, storage.data(), bytes, &bytes) &&
            ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(storage.data())->User.Sid, &sid)) {
            const std::wstring sddl = L"D:P(A;;FA;;;SY)(A;;FA;;;" + std::wstring(sid) + L")";
            ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr);
            LocalFree(sid);
        }
        CloseHandle(token);
    }
    ~Security() { if (descriptor) LocalFree(descriptor); }
    Security(const Security&) = delete;
    Security& operator=(const Security&) = delete;
};
}
bool ProtectUserData(const std::vector<BYTE>& plain, std::vector<BYTE>& encrypted, DWORD& error) {
    if (&plain == &encrypted) { error = ERROR_INVALID_PARAMETER; return false; }
    Clear(encrypted);
    if (plain.empty() || plain.size() > kMaximum) { error = ERROR_INVALID_PARAMETER; return false; }
    DATA_BLOB input{static_cast<DWORD>(plain.size()), const_cast<BYTE*>(plain.data())}, output{};
    DATA_BLOB domain{sizeof(kDomain), const_cast<BYTE*>(kDomain)};
    if (!CryptProtectData(&input, L"CapsLang private data", &domain, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output)) {
        error = GetLastError(); return false;
    }
    encrypted.assign(output.pbData, output.pbData + output.cbData);
    SecureZeroMemory(output.pbData, output.cbData); LocalFree(output.pbData);
    error = 0; return true;
}
bool UnprotectUserData(const std::vector<BYTE>& encrypted, std::vector<BYTE>& plain, DWORD& error) {
    if (&plain == &encrypted) { error = ERROR_INVALID_PARAMETER; return false; }
    Clear(plain);
    if (encrypted.empty() || encrypted.size() > kMaximum + 4096) { error = ERROR_INVALID_DATA; return false; }
    DATA_BLOB input{static_cast<DWORD>(encrypted.size()), const_cast<BYTE*>(encrypted.data())}, output{};
    DATA_BLOB domain{sizeof(kDomain), const_cast<BYTE*>(kDomain)};
    if (!CryptUnprotectData(&input, nullptr, &domain, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output)) {
        error = GetLastError(); return false;
    }
    const bool valid = output.cbData && output.cbData <= kMaximum;
    if (valid) plain.assign(output.pbData, output.pbData + output.cbData);
    SecureZeroMemory(output.pbData, output.cbData); LocalFree(output.pbData);
    error = valid ? 0 : ERROR_INVALID_DATA; return valid;
}
bool SavePrivateData(const std::wstring& path, const std::vector<BYTE>& plain, bool replace, DWORD& error) {
    if (path.empty() || path.size() > 32000) { error = ERROR_INVALID_PARAMETER; return false; }
    std::vector<BYTE> encrypted;
    if (!ProtectUserData(plain, encrypted, error)) return false;
    BYTE random[16]{};
    if (BCryptGenRandom(nullptr, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) { error = NTE_FAIL; return false; }
    const Security security;
    if (!security.descriptor) { error = ERROR_INVALID_SECURITY_DESCR; return false; }
    std::wstring temporary = path + L".tmp-";
    constexpr wchar_t hex[] = L"0123456789abcdef";
    for (BYTE byte : random) { temporary += hex[byte >> 4]; temporary += hex[byte & 15]; }
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), security.descriptor, FALSE};
    HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, &attributes, CREATE_NEW,
                              FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (file == INVALID_HANDLE_VALUE) { error = GetLastError(); return false; }
    DWORD bytes = 0;
    const bool written = WriteFile(file, encrypted.data(), static_cast<DWORD>(encrypted.size()), &bytes, nullptr) &&
        bytes == encrypted.size() && FlushFileBuffers(file);
    error = written ? 0 : GetLastError();
    CloseHandle(file);
    bool committed = written && MoveFileExW(temporary.c_str(), path.c_str(),
        MOVEFILE_WRITE_THROUGH | (replace ? MOVEFILE_REPLACE_EXISTING : 0));
    if (written && !committed) error = GetLastError();
    if (!committed) DeleteFileW(temporary.c_str()); // Exact exclusively created scratch file only.
    if (!committed && !error) error = ERROR_WRITE_FAULT;
    return committed;
}
bool LoadPrivateData(const std::wstring& path, std::vector<BYTE>& plain, DWORD& error) {
    Clear(plain);
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) { error = GetLastError(); return false; }
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > kMaximum + 4096) {
        CloseHandle(file); error = ERROR_INVALID_DATA; return false;
    }
    std::vector<BYTE> encrypted(static_cast<size_t>(size.QuadPart));
    DWORD bytes = 0;
    const bool read = ReadFile(file, encrypted.data(), static_cast<DWORD>(encrypted.size()), &bytes, nullptr) && bytes == encrypted.size();
    error = read ? 0 : GetLastError();
    CloseHandle(file);
    if (!read) { if (!error) error = ERROR_READ_FAULT; return false; }
    return UnprotectUserData(encrypted, plain, error);
}
} // namespace capslang
