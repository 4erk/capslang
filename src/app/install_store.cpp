#include "install_store.hpp"
#include <bcrypt.h>
#include <sddl.h>

namespace capslang::app::install {
namespace {
constexpr size_t kMaximum = 600000;
struct Security {
    PSECURITY_DESCRIPTOR value = nullptr;
    Security() {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)", SDDL_REVISION_1,
            &value, nullptr);
    }
    ~Security() {
        if (value)
            LocalFree(value);
    }
};
void Number(std::vector<BYTE> &out, DWORD n) {
    for (unsigned i = 0; i < 4; ++i)
        out.push_back(static_cast<BYTE>(n >> (8 * i)));
}
void String(std::vector<BYTE> &out, const std::wstring &s) {
    Number(out, static_cast<DWORD>(s.size()));
    for (wchar_t c : s) {
        out.push_back(static_cast<BYTE>(c));
        out.push_back(static_cast<BYTE>(c >> 8));
    }
}
bool Number(const std::vector<BYTE> &in, size_t &at, DWORD &n) {
    if (at > in.size() || in.size() - at < 4)
        return false;
    n = 0;
    for (unsigned i = 0; i < 4; ++i)
        n |= static_cast<DWORD>(in[at++]) << (8 * i);
    return true;
}
bool String(const std::vector<BYTE> &in, size_t &at, std::wstring &s, size_t maximum) {
    DWORD count = 0;
    if (!Number(in, at, count) || count > maximum || count > (in.size() - at) / 2)
        return false;
    s.clear();
    for (DWORD i = 0; i < count; ++i) {
        wchar_t c = static_cast<wchar_t>(in[at] | (in[at + 1] << 8));
        at += 2;
        if (!c)
            return false;
        s += c;
    }
    return true;
}
bool Sha(const BYTE *bytes, size_t size, Hash &hash) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0))
        return false;
    const bool ok =
        size <= ULONG_MAX &&
        BCryptHash(algorithm, nullptr, 0, const_cast<PUCHAR>(bytes), static_cast<ULONG>(size),
                   hash.data(), static_cast<ULONG>(hash.size())) == 0;
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return ok;
}
bool Valid(const Record &r) {
    if (r.phase < Phase::Prepared || r.phase > Phase::Removed || r.sid.empty() ||
        r.sid.size() > 184 || r.engineXml.size() > 65536 || r.brokerXml.size() > 65536 ||
        r.engineSecurity.size() > 8192 || r.brokerSecurity.size() > 8192 ||
        r.engineXml.empty() != r.engineSecurity.empty() ||
        r.brokerXml.empty() != r.brokerSecurity.empty())
        return false;
    const Hash zero{};
    if (r.after == zero || (r.hadExecutable == (r.before == zero)) ||
        (!r.hadExecutable && (!r.engineXml.empty() || !r.brokerXml.empty())))
        return false;
    PSID sid = nullptr;
    const bool parsed = ConvertStringSidToSidW(r.sid.c_str(), &sid) != FALSE;
    if (sid)
        LocalFree(sid);
    return parsed;
}
std::wstring Parent(const std::wstring &path) {
    const auto slash = path.find_last_of(L'\\');
    return slash == std::wstring::npos ? std::wstring{} : path.substr(0, slash);
}
bool Read(const std::wstring &path, std::vector<BYTE> &bytes, size_t max, DWORD &error) {
    bytes.clear();
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        error = GetLastError();
        return false;
    }
    BY_HANDLE_FILE_INFORMATION info{};
    LARGE_INTEGER size{};
    if (!GetFileInformationByHandle(file, &info) ||
        (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) ||
        !GetFileSizeEx(file, &size) || size.QuadPart <= 0 ||
        static_cast<ULONGLONG>(size.QuadPart) > max) {
        CloseHandle(file);
        error = ERROR_INVALID_DATA;
        return false;
    }
    bytes.resize(static_cast<size_t>(size.QuadPart));
    DWORD read = 0;
    const bool ok =
        ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr) &&
        read == bytes.size();
    error = ok ? 0 : GetLastError();
    CloseHandle(file);
    if (!ok && !error)
        error = ERROR_READ_FAULT;
    return ok;
}
} // namespace
bool Encode(const Record &value, std::vector<BYTE> &bytes) {
    bytes.clear();
    if (!Valid(value))
        return false;
    Number(bytes, 0x31494c43);
    Number(bytes, 2);
    Number(bytes, static_cast<DWORD>(value.phase));
    Number(bytes, (value.hadExecutable ? 1U : 0U) | (value.hadRule ? 2U : 0U) | (value.hadLayoutService ? 4U : 0U));
    bytes.insert(bytes.end(), value.before.begin(), value.before.end());
    bytes.insert(bytes.end(), value.after.begin(), value.after.end());
    for (const auto *s : {&value.sid, &value.engineXml, &value.engineSecurity, &value.brokerXml,
                          &value.brokerSecurity})
        String(bytes, *s);
    Hash digest{};
    if (!Sha(bytes.data(), bytes.size(), digest))
        return false;
    bytes.insert(bytes.end(), digest.begin(), digest.end());
    return bytes.size() <= kMaximum;
}
bool Decode(const std::vector<BYTE> &bytes, Record &value) {
    value = {};
    if (bytes.size() < 116 || bytes.size() > kMaximum)
        return false;
    Hash digest{};
    if (!Sha(bytes.data(), bytes.size() - digest.size(), digest) ||
        memcmp(digest.data(), bytes.data() + bytes.size() - digest.size(), digest.size()))
        return false;
    size_t at = 0;
    DWORD magic = 0, version = 0, phase = 0, flags = 0;
    Record r;
    if (!Number(bytes, at, magic) || !Number(bytes, at, version) || !Number(bytes, at, phase) ||
        !Number(bytes, at, flags) || magic != 0x31494c43 || (version != 1 && version != 2) ||
        (flags & ~(version == 1 ? 3U : 7U)))
        return false;
    r.phase = static_cast<Phase>(phase);
    r.hadExecutable = (flags & 1) != 0;
    r.hadRule = (flags & 2) != 0;
    r.hadLayoutService = (flags & 4) != 0;
    memcpy(r.before.data(), bytes.data() + at, 32);
    at += 32;
    memcpy(r.after.data(), bytes.data() + at, 32);
    at += 32;
    if (!String(bytes, at, r.sid, 184) || !String(bytes, at, r.engineXml, 65536) ||
        !String(bytes, at, r.engineSecurity, 8192) || !String(bytes, at, r.brokerXml, 65536) ||
        !String(bytes, at, r.brokerSecurity, 8192) || at + 32 != bytes.size() || !Valid(r))
        return false;
    value = std::move(r);
    return true;
}
bool FileHash(const std::wstring &path, Hash &hash, DWORD &error) {
    std::vector<BYTE> bytes;
    if (!Read(path, bytes, 64 * 1024 * 1024, error))
        return false;
    const bool ok = Sha(bytes.data(), bytes.size(), hash);
    error = ok ? 0 : ERROR_CRC;
    return ok;
}
std::wstring Hex(const Hash &hash) {
    std::wstring result;
    for (BYTE b : hash) {
        result += L"0123456789abcdef"[b >> 4];
        result += L"0123456789abcdef"[b & 15];
    }
    return result;
}
bool CreateRoot(const std::wstring &root, DWORD &error) {
    if (root.empty() || !ProtectedPath(Parent(root), true, error))
        return false;
    Security security;
    if (!security.value) {
        error = ERROR_INVALID_SECURITY_DESCR;
        return false;
    }
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), security.value, FALSE};
    if (!CreateDirectoryW(root.c_str(), &attributes) && GetLastError() != ERROR_ALREADY_EXISTS) {
        error = GetLastError();
        return false;
    }
    return ProtectedPath(root, true, error);
}
bool WriteProtected(const std::wstring &path, const std::vector<BYTE> &bytes, bool replace,
                    DWORD &error) {
    if (bytes.empty() || bytes.size() > 64 * 1024 * 1024 ||
        !ProtectedPath(Parent(path), true, error)) {
        if (!error)
            error = ERROR_INVALID_PARAMETER;
        return false;
    }
    if (replace && GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES &&
        !ProtectedPath(path, false, error))
        return false;
    Security security;
    if (!security.value) {
        error = ERROR_INVALID_SECURITY_DESCR;
        return false;
    }
    BYTE nonce[8]{};
    if (BCryptGenRandom(nullptr, nonce, sizeof(nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG)) {
        error = ERROR_GEN_FAILURE;
        return false;
    }
    auto temp = path + L".tmp-";
    for (BYTE b : nonce) {
        temp += L"0123456789abcdef"[b >> 4];
        temp += L"0123456789abcdef"[b & 15];
    }
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), security.value, FALSE};
    HANDLE file = CreateFileW(temp.c_str(), GENERIC_WRITE, 0, &attributes, CREATE_NEW,
                              FILE_FLAG_WRITE_THROUGH, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        error = GetLastError();
        return false;
    }
    DWORD count = 0;
    const bool wrote =
        WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &count, nullptr) &&
        count == bytes.size() && FlushFileBuffers(file);
    error = wrote ? 0 : GetLastError();
    CloseHandle(file);
    bool ok =
        wrote && MoveFileExW(temp.c_str(), path.c_str(),
                             MOVEFILE_WRITE_THROUGH | (replace ? MOVEFILE_REPLACE_EXISTING : 0));
    if (wrote && !ok)
        error = GetLastError();
    if (!ok)
        DeleteFileW(temp.c_str());
    if (!ok && !error)
        error = ERROR_WRITE_FAULT;
    return ok;
}
bool ReadProtected(const std::wstring &path, std::vector<BYTE> &bytes, DWORD &error) {
    return ProtectedPath(path, false, error) && Read(path, bytes, kMaximum, error);
}
bool CopyProtected(const std::wstring &source, const std::wstring &destination, Hash &hash,
                   DWORD &error) {
    std::vector<BYTE> bytes;
    if (!Read(source, bytes, 64 * 1024 * 1024, error))
        return false;
    if (!Sha(bytes.data(), bytes.size(), hash)) {
        error = ERROR_CRC;
        return false;
    }
    if (GetFileAttributesW(destination.c_str()) != INVALID_FILE_ATTRIBUTES) {
        Hash existing{};
        return ProtectedPath(destination, false, error) && FileHash(destination, existing, error) &&
               (existing == hash || (error = ERROR_FILE_EXISTS, false));
    }
    if (!WriteProtected(destination, bytes, false, error))
        return false;
    Hash check{};
    if (!FileHash(destination, check, error) || check != hash) {
        error = ERROR_CRC;
        return false;
    }
    return true;
}
bool SaveRecord(const std::wstring &root, const Record &value, DWORD &error) {
    std::vector<BYTE> bytes;
    if (!Encode(value, bytes)) {
        error = ERROR_INVALID_DATA;
        return false;
    }
    return WriteProtected(root + L"\\transaction.bin", bytes, true, error);
}
bool LoadRecord(const std::wstring &root, Record &value, DWORD &error) {
    std::vector<BYTE> bytes;
    if (!ReadProtected(root + L"\\transaction.bin", bytes, error))
        return false;
    if (!Decode(bytes, value)) {
        error = ERROR_INVALID_DATA;
        return false;
    }
    return true;
}
} // namespace capslang::app::install
