#include "profile_assets.hpp"
#include <bcrypt.h>

namespace capslang::app {
namespace {
bool Digest(const std::vector<BYTE>& bytes, install::Hash& hash) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0)) return false;
    const bool ok = BCryptHash(algorithm, nullptr, 0, const_cast<BYTE*>(bytes.data()),
        static_cast<ULONG>(bytes.size()), hash.data(), static_cast<ULONG>(hash.size())) == 0;
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return ok;
}
bool ModuleImage(const std::vector<BYTE>& bytes, WORD machine) {
    if (bytes.size() < sizeof(IMAGE_DOS_HEADER)) return false;
    IMAGE_DOS_HEADER dos{}; memcpy(&dos, bytes.data(), sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0) return false;
    const auto offset = static_cast<std::size_t>(dos.e_lfanew);
    if (offset > bytes.size() || bytes.size() - offset < sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)) return false;
    DWORD signature = 0; memcpy(&signature, bytes.data() + offset, sizeof(signature));
    IMAGE_FILE_HEADER file{}; memcpy(&file, bytes.data() + offset + sizeof(signature), sizeof(file));
    return signature == IMAGE_NT_SIGNATURE && file.Machine == machine &&
        (file.Characteristics & IMAGE_FILE_DLL) && (file.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE);
}
}
bool ReadProfileAsset(HMODULE image, WORD machine, ProfileAsset& asset, DWORD& error) {
    asset = {};
    const WORD id = machine == IMAGE_FILE_MACHINE_AMD64 ? 4101 : machine == IMAGE_FILE_MACHINE_I386 ? 4102 : 0;
    if (!image || !id) { error = ERROR_INVALID_PARAMETER; return false; }
    const auto resource = FindResourceW(image, MAKEINTRESOURCEW(id), RT_RCDATA);
    const DWORD size = resource ? SizeofResource(image, resource) : 0;
    const auto loaded = resource ? LoadResource(image, resource) : nullptr;
    const auto data = loaded ? static_cast<const BYTE*>(LockResource(loaded)) : nullptr;
    if (!data || !size || size > 8 * 1024 * 1024) { error = ERROR_RESOURCE_DATA_NOT_FOUND; return false; }
    asset.bytes.assign(data, data + size);
    if (!ModuleImage(asset.bytes, machine) || !Digest(asset.bytes, asset.hash)) {
        asset = {}; error = ERROR_BAD_EXE_FORMAT; return false;
    }
    asset.machine = machine; error = 0; return true;
}
std::wstring ProfileAssetRelativePath(const ProfileAsset& asset) {
    if (asset.machine != IMAGE_FILE_MACHINE_AMD64 && asset.machine != IMAGE_FILE_MACHINE_I386) return {};
    return L"modules\\" + install::Hex(asset.hash) + L"\\" +
        (asset.machine == IMAGE_FILE_MACHINE_AMD64 ? L"CapsLangProfile64.dll" : L"CapsLangProfile32.dll");
}
bool StageProfileAssets(HMODULE image, const std::wstring& root, DWORD& error) {
    ProfileAsset x64, x86;
    // Validate the whole bundle before changing any protected file.
    if (!ReadProfileAsset(image, IMAGE_FILE_MACHINE_AMD64, x64, error) ||
        !ReadProfileAsset(image, IMAGE_FILE_MACHINE_I386, x86, error) ||
        !install::CreateRoot(root + L"\\modules", error)) return false;
    for (const auto* asset : {&x64, &x86}) {
        const auto path = root + L"\\" + ProfileAssetRelativePath(*asset);
        if (!install::CreateRoot(path.substr(0, path.find_last_of(L'\\')), error)) return false;
        const auto attributes = GetFileAttributesW(path.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) {
            if (GetLastError() != ERROR_FILE_NOT_FOUND ||
                !install::WriteProtected(path, asset->bytes, false, error)) {
                if (!error) error = GetLastError();
                return false;
            }
        }
        install::Hash actual{};
        if (!ProtectedPath(path, false, error) || !install::FileHash(path, actual, error)) return false;
        if (actual != asset->hash) { error = ERROR_CRC; return false; }
    }
    error = 0; return true;
}
std::wstring InstalledProfileModule(WORD machine, DWORD& error) {
    ProfileAsset asset;
    const auto executable = InstalledExecutable(error);
    if (executable.empty() || !ProtectedExecutable(ExecutablePath(), error) ||
        !ReadProfileAsset(GetModuleHandleW(nullptr), machine, asset, error)) return {};
    const auto path = executable.substr(0, executable.find_last_of(L'\\')) + L"\\" + ProfileAssetRelativePath(asset);
    install::Hash actual{};
    if (!ProtectedPath(path, false, error) || !install::FileHash(path, actual, error)) return {};
    if (actual != asset.hash) { error = ERROR_CRC; return {}; }
    error = 0; return path;
}
} // namespace capslang::app
