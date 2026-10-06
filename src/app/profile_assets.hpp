#pragma once
#include "install_store.hpp"

namespace capslang::app {
struct ProfileAsset {
    std::vector<BYTE> bytes;
    install::Hash hash{};
    WORD machine = 0;
};
// Read embedded bytes as data only. No DLL execution during installation.
bool ReadProfileAsset(HMODULE image, WORD machine, ProfileAsset& asset, DWORD& error);
std::wstring ProfileAssetRelativePath(const ProfileAsset& asset);
bool StageProfileAssets(HMODULE image, const std::wstring& protectedRoot, DWORD& error);
std::wstring InstalledProfileModule(WORD machine, DWORD& error);
} // namespace capslang::app
