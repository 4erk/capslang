#pragma once
#include "windows_support.hpp"

namespace capslang {
// User-scoped DPAPI; never machine-wide or UI-prompted protection.
// Files receive a private current-user/SYSTEM DACL and are committed by rename.
bool ProtectUserData(const std::vector<BYTE>& plain, std::vector<BYTE>& encrypted, DWORD& error);
bool UnprotectUserData(const std::vector<BYTE>& encrypted, std::vector<BYTE>& plain, DWORD& error);
bool SavePrivateData(const std::wstring& path, const std::vector<BYTE>& plain, bool replace, DWORD& error);
bool LoadPrivateData(const std::wstring& path, std::vector<BYTE>& plain, DWORD& error);
} // namespace capslang
