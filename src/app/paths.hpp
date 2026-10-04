#pragma once
#include "../platform/windows_support.hpp"
namespace capslang::app {
std::wstring ExecutablePath();
std::wstring DataDirectory(DWORD &error);
std::wstring InstalledExecutable(DWORD &error);
// Read-only fail-closed check. A future installer must establish these ACLs;
// being located under Program Files by name alone is NOT enough.
bool ProtectedExecutable(const std::wstring &path, DWORD &error);
bool StartSelf(const wchar_t *arguments, DWORD &error);
bool ExportDiagnosis(const std::wstring &directory, const std::string &json, std::wstring &path,
                     DWORD &error);
} // namespace capslang::app
