#pragma once
#include "paths.hpp"
namespace capslang::app {
enum class AdminAction { Install, Revert, Uninstall };
enum class UserAction { Install, Uninstall, Rollback, RestoreLegacy };
DWORD AdminInstall(AdminAction action);
DWORD UserInstall(UserAction action);
DWORD RestartInstalled();
DWORD EnsureInstalledEngine();
DWORD PrepareMigration();
DWORD CompleteMigration();
DWORD AbortMigration();
DWORD RestorePreviousUserVersion(bool legacy);
DWORD CheckRestoreAvailable(bool legacy);
} // namespace capslang::app
