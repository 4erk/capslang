#pragma once
#include "local_ipc.hpp"
#include "../core/system_layout.hpp"

namespace capslang::system_layout {
// Service and worker modes contain no network/UI/keyboard-hook entry points.
DWORD ServiceMain();
DWORD WorkerMain();
bool IsSystem();
ipc::Endpoint Endpoint(const std::wstring& userSid, DWORD session);
bool Call(const std::wstring& executable, const Request& request, Response& response, DWORD& error);
// Installer-only operations. Validate fixed service ownership/configuration
// before touching it. No arbitrary service name/path/account accepted.
bool Installed(bool& exists, DWORD& error);
bool Install(DWORD& error);
bool Stop(DWORD& error);
bool Remove(DWORD& error);
bool Start(DWORD& error);
} // namespace capslang::system_layout
