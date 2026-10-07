#pragma once
#include "local_ipc.hpp"
#include "../core/system_layout.hpp"

namespace capslang::system_layout {
// Service and worker modes contain no network or input-synthesis entry points.
// The worker's fixed profile role may attach the target-thread observer to a
// validated SYSTEM-owned foreground window on the unlocked console desktop.
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
// Object-local read-only access for the installation owner to authenticate our
// SYSTEM worker. No debug privilege, token duplication or process memory access.
bool WorkerQuerySecurity(const std::wstring& owner, bool token,
    PSECURITY_DESCRIPTOR& descriptor, DWORD& error);
#ifdef CAPSLANG_SYSTEM_PROFILE_PROBE
// Compile-time diagnostic only. Own one bounded worker, no service registration.
DWORD ProbeWorker();
#endif
} // namespace capslang::system_layout
