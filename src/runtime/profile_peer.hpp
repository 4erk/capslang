#pragma once
#include "local_ipc.hpp"
#include <memory>

namespace capslang {
// Module-side bridge: construct/Start/Step/destroy on the HOST's UI thread.
// Only its private worker does authenticated local IPC. WakeMessage carries no
// commands: callers cannot inject an operation by posting a Windows message.
// The module stays loaded until the host exits (PIN) so owner death, a delayed
// timer or an in-flight COM callback cannot execute unloaded code. Installation
// must therefore use immutable versioned modules, not overwrite loaded DLLs.
class ProfilePeer {
public:
    ProfilePeer(ipc::Endpoint endpoint, std::uint64_t binding,
                std::wstring expectedServer, bool requireElevation = true);
    ~ProfilePeer();
    ProfilePeer(const ProfilePeer&) = delete;
    ProfilePeer& operator=(const ProfilePeer&) = delete;
    bool Start();
    void Step();
    bool Detached() const;
    bool Finished() const;
    static UINT WakeMessage();
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace capslang
