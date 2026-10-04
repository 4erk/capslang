#pragma once
#include "engine.hpp"
#include "local_ipc.hpp"
#include <atomic>

namespace capslang {
// The elevated role owns ONLY the engine and local IPC. No settings files,
// user-controlled paths, commands, certificates or sockets are opened here.
// Its caller supplies no options from IPC; test dependencies are code-only.
class EngineHost {
public:
    explicit EngineHost(ipc::Endpoint endpoint = ipc::Endpoint::Current(), EngineOptions options = {});
    ~EngineHost();
    EngineHost(const EngineHost&) = delete;
    EngineHost& operator=(const EngineHost&) = delete;
    bool Start();
    void Stop();
    HANDLE ShutdownEvent() const { return shutdown_; }
    DWORD Error() const { return error_; }
private:
    ipc::Response Handle(const ipc::Request& request);
    Engine engine_;
    ipc::Server server_;
    HANDLE shutdown_ = nullptr;
    std::atomic<bool> ready_{false};
    std::uint64_t epoch_ = 0;
    DWORD error_ = 0;
};
} // namespace capslang
