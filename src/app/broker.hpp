#pragma once
#include "control.hpp"
#include <atomic>

namespace capslang::app {
struct BrokerDependencies {
    std::function<bool(ipc::Response &, DWORD &)> read;
    std::function<bool(ipc::Operation, DWORD &)> command;
    net::SessionEndpoint session;
    std::function<bool(const ipc::Response&,LANGID,std::uint64_t,DWORD,bool)> profile;
};
// Application's ordinary role. UI and logs consume cached state; all IPC and
// network waits run outside the UI and the keyboard hook. Test substitutions
// are C++ dependencies, not environment variables, peer fields or CLI flags.
class Broker {
  public:
    Broker(std::wstring directory, BrokerDependencies dependencies,
           ipc::Endpoint endpoint = ControlEndpoint());
    ~Broker();
    Broker(const Broker &) = delete;
    Broker &operator=(const Broker &) = delete;
    bool Start();
    void Stop();
    DWORD Error() const;
    HANDLE Stopped() const;
    bool TakeShowRequest();
    ControlResponse Snapshot(bool pairing = false);
    bool Submit(const ControlRequest &request, DWORD &error);

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
BrokerDependencies EngineDependencies(const std::wstring &executable, bool requireElevation);
} // namespace capslang::app
