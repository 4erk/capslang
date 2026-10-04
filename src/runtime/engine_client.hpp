#pragma once
#include "local_ipc.hpp"
#include "../core/broker.hpp"

namespace capslang {
// Ordinary broker -> same-user/same-session, validated executable engine.
// Activity evidence is supplied separately by the verified recipient observer;
// raw injected mouse counts or stale physicalAge are NEVER promoted here.
class EngineClient {
public:
    EngineClient(std::wstring executable, ipc::Endpoint endpoint = ipc::Endpoint::Current(), bool requireElevation = true)
        : executable_(std::move(executable)), endpoint_(std::move(endpoint)), elevated_(requireElevation) {}
    bool Read(ipc::Response& result);
    bool Queue(const sync::ApplyCommand& command);
    static bool MakeState(const ipc::Response& response, std::uint64_t activitySerial,
                          sync::Age activity, bool mwb, sync::LocalState& output);
    DWORD Error() const { return error_; }
private:
    std::wstring executable_;
    ipc::Endpoint endpoint_;
    bool elevated_;
    std::uint64_t sequence_ = 0;
    DWORD error_ = 0;
};
} // namespace capslang
