#pragma once
#include "local_ipc.hpp"
#include "../core/broker.hpp"

namespace capslang {
// Ordinary broker -> same-user/same-session, validated executable engine.
// ReadState consumes the elevated recipient adapter, not raw injected-mouse
// counts or physicalAge. Real two-machine acceptance remains mandatory.
class EngineClient {
public:
    EngineClient(std::wstring executable, ipc::Endpoint endpoint = ipc::Endpoint::Current(), bool requireElevation = true)
        : executable_(std::move(executable)), endpoint_(std::move(endpoint)), elevated_(requireElevation) {}
    bool Read(ipc::Response& result);
    bool ReadState(sync::LocalState& result);
    bool Queue(const sync::ApplyCommand& command);
    static bool MakeState(const ipc::Response& response, std::uint64_t activitySerial,
                          sync::Age activity, bool mwb, sync::LocalState& output);
    static bool RecipientState(const ipc::Response& response, std::uint64_t roundTrip,
                               sync::LocalState& output);
    DWORD Error() const { return error_; }
private:
    std::wstring executable_;
    ipc::Endpoint endpoint_;
    bool elevated_;
    std::uint64_t sequence_ = 0;
    DWORD error_ = 0;
};
} // namespace capslang
