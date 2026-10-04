#include "engine_client.hpp"

namespace capslang {
bool EngineClient::Read(ipc::Response& result) {
    result = {};
    ipc::Request request; request.id = ++sequence_;
    if (!ipc::Call(endpoint_, executable_, elevated_, request, result, error_)) return false;
    if (result.error) { error_ = result.error; return false; }
    sync::LocalState state;
    if (!MakeState(result, 0, {}, false, state)) { error_ = ERROR_INVALID_DATA; return false; }
    error_ = 0; return true;
}
bool EngineClient::Queue(const sync::ApplyCommand& command) {
    if (!core::Supported(command.language) || !command.engineEpoch) { error_ = ERROR_INVALID_PARAMETER; return false; }
    ipc::Request request; request.id = ++sequence_; request.operation = ipc::Operation::SetLayoutIfRevision;
    request.language = static_cast<std::uint32_t>(command.language);
    request.engineEpoch = command.engineEpoch; request.expectedRevision = command.expectedRevision;
    ipc::Response result;
    if (!ipc::Call(endpoint_, executable_, elevated_, request, result, error_)) return false;
    error_ = result.error; return !error_;
}
bool EngineClient::ReadState(sync::LocalState& result) {
    const auto start = GetTickCount64();
    ipc::Response response;
    if (!Read(response)) { result = {}; return false; }
    if (!RecipientState(response, GetTickCount64()-start, result)) { error_ = ERROR_INVALID_DATA; return false; }
    return true;
}
bool EngineClient::RecipientState(const ipc::Response& response, std::uint64_t roundTrip,
                                 sync::LocalState& output) {
    output = {};
    if (roundTrip > 3000 || (response.mwbFlags & ~3U) ||
        ((response.mwbFlags & ipc::RecipientAvailable) && !(response.mwbFlags & ipc::MwbRunning)) ||
        ((response.activitySerial == 0) != (response.activityAge == UINT64_MAX))) return false;
    sync::Age age;
    if (response.activitySerial) {
        if (response.activityAge > UINT64_MAX-roundTrip) return false;
        // Timestamp originates at input delivery, not broker observation. IPC
        // latency widens the age interval; wall clocks are never compared.
        age = {response.activityAge, response.activityAge+roundTrip, true};
    }
    const bool enabled = (response.mwbFlags & ipc::MwbRunning) != 0;
    return MakeState(response,response.activitySerial,age,enabled,output);
}
bool EngineClient::MakeState(const ipc::Response& response, std::uint64_t activitySerial,
                             sync::Age activity, bool mwb, sync::LocalState& output) {
    output = {};
    if (response.magic != ipc::kMagic || response.version != ipc::kVersion || response.error ||
        !response.engineEpoch || response.target > UINT16_MAX || response.actual > UINT16_MAX ||
        !core::Supported(static_cast<core::Language>(response.target)) ||
        response.apply > static_cast<std::uint32_t>(core::ApplyState::Locked) || (response.flags & ~63U) ||
        (response.mwbFlags & ~3U)) return false;
    sync::LocalState value;
    value.snapshot = {response.engineEpoch, response.revision, activitySerial,
        static_cast<core::Language>(response.target), activity, mwb};
    value.actual = static_cast<core::Language>(response.actual);
    value.apply = static_cast<core::ApplyState>(response.apply);
    if ((response.flags & ipc::SystemEnabled) && value.apply == core::ApplyState::Applied &&
        (!(response.flags & ipc::ProfileConfirmed) || response.profileError ||
         response.profileLanguage != response.target || response.profileGeneration != response.generation))
        value.apply = core::ApplyState::Pending;
    value.locked = (response.flags & ipc::Locked) != 0;
    if (!sync::Valid(value.snapshot)) return false;
    output = value; return true;
}
} // namespace capslang
