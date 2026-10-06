#include "engine_host.hpp"
#include <bcrypt.h>

namespace capslang {
namespace {
std::uint64_t Age(std::uint64_t now, std::uint64_t then) {
    return then && then <= now ? now - then : UINT64_MAX;
}
}
EngineHost::EngineHost(ipc::Endpoint endpoint, EngineOptions options)
    : engine_(options), server_(std::move(endpoint), [this](const ipc::Request& request) { return Handle(request); }) {}
EngineHost::~EngineHost() { Stop(); }
bool EngineHost::Start() {
    if (ready_) return true;
    if (shutdown_) { error_ = ERROR_BUSY; return false; }
    if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&epoch_), sizeof(epoch_),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0 || !epoch_) {
        error_ = ERROR_GEN_FAILURE; return false;
    }
    shutdown_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!shutdown_) { error_ = GetLastError(); return false; }
    // Acquire the SID/session-specific endpoint BEFORE starting any hooks or
    // applying a layout. A second instance must have zero input side effects.
    if (!server_.Start()) { error_ = server_.Error(); Stop(); return false; }
    if (!engine_.Start()) { error_ = ERROR_NOT_READY; Stop(); return false; }
    const auto status = engine_.Status();
    if (!status.hookRegistered || !status.hookThreadResponsive || status.hookError ||
        status.powerError || status.sessionError) {
        error_ = status.hookError ? status.hookError : status.powerError ? status.powerError :
                 status.sessionError ? status.sessionError : ERROR_NOT_READY;
        Stop(); return false;
    }
    ready_ = true; error_ = 0; return true;
}
void EngineHost::Stop() {
    ready_ = false;
    if (shutdown_) SetEvent(shutdown_);
    server_.Stop(); // Join IPC before destroying anything its handler uses.
    engine_.Stop();
    if (shutdown_) { CloseHandle(shutdown_); shutdown_ = nullptr; }
}
ipc::Response EngineHost::Handle(const ipc::Request& request) {
    ipc::Response response{};
    if (!ready_) { response.error = ERROR_NOT_READY; return response; }
    switch (request.operation) {
    case ipc::Operation::ReportProfile: case ipc::Operation::ManualProfile:
        if (request.engineEpoch != epoch_) response.error = ERROR_REVISION_MISMATCH;
        else if (!engine_.ProfileReport(static_cast<LANGID>(request.language),request.expectedRevision,
            static_cast<DWORD>(request.reserved),request.operation == ipc::Operation::ManualProfile)) response.error = ERROR_NOT_READY;
        break;
    case ipc::Operation::SetLayoutIfRevision:
        if (request.engineEpoch != epoch_) response.error = ERROR_REVISION_MISMATCH;
        else if (!engine_.SetTargetIfRevision(static_cast<core::Language>(request.language), request.expectedRevision))
            response.error = ERROR_NOT_READY;
        break;
    case ipc::Operation::SetLayout:
        if (!engine_.SetTarget(static_cast<core::Language>(request.language))) response.error = ERROR_NOT_READY;
        break;
    case ipc::Operation::RefreshHook:
        if (!engine_.RestartHook()) response.error = ERROR_NOT_READY;
        break;
    case ipc::Operation::Stop:
        // Never stop/join this server from its own handler. The owner waits on
        // this event and performs teardown; it may cancel this final response.
        SetEvent(shutdown_);
        break;
    case ipc::Operation::Status: break;
    default: response.error = ERROR_INVALID_DATA; return response;
    }
    const auto status = engine_.Status();
    const auto now = GetTickCount64();
    response.target = static_cast<std::uint32_t>(status.target);
    response.actual = static_cast<std::uint32_t>(status.actual);
    response.apply = static_cast<std::uint32_t>(status.apply);
    response.flags = (status.elevated ? ipc::Elevated : 0U) |
        (status.hookRegistered ? ipc::HookRegistered : 0U) |
        (status.hookThreadResponsive ? ipc::HookResponsive : 0U) |
        (status.locked ? ipc::Locked : 0U) |
        (status.profileConfirmed ? ipc::ProfileConfirmed : 0U) |
        (status.systemEnabled ? ipc::SystemEnabled : 0U) |
        (status.targetThreadProfile ? ipc::TargetThreadProfile : 0U);
    response.hookError = status.hookError;
    response.layoutError = status.layoutError;
    response.profileError = status.profileError;
    response.generation = status.generation;
    response.revision = status.userRevision;
    response.recovery = status.lastRecovery;
    response.profileLanguage = status.profileLanguage;
    response.profileGeneration = status.profileGeneration;
    response.engineEpoch = epoch_;
    response.activitySerial = status.activitySerial;
    response.activityAge = Age(now, status.lastRecipientInput);
    response.mwbFlags = (status.mwbRunning ? ipc::MwbRunning : 0U) |
        (status.recipientAvailable ? ipc::RecipientAvailable : 0U);
    response.mwbError = status.mwbError;
    // A queued SetLayout request is NOT an acknowledgement of application.
    // Broker must observe its requested target, actual AND Applied later.
    return response;
}
} // namespace capslang
