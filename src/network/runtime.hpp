#pragma once
#include "lan.hpp"
#include "paired_connection.hpp"
#include <memory>

namespace capslang::net {
enum class NetworkPhase { Starting, Unpaired, Inviting, AwaitApproval, Joining, Connecting, AwaitInput, Active, Error, Stopped };
struct NetworkStatus {
    NetworkPhase phase = NetworkPhase::Starting;
    DWORD error = 0;
    DWORD lastError = 0;
    std::uint64_t lastErrorAt = 0;
    bool paired = false, listener = false;
    Pin local{}, peer{}, pendingPeer{};
    std::uint64_t approvalTicket = 0;
    std::string invitation; // UI-only secret; NEVER include in logs/diagnostics.
    SessionStatus session;
};
class NetworkRuntime {
public:
    // Directory is selected by application code, not peer data or elevated IPC.
    NetworkRuntime(std::wstring directory, SessionEndpoint engine);
    ~NetworkRuntime();
    NetworkRuntime(const NetworkRuntime&) = delete;
    NetworkRuntime& operator=(const NetworkRuntime&) = delete;
    bool Start();
    void Stop();
    NetworkStatus Status() const;
    bool Invite(std::string localHost, std::uint16_t port, DWORD& error);
    bool Join(const std::string& invitation, DWORD& error);
    bool Confirm(std::uint64_t ticket, const Pin& peer, bool allow, DWORD& error);
    bool Unpair(DWORD& error);
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace capslang::net
