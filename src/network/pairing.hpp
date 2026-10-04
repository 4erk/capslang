#pragma once
#include "tls.hpp"
#include <cstdint>

namespace capslang::net {
using InvitationSecret = std::array<BYTE, 16>;
struct InvitationCode {
    std::string host;
    std::uint16_t port = 0;
    Pin server{};
    InvitationSecret secret{};
};
bool ValidHost(const std::string& host);
bool EncodeInvitation(const InvitationCode& value, std::string& code);
bool DecodeInvitation(const std::string& code, InvitationCode& value);

struct PairRecord {
    Pin local{}, peer{};
    std::string host; // Listening device, irrespective of language authority.
    std::uint16_t port = 0;
    bool listener = false;
};
bool ValidPair(const PairRecord& value);
bool SamePair(const PairRecord& a, const PairRecord& b);
// User-scoped DPAPI; atomic CREATE_NEW. A different pair is NEVER overwritten
// implicitly. Load binds the record to the current persisted local identity.
bool SavePair(const std::wstring& path, const PairRecord& value, DWORD& error);
bool LoadPair(const std::wstring& path, const Pin& localIdentity, PairRecord& value, DWORD& error);
bool RemovePair(const std::wstring& path, DWORD& error);

enum class InvitationState { Closed, Open, AwaitConfirmation, Confirmed, Expired, Exhausted };
// Owned by the pairing worker, not concurrently by its UI. Every method takes
// monotonic time. UI confirmation must name the exact PendingPeer fingerprint.
// This gate does NOT authorize language traffic on temporary unpinned TLS:
// after saving the pair, close it and reconnect with mutual certificate pins.
class InvitationGate {
public:
    ~InvitationGate();
    bool Open(const Identity& identity, std::string host, std::uint16_t port,
              std::uint64_t now, DWORD& error);
    bool Code(std::uint64_t now, std::string& output);
    bool Submit(const Pin& tlsPeer, const InvitationSecret& proof, std::uint64_t now);
    bool Confirm(const Pin& displayedPeer, std::uint64_t now, PairRecord& record);
    void Cancel();
    InvitationState State(std::uint64_t now);
    Pin PendingPeer() const { return pending_; }
private:
    void Expire(std::uint64_t now);
    InvitationCode invitation_{};
    Pin pending_{};
    InvitationState state_ = InvitationState::Closed;
    std::uint64_t opened_ = 0, expires_ = 0;
    unsigned attempts_ = 0;
};
} // namespace capslang::net
