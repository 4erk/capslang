#include "pairing.hpp"
#include "../platform/private_store.hpp"
#include <bcrypt.h>
#include <algorithm>

namespace capslang::net {
namespace {
template<size_t N> bool Nonzero(const std::array<BYTE, N>& value) {
    BYTE result = 0; for (auto byte : value) result |= byte; return result != 0;
}
template<size_t N> bool Equal(const std::array<BYTE, N>& a, const std::array<BYTE, N>& b) {
    BYTE result = 0; for (size_t i = 0; i < N; ++i) result |= a[i] ^ b[i]; return result == 0;
}
template<size_t N> std::string Hex(const std::array<BYTE, N>& value) {
    std::string result; result.reserve(N * 2);
    for (auto byte : value) { result += "0123456789abcdef"[byte >> 4]; result += "0123456789abcdef"[byte & 15]; }
    return result;
}
int Nibble(char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1; }
template<size_t N> bool Unhex(const std::string& value, std::array<BYTE, N>& output) {
    if (value.size() != N * 2) return false;
    for (size_t i = 0; i < N; ++i) {
        const int a = Nibble(value[2 * i]), b = Nibble(value[2 * i + 1]);
        if (a < 0 || b < 0) return false;
        output[i] = static_cast<BYTE>((a << 4) | b);
    }
    return Nonzero(output);
}
bool ValidCode(const InvitationCode& value) {
    return ValidHost(value.host) && value.port >= 1024 && Nonzero(value.server) && Nonzero(value.secret);
}
constexpr size_t kHeader = 76;
bool DecodePair(const std::vector<BYTE>& bytes, PairRecord& output) {
    if (bytes.size() < kHeader || bytes.size() > kHeader + 253 ||
        bytes[0] != 'C' || bytes[1] != 'L' || bytes[2] != 'P' || bytes[3] != 'R' || bytes[4] != 1 ||
        bytes[5] > 1 || bytes[6] || bytes[7] || bytes[75] || bytes.size() != kHeader + bytes[74]) return false;
    PairRecord value;
    value.listener = bytes[5] != 0;
    std::copy_n(bytes.begin() + 8, 32, value.local.begin());
    std::copy_n(bytes.begin() + 40, 32, value.peer.begin());
    value.port = static_cast<std::uint16_t>((bytes[72] << 8) | bytes[73]);
    value.host.assign(bytes.begin() + kHeader, bytes.end());
    if (!ValidPair(value)) return false;
    output = value; return true;
}
}
bool ValidHost(const std::string& host) {
    if (host.empty() || host.size() > 253) return false;
    size_t label = 0;
    char previous = 0;
    for (char c : host) {
        if (c == '.') {
            if (!label || previous == '-') return false;
            label = 0;
        } else {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-')) return false;
            if ((!label && c == '-') || ++label > 63) return false;
        }
        previous = c;
    }
    return label && previous != '-';
}
bool EncodeInvitation(const InvitationCode& value, std::string& code) {
    code.clear();
    if (!ValidCode(value)) return false;
    code = "CL1|" + value.host + "|" + std::to_string(value.port) + "|" + Hex(value.server) + "|" + Hex(value.secret);
    return true;
}
bool DecodeInvitation(const std::string& code, InvitationCode& output) {
    output = {};
    if (code.size() > 370 || code.compare(0, 4, "CL1|") != 0) return false;
    std::array<std::string, 4> fields;
    struct WipeFields { std::array<std::string, 4>& fields; ~WipeFields() {
        for (auto& field : fields) if (!field.empty()) SecureZeroMemory(field.data(), field.size());
    }} wipeFields{fields};
    size_t begin = 4;
    for (size_t i = 0; i < fields.size(); ++i) {
        const auto end = code.find('|', begin);
        if ((i + 1 == fields.size()) != (end == std::string::npos)) return false;
        fields[i] = code.substr(begin, end == std::string::npos ? end : end - begin);
        begin = end == std::string::npos ? code.size() : end + 1;
    }
    InvitationCode candidate; candidate.host = fields[0];
    struct WipeSecret { InvitationSecret& secret; ~WipeSecret() {
        SecureZeroMemory(secret.data(), secret.size());
    }} wipeSecret{candidate.secret};
    if (fields[1].empty() || fields[1].size() > 5 || fields[1][0] == '0') return false;
    unsigned port = 0;
    for (char c : fields[1]) { if (c < '0' || c > '9') return false; port = port * 10 + static_cast<unsigned>(c - '0'); }
    if (port > 65535) return false;
    candidate.port = static_cast<std::uint16_t>(port);
    if (!Unhex(fields[2], candidate.server) || !Unhex(fields[3], candidate.secret) || !ValidCode(candidate)) return false;
    output = candidate;
    return true;
}
bool ValidPair(const PairRecord& value) {
    return ValidHost(value.host) && value.port >= 1024 && Nonzero(value.local) && Nonzero(value.peer) && !EqualPin(value.local, value.peer);
}
bool SamePair(const PairRecord& a, const PairRecord& b) {
    return EqualPin(a.local, b.local) && EqualPin(a.peer, b.peer) && a.listener == b.listener && a.port == b.port && a.host == b.host;
}
bool LoadPair(const std::wstring& path, const Pin& identity, PairRecord& output, DWORD& error) {
    output = {}; std::vector<BYTE> data;
    if (!LoadPrivateData(path, data, error)) return false;
    PairRecord candidate;
    const bool valid = DecodePair(data, candidate) && EqualPin(candidate.local, identity);
    if (!data.empty()) SecureZeroMemory(data.data(), data.size());
    if (!valid) { error = ERROR_INVALID_DATA; return false; }
    output = candidate; error = 0; return true;
}
bool SavePair(const std::wstring& path, const PairRecord& value, DWORD& error) {
    if (!ValidPair(value)) { error = ERROR_INVALID_DATA; return false; }
    std::vector<BYTE> bytes(kHeader + value.host.size());
    bytes[0] = 'C'; bytes[1] = 'L'; bytes[2] = 'P'; bytes[3] = 'R'; bytes[4] = 1; bytes[5] = value.listener ? 1 : 0;
    std::copy(value.local.begin(), value.local.end(), bytes.begin() + 8);
    std::copy(value.peer.begin(), value.peer.end(), bytes.begin() + 40);
    bytes[72] = static_cast<BYTE>(value.port >> 8); bytes[73] = static_cast<BYTE>(value.port);
    bytes[74] = static_cast<BYTE>(value.host.size());
    std::copy(value.host.begin(), value.host.end(), bytes.begin() + kHeader);
    const bool saved = SavePrivateData(path, bytes, false, error);
    SecureZeroMemory(bytes.data(), bytes.size());
    if (saved) return true;
    if (error != ERROR_ALREADY_EXISTS && error != ERROR_FILE_EXISTS) return false;
    PairRecord existing; DWORD readError = 0;
    if (LoadPair(path, value.local, existing, readError) && SamePair(existing, value)) { error = 0; return true; }
    error = ERROR_ALREADY_EXISTS; return false;
}
bool RemovePair(const std::wstring& path, DWORD& error) {
    if (path.empty()) { error = ERROR_INVALID_PARAMETER; return false; }
    if (DeleteFileW(path.c_str()) || GetLastError() == ERROR_FILE_NOT_FOUND) { error = 0; return true; }
    error = GetLastError(); return false;
}
InvitationGate::~InvitationGate() { Cancel(); }
void InvitationGate::Cancel() {
    SecureZeroMemory(invitation_.secret.data(), invitation_.secret.size());
    invitation_ = {}; pending_ = {}; state_ = InvitationState::Closed; opened_ = expires_ = 0; attempts_ = 0;
}
void InvitationGate::Expire(std::uint64_t now) {
    if ((state_ == InvitationState::Open || state_ == InvitationState::AwaitConfirmation) && (now < opened_ || now >= expires_)) {
        SecureZeroMemory(invitation_.secret.data(), invitation_.secret.size()); pending_ = {}; state_ = InvitationState::Expired;
    }
}
InvitationState InvitationGate::State(std::uint64_t now) { Expire(now); return state_; }
bool InvitationGate::Open(const Identity& identity, std::string host, std::uint16_t port, std::uint64_t now, DWORD& error) {
    Expire(now);
    if (state_ == InvitationState::Open || state_ == InvitationState::AwaitConfirmation) { error = ERROR_BUSY; return false; }
    Cancel();
    if (!identity.Certificate() || !ValidHost(host) || port < 1024 || now > UINT64_MAX - 300000) {
        error = ERROR_INVALID_PARAMETER; return false;
    }
    invitation_.host = std::move(host); invitation_.port = port; invitation_.server = identity.Fingerprint();
    if (BCryptGenRandom(nullptr, invitation_.secret.data(), static_cast<ULONG>(invitation_.secret.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) ||
        !ValidCode(invitation_)) { Cancel(); error = NTE_FAIL; return false; }
    opened_ = now; expires_ = now + 300000; state_ = InvitationState::Open; error = 0; return true;
}
bool InvitationGate::Code(std::uint64_t now, std::string& output) {
    Expire(now); output.clear();
    return state_ == InvitationState::Open && EncodeInvitation(invitation_, output);
}
bool InvitationGate::Submit(const Pin& tlsPeer, const InvitationSecret& proof, std::uint64_t now) {
    Expire(now);
    if (state_ != InvitationState::Open) return false;
    ++attempts_;
    const bool valid = Equal(invitation_.secret, proof) && Nonzero(tlsPeer) && !EqualPin(tlsPeer, invitation_.server);
    if (!valid) {
        if (attempts_ >= 8) { SecureZeroMemory(invitation_.secret.data(), invitation_.secret.size()); state_ = InvitationState::Exhausted; }
        return false;
    }
    pending_ = tlsPeer; state_ = InvitationState::AwaitConfirmation;
    SecureZeroMemory(invitation_.secret.data(), invitation_.secret.size());
    return true;
}
bool InvitationGate::Confirm(const Pin& peer, std::uint64_t now, PairRecord& record) {
    Expire(now); record = {};
    if (state_ != InvitationState::AwaitConfirmation || !EqualPin(peer, pending_)) return false;
    record = {invitation_.server, pending_, invitation_.host, invitation_.port, true};
    state_ = InvitationState::Confirmed; pending_ = {}; return true;
}
} // namespace capslang::net
