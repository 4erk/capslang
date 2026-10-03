#pragma once
#include "keyboard.hpp"
#include <algorithm>
#include <array>
#include <cstddef>
#include <limits>

namespace capslang::sync {
using core::Language;
using Id = std::array<std::uint8_t, 16>;
inline bool Nonzero(const Id& id) { return std::any_of(id.begin(), id.end(), [](auto b) { return b != 0; }); }
struct Version {
    std::uint64_t counter = 0;
    Id author{};
};
inline bool operator==(const Version& a, const Version& b) { return a.counter == b.counter && a.author == b.author; }
inline bool operator<(const Version& a, const Version& b) {
    return a.counter < b.counter || (a.counter == b.counter && a.author < b.author);
}
enum class Kind : std::uint8_t { Update = 1, Ack = 2 };
enum class Applied : std::uint8_t { None = 0, Pending = 1, Yes = 2, Failed = 3, Locked = 4 };
struct Message {
    Kind kind = Kind::Update;
    Id session{};
    Version version{};
    Language language = Language::Unknown;
    Applied applied = Applied::None;
};
inline bool Valid(const Message& m) {
    return Nonzero(m.session) && Nonzero(m.version.author) && m.version.counter &&
        m.version.counter < std::numeric_limits<std::uint64_t>::max() && core::Supported(m.language) &&
        ((m.kind == Kind::Update && m.applied == Applied::None) ||
         (m.kind == Kind::Ack && m.applied >= Applied::Pending && m.applied <= Applied::Locked));
}
// Fixed, endian-independent wire format. No HKL, key codes, wall clocks or
// executable operations. Strict reserved bytes allow safe version evolution.
using Wire = std::array<std::uint8_t, 64>;
inline bool Encode(const Message& m, Wire& wire) {
    wire.fill(0);
    if (!Valid(m)) return false;
    wire[0] = 'C'; wire[1] = 'L'; wire[2] = 'S'; wire[3] = 'P';
    wire[4] = 1; wire[5] = static_cast<std::uint8_t>(m.kind);
    std::copy(m.session.begin(), m.session.end(), wire.begin() + 8);
    std::copy(m.version.author.begin(), m.version.author.end(), wire.begin() + 24);
    for (unsigned i = 0; i < 8; ++i) wire[40 + i] = static_cast<std::uint8_t>(m.version.counter >> (56 - i * 8));
    const auto language = static_cast<std::uint16_t>(m.language);
    wire[48] = static_cast<std::uint8_t>(language >> 8); wire[49] = static_cast<std::uint8_t>(language);
    wire[50] = static_cast<std::uint8_t>(m.applied);
    return true;
}
inline bool Decode(const std::uint8_t* data, std::size_t size, Message& output) {
    if (!data || size != Wire{}.size() || data[0] != 'C' || data[1] != 'L' || data[2] != 'S' || data[3] != 'P' ||
        data[4] != 1 || data[6] || data[7]) return false;
    for (unsigned i = 51; i < 64; ++i) if (data[i]) return false;
    Message m;
    m.kind = static_cast<Kind>(data[5]);
    std::copy_n(data + 8, 16, m.session.begin());
    std::copy_n(data + 24, 16, m.version.author.begin());
    for (unsigned i = 0; i < 8; ++i) m.version.counter = (m.version.counter << 8) | data[40 + i];
    m.language = static_cast<Language>((std::uint16_t(data[48]) << 8) | data[49]);
    m.applied = static_cast<Applied>(data[50]);
    if (!Valid(m)) return false;
    output = m;
    return true;
}
enum class Receive { Rejected, Stale, Duplicate, Changed };

// One worker owns a replica for ONE negotiated, mutually authenticated session.
// Never start a session merely because a TLS socket exists: the broker must
// first reconcile activity, exchange a fresh session ID, and confirm both ends.
// Offline changes/reconnect are NOT ordered by this connection-local counter.
class Replica {
public:
    Replica(Id local, Id peer, Id session, Language agreed)
        : local_(local), peer_(peer), session_(session), target_(agreed) {}
    bool Ready() const { return Nonzero(local_) && Nonzero(peer_) && local_ != peer_ && Nonzero(session_) && core::Supported(target_); }
    bool Local(Language language, Message& message) {
        if (!Ready() || !core::Supported(language) || clock_ >= std::numeric_limits<std::uint64_t>::max() - 1) return false;
        current_ = {++clock_, local_}; target_ = language; peerApplied_ = Applied::None;
        message = {Kind::Update, session_, current_, target_, Applied::None};
        return true;
    }
    Receive Remote(const Message& message) {
        if (!Ready() || !Valid(message) || message.kind != Kind::Update || message.session != session_ ||
            (message.version.author != peer_ && message.version.author != local_)) return Receive::Rejected;
        if (message.version == current_) return message.language == target_ ? Receive::Duplicate : Receive::Rejected;
        if (message.version < current_) return Receive::Stale;
        // A peer may echo an existing local event, never invent a newer one.
        if (message.version.author != peer_) return Receive::Rejected;
        clock_ = std::max(clock_, message.version.counter);
        current_ = message.version; target_ = message.language; peerApplied_ = Applied::None;
        return Receive::Changed;
    }
    bool Acknowledge(Applied result, Language actual, Message& message) const {
        if (!Ready() || !current_.counter || result < Applied::Pending || result > Applied::Locked ||
            (result == Applied::Yes && actual != target_)) return false;
        message = {Kind::Ack, session_, current_, target_, result};
        return true;
    }
    bool AcceptAck(const Message& message) {
        if (!Ready() || !Valid(message) || message.kind != Kind::Ack || message.session != session_ ||
            !(message.version == current_) || message.language != target_) return false;
        // TCP/TLS preserves order. Pending is an initial status, not a later
        // downgrade; a failure/lock can legitimately follow Applied.
        if (message.applied == Applied::Pending && peerApplied_ != Applied::None && peerApplied_ != Applied::Pending) return false;
        peerApplied_ = message.applied;
        return true;
    }
    Language Target() const { return target_; }
    Version Current() const { return current_; }
    Applied PeerApplied() const { return peerApplied_; }
private:
    Id local_, peer_, session_;
    Language target_;
    Version current_{};
    std::uint64_t clock_ = 0;
    Applied peerApplied_ = Applied::None;
};

// Ages, not timestamps: both intervals refer to the SAME measurement instant.
// A reply reporting age X at send time arrives with age in [X, X + RTT].
// The reconciliation coordinator must reject stale responses and send its
// proposal for confirmation; peers must not decide from different samples.
struct Age { std::uint64_t minimum = 0, maximum = 0; bool known = false; };
inline Age RemoteAge(std::uint64_t ageAtReply, std::uint64_t roundTrip) {
    if (ageAtReply > std::numeric_limits<std::uint64_t>::max() - roundTrip) return {};
    return {ageAtReply, ageAtReply + roundTrip, true};
}
enum class Winner { AwaitInput, Local, Peer };
inline Winner Reconcile(Age local, Age peer, std::uint64_t ambiguity = 100) {
    if (!local.known || !peer.known || local.minimum > local.maximum || peer.minimum > peer.maximum) return Winner::AwaitInput;
    if (local.maximum < peer.minimum && peer.minimum - local.maximum > ambiguity) return Winner::Local;
    if (peer.maximum < local.minimum && local.minimum - peer.maximum > ambiguity) return Winner::Peer;
    return Winner::AwaitInput;
}
} // namespace capslang::sync
