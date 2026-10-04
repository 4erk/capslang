#pragma once
#include "broker.hpp"

namespace capslang::sync {
enum class ControlKind : std::uint8_t {
    Hello = 1, Sample, SampleReply, Offer, Accepted, Rejected, Commit, Committed, Poll, PollReply
};
struct Control {
    ControlKind kind = ControlKind::Hello;
    Id session{};
    std::uint64_t round = 0;
    Snapshot first{}, second{};
    Authority authority = Authority::None;
    Language target = Language::Unknown;
    std::optional<Message> update, ack;
};
using ControlWire = std::array<std::uint8_t, 256>;
namespace wire_detail {
inline void Put64(std::uint8_t* p, std::uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) p[i] = static_cast<std::uint8_t>(value >> (56 - 8 * i));
}
inline std::uint64_t Get64(const std::uint8_t* p) {
    std::uint64_t value = 0; for (unsigned i = 0; i < 8; ++i) value = (value << 8) | p[i]; return value;
}
inline void PutSnapshot(std::uint8_t* p, const Snapshot& value) {
    Put64(p, value.engineEpoch); Put64(p + 8, value.userRevision); Put64(p + 16, value.activitySerial);
    if (value.activity.known) { Put64(p + 24, value.activity.minimum); Put64(p + 32, value.activity.maximum); }
    p[40] = static_cast<std::uint8_t>(static_cast<std::uint16_t>(value.language) >> 8);
    p[41] = static_cast<std::uint8_t>(value.language); p[42] = value.activity.known; p[43] = value.mwb;
}
inline Snapshot GetSnapshot(const std::uint8_t* p) {
    return {Get64(p), Get64(p + 8), Get64(p + 16), static_cast<Language>((std::uint16_t(p[40]) << 8) | p[41]),
        {Get64(p + 24), Get64(p + 32), p[42] != 0}, p[43] != 0};
}
inline bool HasSnapshot(ControlKind kind) {
    return kind == ControlKind::Hello || kind == ControlKind::Sample || kind == ControlKind::SampleReply ||
        kind == ControlKind::Offer || kind == ControlKind::Poll || kind == ControlKind::PollReply;
}
}
inline bool EncodeControl(const Control& value, ControlWire& wire) {
    wire.fill(0);
    if (!Nonzero(value.session) || !value.round || value.kind < ControlKind::Hello || value.kind > ControlKind::PollReply) return false;
    wire[0] = 'C'; wire[1] = 'L'; wire[2] = 'B'; wire[3] = 'P'; wire[4] = 2; wire[5] = static_cast<std::uint8_t>(value.kind);
    std::copy(value.session.begin(), value.session.end(), wire.begin() + 8); wire_detail::Put64(wire.data() + 24, value.round);
    if (wire_detail::HasSnapshot(value.kind)) {
        if (!Valid(value.first)) return false;
        wire_detail::PutSnapshot(wire.data() + 32, value.first);
    }
    if (value.kind == ControlKind::Offer) {
        if (!Valid(Proposal{value.session, value.round, value.first, value.second, value.authority, value.target})) return false;
        wire_detail::PutSnapshot(wire.data() + 80, value.second);
        wire[128] = static_cast<std::uint8_t>(value.authority);
        wire[130] = static_cast<std::uint8_t>(static_cast<std::uint16_t>(value.target) >> 8);
        wire[131] = static_cast<std::uint8_t>(value.target);
    }
    if (value.kind == ControlKind::Poll || value.kind == ControlKind::PollReply) {
        Wire inner{};
        if (value.update) {
            if (value.update->kind != Kind::Update || value.update->session != value.session || !Encode(*value.update, inner)) return false;
            wire[6] |= 1; std::copy(inner.begin(), inner.end(), wire.begin() + 128);
        }
        if (value.ack) {
            if (value.ack->kind != Kind::Ack || value.ack->session != value.session || !Encode(*value.ack, inner)) return false;
            wire[6] |= 2; std::copy(inner.begin(), inner.end(), wire.begin() + 192);
        }
    } else if (value.update || value.ack) return false;
    return true;
}
inline bool DecodeControl(const std::uint8_t* bytes, size_t size, Control& output) {
    if (!bytes || size != ControlWire{}.size() || bytes[0] != 'C' || bytes[1] != 'L' || bytes[2] != 'B' || bytes[3] != 'P' || bytes[4] != 2) return false;
    Control value; value.kind = static_cast<ControlKind>(bytes[5]);
    std::copy_n(bytes + 8, 16, value.session.begin()); value.round = wire_detail::Get64(bytes + 24);
    if (wire_detail::HasSnapshot(value.kind)) value.first = wire_detail::GetSnapshot(bytes + 32);
    if (value.kind == ControlKind::Offer) {
        value.second = wire_detail::GetSnapshot(bytes + 80); value.authority = static_cast<Authority>(bytes[128]);
        value.target = static_cast<Language>((std::uint16_t(bytes[130]) << 8) | bytes[131]);
    }
    if (value.kind == ControlKind::Poll || value.kind == ControlKind::PollReply) {
        Message inner;
        if (bytes[6] & 1) { if (!Decode(bytes + 128, 64, inner)) return false; value.update = inner; }
        if (bytes[6] & 2) { if (!Decode(bytes + 192, 64, inner)) return false; value.ack = inner; }
    }
    ControlWire canonical;
    // Canonical re-encoding also rejects EVERY unused/reserved byte, bool >1,
    // hidden payload, nonzero unknown-age fields and wrong inner message kind.
    if (!EncodeControl(value, canonical) || !std::equal(canonical.begin(), canonical.end(), bytes)) return false;
    output = value; return true;
}
} // namespace capslang::sync
