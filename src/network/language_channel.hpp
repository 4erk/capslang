#pragma once
#include "tls.hpp"
#include "../core/sync.hpp"

namespace capslang::net {
// Connection-local adapter, used only AFTER pairing and session reconciliation.
// TLS is a byte stream: do not assume an application frame equals one record.
// Single worker owns both adapters; never call Receive and Send concurrently.
class LanguageChannel {
public:
    LanguageChannel(TlsChannel& tls, sync::Id session) : tls_(tls), session_(session) {}
    bool Send(const sync::Message& message) {
        if (failed_) return false;
        if (!tls_.Paired() || !sync::Nonzero(session_)) return Fail(ERROR_ACCESS_DENIED);
        sync::Wire wire;
        if (message.session != session_ || !sync::Encode(message, wire)) return Fail(ERROR_INVALID_DATA);
        if (!tls_.Send(wire.data(), wire.size())) return Fail(tls_.Error());
        error_ = 0; return true;
    }
    bool Receive(sync::Message& message) {
        if (failed_) return false;
        if (!tls_.Paired() || !sync::Nonzero(session_)) return Fail(ERROR_ACCESS_DENIED);
        const auto deadline = GetTickCount64() + 1500;
        constexpr auto frameSize = sync::Wire{}.size();
        while (pending_.size() < frameSize) {
            const auto now = GetTickCount64();
            if (now >= deadline) return Fail(ERROR_TIMEOUT);
            std::vector<BYTE> part;
            if (!tls_.Receive(part, static_cast<DWORD>(deadline - now))) return Fail(tls_.Error());
            if (part.empty() || part.size() > 1024) return Fail(ERROR_INVALID_DATA);
            // Before append at most 63 bytes; TLS reads at most 1024.
            pending_.insert(pending_.end(), part.begin(), part.end());
        }
        sync::Message candidate;
        if (!sync::Decode(pending_.data(), frameSize, candidate) || candidate.session != session_) return Fail(ERROR_INVALID_DATA);
        pending_.erase(pending_.begin(), pending_.begin() + frameSize);
        message = candidate; error_ = 0; return true;
    }
    DWORD Error() const { return error_; }
private:
    bool Fail(DWORD error) { failed_ = true; error_ = error; pending_.clear(); return false; }
    TlsChannel& tls_;
    sync::Id session_;
    std::vector<BYTE> pending_;
    DWORD error_ = 0;
    bool failed_ = false;
};
} // namespace capslang::net
