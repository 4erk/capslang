#include "application_mode.hpp"
#include <algorithm>

namespace capslang::net {
namespace {
using Frame = std::array<BYTE,8>;
bool Valid(ApplicationMode mode) {
    return mode == ApplicationMode::Session || mode == ApplicationMode::Enroll || mode == ApplicationMode::ResumeEnrollment;
}
Frame Encode(ApplicationMode mode) { return {'C','L','A','P',1,static_cast<BYTE>(mode),0,0}; }
bool Read(TlsChannel& channel, Frame& frame, DWORD& error) {
    size_t used = 0;
    const auto deadline = GetTickCount64()+1500;
    while (used < frame.size()) {
        const auto now = GetTickCount64();
        if (now >= deadline) { error = ERROR_TIMEOUT; return false; }
        std::vector<BYTE> part;
        if (!channel.Receive(part,static_cast<DWORD>(deadline-now))) { error = channel.Error(); return false; }
        if (part.empty() || part.size() > frame.size()-used) { error = ERROR_INVALID_DATA; return false; }
        std::copy(part.begin(),part.end(),frame.begin()+used); used += part.size();
    }
    const auto mode = static_cast<ApplicationMode>(frame[5]);
    if (!Valid(mode) || frame != Encode(mode)) { error = ERROR_INVALID_DATA; return false; }
    return true;
}
}
bool SelectApplicationMode(TlsChannel& channel, ApplicationMode mode, DWORD& error) {
    // An enrolling client still MUST pin the listening server from its invite.
    if (!channel.Paired()) { error = ERROR_ACCESS_DENIED; return false; }
    if (!Valid(mode)) { error = ERROR_INVALID_PARAMETER; return false; }
    const auto request = Encode(mode);
    if (!channel.Send(request.data(),request.size())) { error = channel.Error(); return false; }
    Frame reply{};
    if (!Read(channel,reply,error)) return false;
    if (reply != request) { error = ERROR_INVALID_DATA; return false; }
    error = 0; return true;
}
bool AcceptApplicationMode(TlsChannel& channel, ApplicationMode& mode, DWORD& error) {
    mode = static_cast<ApplicationMode>(0);
    Frame request{};
    if (!Read(channel,request,error)) return false;
    const auto candidate = static_cast<ApplicationMode>(request[5]);
    // Temporary unknown-client channels can enter ONLY enrollment. Existing
    // pins can enter only normal state exchange or recovery of that same pair.
    if ((candidate == ApplicationMode::Enroll) == channel.Paired()) {
        error = ERROR_ACCESS_DENIED; return false;
    }
    if (!channel.Send(request.data(),request.size())) { error = channel.Error(); return false; }
    mode = candidate; error = 0; return true;
}
} // namespace capslang::net
