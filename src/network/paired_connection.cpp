#include "paired_connection.hpp"

namespace capslang::net {
namespace {
bool LocalPair(const Identity& identity, const PairRecord& pair, bool listener, DWORD& error) {
    if (!identity.Certificate() || !ValidPair(pair) || pair.listener != listener ||
        !EqualPin(identity.Fingerprint(),pair.local)) { error = ERROR_INVALID_PARAMETER; return false; }
    return true;
}
bool Handshake(TlsChannel& channel, const Identity& identity, bool listener, const Pin& peer,
               DWORD& error, bool invitation = false) {
    if (!channel.Handshake(identity,listener,peer,invitation)) { error = channel.Error(); return false; }
    return true;
}
}
bool ServePairedConnection(TlsChannel& channel, const Identity& identity,
    const PairRecord& pair, const SessionEndpoint& endpoint, HANDLE cancel, DWORD& error) {
    if (!LocalPair(identity,pair,true,error) || !Handshake(channel,identity,true,pair.peer,error)) return false;
    ApplicationMode mode{};
    if (!AcceptApplicationMode(channel,mode,error)) return false;
    if (mode == ApplicationMode::ResumeEnrollment) return ResumeEnrollmentServer(channel,pair,error);
    if (mode != ApplicationMode::Session) { error = ERROR_ACCESS_DENIED; return false; }
    return RunSession(channel,identity,true,endpoint,cancel,error);
}
bool OpenPairedConnection(TlsChannel& channel, const Identity& identity,
    const PairRecord& pair, const SessionEndpoint& endpoint, HANDLE cancel, DWORD& error) {
    if (!LocalPair(identity,pair,false,error) || !Handshake(channel,identity,false,pair.peer,error) ||
        !SelectApplicationMode(channel,ApplicationMode::Session,error)) return false;
    return RunSession(channel,identity,false,endpoint,cancel,error);
}
bool ServeInvitationConnection(TlsChannel& channel, const Identity& identity,
    InvitationGate& gate, const std::wstring& pairPath,
    const std::function<PairApproval(const Pin&)>& approval, DWORD& error) {
    if (gate.State(GetTickCount64()) != InvitationState::Open || !approval) { error = ERROR_INVALID_STATE; return false; }
    if (!Handshake(channel,identity,true,{},error,true)) return false;
    ApplicationMode mode{};
    if (!AcceptApplicationMode(channel,mode,error)) return false;
    if (mode != ApplicationMode::Enroll) { error = ERROR_ACCESS_DENIED; return false; }
    return EnrollServer(channel,gate,pairPath,approval,error);
}
bool OpenInvitationConnection(TlsChannel& channel, const Identity& identity,
    const InvitationCode& code, const std::wstring& pairPath, bool resume, DWORD& error) {
    if (!Handshake(channel,identity,false,code.server,error) ||
        !SelectApplicationMode(channel,resume ? ApplicationMode::ResumeEnrollment : ApplicationMode::Enroll,error)) return false;
    return resume ? ResumeEnrollmentClient(channel,identity,code,pairPath,error) :
                    EnrollClient(channel,identity,code,pairPath,error);
}
} // namespace capslang::net
