#include "../src/network/runtime.hpp"
#include "../src/platform/private_store.hpp"
#include <bcrypt.h>
#include <cstdio>

using namespace capslang;
using namespace capslang::net;
namespace {
unsigned checks = 0, failures = 0;
void Check(bool yes, const char* name) { ++checks; if (!yes) { ++failures; std::printf("FAIL %s\n",name); } }
template<class Predicate> bool Until(Predicate predicate, DWORD timeout = 6000) {
    const auto deadline = GetTickCount64()+timeout;
    do { if (predicate()) return true; Sleep(10); } while (GetTickCount64() < deadline);
    return predicate();
}
struct Scratch {
    std::wstring root;
    Scratch() {
        wchar_t temp[32768]{}; BYTE nonce[16]{};
        if (!GetTempPathW(ARRAYSIZE(temp),temp) || BCryptGenRandom(nullptr,nonce,sizeof(nonce),BCRYPT_USE_SYSTEM_PREFERRED_RNG)) return;
        std::wstring name = std::wstring(temp)+L"CapsLang-network-runtime-";
        for (const auto byte : nonce) { name += L"0123456789abcdef"[byte>>4]; name += L"0123456789abcdef"[byte&15]; }
        if (CreateDirectoryW(name.c_str(),nullptr)) root = name;
    }
    ~Scratch() {
        if (root.empty()) return;
        DWORD error = 0; Identity identity;
        if (identity.Load(root+L"\\identity.dat",error)) Check(identity.Erase(error),"owned runtime identity and key cleaned");
        RemovePair(root+L"\\pair.dat",error);
        Check(RemoveDirectoryW(root.c_str()) != FALSE,"exclusive fixture directory removed without recursion");
    }
};
SessionEndpoint NoMwb() {
    return {
        [](sync::LocalState& value) { value = {{1,0,0,core::Language::English,{},false},core::Language::English,core::ApplyState::Applied,false}; return true; },
        [](const sync::ApplyCommand&) { return false; }, {}
    };
}
std::uint16_t FreePort() {
    Socket socket(::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP));
    sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int size = sizeof(address);
    if (!socket || bind(socket.Get(),reinterpret_cast<sockaddr*>(&address),size) ||
        getsockname(socket.Get(),reinterpret_cast<sockaddr*>(&address),&size)) return 0;
    return ntohs(address.sin_port);
}
}
int main() {
    Winsock winsock; if (winsock.Error()) return 2;
    {
        Scratch scratch;
        Check(!scratch.root.empty(),"exclusive runtime fixture storage");
        if (scratch.root.empty()) return 3;
        NetworkRuntime runtime(scratch.root,NoMwb());
        HANDLE token = nullptr; TOKEN_ELEVATION elevation{}; DWORD bytes = 0;
        if (!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token) ||
            !GetTokenInformation(token,TokenElevation,&elevation,sizeof(elevation),&bytes)) return 4;
        CloseHandle(token);
        DWORD error = 0;
        if (elevation.TokenIsElevated) {
            Check(!runtime.Start() && runtime.Status().error == ERROR_ACCESS_DENIED,"production networking refuses elevated process");
        } else {
            Check(!runtime.Join("bad invitation",error) && error == ERROR_INVALID_DATA,"malformed invitation rejected before worker start");
            Check(runtime.Start() && runtime.Start(),"ordinary network runtime starts idempotently");
            Check(Until([&] { return runtime.Status().phase == NetworkPhase::Unpaired; }),"new identity persists and unpaired state appears");
            const auto identity = runtime.Status().local;
            Check(!EqualPin(identity,{}),"runtime publishes public local fingerprint");
            Check(!runtime.Invite("bad/host",42519,error) && error == ERROR_INVALID_PARAMETER,"host validation precedes listening");
            Check(!runtime.Invite("test-listener",80,error),"privileged invitation port rejected");
            const auto port = FreePort();
            Check(port && runtime.Invite("test-listener",port,error),"explicit invite request accepted");
            Check(Until([&] { return runtime.Status().phase == NetworkPhase::Inviting; }),"LAN listener enters invitation mode");
            InvitationCode code;
            const auto status = runtime.Status();
            Check(DecodeInvitation(status.invitation,code) && EqualPin(code.server,identity) && code.port == port,
                  "UI-only invitation binds actual runtime identity and listening port");
            SecureZeroMemory(code.secret.data(),code.secret.size());
            Check(!runtime.Confirm(1,identity,true,error),"no approval accepted without exact pending ticket");
            Check(!runtime.Invite("test-listener",port,error) && error == ERROR_BUSY,"active invite cannot be silently replaced");
            Check(runtime.Unpair(error) && runtime.Unpair(error),"repeated explicit unpair cancels invitation idempotently");
            Check(Until([&] { const auto s=runtime.Status(); return s.phase == NetworkPhase::Unpaired && s.invitation.empty(); }),
                  "cancel removes invitation and stops accepting enrollment");
            runtime.Stop(); runtime.Stop();
            Check(runtime.Status().phase == NetworkPhase::Stopped,"ordinary stop idempotent");
            Check(runtime.Start() && Until([&] { return runtime.Status().phase == NetworkPhase::Unpaired; }),"runtime restarts without replaying old commands");
            Check(EqualPin(runtime.Status().local,identity),"restart keeps persisted certificate identity");
            runtime.Stop();
            Check(SavePrivateData(scratch.root+L"\\pair.dat",{1,2,3},false,error),"corrupt-pair fixture written only to owned test directory");
            Check(runtime.Start() && Until([&] { return runtime.Status().phase == NetworkPhase::Error; }),"unreadable pair is not silently replaced");
            Check(runtime.Unpair(error) && Until([&] { return runtime.Status().phase == NetworkPhase::Unpaired; }),"explicit unpair repairs only bad pair record");
            Check(EqualPin(runtime.Status().local,identity),"pair repair does not rotate local identity");
            runtime.Stop();
        }
    }
    std::printf("Network runtime: %u checks, %u failures; isolated storage, no firewall/autostart/input changes.\n",checks,failures);
    return failures ? 1 : 0;
}
