#include "../src/network/tls.hpp"
#include "../src/platform/private_store.hpp"
#include "../src/network/language_channel.hpp"
#include "../src/network/pairing.hpp"
#include "../src/network/enrollment.hpp"
#include "../src/network/paired_connection.hpp"
#include <bcrypt.h>
#include <thread>
#include <cstdio>
#include <cstring>

using namespace capslang::net;
namespace {
unsigned checks = 0, failures = 0;
void Check(bool value, const char* name) {
    ++checks; if (!value) { ++failures; std::printf("FAIL %s\n", name); }
}
std::wstring Hex(const Pin& pin) {
    std::wstring result;
    for (auto byte : pin) { result += L"0123456789abcdef"[byte >> 4]; result += L"0123456789abcdef"[byte & 15]; }
    return result;
}
bool ReloadProcess(const std::wstring& path, const Pin& pin) {
    wchar_t executable[32768]{};
    if (!GetModuleFileNameW(nullptr, executable, 32768)) return false;
    std::wstring command = L"\"" + std::wstring(executable) + L"\" --reload \"" + path + L"\" " + Hex(pin);
    STARTUPINFOW startup{}; startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(executable, command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process)) return false;
    const bool completed = WaitForSingleObject(process.hProcess, 15000) == WAIT_OBJECT_0;
    if (!completed) { TerminateProcess(process.hProcess, 99); WaitForSingleObject(process.hProcess, 5000); }
    DWORD code = 99;
    GetExitCodeProcess(process.hProcess, &code);
    CloseHandle(process.hThread); CloseHandle(process.hProcess);
    return completed && code == 0;
}
struct Scratch {
    std::wstring directory;
    Scratch() {
        wchar_t root[32768]{};
        Pin random{};
        if (!GetTempPathW(32768, root) || BCryptGenRandom(nullptr, random.data(), static_cast<ULONG>(random.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG)) return;
        auto candidate = std::wstring(root) + L"CapsLang-test-" + Hex(random);
        if (CreateDirectoryW(candidate.c_str(), nullptr)) directory = candidate;
    }
    std::wstring File(const wchar_t* name) const { return directory + L"\\" + name; }
    ~Scratch() {
        if (directory.empty()) return;
        // Only these exclusively owned test files, never recursive deletion.
        for (auto name : {L"server", L"client", L"bad", L"data", L"pair", L"listener-pair", L"connector-pair"}) DeleteFileW(File(name).c_str());
        RemoveDirectoryW(directory.c_str());
    }
};
bool PrivateAcl(const std::wstring& path) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<BYTE> user(size);
    const bool haveUser = GetTokenInformation(token, TokenUser, user.data(), size, &size) != FALSE;
    CloseHandle(token);
    if (!haveUser) return false;
    BYTE system[SECURITY_MAX_SID_SIZE]{}; size = sizeof(system);
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, system, &size)) return false;
    size = 0;
    GetFileSecurityW(path.c_str(), DACL_SECURITY_INFORMATION, nullptr, 0, &size);
    std::vector<BYTE> security(size);
    if (!GetFileSecurityW(path.c_str(), DACL_SECURITY_INFORMATION, security.data(), size, &size)) return false;
    PACL acl = nullptr; BOOL present = FALSE, defaulted = FALSE;
    SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision = 0;
    if (!GetSecurityDescriptorControl(security.data(), &control, &revision) || !(control & SE_DACL_PROTECTED) ||
        !GetSecurityDescriptorDacl(security.data(), &present, &acl, &defaulted) || !present || !acl || acl->AceCount != 2) return false;
    bool haveSystem = false, haveOwner = false;
    for (DWORD i = 0; i < acl->AceCount; ++i) {
        void* value = nullptr;
        if (!GetAce(acl, i, &value)) return false;
        const auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(value);
        if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE || ace->Mask != FILE_ALL_ACCESS) return false;
        PSID sid = const_cast<DWORD*>(&ace->SidStart);
        if (EqualSid(sid, system)) haveSystem = true;
        else if (EqualSid(sid, reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid)) haveOwner = true;
        else return false;
    }
    return haveSystem && haveOwner;
}
struct Socket {
    SOCKET value = INVALID_SOCKET;
    Socket() = default;
    explicit Socket(SOCKET s) : value(s) {}
    ~Socket() { if (value != INVALID_SOCKET) { shutdown(value, SD_BOTH); closesocket(value); } }
    Socket(const Socket&) = delete;
};
struct Result { bool serverHandshake = false, clientHandshake = false, exchanged = false; DWORD serverError = 0, clientError = 0; };
Result Session(const Identity& serverIdentity, const Identity& clientIdentity,
               const Pin& serverPin, const Pin& clientPin, bool exchange, bool languageProtocol = false, bool wrongSession = false) {
    Result result;
    Socket listener(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (listener.value == INVALID_SOCKET || bind(listener.value, reinterpret_cast<sockaddr*>(&address), sizeof(address)) || listen(listener.value, 1)) return result;
    int size = sizeof(address);
    if (getsockname(listener.value, reinterpret_cast<sockaddr*>(&address), &size)) return result;
    Socket client(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    if (connect(client.value, reinterpret_cast<sockaddr*>(&address), sizeof(address))) return result;
    Socket accepted(accept(listener.value, nullptr, nullptr));
    if (accepted.value == INVALID_SOCKET) return result;
    bool serverExchange = false;
    capslang::sync::Id sessionId{}, serverId{}, clientId{};
    sessionId[0] = 42;
    std::copy_n(serverPin.begin(), 16, serverId.begin());
    std::copy_n(clientPin.begin(), 16, clientId.begin());
    std::thread server([&] {
        TlsChannel channel(accepted.value);
        result.serverHandshake = channel.Handshake(serverIdentity, true, clientPin);
        if (result.serverHandshake && exchange && languageProtocol) {
            using namespace capslang::sync;
            LanguageChannel language(channel, sessionId);
            Replica replica(serverId, clientId, sessionId, Language::English);
            serverExchange = true;
            for (unsigned i = 0; i < 8; ++i) {
                Message update, ack;
                if (!language.Receive(update) || replica.Remote(update) != Receive::Changed ||
                    !replica.Acknowledge(Applied::Pending, Language::Unknown, ack) || !language.Send(ack) ||
                    // Model-only application: no desktop or keyboard modified.
                    !replica.Acknowledge(Applied::Yes, replica.Target(), ack) || !language.Send(ack)) {
                    result.serverError = language.Error(); serverExchange = false; break;
                }
            }
        } else if (result.serverHandshake && exchange) {
            serverExchange = true;
            for (std::uint64_t index = 0; index < 8; ++index) {
                std::vector<BYTE> input;
                std::uint64_t value = UINT64_MAX;
                if (!channel.Receive(input) || input.size() != sizeof(value)) { serverExchange = false; break; }
                std::memcpy(&value, input.data(), sizeof(value));
                if (value != index) { serverExchange = false; break; }
                ++value;
                if (!channel.Send(&value, sizeof(value))) { serverExchange = false; break; }
            }
        }
        if (!result.serverError) result.serverError = channel.Error();
        shutdown(accepted.value, SD_BOTH);
    });
    TlsChannel channel(client.value);
    result.clientHandshake = channel.Handshake(clientIdentity, false, serverPin);
    bool clientExchange = result.clientHandshake && exchange;
    if (clientExchange && languageProtocol) {
        using namespace capslang::sync;
        LanguageChannel language(channel, sessionId);
        Replica replica(clientId, serverId, sessionId, Language::English);
        // Send eight frames in two deliberately unrelated TLS record sizes.
        std::vector<BYTE> stream;
        std::vector<Message> updates;
        for (unsigned i = 0; i < 8; ++i) {
            Message update; Wire wire;
            replica.Local(capslang::core::Opposite(replica.Target()), update);
            Encode(update, wire); updates.push_back(update);
            stream.insert(stream.end(), wire.begin(), wire.end());
        }
        if (wrongSession) stream[8] ^= 1;
        clientExchange = channel.Send(stream.data(), 7) && channel.Send(stream.data() + 7, stream.size() - 7);
        for (unsigned i = 0; clientExchange && i < 8; ++i) {
            Message pending, applied;
            clientExchange = language.Receive(pending) && language.Receive(applied) &&
                pending.version == updates[i].version && pending.applied == Applied::Pending &&
                applied.version == updates[i].version && applied.language == updates[i].language && applied.applied == Applied::Yes;
        }
    } else if (clientExchange) for (std::uint64_t index = 0; index < 8; ++index) {
        std::vector<BYTE> input;
        std::uint64_t value = UINT64_MAX;
        if (!channel.Send(&index, sizeof(index)) || !channel.Receive(input) || input.size() != sizeof(value)) {
            clientExchange = false; break;
        }
        std::memcpy(&value, input.data(), sizeof(value));
        if (value != index + 1) { clientExchange = false; break; }
    }
    result.clientError = channel.Error();
    shutdown(client.value, SD_BOTH);
    server.join();
    result.exchanged = serverExchange && clientExchange;
    std::printf("TLS session: server=%d client=%d exchange=%d server_error=0x%08lx client_error=0x%08lx\n",
        result.serverHandshake, result.clientHandshake, result.exchanged, result.serverError, result.clientError);
    return result;
}
void Persistence() {
    using namespace capslang;
    Scratch scratch;
    Check(!scratch.directory.empty(), "exclusive disposable storage directory");
    if (scratch.directory.empty()) return;
    DWORD error = 0;
    std::vector<BYTE> plain{1, 2, 3, 4}, encrypted, recovered;
    Check(ProtectUserData(plain, encrypted, error) && encrypted != plain, "user DPAPI encryption");
    Check(UnprotectUserData(encrypted, recovered, error) && recovered == plain, "user DPAPI round trip");
    encrypted.back() ^= 1;
    Check(!UnprotectUserData(encrypted, recovered, error) && recovered.empty(), "DPAPI tamper rejected without stale output");
    Check(!ProtectUserData(plain, plain, error) && plain.size() == 4, "aliased protection rejected without destroying input");
    Check(!UnprotectUserData(plain, plain, error) && plain.size() == 4, "aliased unprotection rejected");
    Check(!ProtectUserData(std::vector<BYTE>(65537), encrypted, error), "oversized private data rejected");
    Check(SavePrivateData(scratch.File(L"data"), plain, false, error), "private file atomically created");
    Check(PrivateAcl(scratch.File(L"data")), "protected DACL grants only current user and SYSTEM");
    Check(!SavePrivateData(scratch.File(L"data"), {9}, false, error), "existing private file not overwritten");
    Check(LoadPrivateData(scratch.File(L"data"), recovered, error) && recovered == plain, "failed create preserves existing data");
    Check(SavePrivateData(scratch.File(L"data"), {9}, true, error) && LoadPrivateData(scratch.File(L"data"), recovered, error) && recovered == std::vector<BYTE>{9}, "explicit atomic replacement");
    Check(PrivateAcl(scratch.File(L"data")), "atomic replacement preserves private DACL");
    Pin serverPin{}, clientPin{};
    {
        Identity server, client;
        const bool ready = server.Generate(error) && client.Generate(error);
        Check(ready, "persistent identities generated");
        if (!ready) return;
        serverPin = server.Fingerprint(); clientPin = client.Fingerprint();
        Check(server.Save(scratch.File(L"server"), error), "server identity saved");
        Check(client.Save(scratch.File(L"client"), error), "client identity saved");
        Check(!server.Save(scratch.File(L"server"), error), "identity cannot silently overwrite persisted state");
    }
    Check(ReloadProcess(scratch.File(L"server"), serverPin), "new process reopens matching persisted private key");
    Identity server, client;
    const bool loaded = server.Load(scratch.File(L"server"), error) && client.Load(scratch.File(L"client"), error);
    Check(loaded, "identities survive destruction of generating objects");
    if (!loaded) { std::printf("Persistence error=0x%08lx\n", error); return; }
    Check(EqualPin(server.Fingerprint(), serverPin) && EqualPin(client.Fingerprint(), clientPin), "persisted certificate pins unchanged");
    auto session = Session(server, client, serverPin, clientPin, true);
    Check(session.exchanged, "reloaded identities perform mutual encrypted exchange");
    session = Session(server, client, serverPin, clientPin, true, true);
    Check(session.exchanged, "absolute language frames and acknowledgements survive fragmented/coalesced TLS records");
    session = Session(server, client, serverPin, clientPin, true, true, true);
    Check(!session.exchanged && session.serverError == ERROR_INVALID_DATA, "authenticated old-session language frame rejected");
    Check(LoadPrivateData(scratch.File(L"server"), recovered, error), "read owned identity fixture");
    // Header and key name remain valid, but the certificate DER is corrupt.
    if (recovered.size() > 98) recovered[98] = 0;
    Check(SavePrivateData(scratch.File(L"bad"), recovered, false, error), "malformed identity fixture stored");
    {
        Identity retry;
        Check(!retry.Load(scratch.File(L"bad"), error) && !retry.Certificate(), "bad certificate fails atomically");
        Check(LoadPrivateData(scratch.File(L"server"), recovered, error), "reload intact identity fixture");
        const DWORD certSize = client.Certificate()->cbCertEncoded;
        if (recovered.size() >= 98) {
            recovered.resize(98 + certSize);
            std::memcpy(recovered.data() + 12, &certSize, sizeof(certSize));
            std::memcpy(recovered.data() + 98, client.Certificate()->pbCertEncoded, certSize);
        }
        Check(SavePrivateData(scratch.File(L"bad"), recovered, true, error), "mismatched public certificate fixture stored");
        Check(!retry.Load(scratch.File(L"bad"), error) && !retry.Certificate(), "public certificate must match referenced private key");
        Check(retry.Load(scratch.File(L"server"), error) && EqualPin(retry.Fingerprint(), serverPin), "failed load neither deletes key nor poisons retry");
    }
    session = Session(server, client, serverPin, clientPin, true);
    Check(session.exchanged, "borrowed key survives loader destruction");
    HANDLE locked = CreateFileW(scratch.File(L"server").c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    Check(locked != INVALID_HANDLE_VALUE, "hold test identity file against deletion");
    if (locked != INVALID_HANDLE_VALUE) {
        Check(!server.Erase(error) && !server.Certificate(), "partial erase invalidates identity and reports sharing failure");
        CloseHandle(locked);
    }
    Check(server.Erase(error) && server.Erase(error), "erase retry and repeated erase are idempotent");
    Check(client.Erase(error), "client test key and identity removed");
    Identity removed;
    Check(!removed.Load(scratch.File(L"server"), error), "erased identity cannot reload");
}
void Pairing(const Identity& server, const Identity& client, const Identity& stranger) {
    DWORD error = 0;
    InvitationGate gate;
    std::string code;
    InvitationCode decoded;
    PairRecord record;
    Check(gate.Open(server, "4ERK-PC", 42519, 1000, error) && gate.Code(1001, code), "five minute invitation generated");
    Check(DecodeInvitation(code, decoded) && decoded.host == "4ERK-PC" && decoded.port == 42519 &&
        EqualPin(decoded.server, server.Fingerprint()), "invitation binds endpoint and exact server certificate");
    std::string encoded;
    Check(EncodeInvitation(decoded, encoded) && encoded == code, "invitation canonical encoding");
    for (const auto& host : {"", "-bad", "bad-", "bad..name", ".bad", "bad.", "bad/command", "bad\"name", "bad name", "bad|name", "bad:port"})
        Check(!ValidHost(host), "invitation host rejects malformed labels and command characters");
    for (const auto& suffix : {"|", "\n", " ", "00"}) {
        InvitationCode bad;
        Check(!DecodeInvitation(code + suffix, bad), "invitation rejects appended data");
    }
    auto malformed = code; malformed[0] = 'X';
    Check(!DecodeInvitation(malformed, decoded), "unknown invitation version refused");
    Check(DecodeInvitation(code, decoded), "recover intact invitation after malformed decode");
    Check(!gate.Open(server, "other", 42519, 1002, error) && error == ERROR_BUSY, "active invitation cannot be silently replaced");
    Check(!gate.Confirm(client.Fingerprint(), 1003, record), "confirmation before proof is rejected");
    auto wrong = decoded.secret; wrong[0] ^= 1;
    Check(!gate.Submit(client.Fingerprint(), wrong, 1004), "incorrect invitation proof rejected");
    Check(!gate.Submit(server.Fingerprint(), decoded.secret, 1005), "cannot pair with self");
    Check(gate.Submit(client.Fingerprint(), decoded.secret, 1006) && gate.State(1007) == InvitationState::AwaitConfirmation,
          "proof authorizes only pending confirmation, not a paired connection");
    Check(!gate.Code(1008, encoded) && !gate.Submit(stranger.Fingerprint(), decoded.secret, 1008), "proof is one-use and pending peer cannot be swapped");
    Check(!gate.Confirm(stranger.Fingerprint(), 1009, record), "UI approval bound to displayed fingerprint");
    Check(gate.Confirm(client.Fingerprint(), 1010, record) && ValidPair(record) && record.listener,
          "explicit confirmation creates listener pair record");
    const auto approved = record;
    Check(!gate.Confirm(client.Fingerprint(), 1011, record) && !gate.Submit(client.Fingerprint(), decoded.secret, 1011),
          "completed invitation cannot be reused");
    Scratch scratch;
    Check(!scratch.directory.empty(), "pair storage scratch directory");
    if (!scratch.directory.empty()) {
        Check(SavePair(scratch.File(L"pair"), approved, error) && PrivateAcl(scratch.File(L"pair")), "pair persisted under user DPAPI and private ACL");
        Check(SavePair(scratch.File(L"pair"), approved, error), "identical pair save is idempotent");
        PairRecord loaded;
        Check(LoadPair(scratch.File(L"pair"), server.Fingerprint(), loaded, error) && SamePair(loaded, approved), "pair round trip");
        auto replacement = approved; replacement.peer = stranger.Fingerprint();
        Check(!SavePair(scratch.File(L"pair"), replacement, error) && error == ERROR_ALREADY_EXISTS, "different peer never silently replaces stored pair");
        Check(!LoadPair(scratch.File(L"pair"), stranger.Fingerprint(), loaded, error) && !ValidPair(loaded), "pair cannot be loaded with another local identity");
        Check(LoadPair(scratch.File(L"pair"), server.Fingerprint(), loaded, error) && SamePair(loaded, approved), "refused overwrite preserved pair");
        Check(RemovePair(scratch.File(L"pair"), error) && RemovePair(scratch.File(L"pair"), error), "unpair is idempotent");
        Check(!LoadPair(scratch.File(L"pair"), server.Fingerprint(), loaded, error), "unpaired record cannot reload");
    }
    gate.Cancel();
    Check(gate.Open(server, "4ERK-PC", 42519, 2000, error), "new invitation after explicit cancel");
    Check(!gate.Code(302000, code) && gate.State(302000) == InvitationState::Expired, "five minute expiry enforced at boundary");
    Check(gate.Open(server, "4ERK-PC", 42519, 400000, error) && gate.Code(400001, code) && DecodeInvitation(code, decoded), "expired invitation can be replaced explicitly");
    Check(gate.Submit(client.Fingerprint(), decoded.secret, 400002) && !gate.Confirm(client.Fingerprint(), 700000, record), "expiry also enforced while UI waits for confirmation");
    gate.Cancel();
    Check(gate.Open(server, "4ERK-PC", 42519, 100, error), "rate-limit fixture opens");
    for (unsigned i = 0; i < 8; ++i) Check(!gate.Submit(client.Fingerprint(), {}, 101 + i), "bad proof attempt rejected");
    Check(gate.State(110) == InvitationState::Exhausted && !gate.Code(110, code), "eight failed proofs revoke invitation");
    gate.Cancel();
    Check(gate.Open(server, "4ERK-PC", 42519, 100, error) && !gate.Code(99, code), "monotonic clock regression fails closed");
    gate.Cancel();
    Check(!gate.Open(server, "4ERK-PC", 42519, UINT64_MAX, error), "invitation expiration cannot overflow");
    SecureZeroMemory(decoded.secret.data(), decoded.secret.size());
    if (!code.empty()) SecureZeroMemory(code.data(), code.size());
}
void ApplicationModes(const Identity& serverIdentity, const Identity& clientIdentity) {
    struct Case { bool temporary; ApplicationMode mode; int mutation; bool accept; DWORD error; };
    const Case cases[]{
        {false,ApplicationMode::Session,0,true,0},
        {false,ApplicationMode::ResumeEnrollment,0,true,0},
        {true,ApplicationMode::Enroll,0,true,0},
        {true,ApplicationMode::Session,0,false,ERROR_ACCESS_DENIED},
        {true,ApplicationMode::ResumeEnrollment,0,false,ERROR_ACCESS_DENIED},
        {false,ApplicationMode::Enroll,0,false,ERROR_ACCESS_DENIED},
        {false,ApplicationMode::Session,1,false,ERROR_INVALID_DATA},
        {false,ApplicationMode::Session,2,false,ERROR_INVALID_DATA},
        {false,ApplicationMode::Session,3,false,ERROR_INVALID_DATA},
        {false,ApplicationMode::Session,4,true,0},
        {false,ApplicationMode::Session,5,false,ERROR_TIMEOUT},
    };
    for (const auto& item : cases) {
        Socket listener(socket(AF_INET,SOCK_STREAM,IPPROTO_TCP));
        sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        int size = sizeof(address);
        if (listener.value == INVALID_SOCKET || bind(listener.value,reinterpret_cast<sockaddr*>(&address),size) ||
            listen(listener.value,1) || getsockname(listener.value,reinterpret_cast<sockaddr*>(&address),&size)) {
            Check(false,"application-mode loopback listener"); continue;
        }
        Socket client(socket(AF_INET,SOCK_STREAM,IPPROTO_TCP));
        if (connect(client.value,reinterpret_cast<sockaddr*>(&address),size)) { Check(false,"mode test connect"); continue; }
        Socket accepted(accept(listener.value,nullptr,nullptr));
        if (accepted.value == INVALID_SOCKET) { Check(false,"mode test accept"); continue; }
        bool serverOk = false, clientOk = false; DWORD serverError = 0, clientError = 0;
        ApplicationMode selected = ApplicationMode::Session;
        HANDLE modeFinished = CreateEventW(nullptr,TRUE,FALSE,nullptr);
        if (!modeFinished) { Check(false,"mode deadline barrier"); continue; }
        std::thread worker([&] {
            TlsChannel tls(accepted.value);
            if (tls.Handshake(serverIdentity,true,item.temporary ? Pin{} : clientIdentity.Fingerprint(),item.temporary))
                serverOk = AcceptApplicationMode(tls,selected,serverError);
            else serverError = tls.Error();
            SetEvent(modeFinished);
            shutdown(accepted.value,SD_BOTH);
        });
        TlsChannel tls(client.value);
        if (tls.Handshake(clientIdentity,false,serverIdentity.Fingerprint())) {
            if (!item.mutation) clientOk = SelectApplicationMode(tls,item.mode,clientError);
            else {
                std::vector<BYTE> frame{'C','L','A','P',1,static_cast<BYTE>(item.mode),0,0};
                if (item.mutation == 1) frame[0] ^= 1;
                if (item.mutation == 2) frame[6] = 1;
                if (item.mutation == 3) frame.push_back(42); // Premature next payload must not be discarded.
                if (item.mutation == 5) frame.pop_back();
                bool sent = item.mutation == 4 ? tls.Send(frame.data(),3) && tls.Send(frame.data()+3,frame.size()-3)
                                               : tls.Send(frame.data(),frame.size());
                std::vector<BYTE> reply;
                // Keep the incomplete client's socket open until the SERVER
                // deadline fires; a simultaneous client close is a different
                // (connection-aborted) failure, not the deadline under test.
                if (item.mutation == 5) WaitForSingleObject(modeFinished,2500);
                clientOk = sent && tls.Receive(reply,1500) && reply == frame;
            }
        }
        shutdown(client.value,SD_BOTH); worker.join();
        CloseHandle(modeFinished);
        if (serverOk != item.accept || clientOk != item.accept || serverError != item.error)
            std::printf("Mode mismatch: temporary=%d mode=%u mutation=%d expected=%d server=%d client=%d error=%lu expected_error=%lu\n",
                item.temporary,static_cast<unsigned>(item.mode),item.mutation,item.accept,serverOk,clientOk,serverError,item.error);
        Check(serverOk == item.accept && clientOk == item.accept && serverError == item.error,
              "application-mode TLS role, framing and deadline enforced");
        Check(item.accept ? selected == item.mode : static_cast<BYTE>(selected) == 0,
              "failed mode negotiation exposes no selected handler");
    }
    DWORD error = 0;
    TlsChannel disconnected(INVALID_SOCKET);
    Check(!SelectApplicationMode(disconnected,ApplicationMode::Session,error) && error == ERROR_ACCESS_DENIED,
          "application mode cannot bypass server pinning");
    PairRecord wrongOwner{clientIdentity.Fingerprint(),serverIdentity.Fingerprint(),"test-listener",42519,true};
    Check(!ServePairedConnection(disconnected,serverIdentity,wrongOwner,{},nullptr,error) && error == ERROR_INVALID_PARAMETER,
          "pair for another local identity rejected before connecting");
}
void Enrollment(const Identity& serverIdentity, const Identity& clientIdentity) {
    Scratch scratch;
    Check(!scratch.directory.empty(), "enrollment isolated storage directory");
    if (scratch.directory.empty()) return;
    auto round = [&](bool resume, bool approve, bool wrongProof) {
        DWORD error = 0;
        InvitationGate gate; InvitationCode invitation; std::string code;
        if (!gate.Open(serverIdentity, "test-listener", 42519, GetTickCount64(), error) ||
            !gate.Code(GetTickCount64(), code) || !DecodeInvitation(code, invitation)) return false;
        if (wrongProof) invitation.secret[0] ^= 1;
        Socket listener(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
        sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (listener.value == INVALID_SOCKET || bind(listener.value, reinterpret_cast<sockaddr*>(&address), sizeof(address)) || listen(listener.value, 1)) return false;
        int size = sizeof(address);
        if (getsockname(listener.value, reinterpret_cast<sockaddr*>(&address), &size)) return false;
        Socket client(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
        if (connect(client.value, reinterpret_cast<sockaddr*>(&address), sizeof(address))) return false;
        Socket accepted(accept(listener.value, nullptr, nullptr));
        if (accepted.value == INVALID_SOCKET) return false;
        bool serverOk = false, serverTrusted = false, gotApproval = false;
        DWORD serverError = 0;
        std::thread worker([&] {
            TlsChannel tls(accepted.value);
            if (resume) {
                PairRecord stored;
                serverOk = LoadPair(scratch.File(L"listener-pair"), serverIdentity.Fingerprint(), stored, serverError) &&
                    ServePairedConnection(tls, serverIdentity, stored, {}, nullptr, serverError);
            } else {
                unsigned polls = 0;
                serverOk = ServeInvitationConnection(tls, serverIdentity, gate, scratch.File(L"listener-pair"), [&](const Pin& peer) {
                    gotApproval = EqualPin(peer, clientIdentity.Fingerprint());
                    if (!gotApproval) return PairApproval::Deny;
                    if (++polls < 3) return PairApproval::Pending;
                    return approve ? PairApproval::Allow : PairApproval::Deny;
                }, serverError);
            }
            serverTrusted = tls.Paired();
            shutdown(accepted.value, SD_BOTH);
        });
        TlsChannel tls(client.value);
        const bool clientOk = OpenInvitationConnection(tls, clientIdentity, invitation, scratch.File(L"connector-pair"), resume, error);
        shutdown(client.value, SD_BOTH); worker.join();
        SecureZeroMemory(invitation.secret.data(), invitation.secret.size());
        SecureZeroMemory(code.data(), code.size());
        if (!resume) Check(!serverTrusted, "temporary invitation TLS is NOT promoted to paired state");
        else Check(serverTrusted, "resume uses mutual pinned TLS only");
        if (wrongProof) Check(!gotApproval, "wrong proof is rejected before displaying approval");
        if (!approve || wrongProof) return !serverOk && !clientOk &&
            GetFileAttributesW(scratch.File(L"listener-pair").c_str()) == INVALID_FILE_ATTRIBUTES &&
            GetFileAttributesW(scratch.File(L"connector-pair").c_str()) == INVALID_FILE_ATTRIBUTES;
        if (!serverOk || !clientOk) std::printf("Enrollment error server=0x%08lx client=0x%08lx\n", serverError, error);
        return serverOk && clientOk;
    };
    Check(round(false, false, false), "denied confirmation leaves both devices unpaired over real TLS");
    Check(round(false, true, true), "wrong invitation cannot persist either side of a pair");
    Check(round(false, true, false), "approved invitation pairs both sides over real Schannel TLS");
    DWORD error = 0; PairRecord server, client;
    Check(LoadPair(scratch.File(L"listener-pair"), serverIdentity.Fingerprint(), server, error) &&
        LoadPair(scratch.File(L"connector-pair"), clientIdentity.Fingerprint(), client, error) &&
        EqualPin(server.peer, client.local) && EqualPin(client.peer, server.local) && server.listener && !client.listener,
        "enrollment stores reciprocal certificate pins and one listener role");
    Check(RemovePair(scratch.File(L"connector-pair"), error), "simulate peer missing local commit after uncertain delivery");
    Check(round(true, true, false), "mutually pinned resume repairs half-committed pair without reusing invitation");
    Check(LoadPair(scratch.File(L"connector-pair"), clientIdentity.Fingerprint(), client, error), "recovered peer pair persisted");
    Check(round(true, true, false), "repeated resume is idempotent");
}
}
int wmain(int argc, wchar_t** argv) {
    if (argc == 4 && std::wstring(argv[1]) == L"--reload") {
        Identity identity; DWORD error = 0;
        return identity.Load(argv[2], error) && Hex(identity.Fingerprint()) == argv[3] ? 0 : 4;
    }
    WSADATA winsock{};
    if (WSAStartup(MAKEWORD(2,2), &winsock)) return 2;
    {
        Identity server, client, stranger;
        DWORD error = 0;
        Check(server.Generate(error), "server CNG identity created");
        Check(client.Generate(error), "client CNG identity created");
        Check(stranger.Generate(error), "unpaired identity created");
        if (failures) { std::printf("Identity error=0x%08lx\n", error); return 3; }
        Check(!EqualPin(server.Fingerprint(), client.Fingerprint()), "distinct certificates have distinct pins");
        Check(!EqualPin(server.Fingerprint(), Pin{}), "fingerprint is nonempty");
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key = 0;
        DWORD spec = 0; BOOL owned = FALSE;
        const bool acquired = CryptAcquireCertificatePrivateKey(server.Certificate(), CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG |
            CRYPT_ACQUIRE_COMPARE_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG, nullptr, &key, &spec, &owned) != FALSE;
        Check(acquired && spec == CERT_NCRYPT_KEY_SPEC, "certificate resolves to usable matching CNG private key");
        if (acquired && owned) NCryptFreeObject(key);
        const auto paired = Session(server, client, server.Fingerprint(), client.Fingerprint(), true);
        Check(paired.serverHandshake && paired.clientHandshake && paired.exchanged, "real mutual Schannel TLS encrypted round trips");
        const auto wrongServer = Session(server, client, stranger.Fingerprint(), client.Fingerprint(), false);
        Check(!wrongServer.clientHandshake && wrongServer.clientError == static_cast<DWORD>(SEC_E_WRONG_PRINCIPAL),
              "client rejects unpinned server certificate");
        const auto wrongClient = Session(server, stranger, server.Fingerprint(), client.Fingerprint(), false);
        Check(!wrongClient.serverHandshake && wrongClient.serverError == static_cast<DWORD>(SEC_E_WRONG_PRINCIPAL),
              "server rejects unpaired client certificate");
        TlsChannel invalid(INVALID_SOCKET);
        Check(!invalid.Handshake(client, false, Pin{}) && invalid.Error() == ERROR_INVALID_PARAMETER,
              "empty server pin cannot enable trust on first use");
        TlsChannel unauthorized(INVALID_SOCKET);
        Check(!unauthorized.Handshake(client, false, server.Fingerprint(), true),
              "client cannot disable pinning using invitation mode");
        capslang::sync::Id unusedSession{}; unusedSession[0] = 1;
        LanguageChannel notPaired(unauthorized, unusedSession);
        capslang::sync::Message noMessage;
        Check(!notPaired.Receive(noMessage) && notPaired.Error() == ERROR_ACCESS_DENIED,
              "language protocol refuses unestablished TLS channel");
        Pairing(server, client, stranger);
        ApplicationModes(server, client);
        Enrollment(server, client);
    }
    Persistence();
    WSACleanup();
    std::printf("Windows TLS: %u checks, %u failures; loopback only, no roots/firewall changes.\n", checks, failures);
    return failures ? 1 : 0;
}
