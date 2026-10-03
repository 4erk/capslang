#include "../src/network/tls.hpp"
#include "../src/platform/private_store.hpp"
#include "../src/network/language_channel.hpp"
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
        for (auto name : {L"server", L"client", L"bad", L"data"}) DeleteFileW(File(name).c_str());
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
    }
    Persistence();
    WSACleanup();
    std::printf("Windows TLS: %u checks, %u failures; loopback only, no roots/firewall changes.\n", checks, failures);
    return failures ? 1 : 0;
}
