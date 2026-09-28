#include "../src/network/tls.hpp"
#include <thread>
#include <cstdio>
#include <cstring>

using namespace capslang::net;
namespace {
unsigned checks = 0, failures = 0;
void Check(bool value, const char* name) {
    ++checks; if (!value) { ++failures; std::printf("FAIL %s\n", name); }
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
               const Pin& serverPin, const Pin& clientPin, bool exchange) {
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
    std::thread server([&] {
        TlsChannel channel(accepted.value);
        result.serverHandshake = channel.Handshake(serverIdentity, true, clientPin);
        if (result.serverHandshake && exchange) {
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
        result.serverError = channel.Error();
        shutdown(accepted.value, SD_BOTH);
    });
    TlsChannel channel(client.value);
    result.clientHandshake = channel.Handshake(clientIdentity, false, serverPin);
    bool clientExchange = result.clientHandshake && exchange;
    if (clientExchange) for (std::uint64_t index = 0; index < 8; ++index) {
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
}
int main() {
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
    }
    WSACleanup();
    std::printf("Windows TLS: %u checks, %u failures; loopback only, no roots/firewall changes.\n", checks, failures);
    return failures ? 1 : 0;
}
