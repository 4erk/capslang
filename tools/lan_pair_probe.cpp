// Development integration probe: mutually pinned LAN transport, no hooks,
// keyboard/LED operations, autostart, layout changes or MWB configuration.
#include "../src/network/lan.hpp"
#include "../src/network/tls.hpp"
#include "../src/network/language_channel.hpp"
#include <bcrypt.h>
#include <cstdio>

using namespace capslang::net;
namespace {
std::wstring Hex(const Pin& pin) {
    std::wstring result;
    for (const auto byte : pin) { result += L"0123456789abcdef"[byte >> 4]; result += L"0123456789abcdef"[byte & 15]; }
    return result;
}
bool ParsePin(const std::wstring& text, Pin& pin) {
    if (text.size() != 64) return false;
    auto nibble = [](wchar_t c) { return c >= L'0' && c <= L'9' ? c - L'0' : c >= L'a' && c <= L'f' ? c - L'a' + 10 : -1; };
    for (size_t i = 0; i < pin.size(); ++i) {
        const auto a = nibble(text[2 * i]), b = nibble(text[2 * i + 1]);
        if (a < 0 || b < 0) return false;
        pin[i] = static_cast<BYTE>((a << 4) | b);
    }
    return !EqualPin(pin, Pin{});
}
bool RoundTrip(TlsChannel& tls, bool server, unsigned& count) {
    capslang::sync::Id session{}, author{}; author[0] = 7;
    if (server) {
        if (BCryptGenRandom(nullptr, session.data(), static_cast<ULONG>(session.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) ||
            !tls.Send(session.data(), session.size())) return false;
    } else {
        std::vector<BYTE> nonce;
        while (nonce.size() < session.size()) {
            std::vector<BYTE> part;
            if (!tls.Receive(part) || part.empty() || nonce.size() + part.size() > session.size()) return false;
            nonce.insert(nonce.end(), part.begin(), part.end());
        }
        std::copy(nonce.begin(), nonce.end(), session.begin());
    }
    if (!capslang::sync::Nonzero(session)) return false;
    LanguageChannel channel(tls, session);
    for (unsigned i = 1; i <= 100; ++i) {
        const auto language = i % 2 ? capslang::core::Language::Russian : capslang::core::Language::English;
        capslang::sync::Message message{capslang::sync::Kind::Update, session, {i, author}, language, capslang::sync::Applied::None};
        if (server) {
            if (!channel.Send(message) || !channel.Receive(message) || message.kind != capslang::sync::Kind::Ack ||
                message.version.counter != i || message.language != language || message.applied != capslang::sync::Applied::Pending) return false;
        } else {
            if (!channel.Receive(message) || message.kind != capslang::sync::Kind::Update || message.version.counter != i || message.language != language) return false;
            // Deliberately Pending: this probe has NOT applied any OS layout.
            message.kind = capslang::sync::Kind::Ack; message.applied = capslang::sync::Applied::Pending;
            if (!channel.Send(message)) return false;
        }
        ++count;
    }
    return true;
}
}
int wmain(int argc, wchar_t** argv) {
    if (argc < 3) return 2;
    DWORD error = 0;
    const std::wstring mode = argv[1], path = argv[2];
    Identity identity;
    if (mode == L"--prepare" && argc == 3) {
        if (!identity.Generate(error) || !identity.Save(path, error)) { std::printf("prepare_error=%lu\n", error); return 3; }
        std::wprintf(L"public_pin=%ls\n", Hex(identity.Fingerprint()).c_str()); return 0;
    }
    if (!identity.Load(path, error)) { std::printf("identity_error=%lu\n", error); return 4; }
    if (mode == L"--cleanup" && argc == 3) return identity.Erase(error) ? 0 : 5;
    if (argc != 6 || (mode != L"--listen" && mode != L"--connect")) return 2;
    Pin peer{}; if (!ParsePin(argv[3], peer)) return 2;
    const std::wstring wideHost = argv[4]; std::string host(wideHost.begin(), wideHost.end());
    wchar_t* end = nullptr; const auto portValue = wcstoul(argv[5], &end, 10);
    if (!end || *end || portValue < 1024 || portValue > 65535) return 2;
    const auto port = static_cast<std::uint16_t>(portValue);
    Winsock winsock; if (winsock.Error()) return 6;
    const bool server = mode == L"--listen";
    LanListener listener;
    if (server && !listener.Open(port, error)) { std::printf("listen_error=%lu\n", error); return 7; }
    std::printf("ready role=%s; no input/layout operations\n", server ? "listener" : "connector"); std::fflush(stdout);
    unsigned count = 0;
    const auto deadline = GetTickCount64() + 45000;
    for (unsigned round = 1; round <= 3; ++round) {
        Socket connection;
        while (!connection && GetTickCount64() < deadline) {
            connection = server ? listener.Accept(nullptr, 1000, error) : ConnectLan(host, port, nullptr, 1500, error);
            if (!connection) Sleep(100);
        }
        if (!connection) { std::printf("connect_error=%lu\n", error); return 8; }
        TlsChannel tls(connection.Get());
        const auto start = GetTickCount64();
        if (!tls.Handshake(identity, server, peer) || !RoundTrip(tls, server, count)) {
            std::printf("tls_error=%lu completed=%u\n", tls.Error(), count); return 9;
        }
        std::printf("round=%u frames=%u elapsed_ms=%llu mutual_pins=%d\n", round, count,
            static_cast<unsigned long long>(GetTickCount64() - start), tls.Paired()); std::fflush(stdout);
    }
    std::printf("PASS 3 independent TLS connections, 300 acknowledged test language frames; actual layout untouched\n");
    return 0;
}
