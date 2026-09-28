#include "tls.hpp"
#include <bcrypt.h>
#include <algorithm>
#include <cstring>

namespace capslang::net {
bool EqualPin(const Pin& a, const Pin& b) {
    BYTE difference = 0;
    for (size_t i = 0; i < a.size(); ++i) difference |= a[i] ^ b[i];
    return difference == 0;
}
bool CertificatePin(PCCERT_CONTEXT certificate, Pin& pin) {
    DWORD bytes = static_cast<DWORD>(pin.size());
    return certificate && CryptHashCertificate2(BCRYPT_SHA256_ALGORITHM, 0, nullptr,
        certificate->pbCertEncoded, certificate->cbCertEncoded, pin.data(), &bytes) && bytes == pin.size();
}
Identity::~Identity() {
    if (certificate_) CertFreeCertificateContext(certificate_);
    // This object currently owns only keys it generated. A failed/finished
    // test leaves no persistent test key, certificate store or trusted root.
    if (key_ && NCryptDeleteKey(key_, 0) != ERROR_SUCCESS) NCryptFreeObject(key_);
    if (provider_) NCryptFreeObject(provider_);
}
bool Identity::Generate(DWORD& error) {
    if (key_ || certificate_) { error = ERROR_ALREADY_EXISTS; return false; }
    BYTE random[16]{};
    if (BCryptGenRandom(nullptr, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        error = NTE_FAIL; return false;
    }
    std::wstring name = L"CapsLang-";
    constexpr wchar_t hex[] = L"0123456789abcdef";
    for (BYTE byte : random) { name += hex[byte >> 4]; name += hex[byte & 15]; }
    SECURITY_STATUS status = NCryptOpenStorageProvider(&provider_, MS_KEY_STORAGE_PROVIDER, 0);
    if (!status) status = NCryptCreatePersistedKey(provider_, &key_, NCRYPT_RSA_ALGORITHM, name.c_str(), 0, 0);
    DWORD bits = 3072;
    if (!status) status = NCryptSetProperty(key_, NCRYPT_LENGTH_PROPERTY, reinterpret_cast<BYTE*>(&bits), sizeof(bits), 0);
    if (!status) status = NCryptFinalizeKey(key_, NCRYPT_SILENT_FLAG);
    if (status) { error = status; return false; }
    BYTE subject[256]{};
    DWORD size = sizeof(subject);
    if (!CertStrToNameW(X509_ASN_ENCODING, L"CN=CapsLang paired device", CERT_X500_NAME_STR,
                        nullptr, subject, &size, nullptr)) { error = GetLastError(); return false; }
    CERT_NAME_BLOB distinguished{size, subject};
    CRYPT_KEY_PROV_INFO providerInfo{};
    providerInfo.pwszContainerName = name.data();
    providerInfo.pwszProvName = const_cast<wchar_t*>(MS_KEY_STORAGE_PROVIDER);
    // This field is NCryptOpenKey's legacy key spec, NOT the sentinel returned
    // by CryptAcquireCertificatePrivateKey. CNG-generated keys use zero here.
    providerInfo.dwKeySpec = 0;
    CRYPT_ALGORITHM_IDENTIFIER algorithm{const_cast<char*>(szOID_RSA_SHA256RSA), {0, nullptr}};
    SYSTEMTIME start{}, end{};
    GetSystemTime(&start); end = start; end.wYear += 5;
    // Avoid invalid February 29 on the fifth anniversary.
    if (end.wMonth == 2 && end.wDay == 29) end.wDay = 28;
    char* usages[]{const_cast<char*>(szOID_PKIX_KP_SERVER_AUTH), const_cast<char*>(szOID_PKIX_KP_CLIENT_AUTH)};
    CERT_ENHKEY_USAGE usage{2, usages};
    BYTE encodedUsage[128]{}; DWORD usageBytes = sizeof(encodedUsage);
    if (!CryptEncodeObject(X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE, &usage, encodedUsage, &usageBytes)) {
        error = GetLastError(); return false;
    }
    CERT_EXTENSION eku{const_cast<char*>(szOID_ENHANCED_KEY_USAGE), FALSE, {usageBytes, encodedUsage}};
    CERT_EXTENSIONS extensions{1, &eku};
    certificate_ = CertCreateSelfSignCertificate(key_, &distinguished, 0, &providerInfo,
                                                &algorithm, &start, &end, &extensions);
    error = certificate_ ? 0 : GetLastError();
    return certificate_ != nullptr;
}
Pin Identity::Fingerprint() const { Pin pin{}; CertificatePin(certificate_, pin); return pin; }

struct TlsChannel::Impl {
    SOCKET socket;
    HANDLE cancel;
    CredHandle credential{};
    CtxtHandle context{};
    bool haveCredential = false, haveContext = false, established = false, failed = false;
    SecPkgContext_StreamSizes sizes{};
    Pin peer{};
    DWORD error = 0;
    std::vector<BYTE> incoming;
    Impl(SOCKET value, HANDLE event) : socket(value), cancel(event) {}
    ~Impl() {
        if (haveContext) DeleteSecurityContext(&context);
        if (haveCredential) FreeCredentialsHandle(&credential);
    }
    bool Fail(DWORD code) { error = code; failed = true; established = false; return false; }
    bool Ready(short events, ULONGLONG deadline) {
        while (GetTickCount64() < deadline) {
            if (cancel && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0) return Fail(ERROR_OPERATION_ABORTED);
            WSAPOLLFD poll{socket, events, 0};
            const int wait = WSAPoll(&poll, 1, 50);
            if (wait < 0) return Fail(WSAGetLastError());
            if (wait > 0) {
                if (poll.revents & events) return true;
                return Fail(ERROR_CONNECTION_ABORTED);
            }
        }
        return Fail(ERROR_TIMEOUT);
    }
    bool Write(const BYTE* data, size_t length, ULONGLONG deadline) {
        while (length) {
            if (!Ready(POLLWRNORM, deadline)) return false;
            const int sent = send(socket, reinterpret_cast<const char*>(data), static_cast<int>(length), 0);
            if (sent < 0 && WSAGetLastError() == WSAEWOULDBLOCK) continue;
            if (sent <= 0) return Fail(sent ? WSAGetLastError() : ERROR_CONNECTION_ABORTED);
            data += sent; length -= sent;
        }
        return true;
    }
    bool Read(ULONGLONG deadline) {
        for (;;) {
            if (incoming.size() >= 65536) return Fail(ERROR_BUFFER_OVERFLOW);
            if (!Ready(POLLRDNORM, deadline)) return false;
            BYTE buffer[16384]{};
            const int bytes = recv(socket, reinterpret_cast<char*>(buffer), sizeof(buffer), 0);
            if (bytes < 0 && WSAGetLastError() == WSAEWOULDBLOCK) continue;
            if (bytes <= 0) return Fail(bytes ? WSAGetLastError() : ERROR_CONNECTION_ABORTED);
            if (incoming.size() + static_cast<size_t>(bytes) > 65536) return Fail(ERROR_BUFFER_OVERFLOW);
            incoming.insert(incoming.end(), buffer, buffer + bytes);
            return true;
        }
    }
    void Extra(const SecBuffer* buffers, size_t count) {
        size_t extra = 0;
        for (size_t i = 0; i < count; ++i) if (buffers[i].BufferType == SECBUFFER_EXTRA) extra = buffers[i].cbBuffer;
        if (extra && extra <= incoming.size()) incoming.erase(incoming.begin(), incoming.end() - extra);
        else incoming.clear();
    }
};
TlsChannel::TlsChannel(SOCKET socket, HANDLE cancel) : impl_(std::make_unique<Impl>(socket, cancel)) {}
TlsChannel::~TlsChannel() = default;
DWORD TlsChannel::Error() const { return impl_->error; }
Pin TlsChannel::Peer() const { return impl_->peer; }
bool TlsChannel::Handshake(const Identity& identity, bool server, const Pin& expected, bool invitation) {
    auto& self = *impl_;
    if (self.haveContext || self.failed || !identity.Certificate() || (invitation && !server)) return self.Fail(ERROR_INVALID_PARAMETER);
    Pin empty{};
    if (!invitation && EqualPin(expected, empty)) return self.Fail(ERROR_INVALID_PARAMETER);
    u_long nonblocking = 1;
    if (ioctlsocket(self.socket, FIONBIO, &nonblocking) != 0) return self.Fail(WSAGetLastError());
    SCHANNEL_CRED config{};
    config.dwVersion = SCHANNEL_CRED_VERSION;
    PCCERT_CONTEXT certificate = identity.Certificate();
    config.cCreds = 1; config.paCred = &certificate;
    config.grbitEnabledProtocols = server ? SP_PROT_TLS1_2_SERVER : SP_PROT_TLS1_2_CLIENT;
    config.dwFlags = SCH_USE_STRONG_CRYPTO | (server ? SCH_CRED_NO_SYSTEM_MAPPER :
        SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS);
    TimeStamp expiry{};
    SECURITY_STATUS status = AcquireCredentialsHandleW(nullptr, const_cast<wchar_t*>(UNISP_NAME_W),
        server ? SECPKG_CRED_INBOUND : SECPKG_CRED_OUTBOUND, nullptr, &config, nullptr, nullptr, &self.credential, &expiry);
    if (status != SEC_E_OK) return self.Fail(status);
    self.haveCredential = true;
    const auto deadline = GetTickCount64() + 4000;
    bool first = true, needRead = server;
    for (unsigned steps = 0; steps < 128; ++steps) {
        if (needRead && !self.Read(deadline)) return false;
        SecBuffer input[2]{{static_cast<ULONG>(self.incoming.size()), SECBUFFER_TOKEN, self.incoming.data()}, {0, SECBUFFER_EMPTY, nullptr}};
        SecBufferDesc inputDesc{SECBUFFER_VERSION, 2, input};
        SecBuffer output{0, SECBUFFER_TOKEN, nullptr};
        SecBufferDesc outputDesc{SECBUFFER_VERSION, 1, &output};
        ULONG attributes = 0;
        if (server) {
            status = AcceptSecurityContext(&self.credential, self.haveContext ? &self.context : nullptr, &inputDesc,
                ASC_REQ_STREAM | ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_CONFIDENTIALITY | ASC_REQ_REPLAY_DETECT |
                ASC_REQ_SEQUENCE_DETECT | ASC_REQ_MUTUAL_AUTH, 0, &self.context, &outputDesc, &attributes, &expiry);
        } else {
            status = InitializeSecurityContextW(&self.credential, self.haveContext ? &self.context : nullptr,
                const_cast<wchar_t*>(L"CapsLang paired device"), ISC_REQ_STREAM | ISC_REQ_ALLOCATE_MEMORY |
                ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT |
                ISC_REQ_MANUAL_CRED_VALIDATION | ISC_REQ_USE_SUPPLIED_CREDS, 0, 0,
                first ? nullptr : &inputDesc, 0, &self.context, &outputDesc, &attributes, &expiry);
        }
        if (status == SEC_E_OK || status == SEC_I_CONTINUE_NEEDED || status == SEC_E_INCOMPLETE_MESSAGE)
            self.haveContext = self.haveContext || status != SEC_E_INCOMPLETE_MESSAGE;
        bool sent = true;
        if (output.pvBuffer && output.cbBuffer) sent = self.Write(static_cast<BYTE*>(output.pvBuffer), output.cbBuffer, deadline);
        if (output.pvBuffer) FreeContextBuffer(output.pvBuffer);
        if (!sent) return false;
        if (status == SEC_E_INCOMPLETE_MESSAGE) { needRead = true; continue; }
        if (status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED) return self.Fail(status);
        self.Extra(input, 2); first = false;
        if (status == SEC_E_OK) {
            PCCERT_CONTEXT peer = nullptr;
            status = QueryContextAttributesW(&self.context, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &peer);
            const bool valid = status == SEC_E_OK && peer && CertificatePin(peer, self.peer) &&
                CertVerifyTimeValidity(nullptr, peer->pCertInfo) == 0 && (invitation || EqualPin(self.peer, expected));
            if (peer) CertFreeCertificateContext(peer);
            if (!valid) return self.Fail(status ? status : static_cast<DWORD>(SEC_E_WRONG_PRINCIPAL));
            status = QueryContextAttributesW(&self.context, SECPKG_ATTR_STREAM_SIZES, &self.sizes);
            if (status != SEC_E_OK || self.sizes.cbMaximumMessage < 1024) return self.Fail(status ? status : ERROR_NOT_SUPPORTED);
            self.established = true; self.error = 0; return true;
        }
        needRead = self.incoming.empty();
    }
    return self.Fail(ERROR_TIMEOUT);
}
bool TlsChannel::Send(const void* data, size_t bytes) {
    auto& self = *impl_;
    if (!self.established || self.failed || !data || !bytes || bytes > 1024) return self.Fail(ERROR_INVALID_PARAMETER);
    std::vector<BYTE> packet(self.sizes.cbHeader + bytes + self.sizes.cbTrailer);
    std::memcpy(packet.data() + self.sizes.cbHeader, data, bytes);
    SecBuffer buffers[4]{{self.sizes.cbHeader, SECBUFFER_STREAM_HEADER, packet.data()},
        {static_cast<ULONG>(bytes), SECBUFFER_DATA, packet.data() + self.sizes.cbHeader},
        {self.sizes.cbTrailer, SECBUFFER_STREAM_TRAILER, packet.data() + self.sizes.cbHeader + bytes},
        {0, SECBUFFER_EMPTY, nullptr}};
    SecBufferDesc message{SECBUFFER_VERSION, 4, buffers};
    const SECURITY_STATUS result = EncryptMessage(&self.context, 0, &message, 0);
    if (result != SEC_E_OK) return self.Fail(result);
    return self.Write(packet.data(), buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer, GetTickCount64() + 1000);
}
bool TlsChannel::Receive(std::vector<BYTE>& data) {
    auto& self = *impl_;
    if (!self.established || self.failed) return self.Fail(ERROR_INVALID_STATE);
    const auto deadline = GetTickCount64() + 1500;
    for (unsigned steps = 0; steps < 128; ++steps) {
        if (self.incoming.empty() && !self.Read(deadline)) return false;
        SecBuffer buffers[4]{{static_cast<ULONG>(self.incoming.size()), SECBUFFER_DATA, self.incoming.data()},
            {0, SECBUFFER_EMPTY, nullptr}, {0, SECBUFFER_EMPTY, nullptr}, {0, SECBUFFER_EMPTY, nullptr}};
        SecBufferDesc message{SECBUFFER_VERSION, 4, buffers};
        const SECURITY_STATUS result = DecryptMessage(&self.context, &message, 0, nullptr);
        if (result == SEC_E_INCOMPLETE_MESSAGE) { if (!self.Read(deadline)) return false; continue; }
        // No unauthenticated renegotiation or silent protocol transitions.
        if (result != SEC_E_OK) return self.Fail(result);
        data.clear();
        for (const auto& buffer : buffers) if (buffer.BufferType == SECBUFFER_DATA && buffer.cbBuffer) {
            if (buffer.cbBuffer > 1024 || !data.empty()) return self.Fail(ERROR_BUFFER_OVERFLOW);
            auto* first = static_cast<BYTE*>(buffer.pvBuffer);
            data.assign(first, first + buffer.cbBuffer);
        }
        self.Extra(buffers, 4);
        if (!data.empty()) return true;
    }
    return self.Fail(ERROR_TIMEOUT);
}
} // namespace capslang::net
