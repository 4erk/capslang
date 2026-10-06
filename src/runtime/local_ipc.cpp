#include "local_ipc.hpp"
#include <sddl.h>
#include <atomic>
#include <exception>

namespace capslang::ipc {
namespace {
std::wstring Sid(HANDLE token) {
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    if (!size || size > 65536) return {};
    std::vector<BYTE> buffer(size);
    if (!GetTokenInformation(token, TokenUser, buffer.data(), size, &size)) return {};
    wchar_t* text = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid, &text)) return {};
    std::wstring result(text); LocalFree(text); return result;
}
bool TokenMatches(HANDLE token, const Endpoint& endpoint) {
    DWORD session = 0, bytes = 0;
    return GetTokenInformation(token, TokenSessionId, &session, sizeof(session), &bytes) &&
        session == endpoint.session && Sid(token) == endpoint.sid;
}
bool ProcessMatches(HANDLE process, const ProcessIdentity& expected) {
    if (!expected.CompleteOrEmpty()) return false;
    if (!expected.id) return true;
    ProcessIdentity actual;
    return IdentifyProcess(process, actual) && actual.id == expected.id && actual.created == expected.created;
}
bool ClientMatches(HANDLE pipe, const Endpoint& endpoint) {
    if (!ImpersonateNamedPipeClient(pipe)) return false;
    HANDLE token = nullptr;
    const bool opened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token) != FALSE;
    DWORD bytes = 0;
    TOKEN_ELEVATION elevation{};
    bool match = opened && TokenMatches(token, endpoint) &&
        (!endpoint.requireClientElevation ||
         (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &bytes) && elevation.TokenIsElevated));
    if (token) CloseHandle(token);
    // Never call the handler while impersonating even the allowed user.
    if (!RevertToSelf()) std::terminate();
    if (match && (!endpoint.clientImage.empty() || endpoint.clientProcess.id)) {
        ULONG pid = 0;
        match = GetNamedPipeClientProcessId(pipe, &pid) != FALSE;
        HANDLE process = match ? OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid) : nullptr;
        wchar_t path[32768]{}; DWORD length = ARRAYSIZE(path);
        match = process && ProcessMatches(process, endpoint.clientProcess) &&
            (endpoint.clientImage.empty() || (QueryFullProcessImageNameW(process, 0, path, &length) &&
            _wcsicmp(path, endpoint.clientImage.c_str()) == 0));
        if (process) CloseHandle(process);
    }
    return match;
}
bool ServerMatches(HANDLE pipe, const Endpoint& endpoint, const std::wstring& path, bool high, ProcessIdentity& identity) {
    ULONG pid = 0;
    if (path.empty() || !GetNamedPipeServerProcessId(pipe, &pid)) return false;
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) return false;
    HANDLE token = nullptr;
    wchar_t actual[32768]{};
    DWORD length = ARRAYSIZE(actual), bytes = 0;
    TOKEN_ELEVATION elevation{};
    auto server = endpoint;
    if (!endpoint.serverSid.empty()) server.sid = endpoint.serverSid;
    const bool valid = ProcessMatches(process, endpoint.serverProcess) && IdentifyProcess(process, identity) &&
        QueryFullProcessImageNameW(process, 0, actual, &length) &&
        _wcsicmp(actual, path.c_str()) == 0 &&
        OpenProcessToken(process, TOKEN_QUERY, &token) && TokenMatches(token, server) &&
        GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &bytes) &&
        (!high || elevation.TokenIsElevated);
    if (token) CloseHandle(token);
    CloseHandle(process);
    return valid;
}
bool FinishIo(HANDLE pipe, OVERLAPPED& overlapped, HANDLE stop, DWORD timeout, DWORD& bytes, DWORD& error) {
    HANDLE events[]{overlapped.hEvent, stop};
    const DWORD wait = WaitForMultipleObjects(stop ? 2 : 1, events, FALSE, timeout);
    if (wait != WAIT_OBJECT_0) {
        error = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : ERROR_OPERATION_ABORTED;
        CancelIoEx(pipe, &overlapped);
        // The kernel named-pipe operation must release its buffer before return.
        GetOverlappedResult(pipe, &overlapped, &bytes, TRUE);
        return false;
    }
    if (!GetOverlappedResult(pipe, &overlapped, &bytes, FALSE)) { error = GetLastError(); return false; }
    error = ERROR_SUCCESS; return true;
}
bool Transfer(HANDLE pipe, void* buffer, DWORD size, bool write, HANDLE stop, DWORD& error) {
    OVERLAPPED overlapped{};
    overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!overlapped.hEvent) { error = GetLastError(); return false; }
    DWORD bytes = 0;
    const BOOL result = write ? WriteFile(pipe, buffer, size, &bytes, &overlapped)
                              : ReadFile(pipe, buffer, size, &bytes, &overlapped);
    bool success = result != FALSE;
    if (!success) {
        error = GetLastError();
        if (error == ERROR_IO_PENDING) success = FinishIo(pipe, overlapped, stop, 1000, bytes, error);
    }
    CloseHandle(overlapped.hEvent);
    if (success && bytes != size) { error = ERROR_INVALID_DATA; return false; }
    if (success) error = 0;
    return success;
}
}
bool IdentifyProcess(HANDLE process, ProcessIdentity& identity) {
    identity = {};
    FILETIME created{}, exited{}, kernel{}, user{};
    const DWORD pid = GetProcessId(process);
    if (!pid || !GetProcessTimes(process, &created, &exited, &kernel, &user)) return false;
    const auto stamp = (std::uint64_t(created.dwHighDateTime) << 32) | created.dwLowDateTime;
    if (!stamp) return false;
    identity = {pid, stamp}; return true;
}
bool Valid(const Request& request) {
    if (request.magic != kMagic || request.version != kVersion || !request.id) return false;
    if (request.operation == Operation::ReportProfile) {
        return request.engineEpoch && request.reserved <= UINT32_MAX &&
            ((request.language == 0 && request.reserved != 0) ||
             ((request.language == 0x409 || request.language == 0x419) && !request.reserved));
    }
    if (request.operation == Operation::ManualProfile)
        return request.engineEpoch && !request.reserved && (request.language == 0x409 || request.language == 0x419);
    if (request.reserved) return false;
    if (request.operation == Operation::SetLayoutIfRevision) {
        if (!request.engineEpoch) return false;
    } else if (request.engineEpoch || request.expectedRevision) return false;
    switch (request.operation) {
    case Operation::SetLayout: case Operation::SetLayoutIfRevision:
        return IsSupportedLanguage(static_cast<LANGID>(request.language)) && request.language <= 0xffff;
    case Operation::Status: case Operation::RefreshHook: case Operation::Stop: return request.language == 0;
    default: return false;
    }
}
Endpoint Endpoint::Current(const std::wstring& instance) {
    Endpoint endpoint;
    if (instance.empty() || instance.size() > 64) { endpoint.error = ERROR_INVALID_PARAMETER; return endpoint; }
    for (wchar_t c : instance) if (!((c >= L'a' && c <= L'z') || (c >= L'0' && c <= L'9') || c == L'.' || c == L'-')) {
        endpoint.error = ERROR_INVALID_PARAMETER; return endpoint;
    }
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) { endpoint.error = GetLastError(); return endpoint; }
    endpoint.sid = Sid(token);
    DWORD bytes = 0;
    if (endpoint.sid.empty() || !GetTokenInformation(token, TokenSessionId, &endpoint.session, sizeof(endpoint.session), &bytes))
        endpoint.error = GetLastError() ? GetLastError() : ERROR_INVALID_SID;
    CloseHandle(token);
    if (!endpoint.error) endpoint.name = L"\\\\.\\pipe\\CapsLang." + instance + L"." +
        std::to_wstring(endpoint.session) + L"." + endpoint.sid;
    return endpoint;
}
struct MessageServer::Impl {
    Endpoint endpoint;
    Handler handler;
    DWORD requestBytes, responseBytes;
    HANDLE thread = nullptr, ready = nullptr, stop = nullptr;
    std::atomic<DWORD> error{0};
    std::atomic<bool> listening{false};
    Impl(Endpoint value, DWORD request, DWORD response, Handler fn)
        : endpoint(std::move(value)), handler(std::move(fn)), requestBytes(request), responseBytes(response) {}
    static DWORD WINAPI Run(void* param) {
        auto& self = *static_cast<Impl*>(param);
        const std::wstring sddl = L"D:P(A;;GA;;;SY)(A;;GRGW;;;" + self.endpoint.sid + L")S:(ML;;NW;;;ME)";
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) {
            self.error = GetLastError(); SetEvent(self.ready); return 1;
        }
        SECURITY_ATTRIBUTES sa{sizeof(sa), descriptor, FALSE};
        const HANDLE pipe = CreateNamedPipeW(self.endpoint.name.c_str(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1, self.responseBytes, self.requestBytes, 1000, &sa);
        const DWORD createError = pipe == INVALID_HANDLE_VALUE ? GetLastError() : 0;
        LocalFree(descriptor);
        if (createError) { self.error = createError; SetEvent(self.ready); return 2; }
        self.listening = true; SetEvent(self.ready);
        while (WaitForSingleObject(self.stop, 0) != WAIT_OBJECT_0) {
            OVERLAPPED connection{};
            connection.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (!connection.hEvent) { self.error = GetLastError(); break; }
            const BOOL connected = ConnectNamedPipe(pipe, &connection);
            DWORD error = connected ? 0 : GetLastError(), bytes = 0;
            bool success = connected || error == ERROR_PIPE_CONNECTED;
            if (error == ERROR_IO_PENDING) success = FinishIo(pipe, connection, self.stop, INFINITE, bytes, error);
            CloseHandle(connection.hEvent);
            if (success) {
                std::vector<BYTE> request(self.requestBytes), response(self.responseBytes);
                if (Transfer(pipe, request.data(), self.requestBytes, false, self.stop, error) && ClientMatches(pipe,self.endpoint)) {
                    bool handled = false;
                    try { self.handler(request.data(),response.data()); handled = true; }
                    catch (...) { /* Fail closed: no incomplete handler output. */ }
                    if (handled) Transfer(pipe, response.data(), self.responseBytes, true, self.stop, error);
                    // Wait for the client to finish reading by having it send a
                    // fixed acknowledgement. No unbounded FlushFileBuffers.
                    std::uint64_t ack = 0;
                    if (handled) Transfer(pipe, &ack, sizeof(ack), false, self.stop, error);
                }
                SecureZeroMemory(request.data(),request.size());
                SecureZeroMemory(response.data(),response.size());
            }
            DisconnectNamedPipe(pipe);
        }
        self.listening = false; CloseHandle(pipe); return 0;
    }
};
MessageServer::MessageServer(Endpoint endpoint, DWORD request, DWORD response, Handler handler)
    : impl_(std::make_unique<Impl>(std::move(endpoint),request,response,std::move(handler))) {}
MessageServer::~MessageServer() { Stop(); }
bool MessageServer::Start() {
    auto& self = *impl_;
    if (self.thread) return self.listening;
    if (self.endpoint.error || self.endpoint.name.empty() || !self.handler ||
        !self.endpoint.clientProcess.CompleteOrEmpty() || !self.endpoint.serverProcess.CompleteOrEmpty() ||
        !self.requestBytes || self.requestBytes > 8192 || !self.responseBytes || self.responseBytes > 8192) {
        self.error = ERROR_INVALID_PARAMETER; return false;
    }
    self.error = 0;
    self.ready = CreateEventW(nullptr, TRUE, FALSE, nullptr); self.stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!self.ready || !self.stop) { self.error = GetLastError(); Stop(); return false; }
    self.thread = CreateThread(nullptr, 0, Impl::Run, &self, 0, nullptr);
    if (!self.thread) { self.error = GetLastError(); Stop(); return false; }
    return WaitForSingleObject(self.ready, 3000) == WAIT_OBJECT_0 && self.listening;
}
void MessageServer::Stop() {
    auto& self = *impl_;
    if (self.stop) SetEvent(self.stop);
    if (self.thread) { WaitForSingleObject(self.thread, INFINITE); CloseHandle(self.thread); self.thread = nullptr; }
    if (self.ready) { CloseHandle(self.ready); self.ready = nullptr; }
    if (self.stop) { CloseHandle(self.stop); self.stop = nullptr; }
}
DWORD MessageServer::Error() const { return impl_->error; }
bool Exchange(const Endpoint& endpoint, const std::wstring& path, bool high,
              const void* request, DWORD requestBytes, void* response, DWORD responseBytes, DWORD& error,
              ProcessIdentity* authenticatedServer) {
    if (authenticatedServer) *authenticatedServer = {};
    if (endpoint.error || endpoint.name.empty() || !request || !response || !requestBytes || requestBytes > 8192 ||
        !responseBytes || responseBytes > 8192 || !endpoint.clientProcess.CompleteOrEmpty() ||
        !endpoint.serverProcess.CompleteOrEmpty()) { error = ERROR_INVALID_PARAMETER; return false; }
    HANDLE pipe = CreateFileW(endpoint.name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
    if (pipe == INVALID_HANDLE_VALUE && GetLastError() == ERROR_PIPE_BUSY && WaitNamedPipeW(endpoint.name.c_str(), 500))
        pipe = CreateFileW(endpoint.name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) { error = GetLastError(); return false; }
    bool ok = false;
    ProcessIdentity serverIdentity;
    DWORD mode = PIPE_READMODE_MESSAGE;
    if (!ServerMatches(pipe, endpoint, path, high, serverIdentity)) error = ERROR_ACCESS_DENIED;
    else if (!SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr)) error = GetLastError();
    else {
        std::vector<BYTE> outgoing(static_cast<const BYTE*>(request),static_cast<const BYTE*>(request)+requestBytes), incoming(responseBytes);
        if (Transfer(pipe, outgoing.data(), requestBytes, true, nullptr, error) &&
            Transfer(pipe, incoming.data(), responseBytes, false, nullptr, error)) {
            std::uint64_t ack = 1;
            Transfer(pipe, &ack, sizeof(ack), true, nullptr, error);
            memcpy(response,incoming.data(),responseBytes); error = 0; ok = true;
        }
        SecureZeroMemory(outgoing.data(),outgoing.size()); SecureZeroMemory(incoming.data(),incoming.size());
    }
    CloseHandle(pipe);
    if (ok && authenticatedServer) *authenticatedServer = serverIdentity;
    return ok;
}
Server::Server(Endpoint endpoint, Handler handler)
    : transport_(std::move(endpoint),sizeof(Request),sizeof(Response),[handler=std::move(handler)](const void* input, void* output) {
        Request request{}; memcpy(&request,input,sizeof(request)); Response response{};
        if (!Valid(request)) response.error = ERROR_INVALID_DATA;
        else if (!handler) response.error = ERROR_INVALID_PARAMETER;
        else {
            try { response = handler(request); }
            catch (...) { response = {}; response.error = ERROR_UNHANDLED_EXCEPTION; }
        }
        response.magic = kMagic; response.version = kVersion; response.id = request.id;
        memcpy(output,&response,sizeof(response));
    }) {}
Server::~Server() = default;
bool Server::Start() { return transport_.Start(); }
void Server::Stop() { transport_.Stop(); }
DWORD Server::Error() const { return transport_.Error(); }
bool Call(const Endpoint& endpoint, const std::wstring& path, bool high, const Request& request, Response& response, DWORD& error) {
    if (!Valid(request)) { error = ERROR_INVALID_PARAMETER; return false; }
    Response incoming{};
    if (!Exchange(endpoint,path,high,&request,sizeof(request),&incoming,sizeof(incoming),error)) return false;
    if (incoming.magic != kMagic || incoming.id != request.id) { error = ERROR_INVALID_DATA; return false; }
    if (incoming.version != kVersion) { error = ERROR_REVISION_MISMATCH; return false; }
    response = incoming; error = 0; return true;
}
bool InstallationCall(const Endpoint& endpoint, const std::wstring& path, const Request& request,
                      Response& response, DWORD& error) {
    if ((request.operation != Operation::Status && request.operation != Operation::Stop) || !Valid(request)) {
        error = ERROR_INVALID_PARAMETER; return false;
    }
    if (Call(endpoint,path,true,request,response,error)) return true;
    if (error != ERROR_REVISION_MISMATCH) return false;
    auto legacy = request; legacy.version = 3;
    Response incoming;
    if (!Exchange(endpoint,path,true,&legacy,sizeof(legacy),&incoming,sizeof(incoming),error)) return false;
    if (incoming.magic != kMagic || incoming.version != 3 || incoming.id != request.id) { error = ERROR_REVISION_MISMATCH; return false; }
    response = incoming; error = incoming.error; return !error;
}
} // namespace capslang::ipc
