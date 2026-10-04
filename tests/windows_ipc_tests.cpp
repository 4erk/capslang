#include "../src/runtime/local_ipc.hpp"
#include <atomic>
#include <cstdio>
#include <array>

using namespace capslang;
using namespace capslang::ipc;
namespace {
unsigned checks = 0, failures = 0;
void Check(bool value, const char* name) {
    ++checks;
    if (!value) { ++failures; std::printf("FAIL %s error=%lu\n", name, GetLastError()); }
}
HANDLE Open(const Endpoint& endpoint) {
    HANDLE pipe = CreateFileW(endpoint.name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
        OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
    if (pipe == INVALID_HANDLE_VALUE && GetLastError() == ERROR_PIPE_BUSY && WaitNamedPipeW(endpoint.name.c_str(), 1500))
        pipe = CreateFileW(endpoint.name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
            OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
    if (pipe != INVALID_HANDLE_VALUE) { DWORD mode = PIPE_READMODE_MESSAGE; SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr); }
    return pipe;
}
bool Malformed(const Endpoint& endpoint, const Request& request) {
    HANDLE pipe = Open(endpoint);
    if (pipe == INVALID_HANDLE_VALUE) return false;
    DWORD bytes = 0;
    Response response{};
    bool rejected = WriteFile(pipe, &request, sizeof(request), &bytes, nullptr) &&
        ReadFile(pipe, &response, sizeof(response), &bytes, nullptr) &&
        bytes == sizeof(response) && response.error == ERROR_INVALID_DATA;
    std::uint64_t ack = request.id;
    WriteFile(pipe, &ack, sizeof(ack), &bytes, nullptr);
    CloseHandle(pipe); return rejected;
}
bool BadLength(const Endpoint& endpoint, DWORD length) {
    HANDLE pipe = Open(endpoint);
    if (pipe == INVALID_HANDLE_VALUE) return false;
    std::array<BYTE, 64> data{};
    DWORD bytes = 0;
    const BOOL written = WriteFile(pipe, data.data(), length, &bytes, nullptr);
    Response response{};
    const BOOL read = ReadFile(pipe, &response, sizeof(response), &bytes, nullptr);
    const DWORD error = read ? 0 : GetLastError();
    CloseHandle(pipe);
    return written && !read && (error == ERROR_BROKEN_PIPE || error == ERROR_PIPE_NOT_CONNECTED);
}
}
int main() {
    const auto endpoint = Endpoint::Current(L"test-" + std::to_wstring(GetCurrentProcessId()));
    Check(!endpoint.error && !endpoint.name.empty(), "SID/session-specific endpoint");
    Check(Endpoint::Current(L"../invalid").error == ERROR_INVALID_PARAMETER, "endpoint traversal refused");
    std::atomic<unsigned> calls{0};
    auto handle = [&](const Request& request) {
        ++calls;
        Response response{};
        response.target = request.operation == Operation::SetLayout ? request.language : kEnglish;
        return response;
    };
    Server server(endpoint, handle);
    Check(server.Start(), "server starts");
    {
        Server duplicate(endpoint, handle);
        Check(!duplicate.Start() && duplicate.Error() == ERROR_ACCESS_DENIED, "first-instance flag rejects pipe collision");
    }
    wchar_t path[32768]{}; GetModuleFileNameW(nullptr, path, ARRAYSIZE(path));
    DWORD error = 0;
    Response response{};
    Request request{}; request.id = 1;
    for (int i = 0; i < 40; ++i) {
        ++request.id;
        Check(Call(endpoint, path, false, request, response, error) && !response.error &&
            response.target == kEnglish && response.id == request.id, "real request/response with identity validation");
    }
    const auto before = calls.load();
    Check(!Call(endpoint, L"C:\\wrong\\program.exe", false, request, response, error) && error == ERROR_ACCESS_DENIED,
          "client rejects wrong server executable");
    if (!ProcessElevation(GetCurrentProcessId()).elevated)
        Check(!Call(endpoint, path, true, request, response, error) && error == ERROR_ACCESS_DENIED,
              "medium server cannot masquerade as elevated engine");
    auto wrongSession = endpoint; ++wrongSession.session;
    Check(!Call(wrongSession, path, false, request, response, error) && error == ERROR_ACCESS_DENIED,
          "server in different claimed session rejected");
    Check(calls == before, "untrusted server checks precede request delivery");
    auto wrongServerSid = endpoint; wrongServerSid.serverSid = L"S-1-5-18";
    Check(!Call(wrongServerSid, path, false, request, response, error) && error == ERROR_ACCESS_DENIED,
          "ordinary process cannot impersonate SYSTEM endpoint");
    auto bad = request; bad.magic ^= 1;
    Check(Malformed(endpoint, bad), "bad magic refused by actual server");
    bad = request; ++bad.version;
    Check(Malformed(endpoint, bad), "unknown protocol version refused");
    bad = request; bad.operation = static_cast<Operation>(1000);
    Check(Malformed(endpoint, bad), "arbitrary operation refused");
    bad = request; bad.language = 0x0407;
    Check(Malformed(endpoint, bad), "unexpected status payload refused");
    bad = request; bad.operation = Operation::SetLayout; bad.language = 0x10409;
    Check(Malformed(endpoint, bad), "truncated language attack refused");
    bad = request; bad.reserved = 1;
    Check(Malformed(endpoint, bad), "unknown flags refused");
    bad = request; bad.engineEpoch = 1;
    Check(Malformed(endpoint, bad), "status refuses an unexpected engine epoch");
    bad = request; bad.expectedRevision = 1;
    Check(Malformed(endpoint, bad), "status refuses an unexpected intent revision");
    bad = request; bad.operation = Operation::SetLayoutIfRevision; bad.language = kEnglish;
    Check(Malformed(endpoint, bad), "conditional update requires nonzero engine epoch");
    bad = request; bad.operation = Operation::ReportProfile; bad.language = kEnglish;
    Check(Malformed(endpoint, bad), "profile report requires an engine incarnation");
    bad.engineEpoch = 1; bad.language = 0;
    Check(Malformed(endpoint, bad), "unknown profile cannot be reported as successful");
    bad.language = kEnglish; bad.reserved = ERROR_ACCESS_DENIED;
    Check(Malformed(endpoint, bad), "successful profile and failure are mutually exclusive");
    bad.language = 0; bad.reserved = UINT64_MAX;
    Check(Malformed(endpoint, bad), "profile error is bounded to DWORD");
    bad.operation = Operation::ManualProfile; bad.language = kEnglish; bad.reserved = 1;
    Check(Malformed(endpoint, bad), "manual choice rejects hidden operation payload");
    Check(BadLength(endpoint, 8), "short frame disconnected");
    Check(BadLength(endpoint, 64), "oversized frame disconnected");
    Check(calls == before, "malformed requests never invoke handler");
    Request profile;
    profile.id = 900; profile.operation = Operation::ReportProfile;
    profile.engineEpoch = 1; profile.expectedRevision = 2; profile.language = kRussian;
    Check(Call(endpoint,path,false,profile,response,error), "well-formed generation-bound profile report accepted");
    profile.language = 0; profile.reserved = ERROR_NOT_READY;
    Check(Call(endpoint,path,false,profile,response,error), "explicit profile failure accepted without fictitious language");
    profile.operation = Operation::ManualProfile; profile.language = kEnglish; profile.reserved = 0;
    Check(Call(endpoint,path,false,profile,response,error), "well-formed manual profile choice accepted");
    HANDLE anonymous = INVALID_HANDLE_VALUE;
    const bool impersonated = ImpersonateAnonymousToken(GetCurrentThread()) != FALSE;
    DWORD anonymousError = 0;
    if (impersonated) {
        anonymous = CreateFileW(endpoint.name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
            SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
        anonymousError = anonymous == INVALID_HANDLE_VALUE ? GetLastError() : 0;
        if (!RevertToSelf()) return 10;
    }
    if (anonymous != INVALID_HANDLE_VALUE) CloseHandle(anonymous);
    Check(impersonated && anonymous == INVALID_HANDLE_VALUE && anonymousError == ERROR_ACCESS_DENIED,
          "real anonymous SID denied by pipe DACL");
    HANDLE idle = Open(endpoint);
    Check(idle != INVALID_HANDLE_VALUE, "idle hostile client connected");
    const auto start = GetTickCount64();
    // An ordinary call has a 500ms connection budget and can legitimately
    // time out before the hostile client's 1s read budget expires.
    bool afterIdle = Call(endpoint, path, false, request, response, error);
    if (!afterIdle && error == ERROR_SEM_TIMEOUT) afterIdle = Call(endpoint, path, false, request, response, error);
    if (!afterIdle && error == ERROR_SEM_TIMEOUT) afterIdle = Call(endpoint, path, false, request, response, error);
    Check(afterIdle && !response.error, "idle client times out and next valid client is served");
    Check(GetTickCount64() - start < 2000, "idle client cannot block engine indefinitely");
    if (idle != INVALID_HANDLE_VALUE) CloseHandle(idle);
    request.operation = Operation::SetLayout; request.language = kRussian; ++request.id;
    Check(Call(endpoint, path, false, request, response, error) && response.target == kRussian,
          "only absolute supported language operation reaches handler");
    const auto stop = GetTickCount64(); server.Stop();
    Check(GetTickCount64() - stop < 1500, "server shutdown cancels pending connection");
    Check(!Call(endpoint, path, false, request, response, error), "stopped server cannot answer");
    Check(server.Start(), "server restart releases first-instance ownership");
    server.Stop();
    {
        auto guarded = endpoint; guarded.clientImage = L"C:\\not-this-client.exe";
        Server guard(guarded, handle); Check(guard.Start(), "image-authenticated endpoint starts");
        Check(!Call(endpoint,path,false,request,response,error), "same-user wrong client image refused");
        guard.Stop();
        guarded.clientImage = path;
        Server allowed(guarded, handle); Check(allowed.Start(), "exact-image endpoint starts");
        Check(Call(endpoint,path,false,request,response,error), "exact image and SID client accepted");
        allowed.Stop();
        if (!ProcessElevation(GetCurrentProcessId()).elevated) {
            guarded.requireClientElevation = true;
            Server highOnly(guarded, handle); Check(highOnly.Start(), "elevated-only endpoint starts");
            Check(!Call(endpoint,path,false,request,response,error), "medium same-image client refused at privileged endpoint");
            highOnly.Stop();
        }
    }
    {
        MessageServer tooLarge(endpoint,8193,16,[](const void*,void*){});
        Check(!tooLarge.Start() && tooLarge.Error()==ERROR_INVALID_PARAMETER,"generic local messages enforce 8KiB maximum");
        MessageServer zero(endpoint,0,16,[](const void*,void*){});
        Check(!zero.Start(),"generic local messages reject zero size");
    }
    {
        MessageServer throwing(endpoint,sizeof(Request),sizeof(Response),[](const void*,void*){throw 1;});
        Check(throwing.Start(),"exception fixture starts");
        Check(!Call(endpoint,path,false,request,response,error),"throwing handler cannot publish partial or uninitialized response");
        throwing.Stop();
    }
    std::printf("Windows IPC: %u checks, %u failures; no hooks, layout changes or install.\n", checks, failures);
    return failures ? 1 : 0;
}
