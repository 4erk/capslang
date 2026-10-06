#pragma once
#include "../platform/windows_support.hpp"
#include <cstdint>
#include <functional>
#include <memory>

namespace capslang::ipc {
constexpr std::uint32_t kMagic = 0x314c5043, kVersion = 4;
enum class Operation : std::uint32_t {
    Status = 1, SetLayout = 2, RefreshHook = 3, Stop = 4, SetLayoutIfRevision = 5,
    ReportProfile = 6, ManualProfile = 7
};
enum StatusFlag : std::uint32_t {
    Elevated = 1U, HookRegistered = 2U, HookResponsive = 4U, Locked = 8U,
    ProfileConfirmed = 16U, SystemEnabled = 32U, TargetThreadProfile = 64U
};
enum MwbFlag : std::uint32_t { MwbRunning = 1U, RecipientAvailable = 2U };
#pragma pack(push, 1)
struct Request {
    std::uint32_t magic = kMagic, version = kVersion;
    Operation operation = Operation::Status;
    std::uint32_t language = 0;
    std::uint64_t id = 0, reserved = 0;
    // Conditional update binds both the engine incarnation and local intent.
    // Profile operations bind expectedRevision to the request generation.
    // All remaining operations require zero in both fields.
    std::uint64_t engineEpoch = 0, expectedRevision = 0;
};
struct Response {
    std::uint32_t magic = kMagic, version = kVersion;
    std::uint64_t id = 0;
    std::uint32_t error = 0, target = 0, actual = 0, apply = 0, flags = 0;
    std::uint32_t hookError = 0, layoutError = 0;
    std::uint32_t profileError = 0;
    std::uint64_t generation = 0, revision = 0, recovery = 0;
    // Same offsets as v3; the installer fallback never interprets these fields.
    std::uint64_t profileLanguage = 0, profileGeneration = 0;
    std::uint64_t engineEpoch = 0;
    std::uint64_t activitySerial = 0, activityAge = UINT64_MAX;
    std::uint32_t mwbFlags = 0, mwbError = 0;
};
#pragma pack(pop)
static_assert(sizeof(Request) == 48 && sizeof(Response) == 120, "fixed wire ABI v4, v3 sizes retained for installer");
bool Valid(const Request& request);
// Optional local-code pin for a particular process incarnation. PID alone is
// insufficient after exit/reuse. Neither field comes from a peer's claim.
struct ProcessIdentity {
    DWORD id = 0;
    std::uint64_t created = 0;
    bool CompleteOrEmpty() const { return (id == 0) == (created == 0); }
};
bool IdentifyProcess(HANDLE process, ProcessIdentity& identity);
struct Endpoint {
    std::wstring name, sid;
    DWORD session = 0, error = 0;
    // Optional stricter trust policy selected by local code, never wire data.
    // sid always identifies the allowed client; serverSid may be SYSTEM.
    std::wstring serverSid, clientImage;
    bool requireClientElevation = false;
    ProcessIdentity clientProcess{}, serverProcess{};
    static Endpoint Current(const std::wstring& instance = L"1.1");
};
// Fixed-size local messages share authentication, limits and cancellation.
// Each protocol MUST validate its own magic/version/operations in the handler.
// Never use this as arbitrary file, command or input forwarding.
class MessageServer {
public:
    using Handler = std::function<void(const void*, void*)>;
    MessageServer(Endpoint endpoint, DWORD requestBytes, DWORD responseBytes, Handler handler);
    ~MessageServer();
    MessageServer(const MessageServer&) = delete;
    MessageServer& operator=(const MessageServer&) = delete;
    bool Start();
    void Stop();
    DWORD Error() const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
bool Exchange(const Endpoint& endpoint, const std::wstring& expectedServerPath,
              bool requireElevation, const void* request, DWORD requestBytes,
              void* response, DWORD responseBytes, DWORD& error, ProcessIdentity* authenticatedServer = nullptr);
class Server {
public:
    using Handler = std::function<Response(const Request&)>;
    Server(Endpoint endpoint, Handler handler);
    ~Server();
    bool Start();
    void Stop();
    DWORD Error() const;
private:
    MessageServer transport_;
};
// The application passes the protected installed EXE path and requires an
// elevated server. Tests may explicitly use their own EXE and medium token.
// No trust decision is supplied by data received from the server itself.
bool Call(const Endpoint& endpoint, const std::wstring& expectedServerPath,
          bool requireElevation, const Request& request, Response& response, DWORD& error);
// Only installer lifecycle uses v3 fallback; never layout/synchronization.
bool InstallationCall(const Endpoint&, const std::wstring&, const Request&, Response&, DWORD&);
} // namespace capslang::ipc
