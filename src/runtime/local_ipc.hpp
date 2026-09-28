#pragma once
#include "../platform/windows_support.hpp"
#include <cstdint>
#include <functional>
#include <memory>

namespace capslang::ipc {
constexpr std::uint32_t kMagic = 0x314c5043, kVersion = 1;
enum class Operation : std::uint32_t { Status = 1, SetLayout = 2, RefreshHook = 3, Stop = 4 };
#pragma pack(push, 1)
struct Request {
    std::uint32_t magic = kMagic, version = kVersion;
    Operation operation = Operation::Status;
    std::uint32_t language = 0;
    std::uint64_t id = 0, reserved = 0;
};
struct Response {
    std::uint32_t magic = kMagic, version = kVersion;
    std::uint64_t id = 0;
    std::uint32_t error = 0, target = 0, actual = 0, apply = 0, flags = 0;
    std::uint32_t hookError = 0, layoutError = 0, ledError = 0;
    std::uint64_t generation = 0, revision = 0, recovery = 0;
    std::uint64_t physicalAge = UINT64_MAX, injectedKeyAge = UINT64_MAX;
};
#pragma pack(pop)
static_assert(sizeof(Request) == 32 && sizeof(Response) == 88, "fixed wire ABI");
bool Valid(const Request& request);
struct Endpoint {
    std::wstring name, sid;
    DWORD session = 0, error = 0;
    static Endpoint Current(const std::wstring& instance = L"1.1");
};
class Server {
public:
    using Handler = std::function<Response(const Request&)>;
    Server(Endpoint endpoint, Handler handler);
    ~Server();
    bool Start();
    void Stop();
    DWORD Error() const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
// The application passes the protected installed EXE path and requires an
// elevated server. Tests may explicitly use their own EXE and medium token.
// No trust decision is supplied by data received from the server itself.
bool Call(const Endpoint& endpoint, const std::wstring& expectedServerPath,
          bool requireElevation, const Request& request, Response& response, DWORD& error);
} // namespace capslang::ipc
