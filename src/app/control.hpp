#pragma once
#include "../network/runtime.hpp"
#include "../runtime/local_ipc.hpp"

namespace capslang::app {
inline constexpr char kVersion[] = "1.1.0-dev";
constexpr std::uint32_t kControlMagic = 0x554c5043, kControlVersion = 1;
enum class Command : std::uint32_t {
    Status = 1,
    Show = 2,
    Refresh = 3,
    Stop = 4,
    Pairing = 5,
    Invite = 6,
    Join = 7,
    Confirm = 8,
    Unpair = 9
};
#pragma pack(push, 1)
struct ControlRequest {
    std::uint32_t magic = kControlMagic, version = kControlVersion;
    Command command = Command::Status;
    std::uint32_t port = 0;
    std::uint64_t id = 0, ticket = 0;
    net::Pin peer{};
    std::uint32_t allow = 0, reserved = 0;
    char text[384]{};
};
struct PublicStatus {
    std::uint64_t sampled = 0;
    std::uint32_t engineError = ERROR_NOT_READY, networkError = ERROR_NOT_READY, commandError = 0;
    ipc::Response engine{};
    std::uint32_t networkPhase = 0, paired = 0, listener = 0, peerApplied = 0, sharedTarget = 0;
    std::uint32_t lastNetworkError = 0;
    std::uint64_t lastNetworkErrorAt = 0;
};
struct ControlResponse {
    std::uint32_t magic = kControlMagic, version = kControlVersion;
    std::uint64_t id = 0;
    std::uint32_t error = 0;
    PublicStatus status{};
    // Only the explicit Pairing operation fills this section. Status, JSON,
    // logs and diagnostics have no invitation/secret fields at all.
    net::Pin local{}, peer{}, pending{};
    std::uint64_t ticket = 0;
    char invitation[384]{};
};
#pragma pack(pop)
static_assert(sizeof(ControlRequest) < 8192 && sizeof(ControlResponse) < 8192,
              "bounded control frames");
bool Valid(const ControlRequest &value);
ipc::Endpoint ControlEndpoint();
bool ControlCall(const std::wstring &executable, const ControlRequest &request,
                 ControlResponse &response, DWORD &error,
                 const ipc::Endpoint &endpoint = ControlEndpoint());
std::string StatusJson(const PublicStatus &value, std::uint64_t now);
std::wstring StatusText(const PublicStatus &value, std::uint64_t now);
const wchar_t *NetworkText(std::uint32_t phase);
const wchar_t *LanguageText(std::uint32_t language);
} // namespace capslang::app
