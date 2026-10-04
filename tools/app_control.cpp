// Local acceptance helper, not part of the release. Invitation output is
// secret and must not be copied into logs, diagnostics or publication assets.
#include "../src/app/control.hpp"
#include "../src/app/paths.hpp"
#include <iomanip>
#include <iostream>
#include <sstream>
using namespace capslang;
std::string Hex(const net::Pin &pin) {
    std::ostringstream out;
    for (auto b : pin)
        out << std::hex << std::setw(2) << std::setfill('0') << unsigned(b);
    return out.str();
}
int main(int argc, char **argv) {
    if (argc < 2)
        return ERROR_INVALID_PARAMETER;
    DWORD error = 0;
    const auto path = app::InstalledExecutable(error);
    if (path.empty() || !app::ProtectedExecutable(path, error))
        return int(error);
    app::ControlRequest request;
    request.id = GetTickCount64() + 1;
    const std::string mode = argv[1];
    if (mode == "pairing")
        request.command = app::Command::Pairing;
    else if (mode == "invite" && argc == 3) {
        request.command = app::Command::Invite;
        request.port = 42519;
        if (strlen(argv[2]) >= sizeof(request.text))
            return ERROR_INVALID_PARAMETER;
        strcpy(request.text, argv[2]);
    } else if (mode == "join" && argc == 2) {
        request.command = app::Command::Join;
        std::string code;
        std::getline(std::cin, code);
        if (code.size() >= sizeof(request.text))
            return ERROR_INVALID_PARAMETER;
        memcpy(request.text, code.data(), code.size());
        SecureZeroMemory(code.data(), code.size());
    } else if (mode == "confirm" && argc == 4) {
        request.command = app::Command::Confirm;
        request.allow = 1;
        request.ticket = std::stoull(argv[2]);
        std::string pin = argv[3];
        if (pin.size() != 64)
            return ERROR_INVALID_PARAMETER;
        for (size_t i = 0; i < 32; i++)
            request.peer[i] = static_cast<BYTE>(std::stoul(pin.substr(i * 2, 2), nullptr, 16));
    } else if (mode != "status")
        return ERROR_INVALID_PARAMETER;
    app::ControlResponse response;
    const bool ok = ipc::Exchange(ipc::Endpoint::Current(L"1.1-ui"), path, false, &request,
                                  sizeof(request), &response, sizeof(response), error);
    SecureZeroMemory(&request, sizeof(request));
    if (!ok) {
        std::cout << "{\"error\":" << error << "}\n";
        return int(error);
    }
    if (response.magic != app::kControlMagic || response.version != app::kControlVersion)
        return ERROR_INVALID_DATA;
    std::cout << "{\"error\":" << response.error << ",\"phase\":" << response.status.networkPhase
              << ",\"command_error\":" << response.status.commandError;
    if (mode == "pairing") {
        // Invitation alphabet is fixed by the application (no JSON escapes).
        std::cout << ",\"local\":\"" << Hex(response.local) << "\",\"peer\":\""
                  << Hex(response.peer) << "\",\"pending\":\"" << Hex(response.pending)
                  << "\",\"ticket\":" << response.ticket << ",\"invitation\":\""
                  << response.invitation << "\"";
    }
    std::cout << "}\n";
    const int result = int(response.error);
    SecureZeroMemory(&response, sizeof(response));
    return result;
}
