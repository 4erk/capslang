#pragma once
#include "windows_support.hpp"

namespace capslang {
// Evidence about MWB's routing UI, NOT a source of user activity by itself.
// Unknown never means that this machine is the recipient.
enum class MwbRoute { Unknown, LocalCandidate, RemoteCandidate };
struct MwbSettings {
    bool known = false, maintenanceInput = true, hideCursor = false, relativeMouse = false;
    DWORD error = 0;
};
// Reads only selected booleans, does not log/retain unrelated values or write
// PowerToys settings. Call off the hook/layout threads.
MwbSettings ReadMwbSettings(const std::wstring& path);
struct MwbEvidence {
    MwbRoute route = MwbRoute::Unknown;
    unsigned applications = 0, helpers = 0, dots = 0;
    bool supportedBinary = false, dotVisible = false;
    DWORD error = 0;
    MwbSettings settings;
    HWND dotWindow = nullptr;
    DWORD helperPid = 0;
    bool RecipientObservationAllowed() const {
        return applications && helpers == 1 && supportedBinary && dots == 1 &&
            settings.known && !settings.maintenanceInput && settings.hideCursor && !settings.error && !error;
    }
};
class MwbObserver {
public:
    MwbEvidence Read();
private:
    DWORD helperPid_ = 0;
    ULONGLONG nextDiscovery_ = 0;
    ULONGLONG nextSettings_ = 0;
    MwbSettings settings_;
    MwbEvidence discovered_;
};
} // namespace capslang
