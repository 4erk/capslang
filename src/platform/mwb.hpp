#pragma once
#include "windows_support.hpp"

namespace capslang {
// Evidence about MWB's routing UI, NOT a source of user activity by itself.
// Unknown never means that this machine is the recipient.
enum class MwbRoute { Unknown, LocalCandidate, RemoteCandidate };
struct MwbEvidence {
    MwbRoute route = MwbRoute::Unknown;
    unsigned applications = 0, helpers = 0, dots = 0;
    bool supportedBinary = false, dotVisible = false;
    DWORD error = 0;
};
class MwbObserver {
public:
    MwbEvidence Read();
private:
    DWORD helperPid_ = 0;
    ULONGLONG nextDiscovery_ = 0;
    MwbEvidence discovered_;
};
} // namespace capslang
