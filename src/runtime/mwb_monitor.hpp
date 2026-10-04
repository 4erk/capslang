#pragma once
#include "../platform/mwb.hpp"
#include <functional>
#include <memory>

namespace capslang {
struct MwbSnapshot {
    MwbEvidence evidence;
    ULONGLONG observedAt = 0, localSince = 0;
    bool responsive = false;
    DWORD error = ERROR_NOT_READY;
};
// Discovery, Authenticode and settings reads must never run on the hook or
// layout thread. A stuck OS/file operation retains at most one owned context.
class MwbMonitor {
public:
    using Operation = std::function<MwbEvidence()>; // Code-only test dependency.
    MwbMonitor() = default;
    ~MwbMonitor();
    MwbMonitor(const MwbMonitor&) = delete;
    MwbMonitor& operator=(const MwbMonitor&) = delete;
    bool Start(Operation operation = {});
    MwbSnapshot Status() const;
    bool Stop(DWORD graceMs = 500);
    DWORD Error() const { return error_; }
private:
    struct Shared;
    std::shared_ptr<Shared> shared_;
    HANDLE thread_ = nullptr;
    DWORD error_ = 0;
};
} // namespace capslang
