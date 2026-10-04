#pragma once
#include "../platform/windows_support.hpp"
#include "../core/keyboard.hpp"
#include <functional>

namespace capslang {
struct LedStatus {
    unsigned written = 0, unsupported = 0;
    DWORD error = ERROR_NOT_READY;
    bool responsive = false;
};
// Driver calls never run on the layout or hook thread. A driver ignoring
// cancellation may retain ONE owned worker/context, but cannot block shutdown
// of the layout engine or trigger an unbounded accumulation of new workers.
class LedWorker {
public:
    using Operation = std::function<LedStatus(core::Language, bool)>; // Test-only code dependency; never IPC/CLI.
    LedWorker() = default;
    ~LedWorker();
    LedWorker(const LedWorker&) = delete;
    LedWorker& operator=(const LedWorker&) = delete;
    bool Start(Operation operation = {});
    void Target(core::Language language);
    void Rediscover();
    LedStatus Status() const;
    bool Stop(DWORD graceMs = 500);
    DWORD Error() const { return error_; }
private:
    struct Shared;
    std::shared_ptr<Shared> shared_;
    HANDLE thread_ = nullptr;
    DWORD error_ = 0;
};
} // namespace capslang
