#pragma once
#include "../platform/windows_support.hpp"
#include "../core/layout.hpp"
#include "profile_host.hpp"
#include <memory>
#include <functional>

namespace capslang {
struct EngineStatus {
    core::Language target = core::Language::Unknown, actual = core::Language::Unknown;
    core::ApplyState apply = core::ApplyState::Idle;
    std::uint64_t generation = 0, userRevision = 0, recoveries = 0, lastRecovery = 0;
    std::uint64_t lastPhysicalInput = 0, lastInjectedKeyInput = 0;
    std::uint64_t activitySerial = 0, lastRecipientInput = 0;
    DWORD mwbError = ERROR_NOT_READY;
    bool mwbRunning = false, recipientAvailable = false;
    DWORD hookError = 0, powerError = 0, sessionError = 0, layoutError = 0;
    bool elevated = false, hookRegistered = false, hookThreadResponsive = false, locked = false;
    LANGID profileLanguage = 0;
    DWORD profileError = ERROR_NOT_READY;
    std::uint64_t profileGeneration = 0;
    bool profileConfirmed = false, systemEnabled = false;
    bool targetThreadProfile = false;
};
struct EngineOptions {
    struct CapsBatch {
        DWORD error = ERROR_NOT_READY;
        std::uint64_t heartbeat = 0, recoveries = 0;
        unsigned count = 0;
        std::uint64_t stamps[8]{};
    };
    // Test dependency supplied by code, not by CLI or IPC. Default uses the
    // foreground target. It cannot be set by a lower-privileged external client.
    LayoutTarget (*capture)() = CaptureLayoutTarget;
    // Fixed local privileged layout channel, selected by installed entry point.
    // Never invoked from a hook. Portable/test engines do not use SYSTEM.
    std::function<DWORD(LANGID)> systemApply{};
    bool requireDesktopProfile = false;
    // Selected by trusted startup code from this EXE's embedded bundle.
    // Empty retains the legacy diagnostic engine, not an automatic fallback.
    std::wstring profileModule{};
    std::function<ProfileHost::Sample(const LayoutTarget&, LANGID, std::uint64_t)> systemProfile{};
    std::function<void()> releaseSystemProfile{};
    // Trusted installed startup selects the sole SYSTEM CapsLock owner. This
    // is never selectable by peer messages or lower-privileged clients.
    std::function<CapsBatch()> systemCaps{};
};

class Engine {
public:
    explicit Engine(EngineOptions options = {});
    ~Engine();
    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;
    bool Start();
    void Stop();
    bool SetTarget(core::Language language);
    // Queue an absolute peer update conditional on the local revision observed
    // by the broker. The worker compares it immediately before applying.
    bool SetTargetIfRevision(core::Language language, std::uint64_t expectedUserRevision);
    bool RestartHook();
    bool ProfileReport(LANGID language, std::uint64_t generation, DWORD error, bool manual);
    EngineStatus Status() const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace capslang
