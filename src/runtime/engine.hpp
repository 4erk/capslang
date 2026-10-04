#pragma once
#include "../platform/windows_support.hpp"
#include "../core/layout.hpp"
#include "led_worker.hpp"
#include <memory>

namespace capslang {
struct EngineStatus {
    core::Language target = core::Language::Unknown, actual = core::Language::Unknown;
    core::ApplyState apply = core::ApplyState::Idle;
    std::uint64_t generation = 0, userRevision = 0, recoveries = 0, lastRecovery = 0;
    std::uint64_t lastPhysicalInput = 0, lastInjectedKeyInput = 0;
    DWORD hookError = 0, powerError = 0, sessionError = 0, layoutError = 0, ledError = 0;
    unsigned ledWritten = 0, ledUnsupported = 0;
    bool elevated = false, hookRegistered = false, hookThreadResponsive = false, locked = false;
};
struct EngineOptions {
    bool hardwareLeds = true;
    // Test dependency supplied by code, not by CLI or IPC. Default uses the
    // foreground target. It cannot be set by a lower-privileged external client.
    LayoutTarget (*capture)() = CaptureLayoutTarget;
    LedWorker::Operation ledOperation{};
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
    EngineStatus Status() const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace capslang
