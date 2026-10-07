#pragma once
#include <windows.h>
#include <msctf.h>
#include <cstdint>

namespace capslang {
// This component runs on the HOST application's input thread, never on the
// CapsLang broker's thread. It contains no hooks, transport, input synthesis,
// file access or network access. The owner must detach it on that same thread
// before unloading the module containing its code.
class ThreadProfile {
public:
    enum class Cause : std::uint32_t { Baseline, OwnRequest, Observed };
    struct Event {
        std::uint64_t serial = 0, generation = 0;
        LANGID language = 0;
        Cause cause = Cause::Observed;
        std::uint64_t occurred = 0;
    };
    struct Result {
        HRESULT error = E_PENDING;
        LANGID actual = 0, profile = 0;
        std::uint64_t generation = 0;
        ULONGLONG sampled = 0;
    };
    // Callback must be bounded, nonblocking and nonthrowing. Observed is NOT
    // synonymous with manual intent: focus/origin arbitration belongs to the
    // controller. A callback is never proof of successful application.
    using Notify = void (*)(void*, const Event&) noexcept;
    using GetManager = HRESULT (WINAPI*)(ITfThreadMgr**);
    // The installed module may own a balanced TSF client when a legacy host
    // has none. Observers/diagnostics default to not initializing their host.
    explicit ThreadProfile(Notify notify, void* context, GetManager get = nullptr,
        bool prepareClient = false, bool desktopScope = false);
    ~ThreadProfile();
    ThreadProfile(const ThreadProfile&) = delete;
    ThreadProfile& operator=(const ThreadProfile&) = delete;
    HRESULT Bind();
    HRESULT Unbind();
    Result Read();
    // Absolute EN/RU only. Newer generations supersede earlier commands even
    // during a reentrant COM call. Installed peers request desktop-wide profile
    // activation; standalone observers default to thread scope. No synthetic input.
    Result Apply(LANGID language, std::uint64_t generation);
private:
    struct Impl;
    Impl* impl_;
};
} // namespace capslang
