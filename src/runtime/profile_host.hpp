#pragma once
#include "local_ipc.hpp"
#include "../core/profile_channel.hpp"
#include <array>
#include <memory>

namespace capslang {
inline std::wstring ProfileInstance(DWORD process, DWORD thread, std::uint64_t binding) {
    return L"profile-" + std::to_wstring(process) + L"-" + std::to_wstring(thread) + L"-" + std::to_wstring(binding);
}
// Authenticated fixed-operation host for ONE observed process/thread. Its I/O
// handler never calls a Windows language API or loads a module. Installation,
// same-bitness hook ownership and foreground arbitration remain the caller's
// responsibility. Start this before asking the module to connect.
class ProfileHost {
public:
    struct Sample {
        profile_channel::Report report{};
        DWORD error = ERROR_NOT_READY;
        ULONGLONG sampled = 0;
        bool confirmed = false;
        std::array<profile_channel::Event, 64> events{};
        std::size_t count = 0;
    };
    explicit ProfileHost(DWORD process, DWORD thread);
    ~ProfileHost();
    ProfileHost(const ProfileHost&) = delete;
    ProfileHost& operator=(const ProfileHost&) = delete;
    bool Start();
    void Stop();
    bool Request(LANGID language, std::uint64_t generation);
    bool Detach();
    Sample Take();
    ipc::Endpoint Endpoint() const;
    std::uint64_t Binding() const;
    DWORD Error() const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace capslang
