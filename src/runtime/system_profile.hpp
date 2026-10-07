#pragma once
#include "profile_host.hpp"
#include "../core/system_profile.hpp"

namespace capslang::system_profile {
// Fixed SYSTEM role, owned by the already authenticated console-user worker.
// It observes only SYSTEM-owned foreground threads on the permitted desktop.
class Server {
public:
    Server(std::wstring owner, DWORD session, std::function<bool()> desktopAllowed);
    ~Server();
    bool Start();
    void Stop();
    void CheckOwner();
    ULONGLONG BusySince() const;
    DWORD Error() const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
// Elevated ordinary engine's fixed local client; never called from a hook.
class Client {
public:
    explicit Client(std::wstring executable);
    ~Client();
    ProfileHost::Sample Apply(const LayoutTarget& target, LANGID language, std::uint64_t generation);
    void Release();
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace capslang::system_profile
