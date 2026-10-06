#pragma once
#include "profile_host.hpp"

namespace capslang {
inline UINT ProfileAttachMessage() {
    return RegisterWindowMessageW(L"CapsLang.TargetThreadProfile.Attach.v1");
}
// One same-bitness, same-session UI thread. No global hook and no DLL remote
// loader: Windows loads the protected module through its thread hook API.
// Owner must poll outside a keyboard callback and discard samples on focus
// changes. Stop closes the authenticated endpoint; the module's private timer
// also detaches when the owner dies without running this destructor.
class ProfileAttachment {
public:
    ProfileAttachment(DWORD process, DWORD thread);
    ~ProfileAttachment();
    ProfileAttachment(const ProfileAttachment&) = delete;
    ProfileAttachment& operator=(const ProfileAttachment&) = delete;
    bool Start(const std::wstring& modulePath);
    void Stop();
    bool Request(LANGID language, std::uint64_t generation);
    ProfileHost::Sample Take();
    DWORD Error() const;
private:
    ProfileHost host_;
    DWORD process_, thread_, error_ = ERROR_NOT_READY;
    HMODULE module_ = nullptr;
    HHOOK hook_ = nullptr;
    ULONGLONG nextWake_ = 0;
    bool observed_ = false;
};
} // namespace capslang
