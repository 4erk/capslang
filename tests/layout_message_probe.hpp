#pragma once
#include "../src/platform/windows_support.hpp"

// Test-only shared page. Not a production IPC or an installation component.
// The parent creates it only for the disposable fixture's exact process/thread.
namespace capslang::test {
constexpr DWORD kProbeMagic = 0x504d4c43;
struct LayoutMessageProbe {
    DWORD magic = kProbeMagic, process = 0, thread = 0;
    volatile LONG queued = 0, queuedLanguage = 0;
    volatile LONG returned = 0, returnedLanguage = 0;
    volatile LONG changed = 0, changedLanguage = 0;
    volatile LONG profileNotifications = 0, profileLanguage = 0, profileError = E_PENDING;
    volatile LONG ownProfiles = 0, externalProfiles = 0;
    volatile LONG commandLanguage = 0, commandResult = E_PENDING, commandProfile = 0;
    volatile LONG initializationStage = 0;
    volatile LONG simulateMissingManagerOnce = 0;
    alignas(8) volatile LONG64 commandGeneration = 0, confirmedGeneration = 0, lastOwnGeneration = 0;
    alignas(8) volatile LONG64 reenterGeneration = 0;
    volatile LONG reenterLanguage = 0, reenterResult = E_PENDING;
    alignas(8) volatile LONG64 channelBinding = 0, serverCreated = 0;
    DWORD serverProcess = 0;
    volatile LONG peerStatus = E_PENDING, peerDetached = 0;
};
inline std::wstring ProbeName(DWORD pid) {
    return L"Local\\CapsLang.PrivateLayoutMessageTest." + std::to_wstring(pid);
}
} // namespace capslang::test
