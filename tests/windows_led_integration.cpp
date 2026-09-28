// Opt-in hardware check. Never sends keyboard input or stops CapsLang.
// Writes just the Scroll indicator bit, reads it back, immediately restores it.
#include "../src/platform/windows_support.hpp"
#include <winioctl.h>
#include <ntddkbd.h>
#include <cstdio>

using namespace capslang;
namespace {
unsigned Locks() {
    return ((GetKeyState(VK_SCROLL) & 1) ? 1U : 0U) |
           ((GetKeyState(VK_NUMLOCK) & 1) ? 2U : 0U) |
           ((GetKeyState(VK_CAPITAL) & 1) ? 4U : 0U);
}
struct Restore {
    KeyboardLeds& leds;
    size_t index;
    bool on;
    bool armed = true;
    bool Apply(DWORD& error) {
        const bool ok = leds.SetScroll(index, on, error);
        if (ok) armed = false;
        return ok;
    }
    ~Restore() {
        if (armed) { DWORD ignored = 0; leds.SetScroll(index, on, ignored); }
    }
};
}

int wmain(int argc, wchar_t** argv) {
    if (argc != 2 || wcscmp(argv[1], L"--write-and-restore") != 0) {
        std::fprintf(stderr, "Requires --write-and-restore; opt-in physical LED writes.\n");
        return 2;
    }
    KeyboardLeds leds;
    leds.Discover();
    unsigned verified = 0, unsupported = 0, failures = 0;
    const unsigned locksBefore = Locks();
    for (size_t index = 0; index < leds.Devices().size(); ++index) {
        const auto& device = leds.Devices()[index];
        // Class endpoints only: do not also test aliases to the same device.
        if (device.path.find(L"GLOBALROOT") == std::wstring::npos || !device.queried) continue;
        DWORD error = 0;
        USHORT before = 0, changed = 0, after = 0;
        if (!leds.ReadFlags(index, before, error)) { ++unsupported; continue; }
        Restore restore{leds, index, (before & KEYBOARD_SCROLL_LOCK_ON) != 0};
        const bool wrote = leds.SetScroll(index, !restore.on, error);
        const DWORD writeError = error;
        const bool readChanged = leds.ReadFlags(index, changed, error);
        const DWORD readError = error;
        const bool restored = restore.Apply(error);
        const DWORD restoreError = error;
        const bool readAfter = leds.ReadFlags(index, after, error);
        const DWORD afterError = error;
        const auto expected = static_cast<USHORT>(before ^ KEYBOARD_SCROLL_LOCK_ON);
        const bool ok = wrote && readChanged && changed == expected && restored && readAfter && after == before;
        const bool unchangedUnsupported = !wrote && readChanged && changed == before && readAfter && after == before;
        if (unchangedUnsupported) restore.armed = false; // No change to undo; IOCTL unsupported.
        std::printf("device=%zu before=%u write=%d write_error=%lu changed=%u read_error=%lu "
                    "restore=%d restore_error=%lu after=%u after_error=%lu verified=%d\n",
            index, before, wrote, writeError, changed, readError, restored, restoreError, after, afterError, ok);
        std::fflush(stdout);
        if (ok) ++verified;
        else if (unchangedUnsupported) ++unsupported;
        else ++failures;
        // Do not continue hardware writes after any restoration anomaly.
        if ((!restored && !unchangedUnsupported) || !readAfter || after != before) break;
    }
    const unsigned locksAfter = Locks();
    if (locksBefore != locksAfter) ++failures;
    std::printf("LED: verified=%u unsupported=%u failures=%u queue_lock_state_before=%u after=%u. "
                "No synthesized input. Driver readback is not optical LED acceptance.\n",
        verified, unsupported, failures, locksBefore, locksAfter);
    return verified && !failures ? 0 : 1;
}
