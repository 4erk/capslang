#pragma once
#include "mwb_monitor.hpp"

namespace capslang {
// MWB's 4x4 DotForm becomes foreground while input is routed away. It is
// not a text target. Keep the last real target synchronized in the background
// instead of posting to the SYSTEM helper (which correctly denies access).
// No focus stealing, input synthesis, window text or remote window handles.
class FocusTarget {
  public:
    LayoutTarget Select(const LayoutTarget &captured, const MwbSnapshot &mwb) {
        const auto &evidence = mwb.evidence;
        if (!mwb.responsive || !evidence.RecipientObservationAllowed())
            return captured;
        const bool dot =
            captured.foreground == evidence.dotWindow && captured.processId == evidence.helperPid;
        if (!dot) {
            if (TargetStillValid(captured))
                remembered_ = captured;
            return captured;
        }
        if (TargetStillValid(remembered_) && IsWindowVisible(remembered_.foreground))
            return remembered_;
        remembered_ = {};
        Search search{evidence.helperPid, {}};
        // On cold start the dot may already own foreground. Windows enumerates
        // top-level windows in Z order; select the first usable window owned by
        // this user, excluding helper/tool/noactivate windows. Never activate it.
        EnumWindows(Find, reinterpret_cast<LPARAM>(&search));
        remembered_ = search.target;
        return remembered_;
    }

  private:
    struct Search {
        DWORD helper;
        LayoutTarget target;
    };
    LayoutTarget remembered_;
    static bool SameUser(DWORD pid) {
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid),
               token = nullptr, current = nullptr;
        if (!process)
            return false;
        const bool opened = OpenProcessToken(process, TOKEN_QUERY, &token) &&
                            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &current);
        CloseHandle(process);
        bool equal = false;
        if (opened) {
            DWORD a = 0, b = 0;
            GetTokenInformation(token, TokenUser, nullptr, 0, &a);
            GetTokenInformation(current, TokenUser, nullptr, 0, &b);
            if (a && b && a <= 65536 && b <= 65536) {
                std::vector<BYTE> one(a), two(b);
                equal = GetTokenInformation(token, TokenUser, one.data(), a, &a) &&
                        GetTokenInformation(current, TokenUser, two.data(), b, &b) &&
                        EqualSid(reinterpret_cast<TOKEN_USER *>(one.data())->User.Sid,
                                 reinterpret_cast<TOKEN_USER *>(two.data())->User.Sid);
            }
        }
        if (token)
            CloseHandle(token);
        if (current)
            CloseHandle(current);
        return equal;
    }
    static BOOL CALLBACK Find(HWND window, LPARAM param) {
        auto &search = *reinterpret_cast<Search *>(param);
        if (!IsWindowVisible(window) || !IsWindowEnabled(window) || IsIconic(window))
            return TRUE;
        const auto style = GetWindowLongPtrW(window, GWL_EXSTYLE);
        if (style & (WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE))
            return TRUE;
        RECT bounds{};
        if (!GetWindowRect(window, &bounds) || bounds.right - bounds.left < 100 ||
            bounds.bottom - bounds.top < 100)
            return TRUE;
        DWORD pid = 0;
        const DWORD thread = GetWindowThreadProcessId(window, &pid);
        if (!thread || pid == search.helper || pid == GetCurrentProcessId() || !SameUser(pid))
            return TRUE;
        GUITHREADINFO info{};
        info.cbSize = sizeof(info);
        if (!GetGUIThreadInfo(thread, &info))
            return TRUE;
        const HWND focus = info.hwndFocus ? info.hwndFocus : window;
        DWORD focusPid = 0;
        const auto focusThread = GetWindowThreadProcessId(focus, &focusPid);
        if (focusPid != pid || !focusThread)
            return TRUE;
        search.target = {window, focus, pid, focusThread, GetKeyboardLayout(focusThread)};
        return FALSE;
    }
};
} // namespace capslang
