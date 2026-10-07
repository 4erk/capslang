#pragma once
#ifdef CAPSLANG_SYSTEM_PROFILE_PROBE
#include "../app/paths.hpp"
#include "../platform/windows_support.hpp"
#include <atomic>
namespace capslang {
struct ProbeCapsCounters {
    std::atomic<unsigned> physical{0}, injected{0}, consumed{0}, toggles{0};
    void Observe(bool down, bool synthetic, bool swallowed) noexcept {
        if (!down) return;
        if (synthetic) ++injected; else ++physical;
        if (swallowed) ++consumed;
    }
    void Flush(const char* role) {
        const unsigned values[]{physical.load(), injected.load(), consumed.load(), toggles.load()};
        const auto signature = std::to_string(values[0])+":"+std::to_string(values[1])+":"+
            std::to_string(values[2])+":"+std::to_string(values[3]);
        if (signature == previous) return;
        previous = signature;
        DWORD error = 0; auto path = app::InstalledExecutable(error);
        if (path.empty()) return;
        path = path.substr(0,path.find_last_of(L'\\')) + L"\\caps-trace.jsonl";
        HANDLE file = CreateFileW(path.c_str(),FILE_APPEND_DATA,FILE_SHARE_READ|FILE_SHARE_WRITE,
            nullptr,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
        if (file == INVALID_HANDLE_VALUE) return;
        const auto target = CaptureLayoutTarget();
        const auto line = "{\"tick\":"+std::to_string(GetTickCount64())+",\"role\":\""+role+
            "\",\"caller\":"+std::to_string(GetCurrentProcessId())+",\"pid\":"+std::to_string(target.processId)+
            ",\"tid\":"+std::to_string(target.threadId)+",\"physical_down\":"+std::to_string(values[0])+
            ",\"injected_down\":"+std::to_string(values[1])+",\"consumed_down\":"+std::to_string(values[2])+
            ",\"toggle_posts\":"+std::to_string(values[3])+"}\n";
        DWORD written = 0; WriteFile(file,line.data(),static_cast<DWORD>(line.size()),&written,nullptr);
        CloseHandle(file);
    }
private:
    std::string previous;
};
// Compile-time diagnostic only; called from controller/IPC workers, never hooks.
// Technical window/process identities only: no titles, text or keyboard input.
inline void ProbeTrace(const char* stage, const LayoutTarget& target, DWORD error) {
    static thread_local ULONGLONG previous = 0;
    const auto now = GetTickCount64();
    if (now - previous < 500) return;
    previous = now;
    DWORD pathError = 0;
    auto path = app::InstalledExecutable(pathError);
    if (path.empty()) return;
    path = path.substr(0, path.find_last_of(L'\\')) + L"\\profile-trace.jsonl";
    HANDLE file = CreateFileW(path.c_str(), FILE_APPEND_DATA | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return;
    LARGE_INTEGER size{};
    if (GetFileSizeEx(file, &size) && size.QuadPart < 2 * 1024 * 1024) {
        const auto line = "{\"tick\":" + std::to_string(now) + ",\"caller\":" + std::to_string(GetCurrentProcessId()) +
            ",\"stage\":\"" + stage + "\",\"pid\":" + std::to_string(target.processId) +
            ",\"tid\":" + std::to_string(target.threadId) + ",\"foreground\":" +
            std::to_string(reinterpret_cast<ULONG_PTR>(target.foreground)) + ",\"focus\":" +
            std::to_string(reinterpret_cast<ULONG_PTR>(target.focus)) + ",\"error\":" + std::to_string(error) + "}\n";
        DWORD written = 0; WriteFile(file, line.data(), static_cast<DWORD>(line.size()), &written, nullptr);
    }
    CloseHandle(file);
}
}
#endif
