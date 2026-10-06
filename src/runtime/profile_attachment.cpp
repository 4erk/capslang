#include "profile_attachment.hpp"
#include "../app/paths.hpp"

namespace capslang {
namespace {
bool SameArchitecture(HANDLE process) {
    USHORT target = 0, native = 0, own = 0, ownNative = 0;
    return IsWow64Process2(process, &target, &native) &&
        IsWow64Process2(GetCurrentProcess(), &own, &ownNative) && target == own && native == ownNative;
}
bool AllowedModule(const std::wstring& path, DWORD& error) {
#ifdef CAPSLANG_PROFILE_TEST
    // Compile-time fixture policy, never accepted as a production CLI option.
    const auto image = app::ExecutablePath();
    const auto expected = image.substr(0, image.find_last_of(L'\\')) + L"\\profile_module_test.dll";
    error = _wcsicmp(expected.c_str(), path.c_str()) ? ERROR_ACCESS_DENIED : 0;
    return !error;
#else
    if (!app::ProtectedExecutable(app::ExecutablePath(), error)) return false;
    const auto exe = app::InstalledExecutable(error);
    const auto root = exe.substr(0, exe.find_last_of(L'\\')) + L"\\modules";
    const auto name = sizeof(void*) == 8 ? L"CapsLangProfile64.dll" : L"CapsLangProfile32.dll";
    const auto prefix = root + L"\\";
    const auto suffix = std::wstring(L"\\") + name;
    if (path.size() != prefix.size() + 64 + suffix.size() || path.compare(0, prefix.size(), prefix) ||
        path.compare(path.size() - suffix.size(), suffix.size(), suffix)) { error = ERROR_ACCESS_DENIED; return false; }
    for (std::size_t i = prefix.size(); i < prefix.size() + 64; ++i)
        if (!((path[i] >= L'0' && path[i] <= L'9') || (path[i] >= L'a' && path[i] <= L'f'))) {
            error = ERROR_ACCESS_DENIED; return false;
        }
    return app::ProtectedPath(root, true, error) &&
        app::ProtectedPath(path.substr(0, path.find_last_of(L'\\')), true, error) &&
        app::ProtectedPath(path, false, error);
#endif
}
}
ProfileAttachment::ProfileAttachment(DWORD process, DWORD thread) : host_(process, thread), process_(process), thread_(thread) {}
ProfileAttachment::~ProfileAttachment() { Stop(); }
bool ProfileAttachment::Start(const std::wstring& path) {
    if (hook_) return true;
    if (!AllowedModule(path, error_)) return false;
    HANDLE target = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process_);
    const bool same = target && SameArchitecture(target);
    if (target) CloseHandle(target);
    if (!same) { error_ = ERROR_EXE_MACHINE_TYPE_MISMATCH; return false; }
    if (!host_.Start()) { error_ = host_.Error(); return false; }
    module_ = LoadLibraryExW(path.c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    const auto callback = module_ ? reinterpret_cast<HOOKPROC>(GetProcAddress(module_, "CapsLangProfileHook")) : nullptr;
    if (!callback) { error_ = GetLastError(); Stop(); return false; }
    hook_ = SetWindowsHookExW(WH_GETMESSAGE, callback, module_, thread_);
    if (!hook_) { error_ = GetLastError(); Stop(); return false; }
    error_ = 0;
    Take();
    return true;
}
void ProfileAttachment::Stop() {
    // A module-owned timer survives removal of the hook and observes pipe loss.
    host_.Stop();
    if (hook_) { UnhookWindowsHookEx(hook_); hook_ = nullptr; }
    if (module_) { FreeLibrary(module_); module_ = nullptr; }
}
bool ProfileAttachment::Request(LANGID language, std::uint64_t generation) { return hook_ && host_.Request(language, generation); }
ProfileHost::Sample ProfileAttachment::Take() {
    auto result = host_.Take();
    if (result.report.poll) observed_ = true;
    const auto now = GetTickCount64();
    if (hook_ && !observed_ && now >= nextWake_) {
        nextWake_ = now + 100;
        const auto binding = host_.Binding();
        const auto message = ProfileAttachMessage();
        if (!message || !PostThreadMessageW(thread_, message, static_cast<WPARAM>(binding & UINT32_MAX),
            static_cast<LPARAM>(binding >> 32))) error_ = GetLastError();
    }
    if (error_) { result.error = error_; result.confirmed = false; }
    return result;
}
DWORD ProfileAttachment::Error() const { return error_ ? error_ : host_.Error(); }
} // namespace capslang
