// Reuse the tested lease+watchdog implementation in the single distributed EXE.
#define CAPSLANG_SAVER_EMBEDDED
#include "../../tools/mwb_saver_guard.cpp"
#include <thread>
#include <memory>
namespace {
struct EmbeddedSaver {
    HANDLE stop = CreateEventW(nullptr,TRUE,FALSE,nullptr);
    std::thread thread;
    bool Start() {
        if (!stop) return false;
        try {
            thread = std::thread([this] {
                // The legacy companion retains responsibility until explicitly
                // migrated. Never duplicate its lease or stop somebody else's.
                while (WaitForSingleObject(stop,0) != WAIT_OBJECT_0) {
                    Run(false,false,stop);
                    if (WaitForSingleObject(stop,500) == WAIT_OBJECT_0) break;
                }
            });
            return true;
        } catch (...) { return false; }
    }
    ~EmbeddedSaver() {
        if (stop) SetEvent(stop);
        if (thread.joinable()) thread.join();
        if (stop) CloseHandle(stop);
    }
};
std::unique_ptr<EmbeddedSaver> embeddedSaver;
}
bool StartCapsLangSaver() {
    if (embeddedSaver) return true;
    auto saver = std::make_unique<EmbeddedSaver>();
    if (!saver->Start()) return false;
    embeddedSaver = std::move(saver); return true;
}
void StopCapsLangSaver() { embeddedSaver.reset(); }
