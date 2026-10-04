#include "led_worker.hpp"
#include <atomic>
#include <algorithm>
#include <mutex>

namespace capslang {
struct LedWorker::Shared {
    HANDLE stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE wake = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    std::atomic<core::Language> target{core::Language::Unknown};
    std::atomic<bool> discover{true}, done{false}, busy{false};
    std::atomic<ULONGLONG> started{0};
    std::mutex mutex;
    LedStatus result;
    core::Language applied = core::Language::Unknown;
    Operation operation;
    ~Shared() { if (wake) CloseHandle(wake); if (stop) CloseHandle(stop); }
    static LedStatus Apply(KeyboardLeds& leds, core::Language language, bool discover, HANDLE stop) {
        LedStatus result;
        if (discover) leds.Discover();
        DWORD lastError = leds.EnumerationError();
        for (size_t i = 0; i < leds.Devices().size(); ++i) {
            if (WaitForSingleObject(stop, 0) == WAIT_OBJECT_0) { result.error = ERROR_CANCELLED; return result; }
            const auto& device = leds.Devices()[i];
            if (device.path.find(L"GLOBALROOT") == std::wstring::npos) continue;
            if (!device.queried) { ++result.unsupported; lastError = device.queryError ? device.queryError : device.openError; continue; }
            DWORD error = 0;
            if (leds.SetScroll(i, language == core::Language::Russian, error)) ++result.written;
            else { ++result.unsupported; lastError = error; }
        }
        result.error = lastError ? lastError : result.written ? 0 : ERROR_NOT_SUPPORTED;
        result.responsive = true; return result;
    }
    static DWORD WINAPI Thread(void* parameter) {
        std::unique_ptr<std::shared_ptr<Shared>> passed(static_cast<std::shared_ptr<Shared>*>(parameter));
        auto state = *passed; passed.reset();
        {
            // Construction, every IOCTL, and handle destruction all belong to
            // this thread; even a stuck driver close cannot stall its owner.
            KeyboardLeds leds;
            ULONGLONG nextDiscovery = 0;
            HANDLE waits[]{state->stop, state->wake};
            while (WaitForSingleObject(state->stop, 0) != WAIT_OBJECT_0) {
                const auto language = state->target.load();
                const auto now = GetTickCount64();
                if (core::Supported(language)) {
                    const bool rediscover = state->discover.exchange(false) || now >= nextDiscovery;
                    if (rediscover) nextDiscovery = now + 10000;
                    state->started = now; state->busy = true;
                    auto result = state->operation ? state->operation(language, rediscover) : Apply(leds, language, rediscover, state->stop);
                    state->busy = false; result.responsive = true;
                    if (state->target == language && WaitForSingleObject(state->stop, 0) != WAIT_OBJECT_0) {
                        std::lock_guard<std::mutex> guard(state->mutex);
                        state->result = result; state->applied = language;
                    }
                }
                if (WaitForMultipleObjects(2, waits, FALSE, 500) == WAIT_OBJECT_0) break;
            }
            // Close may itself enter a driver. Keep busy/deadline visible and
            // keep the process-wide slot occupied until destruction finishes.
            state->started = GetTickCount64(); state->busy = true;
        }
        state->busy = false; state->done = true; return 0;
    }
};
LedWorker::~LedWorker() { Stop(); }
bool LedWorker::Start(Operation operation) {
    if (thread_) return true;
    static std::mutex registryMutex;
    static std::weak_ptr<Shared> previous;
    std::lock_guard<std::mutex> guard(registryMutex);
    if (const auto active = previous.lock(); active && !active->done) { error_ = ERROR_BUSY; return false; }
    auto state = std::make_shared<Shared>();
    if (!state->stop || !state->wake) { error_ = GetLastError(); return false; }
    state->operation = std::move(operation);
    auto parameter = std::make_unique<std::shared_ptr<Shared>>(state);
    thread_ = CreateThread(nullptr, 0, Shared::Thread, parameter.get(), 0, nullptr);
    if (!thread_) { error_ = GetLastError(); return false; }
    parameter.release(); shared_ = state; previous = state; error_ = 0; return true;
}
void LedWorker::Target(core::Language language) {
    if (!shared_ || !thread_) return;
    if (shared_->target.exchange(language) != language) SetEvent(shared_->wake);
}
void LedWorker::Rediscover() {
    if (!shared_) return;
    shared_->discover = true; SetEvent(shared_->wake);
}
LedStatus LedWorker::Status() const {
    if (!shared_) return {0, 0, error_ ? error_ : ERROR_NOT_READY, false};
    std::lock_guard<std::mutex> guard(shared_->mutex);
    auto result = shared_->result;
    if (shared_->busy && GetTickCount64() - shared_->started.load() >= 2000) return {0, result.unsupported, ERROR_TIMEOUT, false};
    if (shared_->applied != shared_->target) return {0, result.unsupported, ERROR_IO_PENDING, true};
    return result;
}
bool LedWorker::Stop(DWORD graceMs) {
    if (!thread_) return true;
    SetEvent(shared_->stop); SetEvent(shared_->wake);
    // Best effort: Windows explicitly allows drivers not to honor cancel.
    // Never TerminateThread, free a live context, or wait forever for them.
    CancelSynchronousIo(thread_);
    const auto wait = WaitForSingleObject(thread_, std::min<DWORD>(graceMs, 1000));
    const bool ended = wait == WAIT_OBJECT_0;
    if (!ended) error_ = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
    CloseHandle(thread_); thread_ = nullptr; shared_.reset();
    return ended;
}
} // namespace capslang
