#include "mwb_monitor.hpp"
#include <algorithm>
#include <atomic>
#include <mutex>

namespace capslang {
struct MwbMonitor::Shared {
    HANDLE stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HDESK desktop = GetThreadDesktop(GetCurrentThreadId());
    std::atomic<bool> done{false};
    std::mutex mutex;
    MwbSnapshot result;
    Operation operation;
    ~Shared() { if (stop) CloseHandle(stop); }
    static DWORD WINAPI Thread(void* parameter) {
        std::unique_ptr<std::shared_ptr<Shared>> passed(static_cast<std::shared_ptr<Shared>*>(parameter));
        const auto state = *passed; passed.reset();
        if (!SetThreadDesktop(state->desktop)) {
            { std::lock_guard<std::mutex> guard(state->mutex); state->result.error = GetLastError(); }
            state->done = true; return 1;
        }
        MwbObserver observer;
        MwbSnapshot previous;
        do {
            const auto start = GetTickCount64();
            MwbSnapshot sample;
            sample.evidence = state->operation ? state->operation() : observer.Read();
            sample.observedAt = GetTickCount64();
            sample.responsive = sample.observedAt - start <= 500;
            sample.error = sample.responsive ? sample.evidence.error : ERROR_TIMEOUT;
            const bool local = sample.responsive && sample.evidence.RecipientObservationAllowed() &&
                sample.evidence.route == MwbRoute::LocalCandidate;
            if (local) {
                const bool continuous = previous.localSince && previous.responsive &&
                    sample.observedAt - previous.observedAt <= 500 &&
                    previous.evidence.helperPid == sample.evidence.helperPid &&
                    previous.evidence.dotWindow == sample.evidence.dotWindow &&
                    previous.evidence.settings.relativeMouse == sample.evidence.settings.relativeMouse;
                sample.localSince = continuous ? previous.localSince : sample.observedAt;
            }
            previous = sample;
            { std::lock_guard<std::mutex> guard(state->mutex); state->result = sample; }
        } while (WaitForSingleObject(state->stop, 100) == WAIT_TIMEOUT);
        state->done = true; return 0;
    }
};
MwbMonitor::~MwbMonitor() { Stop(); }
bool MwbMonitor::Start(Operation operation) {
    if (thread_) return true;
    static std::mutex registryMutex;
    static std::weak_ptr<Shared> previous;
    std::lock_guard<std::mutex> registry(registryMutex);
    if (const auto active = previous.lock(); active && !active->done) { error_ = ERROR_BUSY; return false; }
    auto state = std::make_shared<Shared>();
    if (!state->stop || !state->desktop) { error_ = GetLastError(); return false; }
    state->operation = std::move(operation);
    auto argument = std::make_unique<std::shared_ptr<Shared>>(state);
    thread_ = CreateThread(nullptr, 0, Shared::Thread, argument.get(), 0, nullptr);
    if (!thread_) { error_ = GetLastError(); return false; }
    argument.release(); shared_ = state; previous = state; error_ = 0; return true;
}
MwbSnapshot MwbMonitor::Status() const {
    if (!shared_) { MwbSnapshot result; result.error = error_ ? error_ : ERROR_NOT_READY; return result; }
    MwbSnapshot result;
    { std::lock_guard<std::mutex> guard(shared_->mutex); result = shared_->result; }
    const auto now = GetTickCount64();
    if (!result.observedAt || result.observedAt > now || now - result.observedAt > 500) {
        result.responsive = false; result.localSince = 0; result.error = ERROR_TIMEOUT;
    }
    return result;
}
bool MwbMonitor::Stop(DWORD graceMs) {
    if (!thread_) return true;
    SetEvent(shared_->stop); CancelSynchronousIo(thread_);
    const auto wait = WaitForSingleObject(thread_, std::min<DWORD>(graceMs, 1000));
    const bool ended = wait == WAIT_OBJECT_0;
    if (!ended) error_ = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
    CloseHandle(thread_); thread_ = nullptr; shared_.reset(); return ended;
}
} // namespace capslang
