#include "profile_host.hpp"
#include <bcrypt.h>
#include <mutex>

namespace capslang {
namespace pc = profile_channel;
struct ProfileHost::Impl {
    DWORD process, thread;
    HANDLE target = nullptr, targetThread = nullptr;
    std::uint64_t binding = 0, lastPoll = 0, highestGeneration = 0;
    ipc::Endpoint endpoint;
    std::unique_ptr<ipc::MessageServer> server;
    mutable std::mutex mutex;
    DWORD error = ERROR_NOT_READY;
    bool ready = false, attempted = false, lostEvents = false;
    pc::Command command{};
    pc::EventCursor cursor;
    Sample sample;
    Impl(DWORD pid, DWORD tid) : process(pid), thread(tid) {}
    ~Impl() {
        if (server) server->Stop();
        if (targetThread) CloseHandle(targetThread);
        if (target) CloseHandle(target);
    }
    bool Alive() const {
        return target && targetThread && WaitForSingleObject(target, 0) == WAIT_TIMEOUT &&
            WaitForSingleObject(targetThread, 0) == WAIT_TIMEOUT;
    }
    void Handle(const void* input, void* output) {
        pc::Report report;
        memcpy(&report, input, sizeof(report));
        // An invalid/unauthenticated result must never produce an Apply reply.
        // All-zero bytes are deliberately invalid for the module protocol.
        SecureZeroMemory(output, sizeof(pc::Command));
        std::lock_guard<std::mutex> lock(mutex);
        if (!ready || !Alive() || !pc::Valid(report, binding, process, thread) || report.poll <= lastPoll ||
            report.sampled > GetTickCount64() ||
            report.processedCommand > command.command ||
            (report.confirmedGeneration && (report.confirmedGeneration > highestGeneration ||
             !report.processedCommand))) { error = ERROR_INVALID_DATA; return; }
        if (lostEvents) { error = ERROR_MORE_DATA; return; }
        const auto before = cursor.Through();
        std::size_t added = 0;
        for (std::size_t i = 0; i < report.count; ++i) if (report.events[i].serial > before) ++added;
        if (added > sample.events.size() - sample.count || !cursor.Accept(report)) {
            lostEvents = true; sample.confirmed = false; error = ERROR_MORE_DATA; return;
        }
        for (std::size_t i = 0; i < report.count; ++i)
            if (report.events[i].serial > before) sample.events[sample.count++] = report.events[i];
        sample.report = report; sample.sampled = report.sampled;
        sample.confirmed = command.operation == pc::Operation::Apply && !report.error &&
            report.processedCommand == command.command && report.confirmedGeneration == command.generation &&
            report.actual == command.language && report.profile == command.language;
        sample.error = report.error; error = 0; lastPoll = report.poll;
        auto reply = command; reply.poll = report.poll; reply.eventsThrough = cursor.Through();
        memcpy(output, &reply, sizeof(reply));
    }
};
ProfileHost::ProfileHost(DWORD process, DWORD thread) : impl_(std::make_unique<Impl>(process, thread)) {}
ProfileHost::~ProfileHost() = default;
bool ProfileHost::Start() {
    auto& self = *impl_;
    if (self.ready) return true;
    // A stopped binding is never reused. Create a new owner/nonce instead.
    if (self.attempted || !self.process || !self.thread) { self.error = ERROR_INVALID_PARAMETER; return false; }
    self.attempted = true;
    self.target = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, self.process);
    self.targetThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, self.thread);
    DWORD session = 0, ownSession = 0;
    if (!self.Alive() || GetProcessIdOfThread(self.targetThread) != self.process ||
        !ProcessIdToSessionId(self.process, &session) ||
        !ProcessIdToSessionId(GetCurrentProcessId(), &ownSession) || session != ownSession) {
        self.error = ERROR_ACCESS_DENIED; return false;
    }
    if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&self.binding), sizeof(self.binding),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG) || !self.binding) { self.error = ERROR_GEN_FAILURE; return false; }
    self.endpoint = ipc::Endpoint::Current(ProfileInstance(self.process, self.thread, self.binding));
    if (self.endpoint.error || !ipc::IdentifyProcess(self.target, self.endpoint.clientProcess) ||
        !ipc::IdentifyProcess(GetCurrentProcess(), self.endpoint.serverProcess)) {
        self.error = ERROR_INVALID_DATA; return false;
    }
    self.command.binding = self.binding; self.command.command = 1;
    self.server = std::make_unique<ipc::MessageServer>(self.endpoint, sizeof(pc::Report), sizeof(pc::Command),
        [&self](const void* in, void* out) { self.Handle(in, out); });
    // Endpoint publication precedes any hook/activation in the external owner.
    { std::lock_guard<std::mutex> lock(self.mutex); self.ready = true; }
    if (!self.server->Start()) {
        std::lock_guard<std::mutex> lock(self.mutex);
        self.ready = false; self.error = self.server->Error(); return false;
    }
    { std::lock_guard<std::mutex> lock(self.mutex); self.error = 0; }
    return true;
}
void ProfileHost::Stop() {
    auto& self = *impl_;
    { std::lock_guard<std::mutex> lock(self.mutex); self.ready = false; }
    if (self.server) self.server->Stop();
}
bool ProfileHost::Request(LANGID language, std::uint64_t generation) {
    auto& self = *impl_;
    std::lock_guard<std::mutex> lock(self.mutex);
    if (!self.ready || self.lostEvents || !self.Alive() || !pc::Language(language) || !generation ||
        self.command.operation == pc::Operation::Detach || generation < self.command.generation ||
        (generation == self.command.generation && language != self.command.language)) return false;
    if (generation == self.command.generation) return true;
    if (self.command.command == UINT64_MAX) return false;
    ++self.command.command; self.command.operation = pc::Operation::Apply;
    self.command.language = language; self.command.generation = generation;
    self.highestGeneration = generation;
    self.sample.confirmed = false; return true;
}
bool ProfileHost::Detach() {
    auto& self = *impl_;
    std::lock_guard<std::mutex> lock(self.mutex);
    if (!self.ready || self.command.command == UINT64_MAX) return false;
    if (self.command.operation != pc::Operation::Detach) ++self.command.command;
    self.command.operation = pc::Operation::Detach;
    self.command.language = 0; self.command.generation = 0; self.sample.confirmed = false;
    return true;
}
ProfileHost::Sample ProfileHost::Take() {
    auto& self = *impl_;
    std::lock_guard<std::mutex> lock(self.mutex);
    auto sample = self.sample;
    if (!self.ready || !self.Alive()) sample.error = ERROR_NOT_READY;
    else if (self.error) sample.error = self.error;
    else if (!sample.sampled || GetTickCount64() - sample.sampled >= 1000) sample.error = ERROR_TIMEOUT;
    if (sample.error) sample.confirmed = false;
    self.sample.count = 0; return sample;
}
ipc::Endpoint ProfileHost::Endpoint() const { return impl_->endpoint; }
std::uint64_t ProfileHost::Binding() const { return impl_->binding; }
DWORD ProfileHost::Error() const { std::lock_guard<std::mutex> lock(impl_->mutex); return impl_->error; }
} // namespace capslang
