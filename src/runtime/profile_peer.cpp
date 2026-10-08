#include "profile_peer.hpp"
#include "profile_host.hpp"
#include "thread_profile.hpp"
#include "../core/profile_queue.hpp"
#include <thread>
#include <atomic>

namespace capslang {
namespace pc = profile_channel;
namespace {
struct Update {
    bool event = false;
    pc::Event notification{};
    std::uint64_t command = 0;
    ThreadProfile::Result result{};
    bool conversion = false;
    HRESULT conversionResult = E_PENDING;
};
struct Inbox {
    pc::Command command{};
    bool apply = false;
};
struct Transport {
    ipc::Endpoint endpoint;
    std::wstring expectedServer;
    bool requireElevation;
    std::uint64_t binding;
    DWORD thread = GetCurrentThreadId(), process = GetCurrentProcessId();
    pc::Queue<Update, 64> outgoing;
    pc::Queue<Inbox, 16> incoming;
    std::atomic<bool> stop{false}, lost{false}, finished{false};
    Transport(ipc::Endpoint ep, std::uint64_t epoch, std::wstring image, bool high)
        : endpoint(std::move(ep)), expectedServer(std::move(image)), requireElevation(high), binding(epoch) {}
};
void Notify(void* context, const ThreadProfile::Event& event) noexcept {
    auto& state = *static_cast<Transport*>(context);
    Update update; update.event = true;
    update.notification = {event.serial, event.generation, event.language, static_cast<pc::Cause>(event.cause), event.occurred};
    if (!state.outgoing.TryPush(update)) state.lost = true;
}
void Worker(std::shared_ptr<Transport> state) noexcept {
    try {
        pc::Report report; report.binding = state->binding;
        report.process = state->process; report.thread = state->thread;
        report.error = ERROR_NOT_READY;
        std::uint64_t delivered = 0, retryAt = 0, acknowledged = 0;
        pc::Command previous;
        while (!state->stop) {
            Update update;
            while (report.count < pc::kBatch && state->outgoing.TryPop(update)) {
                if (update.event) report.events[report.count++] = update.notification;
                else if (update.command >= report.processedCommand) {
                    report.processedCommand = update.command;
                    report.confirmedGeneration = update.result.generation;
                    report.actual = pc::Language(update.result.actual) ? update.result.actual : 0;
                    report.profile = pc::Language(update.result.profile) ? update.result.profile : 0;
                    report.error = static_cast<DWORD>(update.result.error);
                    report.sampled = update.result.sampled;
                    if(update.conversion){report.conversionCommand=update.command;report.conversionResult=static_cast<DWORD>(update.conversionResult);}
                }
            }
            if (state->lost) { report.error = ERROR_MORE_DATA; report.confirmedGeneration = 0; }
            if (report.poll == UINT64_MAX) break;
            ++report.poll;
            pc::Command reply; DWORD error = 0;
            ipc::ProcessIdentity server;
            if (!ipc::Exchange(state->endpoint, state->expectedServer, state->requireElevation,
                &report, sizeof(report), &reply, sizeof(reply), error, &server) || !pc::Valid(reply, state->binding, report.poll)) break;
            // Bootstrap discovers no path/PID through window messages. Pin the
            // first server only AFTER its protected image, SID, session and
            // elevation have been authenticated against kernel pipe identity.
            if (!state->endpoint.serverProcess.id) state->endpoint.serverProcess = server;
            // The host may acknowledge only events actually sent on this poll.
            const auto sentThrough = report.count ? report.events[report.count - 1].serial : acknowledged;
            if (reply.eventsThrough < acknowledged || reply.eventsThrough > sentThrough || reply.command < delivered ||
                (reply.command == delivered && (reply.operation != previous.operation ||
                 reply.language != previous.language || reply.generation != previous.generation ||
                 reply.focus != previous.focus || reply.deadline != previous.deadline))) break;
            acknowledged = reply.eventsThrough;
            std::size_t retained = 0;
            for (std::size_t i = 0; i < report.count; ++i)
                if (report.events[i].serial > reply.eventsThrough) report.events[retained++] = report.events[i];
            for (std::size_t i = retained; i < pc::kBatch; ++i) report.events[i] = {};
            report.count = static_cast<std::uint32_t>(retained);
            if (reply.operation == pc::Operation::Detach && report.processedCommand == reply.command &&
                report.error == ERROR_OPERATION_ABORTED) break;
            const auto now = GetTickCount64();
            const bool apply = reply.operation == pc::Operation::Apply &&
                (reply.command != delivered || (report.error && now >= retryAt));
            if (!state->lost && !state->incoming.TryPush({reply, apply})) { state->lost = true; }
            if (!PostThreadMessageW(state->thread, ProfilePeer::WakeMessage(), 0, 0)) break;
            if (apply) retryAt = now + 500;
            delivered = reply.command;
            previous = reply;
            // This wait is on the private IPC worker, never the UI/hook thread.
            Sleep(25);
        }
    } catch (...) { state->lost = true; }
    state->stop = true;
    state->finished = true;
    PostThreadMessageW(state->thread, ProfilePeer::WakeMessage(), 0, 0);
}
}
struct ProfilePeer::Impl {
    std::shared_ptr<Transport> state;
    ThreadProfile profile;
    bool started = false, detached = false;
    std::uint64_t processed = 0;
    std::uint64_t converted = 0;
    HRESULT conversionResult = E_PENDING;
    Impl(ipc::Endpoint endpoint, std::uint64_t binding, std::wstring server, bool high)
        : state(std::make_shared<Transport>(std::move(endpoint), binding, std::move(server), high)),
          profile(Notify, state.get(), nullptr, true, true) {}
    ~Impl() { state->stop = true; profile.Unbind(); }
    void Send(std::uint64_t command, ThreadProfile::Result result) {
        Update update; update.command = command; update.result = result;
        if (!state->outgoing.TryPush(update)) state->lost = true;
    }
};
ProfilePeer::ProfilePeer(ipc::Endpoint endpoint, std::uint64_t binding, std::wstring expectedServer, bool high)
    : impl_(std::make_unique<Impl>(std::move(endpoint), binding, std::move(expectedServer), high)) {}
ProfilePeer::~ProfilePeer() = default;
UINT ProfilePeer::WakeMessage() {
    return RegisterWindowMessageW(L"CapsLang.TargetThreadProfile.Wake.v1");
}
bool ProfilePeer::Start() {
    auto& self = *impl_;
    auto& state = *self.state;
    if (GetCurrentThreadId() != state.thread || self.started || !state.binding || !WakeMessage()) return false;
    const auto expected = ipc::Endpoint::Current(ProfileInstance(state.process, state.thread, state.binding));
    ipc::ProcessIdentity own;
    if (expected.error || state.endpoint.name != expected.name || state.endpoint.sid != expected.sid ||
        state.endpoint.session != expected.session || state.expectedServer.empty() ||
        !ipc::IdentifyProcess(GetCurrentProcess(), own) || state.endpoint.clientProcess.id != own.id ||
        state.endpoint.clientProcess.created != own.created) return false;
    // Never unload code still referenced by an app-owned TSF source/timer or
    // by a disconnected worker. This does not retain any keyboard hooks.
    HMODULE module = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
        reinterpret_cast<LPCWSTR>(&ProfilePeer::WakeMessage), &module)) return false;
    try {
        self.started = true;
        std::thread(Worker, self.state).detach();
        return true;
    } catch (...) { state.stop = true; return false; }
}
void ProfilePeer::Step() {
    auto& self = *impl_;
    auto& state = *self.state;
    if (GetCurrentThreadId() != state.thread || !self.started) return;
    if (state.stop || state.lost) { if (SUCCEEDED(self.profile.Unbind())) self.detached = true; return; }
    Inbox request;
    for (unsigned budget = 0; budget < 16 && state.incoming.TryPop(request); ++budget) {
        const auto& command = request.command;
        if (command.command < self.processed) continue;
        self.processed = command.command;
        ThreadProfile::Result result;
        if (command.operation == pc::Operation::Detach) {
            result.error = self.profile.Unbind();
            if (SUCCEEDED(result.error)) { self.detached = true; result.error = HRESULT(ERROR_OPERATION_ABORTED); }
            self.Send(command.command, result);
            continue;
        }
        if (self.detached) { result.error = HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED); self.Send(command.command, result); continue; }
        result.error = self.profile.Bind();
        if(command.operation==pc::Operation::ConvertSelection) {
            if(command.command!=self.converted) {
                self.converted=command.command;
                self.conversionResult=FAILED(result.error)?result.error:
                    (GetTickCount64()>command.deadline || reinterpret_cast<ULONG_PTR>(GetFocus())!=command.focus ?
                     HRESULT_FROM_WIN32(ERROR_CANCELLED) : self.profile.ConvertSelection(static_cast<LANGID>(command.language)));
            }
            Update update;update.command=command.command;update.result=self.profile.Read();
            update.conversion=true;update.conversionResult=self.conversionResult;
            if(!state.outgoing.TryPush(update))state.lost=true;
            continue;
        }
        if (SUCCEEDED(result.error)) result = request.apply ?
            self.profile.Apply(static_cast<LANGID>(command.language), command.generation) : self.profile.Read();
        self.Send(command.command, result);
    }
}
bool ProfilePeer::Detached() const { return impl_->detached; }
bool ProfilePeer::Finished() const { return impl_->state->finished.load(); }
} // namespace capslang
