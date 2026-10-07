#include "system_profile.hpp"
#include "system_layout.hpp"
#include "profile_attachment.hpp"
#include "probe_trace.hpp"
#include "../app/profile_assets.hpp"
#include <bcrypt.h>
#include <algorithm>
#include <atomic>
#include <mutex>

namespace capslang::system_profile {
namespace {
ipc::Endpoint Endpoint(const std::wstring& owner, DWORD session) {
    auto endpoint = system_layout::Endpoint(owner, session);
    endpoint.name = L"\\\\.\\pipe\\CapsLang.system-profile-v1." + std::to_wstring(session) + L"." + owner;
    return endpoint;
}
bool Same(ipc::ProcessIdentity a, ipc::ProcessIdentity b) { return a.id == b.id && a.created == b.created; }
}
struct Server::Impl {
    std::wstring owner;
    DWORD session, error = ERROR_NOT_READY;
    std::function<bool()> allowed;
    std::unique_ptr<ipc::MessageServer> server;
    std::unique_ptr<ProfileAttachment> attachment;
    LayoutTarget target{};
    HANDLE caller = nullptr;
    ipc::ProcessIdentity identity{};
    std::uint64_t epoch = 0, poll = 0, acknowledged = 0, emitted = 0, collected = 0;
    ULONGLONG lastCall = 0;
    std::vector<profile_channel::Event> pending;
    std::mutex mutex;
    std::atomic<ULONGLONG> busy{0};
    Impl(std::wstring sid, DWORD id, std::function<bool()> check)
        : owner(std::move(sid)), session(id), allowed(std::move(check)) {}
    ~Impl() { if (server) server->Stop(); Reset(); }
    void Reset() {
        attachment.reset(); target = {}; epoch = poll = acknowledged = emitted = collected = 0;
        pending.clear(); identity = {};
        if (caller) CloseHandle(caller);
        caller = nullptr; lastCall = 0;
    }
    bool Alive() const { return caller && WaitForSingleObject(caller, 0) == WAIT_TIMEOUT; }
    Response Handle(const Request& request) {
        Response output; output.id = request.id; output.epoch = request.epoch;
        if (!Valid(request)) { output.error = ERROR_INVALID_DATA; return output; }
        const auto incoming = ipc::MessageServer::Caller();
        if (!incoming.id || !incoming.created || !allowed || !allowed()) {
            Reset(); output.error = ERROR_NOT_READY; return output;
        }
        if (request.operation == Operation::Release) {
            if (Same(identity, incoming) && epoch == request.epoch) Reset();
            return output;
        }
        const auto focus = CaptureLayoutTarget();
        DWORD focusSession = 0;
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, focus.processId);
        const auto own = ipc::Endpoint::Current();
        const bool systemTarget = process && !own.error && own.sid == L"S-1-5-18" &&
            ipc::ProcessAllowed(process, own) && ProcessIdToSessionId(focus.processId, &focusSession) &&
            focusSession == session && TargetStillValid(focus);
        if (process) CloseHandle(process);
        // Never turn this role into an arbitrary-process hook loader.
        if (!systemTarget) {
#ifdef CAPSLANG_SYSTEM_PROFILE_PROBE
            ProbeTrace("system-target-denied", focus, ERROR_ACCESS_DENIED);
#endif
            Reset(); output.error = ERROR_ACCESS_DENIED; return output;
        }
        if (!Alive() || !Same(identity, incoming) || epoch != request.epoch ||
            target.processId != focus.processId || target.threadId != focus.threadId) {
            Reset();
            caller = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, incoming.id);
            ipc::ProcessIdentity actual;
            auto clientPolicy = Endpoint(owner, session); clientPolicy.clientProcess = incoming;
            if (!caller || !ipc::IdentifyProcess(caller, actual) || !Same(actual, incoming) ||
                !ipc::ProcessAllowed(caller, clientPolicy)) {
#ifdef CAPSLANG_SYSTEM_PROFILE_PROBE
                ProbeTrace("system-caller-denied", focus, ERROR_ACCESS_DENIED);
#endif
                Reset(); output.error = ERROR_ACCESS_DENIED; return output;
            }
            identity = incoming; epoch = request.epoch; target = focus;
            DWORD moduleError = 0;
            const auto module = app::InstalledProfileModule(IMAGE_FILE_MACHINE_AMD64, moduleError);
            output.error = moduleError;
            attachment = std::make_unique<ProfileAttachment>(focus.processId, focus.threadId);
            if (module.empty() || !attachment->Start(module)) {
                if (!output.error) output.error = attachment->Error();
#ifdef CAPSLANG_SYSTEM_PROFILE_PROBE
                ProbeTrace("system-module-denied", focus, output.error);
#endif
                Reset(); return output;
            }
        }
        lastCall = GetTickCount64();
        const auto nonce = attachment->Binding();
        if (request.binding == nonce) {
            if (request.eventsThrough < acknowledged || request.eventsThrough > emitted) {
                output.error = ERROR_INVALID_DATA; return output;
            }
            acknowledged = request.eventsThrough;
            pending.erase(std::remove_if(pending.begin(), pending.end(),
                [&](const auto& event) { return event.serial <= acknowledged; }), pending.end());
        }
        if (!attachment->Request(static_cast<LANGID>(request.language), request.generation)) {
            output.error = ERROR_REVISION_MISMATCH; return output;
        }
        auto sample = attachment->Take();
        // Only events actually returned by the authenticated host enter this
        // bounded resend queue. Receipt ACK is scoped to this exact binding.
        for (std::size_t i = 0; i < sample.count; ++i) {
            const auto& event = sample.events[i];
            if (event.serial <= collected) continue;
            if (event.serial != collected + 1 || pending.size() == 64) {
                output.error = ERROR_MORE_DATA; Reset(); return output;
            }
            pending.push_back(event); collected = event.serial;
        }
        auto& report = output.report;
        report = sample.report; report.binding = nonce; report.process = target.processId; report.thread = target.threadId;
        if (poll == UINT64_MAX) { output.error = ERROR_ARITHMETIC_OVERFLOW; Reset(); output.report = {}; return output; }
        report.poll = ++poll; report.error = sample.error;
        report.events = {}; report.count = static_cast<std::uint32_t>(std::min(pending.size(), profile_channel::kBatch));
        for (std::size_t i = 0; i < report.count; ++i) report.events[i] = pending[i];
        if (report.count) emitted = std::max(emitted, report.events[report.count - 1].serial);
        const bool current = allowed() && TargetStillValid(focus) && GetForegroundWindow() == focus.foreground;
        const bool confirmed = current && sample.confirmed && report.confirmedGeneration == request.generation &&
            report.actual == request.language && report.profile == request.language;
        if (!confirmed) report.confirmedGeneration = 0;
        output.error = current ? sample.error : ERROR_RETRY;
        if (!current) report.error = output.error;
        return output;
    }
};
Server::Server(std::wstring owner, DWORD session, std::function<bool()> desktopAllowed)
    : impl_(std::make_unique<Impl>(std::move(owner), session, std::move(desktopAllowed))) {}
Server::~Server() = default;
bool Server::Start() {
    auto& self = *impl_;
    if (self.server) return false;
    if (!system_layout::IsSystem() || !app::ProtectedExecutable(app::ExecutablePath(), self.error) || !self.allowed) {
        self.error = ERROR_ACCESS_DENIED; return false;
    }
    auto endpoint = Endpoint(self.owner, self.session);
    endpoint.clientImage = app::ExecutablePath(); endpoint.requireClientElevation = true;
    self.server = std::make_unique<ipc::MessageServer>(endpoint, sizeof(Request), sizeof(Response),
        [&self](const void* input, void* output) {
            struct Busy { std::atomic<ULONGLONG>& value; explicit Busy(std::atomic<ULONGLONG>& v) : value(v) { value = GetTickCount64(); } ~Busy() { value = 0; } } busy(self.busy);
            std::lock_guard<std::mutex> lock(self.mutex);
            Request request; memcpy(&request, input, sizeof(request));
            const auto response = self.Handle(request); memcpy(output, &response, sizeof(response));
        });
    if (!self.server->Start()) { self.error = self.server->Error(); self.server.reset(); return false; }
    self.error = 0; return true;
}
void Server::Stop() { if (impl_->server) impl_->server->Stop(); std::lock_guard<std::mutex> lock(impl_->mutex); impl_->Reset(); }
void Server::CheckOwner() {
    std::unique_lock<std::mutex> lock(impl_->mutex, std::try_to_lock);
    if (lock.owns_lock() && impl_->attachment && (!impl_->Alive() || GetTickCount64() - impl_->lastCall >= 3000 || !impl_->allowed()))
        impl_->Reset();
}
ULONGLONG Server::BusySince() const { return impl_->busy.load(); }
DWORD Server::Error() const { return impl_->error; }

struct Client::Impl {
    std::wstring executable;
    ipc::Endpoint endpoint;
    std::uint64_t epoch = 0, id = 0, binding = 0, poll = 0;
    profile_channel::EventCursor cursor;
    explicit Impl(std::wstring image) : executable(std::move(image)) {
        const auto current = ipc::Endpoint::Current(); endpoint = Endpoint(current.sid, current.session);
        if (current.error || BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&epoch), sizeof(epoch), BCRYPT_USE_SYSTEM_PREFERRED_RNG)) epoch = 0;
    }
};
Client::Client(std::wstring executable) : impl_(std::make_unique<Impl>(std::move(executable))) {}
Client::~Client() { Release(); }
ProfileHost::Sample Client::Apply(const LayoutTarget& target, LANGID language, std::uint64_t generation) {
    auto& self = *impl_;
    ProfileHost::Sample sample;
    DWORD error = 0;
    if (!self.epoch || self.id == UINT64_MAX || !app::ProtectedExecutable(self.executable, error)) {
        sample.error = error ? error : ERROR_NOT_READY; return sample;
    }
    Request request; request.id = ++self.id; request.epoch = self.epoch;
    request.language = language; request.generation = generation; request.binding = self.binding; request.eventsThrough = self.cursor.Through();
    Response response; ipc::ProcessIdentity server;
    if (!Valid(request) || !ipc::Exchange(self.endpoint, self.executable, true, &request, sizeof(request), &response, sizeof(response), error, &server)) {
        self.endpoint.serverProcess = {}; sample.error = error ? error : ERROR_INVALID_PARAMETER; return sample;
    }
    if (!Valid(response, request)) { sample.error = ERROR_INVALID_DATA; return sample; }
    self.endpoint.serverProcess = server;
    const auto& report = response.report;
    if (!report.binding) { sample.error = response.error; return sample; }
    if (report.process != target.processId || report.thread != target.threadId || report.sampled > GetTickCount64()) {
        sample.error = ERROR_RETRY; return sample;
    }
    if (self.binding != report.binding) { self.binding = report.binding; self.poll = 0; self.cursor = {}; }
    if (report.poll <= self.poll) { sample.error = ERROR_INVALID_DATA; return sample; }
    const auto before = self.cursor.Through();
    if (!self.cursor.Accept(report)) { sample.error = ERROR_MORE_DATA; return sample; }
    self.poll = report.poll;
    for (std::size_t i = 0; i < report.count; ++i)
        if (report.events[i].serial > before) sample.events[sample.count++] = report.events[i];
    sample.report = report; sample.sampled = report.sampled; sample.error = response.error;
    if (!sample.error && (!report.sampled || GetTickCount64() - report.sampled >= 1000)) sample.error = ERROR_TIMEOUT;
    sample.confirmed = !sample.error && report.confirmedGeneration == generation && report.actual == language && report.profile == language;
    return sample;
}
void Client::Release() {
    auto& self = *impl_;
    if (!self.binding || !self.epoch || self.id == UINT64_MAX) return;
    Request request; request.operation = Operation::Release; request.id = ++self.id; request.epoch = self.epoch;
    Response response; DWORD error = 0;
    ipc::Exchange(self.endpoint, self.executable, true, &request, sizeof(request), &response, sizeof(response), error);
    self.binding = self.poll = 0; self.cursor = {};
}
} // namespace capslang::system_profile
