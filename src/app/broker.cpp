#include "broker.hpp"
#include "../runtime/engine_client.hpp"
#include "desktop_profile.hpp"
#include <mutex>
#include <optional>
#include <thread>

namespace capslang::app {
namespace {
void Clear(ControlRequest &request) { SecureZeroMemory(&request, sizeof(request)); }
void Clear(net::NetworkStatus &state) {
    if (!state.invitation.empty())
        SecureZeroMemory(state.invitation.data(), state.invitation.size());
    state.invitation.clear();
}
} // namespace
struct Broker::Impl {
    std::wstring directory;
    BrokerDependencies dependencies;
    net::NetworkRuntime network;
    ipc::MessageServer server;
    mutable std::mutex mutex;
    PublicStatus status;
    net::NetworkStatus pairing;
    std::optional<ControlRequest> pending;
    HANDLE stop = nullptr, wake = nullptr, done = nullptr;
    std::thread worker;
    std::atomic<bool> show{false}, ready{false};
    std::atomic<DWORD> error{0};
    bool stopEngine = false;
    Impl(std::wstring root, BrokerDependencies deps, ipc::Endpoint endpoint)
        : directory(std::move(root)), dependencies(std::move(deps)),
          network(directory, dependencies.session),
          server(std::move(endpoint), sizeof(ControlRequest), sizeof(ControlResponse),
                 [this](const void *input, void *output) { Handle(input, output); }) {}
    ~Impl() {
        Clear(pairing);
        if (pending)
            Clear(*pending);
        for (auto handle : {stop, wake, done})
            if (handle)
                CloseHandle(handle);
    }
    void Handle(const void *input, void *output) {
        ControlRequest request;
        memcpy(&request, input, sizeof(request));
        ControlResponse response;
        response.id = request.id;
        {
            std::lock_guard<std::mutex> lock(mutex);
            response.status = status;
            if (!Valid(request))
                response.error = ERROR_INVALID_DATA;
            else if (!ready)
                response.error = ERROR_NOT_READY;
            else if (request.command == Command::Pairing) {
                response.local = pairing.local;
                response.peer = pairing.peer;
                response.pending = pairing.pendingPeer;
                response.ticket = pairing.approvalTicket;
                if (pairing.invitation.size() < sizeof(response.invitation))
                    memcpy(response.invitation, pairing.invitation.data(),
                           pairing.invitation.size());
                else
                    response.error = ERROR_INVALID_DATA;
            } else if (request.command == Command::Show)
                show = true;
            else if (request.command != Command::Status) {
                if (pending)
                    response.error = ERROR_BUSY;
                else {
                    pending = request;
                    SetEvent(wake);
                }
            }
        }
        memcpy(output, &response, sizeof(response));
        Clear(request);
        SecureZeroMemory(&response, sizeof(response));
    }
    void Log(const PublicStatus &old, const PublicStatus &next) {
        // No text input, event history, window identity, pairing code or peer
        // secrets. Only transitions/errors. Disk I/O is on the broker worker.
        if (old.engineError == next.engineError && old.engine.flags == next.engine.flags &&
            old.engine.hookError == next.engine.hookError &&
            old.engine.layoutError == next.engine.layoutError &&
            old.engine.profileError == next.engine.profileError && old.networkPhase == next.networkPhase &&
            old.networkError == next.networkError && old.commandError == next.commandError &&
            old.engine.recovery == next.engine.recovery &&
            old.engine.target == next.engine.target && old.engine.actual == next.engine.actual &&
            old.engine.generation == next.engine.generation && old.engine.revision == next.engine.revision &&
            old.engine.apply == next.engine.apply && old.peerApplied == next.peerApplied &&
            old.sharedTarget == next.sharedTarget)
            return;
        const auto path = directory + L"\\capslang.log";
        WIN32_FILE_ATTRIBUTE_DATA attr{};
        if (GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &attr) &&
            (attr.nFileSizeHigh || attr.nFileSizeLow >= 1024 * 1024)) {
            // Only fixed app log files. Do not overwrite arbitrary paths.
            MoveFileExW(path.c_str(), (directory + L"\\capslang.log.1").c_str(),
                        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
        }
        HANDLE file = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
                                  OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
            return;
        const auto line = StatusJson(next, GetTickCount64());
        DWORD written = 0;
        WriteFile(file, line.data(), static_cast<DWORD>(line.size()), &written, nullptr);
        CloseHandle(file);
    }
    bool Execute(ControlRequest &request, DWORD &failure) {
        switch (request.command) {
        case Command::Stop:
            stopEngine = true;
            SetEvent(stop);
            return true;
        case Command::Refresh:
            return dependencies.command(ipc::Operation::RefreshHook, failure);
        case Command::Invite:
            return network.Invite(request.text, static_cast<std::uint16_t>(request.port), failure);
        case Command::Join:
            return network.Join(request.text, failure);
        case Command::Confirm:
            return network.Confirm(request.ticket, request.peer, request.allow != 0, failure);
        case Command::Unpair:
            return network.Unpair(failure);
        default:
            failure = ERROR_INVALID_PARAMETER;
            return false;
        }
    }
    void Run() {
        std::unique_ptr<DesktopProfile> profile;
        if (dependencies.profile) profile = std::make_unique<DesktopProfile>();
        network.Start(); // A failed network must not take down local CapsLock.
        while (WaitForSingleObject(stop, 0) != WAIT_OBJECT_0) {
            if (profile) {
                MSG message{};
                while (PeekMessageW(&message,nullptr,0,0,PM_REMOVE)) { TranslateMessage(&message); DispatchMessageW(&message); }
            }
            std::optional<ControlRequest> command;
            {
                std::lock_guard<std::mutex> lock(mutex);
                command = pending;
                if (pending)
                    Clear(*pending);
                pending.reset();
            }
            DWORD failure = 0;
            if (command) {
                if (!Execute(*command, failure) && !failure)
                    failure = ERROR_GEN_FAILURE;
                Clear(*command);
            }
            PublicStatus next;
            DWORD readError = 0;
            if (dependencies.read(next.engine, readError))
                next.engineError = 0;
            else {
                next.engine = {};
                next.engineError = readError ? readError : ERROR_NOT_READY;
            }
            if (profile && !next.engineError) profile->Update(next.engine,
                [&](LANGID language,std::uint64_t generation,DWORD failure,bool manual) {
                    return dependencies.profile(next.engine,language,generation,failure,manual);
                });
            auto net = network.Status();
            next.sampled = GetTickCount64();
            next.networkPhase = static_cast<std::uint32_t>(net.phase);
            next.networkError = net.error;
            next.paired = net.paired;
            next.listener = net.listener;
            next.peerApplied = static_cast<std::uint32_t>(net.session.peerApplied);
            next.sharedTarget = static_cast<std::uint32_t>(net.session.target);
            next.lastNetworkError = net.lastError;
            next.lastNetworkErrorAt = net.lastErrorAt;
            PublicStatus old;
            {
                std::lock_guard<std::mutex> lock(mutex);
                old = status;
                next.commandError = command ? failure : status.commandError;
                status = next;
                Clear(pairing);
                pairing = std::move(net);
            }
            Log(old, next);
            HANDLE waits[]{stop, wake};
            MsgWaitForMultipleObjects(2, waits, FALSE, 50, QS_ALLINPUT);
        }
        network.Stop();
        if (stopEngine) {
            DWORD failure = 0;
            if (!dependencies.command(ipc::Operation::Stop, failure))
                error = failure ? failure : ERROR_GEN_FAILURE;
        }
        ready = false;
    }
};
Broker::Broker(std::wstring root, BrokerDependencies deps, ipc::Endpoint endpoint)
    : impl_(std::make_unique<Impl>(std::move(root), std::move(deps), std::move(endpoint))) {}
Broker::~Broker() { Stop(); }
bool Broker::Start() {
    auto &s = *impl_;
    if (s.worker.joinable())
        return s.ready;
    const auto elevation = ProcessElevation(GetCurrentProcessId());
    if (!elevation.known || elevation.elevated) {
        s.error = elevation.known ? ERROR_ACCESS_DENIED : elevation.error;
        return false;
    }
    if (!s.dependencies.read || !s.dependencies.command) {
        s.error = ERROR_INVALID_PARAMETER;
        return false;
    }
    if (!s.stop)
        s.stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!s.done)
        s.done = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!s.wake)
        s.wake = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!s.stop || !s.done || !s.wake) {
        s.error = GetLastError();
        return false;
    }
    ResetEvent(s.stop);
    ResetEvent(s.done);
    ResetEvent(s.wake);
    s.stopEngine = false;
    {
        std::lock_guard<std::mutex> lock(s.mutex);
        s.status = {};
        Clear(s.pairing);
        s.pairing = {};
    }
    if (!s.server.Start()) {
        s.error = s.server.Error();
        return false;
    }
    s.ready = true;
    try {
        s.worker = std::thread([&s] {
            try {
                s.Run();
            } catch (...) {
                s.error = ERROR_UNHANDLED_EXCEPTION;
                s.ready = false;
                s.network.Stop();
            }
            SetEvent(s.done);
        });
    } catch (...) {
        s.ready = false;
        s.server.Stop();
        s.error = ERROR_NOT_ENOUGH_MEMORY;
        return false;
    }
    s.error = 0;
    return true;
}
void Broker::Stop() {
    auto &s = *impl_;
    s.ready = false;
    if (s.stop)
        SetEvent(s.stop);
    s.server.Stop();
    if (s.worker.joinable())
        s.worker.join();
    std::lock_guard<std::mutex> lock(s.mutex);
    if (s.pending) {
        Clear(*s.pending);
        s.pending.reset();
    }
    Clear(s.pairing);
    s.show = false;
}
DWORD Broker::Error() const { return impl_->error; }
HANDLE Broker::Stopped() const { return impl_->done; }
bool Broker::TakeShowRequest() { return impl_->show.exchange(false); }
ControlResponse Broker::Snapshot(bool pairing) {
    ControlRequest request;
    request.id = 1;
    request.command = pairing ? Command::Pairing : Command::Status;
    ControlResponse response;
    impl_->Handle(&request, &response);
    return response;
}
bool Broker::Submit(const ControlRequest &request, DWORD &error) {
    ControlResponse response;
    impl_->Handle(&request, &response);
    error = response.error;
    SecureZeroMemory(&response, sizeof(response));
    return !error;
}
BrokerDependencies EngineDependencies(const std::wstring &executable, bool high) {
    // Separate clients: cache worker and network worker must never race the
    // client's monotonically increasing request sequence/error fields.
    auto status = std::make_shared<EngineClient>(executable, ipc::Endpoint::Current(), high);
    auto peer = std::make_shared<EngineClient>(executable, ipc::Endpoint::Current(), high);
    auto sequence = std::make_shared<std::uint64_t>(0);
    return {[status](ipc::Response &value, DWORD &error) {
                const bool ok = status->Read(value);
                error = status->Error();
                return ok;
            },
            [executable, high, sequence](ipc::Operation operation, DWORD &error) {
                ipc::Request request;
                request.id = ++*sequence;
                request.operation = operation;
                ipc::Response response;
                const bool called =
                    ipc::Call(ipc::Endpoint::Current(), executable, high, request, response, error);
                if (operation == ipc::Operation::Stop) {
                    if ((called && response.error) ||
                        (!called && error != ERROR_FILE_NOT_FOUND && error != ERROR_BROKEN_PIPE &&
                         error != ERROR_PIPE_NOT_CONNECTED && error != ERROR_OPERATION_ABORTED)) {
                        if (called)
                            error = response.error;
                        return false;
                    }
                    // The owner may tear down IPC before its final response. Do
                    // not equate that race with successful shutdown: verify the
                    // authenticated engine endpoint actually disappears.
                    const auto deadline = GetTickCount64() + 3000;
                    request.operation = ipc::Operation::Status;
                    do {
                        request.id = ++*sequence;
                        if (!ipc::Call(ipc::Endpoint::Current(), executable, high, request,
                                       response, error) &&
                            error == ERROR_FILE_NOT_FOUND) {
                            error = 0;
                            return true;
                        }
                        Sleep(20);
                    } while (GetTickCount64() < deadline);
                    error = ERROR_TIMEOUT;
                    return false;
                }
                if (!called)
                    return false;
                error = response.error;
                return !error;
            },
            {[peer](sync::LocalState &value) { return peer->ReadState(value); },
             [peer](const sync::ApplyCommand &value) { return peer->Queue(value); },
             {}},
            [executable,high,sequence](const ipc::Response& state,LANGID language,std::uint64_t generation,DWORD failure,bool manual) {
                ipc::Request request;
                request.id = ++*sequence; request.operation = manual ? ipc::Operation::ManualProfile : ipc::Operation::ReportProfile;
                request.language = language; request.engineEpoch = state.engineEpoch;
                request.expectedRevision = generation; request.reserved = failure;
                ipc::Response response; DWORD error = 0;
                return ipc::Call(ipc::Endpoint::Current(),executable,high,request,response,error) && !response.error;
            }};
}
} // namespace capslang::app
