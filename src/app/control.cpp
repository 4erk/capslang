#include "control.hpp"
#include <algorithm>
#include <sstream>

namespace capslang::app {
namespace {
bool Empty(const char *data, size_t bytes) {
    for (size_t i = 0; i < bytes; ++i)
        if (data[i])
            return false;
    return true;
}
bool Text(const char *data, size_t bytes, std::string &output) {
    const auto *end = static_cast<const char *>(memchr(data, 0, bytes));
    if (!end || !Empty(end, bytes - static_cast<size_t>(end - data)))
        return false;
    output.assign(data, end);
    return true;
}
const wchar_t *AppliedText(std::uint32_t value) {
    switch (static_cast<sync::Applied>(value)) {
    case sync::Applied::None:
        return L"нет подтверждения";
    case sync::Applied::Pending:
        return L"ожидается";
    case sync::Applied::Yes:
        return L"подтверждено";
    case sync::Applied::Failed:
        return L"не удалось";
    case sync::Applied::Locked:
        return L"устройство заблокировано";
    }
    return L"неизвестно";
}
const wchar_t *ApplyText(std::uint32_t value) {
    switch (static_cast<core::ApplyState>(value)) {
    case core::ApplyState::Idle:
        return L"нет запроса";
    case core::ApplyState::Pending:
        return L"ожидается";
    case core::ApplyState::Applied:
        return L"подтверждено";
    case core::ApplyState::Failed:
        return L"не удалось";
    case core::ApplyState::Locked:
        return L"сеанс заблокирован";
    }
    return L"неизвестно";
}
} // namespace
bool Valid(const ControlRequest &value) {
    if (value.magic != kControlMagic || value.version != kControlVersion || !value.id ||
        value.reserved)
        return false;
    std::string text;
    if (!Text(value.text, sizeof(value.text), text))
        return false;
    struct Clear {
        std::string &s;
        ~Clear() {
            if (!s.empty())
                SecureZeroMemory(s.data(), s.size());
        }
    } clear{text};
    if (value.command == Command::Confirm)
        return value.ticket && !net::EqualPin(value.peer, {}) && value.allow <= 1 && !value.port &&
               text.empty();
    if (value.ticket || !net::EqualPin(value.peer, {}) || value.allow)
        return false;
    if (value.command == Command::Invite)
        return value.port >= 1024 && value.port <= 65535 && net::ValidHost(text);
    if (value.port)
        return false;
    if (value.command == Command::Join) {
        net::InvitationCode invitation;
        const bool ok = net::DecodeInvitation(text, invitation);
        SecureZeroMemory(invitation.secret.data(), invitation.secret.size());
        return ok;
    }
    if (!text.empty())
        return false;
    switch (value.command) {
    case Command::Status:
    case Command::Show:
    case Command::Refresh:
    case Command::Stop:
    case Command::Pairing:
    case Command::Unpair:
        return true;
    default:
        return false;
    }
}
ipc::Endpoint ControlEndpoint() { return ipc::Endpoint::Current(L"1.1-ui"); }
bool ControlCall(const std::wstring &executable, const ControlRequest &request,
                 ControlResponse &response, DWORD &error, const ipc::Endpoint &endpoint) {
    if (!Valid(request)) {
        error = ERROR_INVALID_PARAMETER;
        return false;
    }
    ControlResponse incoming;
    if (!ipc::Exchange(endpoint, executable, false, &request, sizeof(request), &incoming,
                       sizeof(incoming), error))
        return false;
    const bool valid = incoming.magic == kControlMagic && incoming.version == kControlVersion &&
                       incoming.id == request.id &&
                       (request.command == Command::Pairing ||
                        (!incoming.ticket && net::EqualPin(incoming.local, {}) &&
                         net::EqualPin(incoming.peer, {}) && net::EqualPin(incoming.pending, {}) &&
                         Empty(incoming.invitation, sizeof(incoming.invitation))));
    if (!valid || !memchr(incoming.invitation, 0, sizeof(incoming.invitation))) {
        SecureZeroMemory(&incoming, sizeof(incoming));
        error = ERROR_INVALID_DATA;
        return false;
    }
    response = incoming;
    SecureZeroMemory(&incoming, sizeof(incoming));
    error = 0;
    return true;
}
const wchar_t *LanguageText(std::uint32_t language) {
    return language == 0x409 ? L"EN" : language == 0x419 ? L"RU" : L"?";
}
const wchar_t *NetworkText(std::uint32_t phase) {
    switch (static_cast<net::NetworkPhase>(phase)) {
    case net::NetworkPhase::Starting:
        return L"запуск";
    case net::NetworkPhase::Unpaired:
        return L"нет пары";
    case net::NetworkPhase::Inviting:
        return L"ожидание второго устройства";
    case net::NetworkPhase::AwaitApproval:
        return L"нужно подтверждение пары";
    case net::NetworkPhase::Joining:
        return L"сопряжение";
    case net::NetworkPhase::Connecting:
        return L"подключение";
    case net::NetworkPhase::AwaitInput:
        return L"ожидание явного переключения языка";
    case net::NetworkPhase::Active:
        return L"соединение активно";
    case net::NetworkPhase::Error:
        return L"ошибка";
    case net::NetworkPhase::Stopped:
        return L"остановлено";
    }
    return L"неизвестно";
}
std::string StatusJson(const PublicStatus &s, std::uint64_t now) {
    // Allowlist only. Never serialize NetworkStatus or arbitrary OS strings.
    std::ostringstream out;
    const bool fresh = s.sampled && now >= s.sampled && now - s.sampled <= 3000;
    const auto &e = s.engine;
    out << "{\"version\":\"" << kVersion << "\",\"fresh\":" << (fresh ? "true" : "false")
        << ",\"engine_error\":" << s.engineError << ",\"target\":" << e.target
        << ",\"actual\":" << e.actual << ",\"apply\":" << e.apply
        << ",\"elevated\":" << ((e.flags & ipc::Elevated) ? "true" : "false")
        << ",\"hook_registered\":" << ((e.flags & ipc::HookRegistered) ? "true" : "false")
        << ",\"hook_responsive\":" << ((e.flags & ipc::HookResponsive) ? "true" : "false")
        << ",\"locked\":" << ((e.flags & ipc::Locked) ? "true" : "false")
        << ",\"hook_error\":" << e.hookError << ",\"layout_error\":" << e.layoutError
        << ",\"profile_error\":" << e.profileError
        << ",\"profile_language\":" << e.profileLanguage
        << ",\"profile_scope\":\"" << ((e.flags & ipc::TargetThreadProfile) ? "target_thread" : "broker_thread") << "\""
        << ",\"profile_generation\":" << e.profileGeneration
        << ",\"generation\":" << e.generation << ",\"revision\":" << e.revision
        << ",\"profile_confirmed\":" << ((e.flags & ipc::ProfileConfirmed) ? "true" : "false")
        << ",\"system_enabled\":" << ((e.flags & ipc::SystemEnabled) ? "true" : "false")
        << ",\"last_recovery_tick\":" << e.recovery << ",\"mwb_flags\":" << e.mwbFlags
        << ",\"mwb_error\":" << e.mwbError << ",\"network_phase\":" << s.networkPhase
        << ",\"network_error\":" << s.networkError
        << ",\"paired\":" << (s.paired ? "true" : "false")
        << ",\"listener\":" << (s.listener ? "true" : "false")
        << ",\"peer_applied\":" << s.peerApplied << ",\"shared_target\":" << s.sharedTarget
        << ",\"last_network_error\":" << s.lastNetworkError
        << ",\"last_network_error_tick\":" << s.lastNetworkErrorAt
        << ",\"command_error\":" << s.commandError << "}\n";
    return out.str();
}
std::wstring StatusText(const PublicStatus &s, std::uint64_t now) {
    std::wostringstream out;
    out << L"CapsLang 1.1.0-rc.2 — предварительная версия\r\n";
    if (!s.sampled || now < s.sampled || now - s.sampled > 3000)
        out << L"Состояние устарело или ещё не получено.\r\n";
    if (s.engineError)
        out << L"Движок недоступен: " << s.engineError << L"\r\n";
    else {
        const auto &e = s.engine;
        out << L"Язык: " << LanguageText(e.actual) << L"; цель: " << LanguageText(e.target)
            << L"\r\n"
            << L"Права: "
            << ((e.flags & ipc::Elevated) ? L"повышенные"
                                          : L"ограниченные — повышенные окна не поддерживаются")
            << L"\r\n"
            << L"Перехватчик: "
            << ((e.flags & ipc::HookRegistered) && (e.flags & ipc::HookResponsive) ? L"отвечает"
                                                                                   : L"не готов")
            << L"; ошибка: " << e.hookError << L"\r\n"
            << L"Применение: " << ApplyText(e.apply) << L"; ошибка: " << e.layoutError << L"\r\n"
            << L"MWB: " << ((e.mwbFlags & ipc::MwbRunning) ? L"запущен" : L"не запущен")
            << L"\r\n"
            << ((e.flags & ipc::TargetThreadProfile) ? L"Профиль рабочего потока: " :
                L"Профиль фонового процесса (не системный индикатор): ")
            << LanguageText(static_cast<std::uint32_t>(e.profileLanguage))
            << L"; подтверждение текущего запроса: " << ((e.flags & ipc::ProfileConfirmed) ? L"да" : L"нет")
            << L"; ошибка: " << e.profileError << L"\r\n"
            << L"Доступ к SYSTEM-окнам: " << ((e.flags & ipc::SystemEnabled) ? L"включён" : L"нет") << L"\r\n";
        if (e.recovery && now >= e.recovery)
            out << L"Восстановление hook: " << (now - e.recovery) / 1000 << L" сек. назад\r\n";
    }
    out << L"Второе устройство: " << NetworkText(s.networkPhase) << L"; ошибка: " << s.networkError
        << L"\r\n"
        << L"Применение на втором устройстве: " << AppliedText(s.peerApplied) << L"\r\n";
    if (s.commandError)
        out << L"Последняя команда: ошибка " << s.commandError << L"\r\n";
    return out.str();
}
} // namespace capslang::app
