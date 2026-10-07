#include "window.hpp"
#include "paths.hpp"
#include <commctrl.h>

namespace capslang::app {
namespace {
enum : int {
    Refresh = 101,
    Invite = 102,
    Join = 103,
    Approve = 104,
    Deny = 105,
    Unpair = 106,
    Diagnose = 107,
    Exit = 108,
    Install = 109,
    Rollback = 110,
    Legacy = 111,
    Uninstall = 112,
    Host = 201,
    Code = 202,
    Invitation = 203
};
std::wstring Wide(const std::string &value) { return std::wstring(value.begin(), value.end()); }
std::wstring PinText(const net::Pin &pin) {
    std::wstring result;
    for (size_t i = 0; i < pin.size(); ++i) {
        if (i && i % 4 == 0)
            result += L' ';
        result += L"0123456789ABCDEF"[pin[i] >> 4];
        result += L"0123456789ABCDEF"[pin[i] & 15];
    }
    return result;
}
std::string AsciiText(HWND window, int id) {
    wchar_t value[512]{};
    const int length = GetDlgItemTextW(window, id, value, ARRAYSIZE(value));
    std::string out;
    for (int i = 0; i < length; ++i) {
        if (value[i] > 127) {
            out.clear();
            break;
        }
        out += static_cast<char>(value[i]);
    }
    SecureZeroMemory(value, sizeof(value));
    return out;
}
void Error(HWND window, DWORD error) {
    const auto text = L"Операция не выполнена. Код: " + std::to_wstring(error);
    MessageBoxW(window, text.c_str(), L"CapsLang", MB_OK | MB_ICONERROR);
}
struct Window {
    Broker &broker;
    std::wstring directory;
    HANDLE ownedEngineShutdown = nullptr;
    HWND hwnd = nullptr, status = nullptr, fingerprints = nullptr;
    std::uint64_t sequence = 1, ticket = 0;
    net::Pin pending{};
    bool shown = false;
    HWND Add(const wchar_t *type, const wchar_t *text, DWORD style, int id, int x, int y, int width,
             int height) {
        HWND child = CreateWindowExW(type == std::wstring(L"EDIT") ? WS_EX_CLIENTEDGE : 0, type,
                                     text, WS_CHILD | WS_VISIBLE | style, x, y, width, height, hwnd,
                                     reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
                                     GetModuleHandleW(nullptr), nullptr);
        SendMessageW(child, WM_SETFONT, reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)),
                     TRUE);
        return child;
    }
    void Create() {
        HMENU menu = CreateMenu(), actions = CreatePopupMenu();
        AppendMenuW(actions, MF_STRING, Install, L"Установить / обновить");
        AppendMenuW(actions, MF_STRING, Rollback, L"Откат к предыдущей установленной сборке");
        AppendMenuW(actions, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(actions, MF_STRING, Uninstall, L"Удалить CapsLang");
        AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(actions), L"Приложение");
        SetMenu(hwnd, menu);
        status = Add(L"EDIT", L"Получение состояния…", ES_MULTILINE | ES_READONLY | WS_VSCROLL, 0,
                     16, 12, 744, 230);
        Add(L"BUTTON", L"Перезапустить hook", WS_TABSTOP, Refresh, 16, 250, 160, 30);
        Add(L"BUTTON", L"Экспорт диагностики", WS_TABSTOP, Diagnose, 186, 250, 170, 30);
        Add(L"BUTTON", L"Отключить пару", WS_TABSTOP, Unpair, 366, 250, 150, 30);
        Add(L"BUTTON", L"Остановить CapsLang", WS_TABSTOP, Exit, 526, 250, 190, 30);
        Add(L"STATIC", L"Создать приглашение на слушающем устройстве (обычно ПК):", 0, 0, 16, 297,
            720, 22);
        wchar_t host[256]{};
        DWORD size = ARRAYSIZE(host);
        GetComputerNameW(host, &size);
        Add(L"EDIT", host, ES_AUTOHSCROLL | WS_TABSTOP, Host, 16, 322, 360, 26);
        Add(L"BUTTON", L"Создать код (5 минут)", WS_TABSTOP, Invite, 390, 320, 220, 30);
        Add(L"EDIT", L"", ES_AUTOHSCROLL | ES_READONLY | WS_TABSTOP, Invitation, 16, 360, 744, 26);
        Add(L"STATIC",
            L"На втором устройстве: вставить код, подключиться, затем подтвердить пару на ПК.", 0,
            0, 16, 403, 744, 22);
        Add(L"EDIT", L"", ES_AUTOHSCROLL | WS_TABSTOP, Code, 16, 430, 555, 26);
        SendDlgItemMessageW(hwnd, Code, EM_SETLIMITTEXT, 370, 0);
        SendDlgItemMessageW(hwnd, Host, EM_SETLIMITTEXT, 253, 0);
        Add(L"BUTTON", L"Подключиться", WS_TABSTOP, Join, 585, 428, 175, 30);
        fingerprints = Add(L"EDIT", L"", ES_MULTILINE | ES_READONLY, 0, 16, 475, 744, 90);
        Add(L"BUTTON", L"Подтвердить этот отпечаток", WS_TABSTOP, Approve, 16, 578, 250, 30);
        Add(L"BUTTON", L"Отказать", WS_TABSTOP, Deny, 280, 578, 120, 30);
        Add(L"STATIC",
            L"Закрытие окна оставляет CapsLang в фоне. Код приглашения не включается в "
            L"диагностику.",
            0, 0, 16, 625, 744, 34);
        SetTimer(hwnd, 1, 250, nullptr);
    }
    void Show() {
        shown = true;
        ShowWindow(hwnd, SW_SHOWNORMAL);
        SetForegroundWindow(hwnd);
    }
    void Update() {
        if (broker.TakeShowRequest())
            Show();
        if (WaitForSingleObject(broker.Stopped(), 0) == WAIT_OBJECT_0 ||
            (ownedEngineShutdown && WaitForSingleObject(ownedEngineShutdown, 0) == WAIT_OBJECT_0)) {
            DestroyWindow(hwnd);
            return;
        }
        // The broker-owned saver thread retries its lease itself. The window
        // must not spawn a competing standalone guard during lease handoff.
        if (!IsWindowVisible(hwnd))
            return;
        auto snapshot = broker.Snapshot(true);
        SetWindowTextW(status, StatusText(snapshot.status, GetTickCount64()).c_str());
        auto invitation = Wide(snapshot.invitation);
        SetDlgItemTextW(hwnd, Invitation, invitation.c_str());
        if (!invitation.empty())
            SecureZeroMemory(invitation.data(), invitation.size() * sizeof(wchar_t));
        ticket = snapshot.ticket;
        pending = snapshot.pending;
        auto pins = L"Это устройство: " + PinText(snapshot.local) + L"\r\n";
        pins += ticket ? L"Запрос пары: " + PinText(pending)
                       : L"Сохранённая пара: " + PinText(snapshot.peer);
        SetWindowTextW(fingerprints, pins.c_str());
        EnableWindow(GetDlgItem(hwnd, Approve), ticket != 0);
        EnableWindow(GetDlgItem(hwnd, Deny), ticket != 0);
        SecureZeroMemory(&snapshot, sizeof(snapshot));
    }
    void OnCommand(int id) {
        ControlRequest request;
        request.id = ++sequence;
        DWORD error = 0;
        if (id == Install || id == Rollback || id == Uninstall) {
            if (id != Install && MessageBoxW(hwnd,
                                             L"Остановить текущий CapsLang и выполнить выбранное "
                                             L"действие? Файлы прежних версий сохранятся.",
                                             L"CapsLang", MB_YESNO | MB_DEFBUTTON2) != IDYES)
                return;
            const auto *option = id == Install    ? L"--install"
                                 : id == Rollback ? L"--rollback"
                                                  : L"--uninstall";
            if (!StartSelf(option, error))
                Error(hwnd, error);
            return;
        }
        if (id == Diagnose) {
            auto snapshot = broker.Snapshot();
            std::wstring path;
            if (ExportDiagnosis(directory, StatusJson(snapshot.status, GetTickCount64()), path,
                                error))
                MessageBoxW(hwnd, (L"Сохранено:\r\n" + path).c_str(), L"CapsLang", MB_OK);
            else
                Error(hwnd, error);
            return;
        }
        switch (id) {
        case Refresh:
            request.command = Command::Refresh;
            break;
        case Exit:
            request.command = Command::Stop;
            break;
        case Unpair:
            if (MessageBoxW(hwnd, L"Отключить пару? Локальное переключение продолжит работать.",
                            L"CapsLang", MB_YESNO | MB_DEFBUTTON2) != IDYES)
                return;
            request.command = Command::Unpair;
            break;
        case Invite:
        case Join: {
            auto text = AsciiText(hwnd, id == Invite ? Host : Code);
            if (text.size() >= sizeof(request.text)) {
                Error(hwnd, ERROR_INVALID_DATA);
                return;
            }
            memcpy(request.text, text.data(), text.size());
            if (!text.empty())
                SecureZeroMemory(text.data(), text.size());
            request.command = id == Invite ? Command::Invite : Command::Join;
            if (id == Invite)
                request.port = 42519;
            else
                SetDlgItemTextW(hwnd, Code, L"");
            break;
        }
        case Approve:
        case Deny:
            request.command = Command::Confirm;
            request.ticket = ticket;
            request.peer = pending;
            request.allow = id == Approve;
            break;
        default:
            return;
        }
        if (!broker.Submit(request, error))
            Error(hwnd, error);
        SecureZeroMemory(&request, sizeof(request));
    }
    static LRESULT CALLBACK Proc(HWND hwnd, UINT message, WPARAM wp, LPARAM lp) {
        auto *self = reinterpret_cast<Window *>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        if (message == WM_NCCREATE) {
            self = static_cast<Window *>(reinterpret_cast<CREATESTRUCTW *>(lp)->lpCreateParams);
            self->hwnd = hwnd;
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        }
        if (!self)
            return DefWindowProcW(hwnd, message, wp, lp);
        switch (message) {
        case WM_CREATE:
            self->Create();
            return 0;
        case WM_TIMER:
            self->Update();
            return 0;
        case WM_COMMAND:
            if (HIWORD(wp) == BN_CLICKED)
                self->OnCommand(LOWORD(wp));
            return 0;
        case WM_CLOSE:
            SetDlgItemTextW(hwnd, Code, L"");
            SetDlgItemTextW(hwnd, Invitation, L"");
            ShowWindow(hwnd, SW_HIDE);
            return 0;
        case WM_QUERYENDSESSION:
            return TRUE;
        case WM_ENDSESSION:
            if (wp)
                DestroyWindow(hwnd);
            return 0;
        case WM_DESTROY:
            KillTimer(hwnd, 1);
            PostQuitMessage(0);
            return 0;
        default:
            return DefWindowProcW(hwnd, message, wp, lp);
        }
    }
};
} // namespace
int RunWindow(Broker &broker, const std::wstring &directory, bool show, HANDLE ownedEngineShutdown) {
    Window window{broker, directory, ownedEngineShutdown};
    WNDCLASSW cls{};
    cls.lpfnWndProc = Window::Proc;
    cls.hInstance = GetModuleHandleW(nullptr);
    cls.lpszClassName = L"CapsLang.Status.1.1";
    cls.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    cls.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    if (!RegisterClassW(&cls) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
        return static_cast<int>(GetLastError());
    HWND hwnd =
        CreateWindowExW(0, cls.lpszClassName, L"CapsLang 1.1.0-rc.2",
                        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, CW_USEDEFAULT,
                        CW_USEDEFAULT, 800, 715, nullptr, nullptr, cls.hInstance, &window);
    if (!hwnd)
        return static_cast<int>(GetLastError());
    if (show)
        window.Show();
    MSG message{};
    BOOL result;
    while ((result = GetMessageW(&message, nullptr, 0, 0)) > 0) {
        if (!IsDialogMessageW(hwnd, &message)) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    return result < 0 ? static_cast<int>(GetLastError()) : 0;
}
} // namespace capslang::app
