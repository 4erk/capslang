// Owned disposable application, not the installed switcher. No text is logged.
#include "../src/runtime/thread_profile.hpp"
#include <windows.h>
namespace {
HWND window=nullptr,field=nullptr,label=nullptr;
HHOOK hook=nullptr;
capslang::ThreadProfile profile(nullptr,nullptr,nullptr,true);
bool held=false;
LRESULT CALLBACK Keyboard(int code,WPARAM message,LPARAM pointer) {
    if(code!=HC_ACTION)return CallNextHookEx(hook,code,message,pointer);
    const auto& key=*reinterpret_cast<KBDLLHOOKSTRUCT*>(pointer);
    if(key.vkCode==VK_CAPITAL && GetForegroundWindow()==window) {
        const bool down=message==WM_KEYDOWN||message==WM_SYSKEYDOWN;
        if(held) {if(!down)held=false;return 1;}
        if(down && (GetAsyncKeyState(VK_CONTROL)&0x8000) && !(GetAsyncKeyState(VK_SHIFT)&0x8000)) {
            held=true;PostMessageW(window,WM_APP+1,0,0);return 1;
        }
    }
    return CallNextHookEx(hook,code,message,pointer);
}
LRESULT CALLBACK Window(HWND hwnd,UINT message,WPARAM wp,LPARAM lp) {
    switch(message) {
    case WM_CREATE:
        window=hwnd;
        label=CreateWindowW(L"STATIC",L"Выделите ghbdtn и нажмите Ctrl+CapsLock. Повторное нажатие вернёт текст.",WS_CHILD|WS_VISIBLE,12,12,570,40,hwnd,nullptr,nullptr,nullptr);
        field=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"ghbdtn",WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_MULTILINE,12,60,570,100,hwnd,nullptr,nullptr,nullptr);
        SetTimer(hwnd,1,150000,nullptr);return 0;
    case WM_APP+1: {
        const LANGID before=LOWORD(reinterpret_cast<ULONG_PTR>(GetKeyboardLayout(0)));
        const LANGID destination=before==0x419 ? 0x409 : 0x419;
        const auto converted=profile.ConvertSelection(destination);
        if(converted==2||converted==3)profile.Apply(converted==2?0x409:0x419,GetTickCount64());
        wchar_t status[128]{};wsprintfW(status,L"Результат операции: 0x%08X. Буфер обмена не используется.",static_cast<unsigned>(converted));
        SetWindowTextW(label,status);return 0;
    }
    case WM_TIMER:DestroyWindow(hwnd);return 0;
    case WM_DESTROY:PostQuitMessage(0);return 0;
    }
    return DefWindowProcW(hwnd,message,wp,lp);
}
}
int WINAPI wWinMain(HINSTANCE instance,HINSTANCE,LPWSTR,int) {
    profile.Bind();
    profile.Apply(0x409,1);
    WNDCLASSW cls{};cls.hInstance=instance;cls.lpfnWndProc=Window;cls.lpszClassName=L"CapsLang.SelectionFixture";
    RegisterClassW(&cls);
    window=CreateWindowW(cls.lpszClassName,L"CapsLang — тест выделенного текста",WS_OVERLAPPEDWINDOW,CW_USEDEFAULT,CW_USEDEFAULT,620,230,nullptr,nullptr,instance,nullptr);
    if(!window)return 1;
    hook=SetWindowsHookExW(WH_KEYBOARD_LL,Keyboard,instance,0);
    if(!hook){DestroyWindow(window);return 2;}
    ShowWindow(window,SW_SHOW);SetForegroundWindow(window);SetFocus(field);SendMessageW(field,EM_SETSEL,0,6);
    MSG message{};while(GetMessageW(&message,nullptr,0,0)>0){TranslateMessage(&message);DispatchMessageW(&message);}
    UnhookWindowsHookEx(hook);profile.Unbind();return 0;
}
