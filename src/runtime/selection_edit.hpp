#pragma once
#include <windows.h>
#include <msctf.h>
#include <inputscope.h>
#include <vector>
#include "../core/text_layout.hpp"
namespace capslang {
// Successful edit outcomes carry only resulting language, never selected text.
inline constexpr HRESULT kSelectionEnglish=core::kSelectionEnglish,kSelectionRussian=core::kSelectionRussian,kSelectionMixed=core::kSelectionMixed;
inline HRESULT SelectionOutcome(core::Language language) {
    return language==core::Language::English?kSelectionEnglish:language==core::Language::Russian?kSelectionRussian:kSelectionMixed;
}
// MinGW's uuid import library omits these documented inputscope.h GUIDs.
inline constexpr GUID kInputScopeProperty{0x1713dd5a,0x68e7,0x4a5b,{0x9a,0xf6,0x59,0x2a,0x59,0x5c,0x77,0x8d}};
inline constexpr GUID kInputScopeInterface{0xfde1eaee,0x6924,0x4cdf,{0x91,0xe7,0xda,0x38,0xcf,0xf5,0x55,0x9d}};
// Executed only on the application's own foreground UI thread. No clipboard,
// synthetic input, transport or logging of content.
inline HRESULT ConvertClassicSelection(HWND focus, core::Language destination) {
    (void)destination; // Direction is determined by the selection, not the keyboard.
    wchar_t name[64]{}; GetClassNameW(focus,name,64);
    if (_wcsicmp(name,L"Edit") != 0) return E_NOTIMPL;
    const auto style=GetWindowLongPtrW(focus,GWL_STYLE);
    if ((style & (ES_PASSWORD|ES_READONLY)) || SendMessageW(focus,EM_GETPASSWORDCHAR,0,0)) return E_ACCESSDENIED;
    DWORD start=0,end=0; SendMessageW(focus,EM_GETSEL,reinterpret_cast<WPARAM>(&start),reinterpret_cast<LPARAM>(&end));
    const int length=GetWindowTextLengthW(focus);
    if(start==end) return S_FALSE;
    if(length<0 || length>65536 || end>static_cast<DWORD>(length)) return HRESULT_FROM_WIN32(ERROR_MORE_DATA);
    std::vector<wchar_t> buffer(length+1);
    const auto count=GetWindowTextW(focus,buffer.data(),static_cast<int>(buffer.size()));
    if(count!=length) { SecureZeroMemory(buffer.data(),buffer.size()*sizeof(wchar_t)); return E_FAIL; }
    std::wstring replacement(buffer.data()+start,buffer.data()+end);
    SecureZeroMemory(buffer.data(),buffer.size()*sizeof(wchar_t));
    const auto resulting=core::InvertSelection(replacement.data(),replacement.size());
    SendMessageW(focus,EM_REPLACESEL,TRUE,reinterpret_cast<LPARAM>(replacement.c_str()));
    SendMessageW(focus,EM_SETSEL,start,end);
    SecureZeroMemory(replacement.data(),replacement.size()*sizeof(wchar_t));
    return SelectionOutcome(resulting);
}
class SelectionEdit final : public ITfEditSession {
    ULONG refs=1;
    ITfContext* context;
    HWND focus;
public:
    SelectionEdit(ITfContext* value,core::Language language,HWND window):context(value),focus(window) {(void)language;context->AddRef();}
    ~SelectionEdit(){context->Release();}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid,void** out) override {
        if(!out) return E_POINTER; *out=nullptr;
        if(iid!=IID_IUnknown && iid!=IID_ITfEditSession) return E_NOINTERFACE;
        *out=static_cast<ITfEditSession*>(this); AddRef(); return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override{return ++refs;}
    ULONG STDMETHODCALLTYPE Release() override{auto n=--refs;if(!n)delete this;return n;}
    HRESULT STDMETHODCALLTYPE DoEditSession(TfEditCookie cookie) override {
        if(GetFocus()!=focus || GetWindowThreadProcessId(GetForegroundWindow(),nullptr)!=GetCurrentThreadId()) return HRESULT_FROM_WIN32(ERROR_CANCELLED);
        TF_SELECTION selection{}; ULONG fetched=0;
        HRESULT hr=context->GetSelection(cookie,TF_DEFAULT_SELECTION,1,&selection,&fetched);
        if(FAILED(hr) || !fetched || !selection.range) return FAILED(hr)?hr:S_FALSE;
        struct ReleaseRange {ITfRange* value;~ReleaseRange(){value->Release();}} release{selection.range};
        BOOL empty=TRUE; hr=selection.range->IsEmpty(cookie,&empty); if(FAILED(hr)||empty)return FAILED(hr)?hr:S_FALSE;
        // Fail closed if an app cannot provide input-scope privacy metadata.
        ITfReadOnlyProperty* property=nullptr;
        hr=context->GetAppProperty(kInputScopeProperty,&property);
        if(FAILED(hr)||!property)return E_ACCESSDENIED;
        VARIANT value;VariantInit(&value); hr=property->GetValue(cookie,selection.range,&value);property->Release();
        ITfInputScope* scope=nullptr;
        if(SUCCEEDED(hr)&&value.vt==VT_UNKNOWN&&value.punkVal)hr=value.punkVal->QueryInterface(kInputScopeInterface,reinterpret_cast<void**>(&scope));
        else hr=E_ACCESSDENIED;
        VariantClear(&value);
        if(FAILED(hr)||!scope)return E_ACCESSDENIED;
        InputScope* scopes=nullptr;UINT count=0;hr=scope->GetInputScopes(&scopes,&count);scope->Release();
        bool password=FAILED(hr);for(UINT i=0;i<count&&scopes;++i)if(scopes[i]==IS_PASSWORD)password=true;
        CoTaskMemFree(scopes);if(password)return E_ACCESSDENIED;
        std::vector<wchar_t> buffer(65537);ULONG read=0;
        hr=selection.range->GetText(cookie,0,buffer.data(),static_cast<ULONG>(buffer.size()),&read);
        if(FAILED(hr)||read==buffer.size()){SecureZeroMemory(buffer.data(),buffer.size()*sizeof(wchar_t));return FAILED(hr)?hr:HRESULT_FROM_WIN32(ERROR_MORE_DATA);}
        if(!read)return S_FALSE;
        const auto resulting=core::InvertSelection(buffer.data(),read);
        hr=selection.range->SetText(cookie,0,buffer.data(),read);
        SecureZeroMemory(buffer.data(),buffer.size()*sizeof(wchar_t));
        if(SUCCEEDED(hr))hr=context->SetSelection(cookie,1,&selection);
        return SUCCEEDED(hr)?SelectionOutcome(resulting):hr;
    }
};
}
