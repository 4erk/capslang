#pragma once
#include <windows.h>
#include <msctf.h>
#include <inputscope.h>
#include <vector>
#include <algorithm>
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
    wchar_t name[64]{}; GetClassNameW(focus,name,64);
    if (_wcsicmp(name,L"Edit") != 0) return E_NOTIMPL;
    const auto style=GetWindowLongPtrW(focus,GWL_STYLE);
    if ((style & (ES_PASSWORD|ES_READONLY)) || SendMessageW(focus,EM_GETPASSWORDCHAR,0,0)) return E_ACCESSDENIED;
    DWORD start=0,end=0; SendMessageW(focus,EM_GETSEL,reinterpret_cast<WPARAM>(&start),reinterpret_cast<LPARAM>(&end));
    const int length=GetWindowTextLengthW(focus);
    if(start==end) return S_FALSE;
    if(length<0 || length>65536 || end>static_cast<DWORD>(length)) return HRESULT_FROM_WIN32(ERROR_MORE_DATA);
    const auto limit=static_cast<ULONG_PTR>(SendMessageW(focus,EM_GETLIMITTEXT,0,0));
    if(limit && static_cast<ULONG_PTR>(length)>limit)return HRESULT_FROM_WIN32(ERROR_MORE_DATA);
    std::vector<wchar_t> buffer(length+1);
    const auto count=GetWindowTextW(focus,buffer.data(),static_cast<int>(buffer.size()));
    if(count!=length) { SecureZeroMemory(buffer.data(),buffer.size()*sizeof(wchar_t)); return E_FAIL; }
    std::wstring replacement(buffer.data()+start,buffer.data()+end);
    const auto resulting=core::InvertSelection(replacement.data(),replacement.size(),destination);
    std::wstring expected(buffer.data(),static_cast<std::size_t>(length));
    expected.replace(start,end-start,replacement);
    SendMessageW(focus,EM_REPLACESEL,TRUE,reinterpret_cast<LPARAM>(replacement.c_str()));
    std::vector<wchar_t> observed(length+1);
    const auto actualLength=GetWindowTextLengthW(focus);
    const auto actualRead=GetWindowTextW(focus,observed.data(),static_cast<int>(observed.size()));
    const bool sameLength=actualLength==length && actualRead==length;
    const bool applied=sameLength && std::equal(expected.begin(),expected.end(),observed.begin());
    const bool unchanged=sameLength && std::equal(buffer.begin(),buffer.end(),observed.begin());
    // Do not undo a previous user action if this replacement was simply refused.
    if(!applied && !unchanged) {
        SendMessageW(focus,EM_UNDO,0,0);
        const auto restoredRead=GetWindowTextW(focus,observed.data(),static_cast<int>(observed.size()));
        const bool restored=GetWindowTextLengthW(focus)==length && restoredRead==length &&
            std::equal(buffer.begin(),buffer.end(),observed.begin());
        // Some bounded controls refuse undo insertion too. Restore the captured
        // pre-edit snapshot synchronously on this same UI thread, never clipboard.
        if(!restored)SetWindowTextW(focus,buffer.data());
    }
    SendMessageW(focus,EM_SETSEL,start,end);
    SecureZeroMemory(buffer.data(),buffer.size()*sizeof(wchar_t));
    SecureZeroMemory(observed.data(),observed.size()*sizeof(wchar_t));
    SecureZeroMemory(expected.data(),expected.size()*sizeof(wchar_t));
    SecureZeroMemory(replacement.data(),replacement.size()*sizeof(wchar_t));
    return applied?SelectionOutcome(resulting):HRESULT_FROM_WIN32(ERROR_WRITE_FAULT);
}
class SelectionEdit final : public ITfEditSession {
    ULONG refs=1;
    ITfContext* context;
    core::Language fallback;
    HWND focus;
public:
    SelectionEdit(ITfContext* value,core::Language language,HWND window):context(value),fallback(language),focus(window) {context->AddRef();}
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
        const auto resulting=core::InvertSelection(buffer.data(),read,fallback);
        hr=selection.range->SetText(cookie,0,buffer.data(),read);
        SecureZeroMemory(buffer.data(),buffer.size()*sizeof(wchar_t));
        if(SUCCEEDED(hr))hr=context->SetSelection(cookie,1,&selection);
        return SUCCEEDED(hr)?SelectionOutcome(resulting):hr;
    }
};
}
