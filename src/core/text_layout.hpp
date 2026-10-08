#pragma once
#include <string>
#include "keyboard.hpp"
namespace capslang::core {
constexpr std::uint32_t kSelectionEnglish=2,kSelectionRussian=3,kSelectionMixed=4;
// Physical key correspondence, not transliteration. Unmapped Unicode survives.
inline wchar_t ConvertKey(wchar_t value, Language destination) {
    constexpr wchar_t en[] = L"`qwertyuiop[]asdfghjkl;'zxcvbnm,./~QWERTYUIOP{}ASDFGHJKL:\"ZXCVBNM<>?@#$^&|";
    constexpr wchar_t ru[] = L"ёйцукенгшщзхъфывапролджэячсмитьбю.ЁЙЦУКЕНГШЩЗХЪФЫВАПРОЛДЖЭЯЧСМИТЬБЮ,\"№;:?/";
    static_assert(sizeof(en) == sizeof(ru), "paired physical key tables");
    if (!Supported(destination)) return value;
    const auto* from = destination == Language::Russian ? en : ru;
    const auto* to = destination == Language::Russian ? ru : en;
    for (unsigned i = 0; from[i]; ++i) if (value == from[i]) return to[i];
    return value;
}
inline std::wstring ConvertText(const std::wstring& text, Language destination) {
    auto result = text;
    for (auto& value : result) value = ConvertKey(value,destination);
    return result;
}
inline Language SelectionDestination(const wchar_t* text, std::size_t count) {
    bool en=false,ru=false;
    for(std::size_t i=0;i<count;++i) {
        const auto c=text[i];
        en |= (c>=L'a'&&c<=L'z')||(c>=L'A'&&c<=L'Z');
        ru |= (c>=L'а'&&c<=L'я')||(c>=L'А'&&c<=L'Я')||c==L'ё'||c==L'Ё';
    }
    return en==ru ? Language::Unknown : en ? Language::Russian : Language::English;
}
inline Language InvertSelection(wchar_t* text,std::size_t count,Language fallback=Language::Unknown) {
    const auto selection=SelectionDestination(text,count);
    bool anyLetters=false;
    for(std::size_t i=0;i<count;++i)anyLetters |= Supported(SelectionDestination(text+i,1));
    bool changed=false;
    for(std::size_t start=0;start<count;) {
        if(text[start]==L' '||text[start]==L'\t'||text[start]==L'\r'||text[start]==L'\n'){++start;continue;}
        auto end=start;
        while(end<count && text[end]!=L' ' && text[end]!=L'\t' && text[end]!=L'\r' && text[end]!=L'\n')++end;
        auto destination=SelectionDestination(text+start,end-start);
        if(!Supported(destination))destination=Supported(selection)?selection:fallback;
        for(auto i=start;i<end;++i) {
            auto direction=destination;
            // A contiguous mixed-script token still swaps both alphabets.
            const auto letterDirection=SelectionDestination(text+i,1);
            if(!Supported(selection)&&Supported(letterDirection))direction=letterDirection;
            const auto converted=ConvertKey(text[i],direction);
            changed |= converted!=text[i];text[i]=converted;
        }
        start=end;
    }
    return !changed ? Language::Unknown : Supported(selection)?selection:
        anyLetters?Language::Unknown:fallback;
}
}
