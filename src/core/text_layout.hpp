#pragma once
#include <string>
#include "keyboard.hpp"
namespace capslang::core {
constexpr std::uint32_t kSelectionEnglish=2,kSelectionRussian=3,kSelectionMixed=4;
// Physical key correspondence, not transliteration. Unmapped Unicode survives.
inline wchar_t ConvertKey(wchar_t value, Language destination) {
    constexpr wchar_t en[] = L"`qwertyuiop[]asdfghjkl;'zxcvbnm,./~QWERTYUIOP{}ASDFGHJKL:\"ZXCVBNM<>?@#$^&";
    constexpr wchar_t ru[] = L"ёйцукенгшщзхъфывапролджэячсмитьбю.ЁЙЦУКЕНГШЩЗХЪФЫВАПРОЛДЖЭЯЧСМИТЬБЮ,\"№;:?";
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
inline Language InvertSelection(wchar_t* text,std::size_t count) {
    const auto destination=SelectionDestination(text,count);
    for(std::size_t i=0;i<count;++i) {
        auto& c=text[i];
        if(Supported(destination)) c=ConvertKey(c,destination);
        else {
            // Mixed text: swap pairs with a Russian letter endpoint. Other
            // punctuation is ambiguous and remains unchanged, making this reversible.
            const auto russian=ConvertKey(c,Language::Russian);
            const auto english=ConvertKey(c,Language::English);
            if(russian!=c && ((russian>=L'а'&&russian<=L'я')||(russian>=L'А'&&russian<=L'Я')||russian==L'ё'||russian==L'Ё'))c=russian;
            else if((c>=L'а'&&c<=L'я')||(c>=L'А'&&c<=L'Я')||c==L'ё'||c==L'Ё')c=english;
        }
    }
    return destination;
}
}
