#pragma once
#include <array>
#include <string>
#include <string_view>

namespace capslang::core {
enum class JsonBool { Unknown, False, True };
// Bounded selective reader: retain keys on the requested path, never values
// of unrelated settings (in particular, never retain MWB's SecurityKey).
class JsonBoolReader {
public:
    JsonBoolReader(std::string_view text, std::array<std::string_view, 3> path)
        : text_(text), path_(path) {}
    JsonBool Read() {
        if (text_.size() > 1024 * 1024) return JsonBool::Unknown;
        if (text_.substr(0, 3) == "\xef\xbb\xbf") pos_ = 3;
        if (!Value(0, 0)) return JsonBool::Unknown;
        Space(); return pos_ == text_.size() && found_ == 1 ? result_ : JsonBool::Unknown;
    }
private:
    void Space() { while (pos_ < text_.size() && (text_[pos_] == ' ' || text_[pos_] == '\r' || text_[pos_] == '\n' || text_[pos_] == '\t')) ++pos_; }
    bool Take(char value) { Space(); if (pos_ == text_.size() || text_[pos_] != value) return false; ++pos_; return true; }
    bool Literal(std::string_view value) {
        if (text_.substr(pos_, value.size()) != value) return false;
        pos_ += value.size(); return true;
    }
    static int Hex(char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1; }
    bool String(std::string* key = nullptr) {
        if (!Take('"')) return false;
        while (pos_ < text_.size()) {
            unsigned char c = static_cast<unsigned char>(text_[pos_++]);
            if (c == '"') return true;
            if (c < 32) return false;
            if (c == '\\') {
                if (pos_ == text_.size()) return false;
                c = static_cast<unsigned char>(text_[pos_++]);
                if (c == 'u') {
                    unsigned value = 0;
                    for (unsigned i = 0; i < 4; ++i) {
                        if (pos_ == text_.size()) return false;
                        const int hex = Hex(text_[pos_++]); if (hex < 0) return false;
                        value = value * 16 + static_cast<unsigned>(hex);
                    }
                    // Selected keys are ASCII. Non-ASCII can never match them.
                    c = value < 128 ? static_cast<unsigned char>(value) : 255;
                } else {
                    switch (c) {
                    case '"': case '\\': case '/': break;
                    case 'b': c = '\b'; break; case 'f': c = '\f'; break;
                    case 'n': c = '\n'; break; case 'r': c = '\r'; break; case 't': c = '\t'; break;
                    default: return false;
                    }
                }
            }
            if (key) { if (key->size() >= 256) return false; key->push_back(static_cast<char>(c)); }
        }
        return false;
    }
    bool Digits() {
        const auto start = pos_;
        while (pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9') ++pos_;
        return pos_ != start;
    }
    bool Number() {
        if (pos_ < text_.size() && text_[pos_] == '-') ++pos_;
        if (pos_ == text_.size()) return false;
        if (text_[pos_] == '0') ++pos_; else if (!Digits()) return false;
        if (pos_ < text_.size() && text_[pos_] == '.') { ++pos_; if (!Digits()) return false; }
        if (pos_ < text_.size() && (text_[pos_] == 'e' || text_[pos_] == 'E')) {
            ++pos_; if (pos_ < text_.size() && (text_[pos_] == '+' || text_[pos_] == '-')) ++pos_;
            if (!Digits()) return false;
        }
        return true;
    }
    bool Value(unsigned depth, int pathIndex) {
        Space(); if (depth > 32 || pos_ == text_.size()) return false;
        if (pathIndex == 3) {
            if (++found_ != 1) return false;
            if (Literal("true")) { result_ = JsonBool::True; return true; }
            if (Literal("false")) { result_ = JsonBool::False; return true; }
            return false;
        }
        if (text_[pos_] == '{') {
            ++pos_; if (Take('}')) return true;
            unsigned matchingMembers = 0;
            do {
                std::string key;
                if (!String(pathIndex >= 0 ? &key : nullptr) || !Take(':')) return false;
                const bool match = pathIndex >= 0 && key == path_[static_cast<size_t>(pathIndex)];
                if (match && ++matchingMembers > 1) return false;
                if (!Value(depth + 1, match ? pathIndex + 1 : -1)) return false;
                if (Take('}')) return true;
            } while (Take(','));
            return false;
        }
        if (text_[pos_] == '[') {
            ++pos_; if (Take(']')) return true;
            do { if (!Value(depth + 1, -1)) return false; if (Take(']')) return true; } while (Take(','));
            return false;
        }
        if (text_[pos_] == '"') return String();
        if (Literal("true") || Literal("false") || Literal("null")) return true;
        return Number();
    }
    std::string_view text_;
    std::array<std::string_view, 3> path_;
    size_t pos_ = 0;
    unsigned found_ = 0;
    JsonBool result_ = JsonBool::Unknown;
};
inline JsonBool ReadSettingBool(std::string_view text, std::string_view name) {
    return JsonBoolReader(text, {"properties", name, "value"}).Read();
}
} // namespace capslang::core
