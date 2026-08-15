#pragma once
#include <windows.h>
#include <string>

namespace hinv {
namespace util {

// argv arrives in the ANSI/UTF-8 codepage of the console; decode properly
// instead of byte-widening (which corrupts any character above 0x7F).
// MB_ERR_INVALID_CHARS makes the UTF-8 attempt actually FAIL on non-UTF-8
// input (without it, invalid sequences become U+FFFD and the ACP fallback
// never fires).
inline std::wstring ToWstring(const std::string& s) {
    if (s.empty()) return {};
    int len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0);
    UINT cp = CP_UTF8;
    if (len <= 0) { // not valid UTF-8: fall back to the ANSI codepage
        cp = CP_ACP;
        len = MultiByteToWideChar(cp, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
        if (len <= 0) return std::wstring(s.begin(), s.end());
    }
    std::wstring out(len, L'\0');
    MultiByteToWideChar(cp, 0, s.data(), static_cast<int>(s.size()), out.data(), len);
    return out;
}

} // namespace util
} // namespace hinv
