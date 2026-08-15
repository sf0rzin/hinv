#pragma once
#include <windows.h>
#include <cstddef>
#include <cwchar>
#include <iterator>
#include <limits>
#include <string>
#include <string_view>
#include <utility>

namespace hinv {

namespace ipc {

// The cap applies to the complete named-pipe message, including its trailing
// newline. Both the server and header-only client use these protocol limits.
inline constexpr std::size_t kMaxMessageBytes = 64 * 1024;
inline constexpr DWORD kDefaultOperationTimeoutMs = 120000;

inline DWORD OperationTimeoutMs() {
    static const DWORD timeout = [] {
        wchar_t buffer[32]{};
        const DWORD length = GetEnvironmentVariableW(
            L"HINV_IPC_TIMEOUT_MS", buffer, static_cast<DWORD>(std::size(buffer)));
        if (length == 0 || length >= std::size(buffer)) return kDefaultOperationTimeoutMs;
        wchar_t* end = nullptr;
        const unsigned long parsed = std::wcstoul(buffer, &end, 10);
        if (!end || *end != L'\0' || parsed < 1000 || parsed > 900000)
            return kDefaultOperationTimeoutMs;
        return static_cast<DWORD>(parsed);
    }();
    return timeout;
}

} // namespace ipc

namespace util {

// IPC narrow strings are UTF-8 by definition. Never fall back to the active
// ANSI code page: doing so makes the same byte sequence name different files
// on different machines.
inline bool Utf8ToWide(std::string_view input, std::wstring* output) {
    if (!output || input.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
        return false;
    if (input.empty()) {
        output->clear();
        return true;
    }

    const int inputLength = static_cast<int>(input.size());
    const int length = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), inputLength, nullptr, 0);
    if (length <= 0) return false;

    std::wstring converted(static_cast<std::size_t>(length), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), inputLength,
                            converted.data(), length) != length)
        return false;
    *output = std::move(converted);
    return true;
}

inline bool WideToUtf8(std::wstring_view input, std::string* output) {
    if (!output || input.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
        return false;
    if (input.empty()) {
        output->clear();
        return true;
    }

    const int inputLength = static_cast<int>(input.size());
    const int length = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, input.data(), inputLength, nullptr, 0, nullptr, nullptr);
    if (length <= 0) return false;

    std::string converted(static_cast<std::size_t>(length), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, input.data(), inputLength,
                            converted.data(), length, nullptr, nullptr) != length)
        return false;
    *output = std::move(converted);
    return true;
}

// Retain the convenience API, but with the strict UTF-8 contract above.
inline std::wstring ToWstring(const std::string& input) {
    std::wstring output;
    Utf8ToWide(input, &output);
    return output;
}

} // namespace util
} // namespace hinv
