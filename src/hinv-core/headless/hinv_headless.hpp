#pragma once
#include <windows.h>
#include <string>
#include <atomic>
#include <memory>

#include "../hinv_byovd.hpp"

namespace hinv {
namespace headless {

constexpr const wchar_t* HINV_PIPE_NAME = L"\\\\.\\pipe\\hinv_headless";

struct HeadlessConfig {
    bool        silentMode = true;
    bool        autoCloakDriver = true;
    std::string scriptPath = "";
    std::string logFilePath = "hinv_events.log";
    std::wstring byovdDriverPath = L""; // e.g. C:\\path\\to\\dbutil_2_3.sys
};

// Run the headless engine. Blocks until StopHeadlessSession is called or 'exit' received.
bool RunHeadlessSession(const HeadlessConfig& config);

// Request the running headless engine to stop.
void StopHeadlessSession();

// Execute a script file non-interactively.
bool ExecuteScriptFile(const std::string& scriptPath);

// Process a single command string. Used by IPC server and script engine.
// Returns a human-readable response.
std::string ProcessCommand(const std::string& command);

// Access the currently loaded BYOVD backend (owned by headless session).
byovd::IByovdBackend* GetActiveBackend();

} // namespace headless
} // namespace hinv
