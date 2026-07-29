#pragma once
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>

namespace hinv {
    namespace headless {
        constexpr const wchar_t* HINV_PIPE_NAME = L"\\\\.\\pipe\\hinv_headless";

        struct HeadlessConfig {
            bool silentMode = true;
            bool autoCloakDriver = true;
            std::string scriptPath = "";
            std::string logFilePath = "hinv_events.log";
        };

        // Starts the hinv engine in headless (silent background) mode
        bool RunHeadlessSession(const HeadlessConfig& config);

        // Executes a script of HyperDbg/hinv commands non-interactively
        bool ExecuteScriptFile(const std::string& scriptPath);

        // Launches the Named Pipe IPC listener for silent background control
        void StartIpcControlServer();
    }
}
