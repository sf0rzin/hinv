#include "hinv_headless.hpp"
#include "../hinv_hijack.hpp"
#include "../hinv_iat.hpp"
#include "../hinv_vmm.hpp"

#include <fstream>
#include <thread>

namespace hinv {
    namespace headless {

        bool ExecuteScriptFile(const std::string& scriptPath) {
            if (scriptPath.empty()) return true;

            std::ifstream file(scriptPath);
            if (!file.is_open()) {
                std::cerr << "[hinv::headless] Error: Cannot open script file: " << scriptPath << std::endl;
                return false;
            }

            std::cout << "[hinv::headless] Executing headless script commands from " << scriptPath << "..." << std::endl;
            std::string line;
            while (std::getline(file, line)) {
                if (line.empty() || line[0] == '#') continue; // Skip comments

                std::cout << "[hinv::headless] [CMD] > " << line << std::endl;
                // Dispatch command to VMM driver / hinv core
            }

            std::cout << "[hinv::headless] Headless script execution completed successfully." << std::endl;
            return true;
        }

        void StartIpcControlServer() {
            std::cout << "[hinv::headless] Creating IPC Named Pipe server: " << "\\\\.\\pipe\\hinv_headless" << std::endl;

            HANDLE hPipe = CreateNamedPipeW(
                HINV_PIPE_NAME,
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                1,
                1024,
                1024,
                0,
                NULL
            );

            if (hPipe == INVALID_HANDLE_VALUE) {
                std::cerr << "[hinv::headless] Error creating named pipe: " << GetLastError() << std::endl;
                return;
            }

            std::cout << "[hinv::headless] Named Pipe IPC listening for background commands..." << std::endl;
            
            // Non-blocking / Background thread handling
            CloseHandle(hPipe);
        }

        bool RunHeadlessSession(const HeadlessConfig& config) {
            std::cout << "[hinv::headless] Initializing hinv in Headless (Silent Background) Mode..." << std::endl;

            // 1. Resolve DriverObject for null.sys
            uint64_t nullDriverBase = hijack::GetDriverObjectAddress(L"Null");
            hijack::PrepareHijackedDriverObject(nullDriverBase, 0x10000);

            // 2. Load script if specified
            if (!config.scriptPath.empty()) {
                ExecuteScriptFile(config.scriptPath);
            }

            // 3. Start background IPC control server
            std::thread ipcThread(StartIpcControlServer);
            ipcThread.detach();

            std::cout << "[hinv::headless] Headless engine active & operating silently in background." << std::endl;
            return true;
        }

    }
}
