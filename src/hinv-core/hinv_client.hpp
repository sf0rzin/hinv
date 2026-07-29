#pragma once
#include <windows.h>
#include <string>
#include <iostream>

namespace hinv {
    // Header-only C++ Client SDK for communicating with hinv headless engine via Named Pipe IPC
    class Client {
    public:
        Client(const std::wstring& pipeName = L"\\\\.\\pipe\\hinv_headless")
            : m_pipeName(pipeName), m_hPipe(INVALID_HANDLE_VALUE) {}

        ~Client() {
            Disconnect();
        }

        // Connects to active hinv Named Pipe IPC server
        bool Connect() {
            m_hPipe = CreateFileW(
                m_pipeName.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                NULL,
                OPEN_EXISTING,
                0,
                NULL
            );

            return (m_hPipe != INVALID_HANDLE_VALUE);
        }

        // Disconnects pipe connection
        void Disconnect() {
            if (m_hPipe != INVALID_HANDLE_VALUE) {
                CloseHandle(m_hPipe);
                m_hPipe = INVALID_HANDLE_VALUE;
            }
        }

        // Sends arbitrary string command to hinv headless server
        bool SendCommand(const std::string& command) {
            if (m_hPipe == INVALID_HANDLE_VALUE) return false;
            DWORD bytesWritten = 0;
            return WriteFile(m_hPipe, command.c_str(), static_cast<DWORD>(command.length()), &bytesWritten, NULL);
        }

        // Triggers EPT Shadow Pages / Split TLB memory cloaking
        bool SetupSplitTLB(uint64_t address, size_t size) {
            char buffer[128];
            snprintf(buffer, sizeof(buffer), "splittlb 0x%llx %zu", address, size);
            return SendCommand(buffer);
        }

        // Triggers deep kernel trace sanitization for a driver name (e.g. RTCore64.sys)
        bool CleanKernelTraces(const std::string& driverName) {
            char buffer[128];
            snprintf(buffer, sizeof(buffer), "clean 0x%s", driverName.c_str());
            return SendCommand(buffer);
        }

        // Helper alias for EPT cloaking
        bool CloakMemoryRegion(uint64_t address, size_t size) {
            return SetupSplitTLB(address, size);
        }

    private:
        std::wstring m_pipeName;
        HANDLE m_hPipe;
    };
}
