#pragma once
#include <windows.h>
#include <string>
#include <cstdint>
#include <vector>

namespace hinv {

// Header-only C++ Client SDK for communicating with hinv headless engine via Named Pipe IPC.
class Client {
public:
    explicit Client(const std::wstring& pipeName = L"\\\\.\\pipe\\hinv_headless")
        : m_pipeName(pipeName), m_hPipe(INVALID_HANDLE_VALUE) {}

    ~Client() { Disconnect(); }

    bool Connect() {
        m_hPipe = CreateFileW(
            m_pipeName.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr
        );
        return (m_hPipe != INVALID_HANDLE_VALUE);
    }

    void Disconnect() {
        if (m_hPipe != INVALID_HANDLE_VALUE) {
            CloseHandle(m_hPipe);
            m_hPipe = INVALID_HANDLE_VALUE;
        }
    }

    bool IsConnected() const { return m_hPipe != INVALID_HANDLE_VALUE; }

    // Send a raw command and receive the response line.
    bool SendCommand(const std::string& command, std::string* outResponse = nullptr) {
        if (!IsConnected()) return false;

        std::string payload = command + "\n";
        DWORD written = 0;
        if (!WriteFile(m_hPipe, payload.c_str(), static_cast<DWORD>(payload.size()), &written, nullptr))
            return false;

        if (outResponse) {
            char buffer[4096]{};
            DWORD bytesRead = 0;
            if (!ReadFile(m_hPipe, buffer, sizeof(buffer) - 1, &bytesRead, nullptr))
                return false;
            *outResponse = std::string(buffer, bytesRead);
            // Trim trailing newline / CR.
            while (!outResponse->empty() && ((*outResponse)[0] == '\n' || (*outResponse)[0] == '\r'))
                outResponse->erase(outResponse->begin());
            while (!outResponse->empty() && (outResponse->back() == '\n' || outResponse->back() == '\r'))
                outResponse->pop_back();
        }
        return true;
    }

    bool SetupSplitTLB(uint64_t address, size_t size) {
        return SendCommand("splittlb 0x" + std::to_string(address) + " " + std::to_string(size));
    }

    bool CleanKernelTraces(const std::string& driverName) {
        return SendCommand("clean " + driverName);
    }

    bool LoadDriver(const std::string& driverPath) {
        return SendCommand("load " + driverPath);
    }

    bool HyperDbgCommand(const std::string& cmd) {
        return SendCommand("hypercmd " + cmd);
    }

    bool CloakMemoryRegion(uint64_t address, size_t size) {
        return SetupSplitTLB(address, size);
    }

private:
    std::wstring m_pipeName;
    HANDLE       m_hPipe;
};

} // namespace hinv
