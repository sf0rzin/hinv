#include "hinv_headless.hpp"
#include "../hinv_hijack.hpp"
#include "../hinv_iat.hpp"
#include "../hinv_vmm.hpp"
#include "../hinv_ept_shadow.hpp"
#include "../hinv_cleaner.hpp"
#include "../hinv_mapper.hpp"
#include "../hinv_kmem.hpp"

#include <fstream>
#include <iostream>
#include <sstream>
#include <thread>
#include <mutex>
#include <atomic>
#include <vector>
#include <cstring>
#include <chrono>

namespace hinv {
namespace headless {

static std::unique_ptr<byovd::IByovdBackend> g_backend;
static std::mutex g_backendMutex;
static std::atomic<bool> g_running{ false };

byovd::IByovdBackend* GetActiveBackend() {
    std::lock_guard<std::mutex> lock(g_backendMutex);
    return g_backend.get();
}

// ---------------------------------------------------------------------------
// Command processing
// ---------------------------------------------------------------------------

static std::vector<std::string> Tokenize(const std::string& line) {
    std::vector<std::string> tokens;
    std::istringstream iss(line);
    std::string tok;
    while (iss >> tok) tokens.push_back(tok);
    return tokens;
}

std::string ProcessCommand(const std::string& command) {
    auto tokens = Tokenize(command);
    if (tokens.empty()) return "OK";

    const std::string& cmd = tokens[0];

    if (cmd == "load" && tokens.size() >= 2) {
        std::wstring path(tokens[1].begin(), tokens[1].end());
        std::lock_guard<std::mutex> lock(g_backendMutex);
        if (!g_backend) return "ERR no BYOVD backend loaded";
        auto result = mapper::MapDriver(g_backend.get(), path);
        if (!result.success) return "ERR map failed: " + result.error;
        std::ostringstream ss;
        ss << "OK image=0x" << std::hex << result.imageBase
           << " status=0x" << result.driverEntryStatus << std::dec;
        return ss.str();
    }

    if (cmd == "clean" && tokens.size() >= 2) {
        std::wstring name(tokens[1].begin(), tokens[1].end());
        std::lock_guard<std::mutex> lock(g_backendMutex);
        if (!g_backend) return "ERR no BYOVD backend loaded";
        auto result = cleaner::CleanDriverTraces(g_backend.get(), name);
        if (!result.mmUnloadedDrivers && !result.piDdbCache)
            return "WARN " + std::string(result.error.begin(), result.error.end());
        return "OK";
    }

    if (cmd == "splittlb" && tokens.size() >= 3) {
        uint64_t addr = std::strtoull(tokens[1].c_str(), nullptr, 0);
        size_t size = std::strtoull(tokens[2].c_str(), nullptr, 0);
        if (ept::ApplySplitTLB(addr, size)) return "OK";
        return "ERR EPT cloak failed";
    }

    if (cmd == "hypercmd" && tokens.size() >= 2) {
        std::string sub = command.substr(command.find_first_of(" \t") + 1);
        if (vmm::SendVmmCommand(sub)) return "OK";
        return "ERR HyperDbg command failed";
    }

    if (cmd == "status") {
        std::ostringstream ss;
        ss << "OK backend=" << (g_backend ? "ready" : "none")
           << " hyperdbg=" << (vmm::IsVmmDeviceActive() ? "ready" : "none");
        return ss.str();
    }

    if (cmd == "initvmm") {
        return vmm::InitializeVmm() ? "OK" : "ERR init failed";
    }

    if (cmd == "exit") {
        g_running = false;
        return "OK bye";
    }

    return "ERR unknown command";
}

// ---------------------------------------------------------------------------
// Script execution
// ---------------------------------------------------------------------------

bool ExecuteScriptFile(const std::string& scriptPath) {
    if (scriptPath.empty()) return true;

    std::ifstream file(scriptPath);
    if (!file.is_open()) {
        std::cerr << "[hinv::headless] Cannot open script: " << scriptPath << "\n";
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::string resp = ProcessCommand(line);
        std::cout << "[hinv::headless] [CMD] " << line << " -> " << resp << "\n";
    }
    return true;
}

// ---------------------------------------------------------------------------
// Named Pipe IPC server
// ---------------------------------------------------------------------------

static void HandleClient(HANDLE hPipe) {
    constexpr size_t BUF_SIZE = 4096;
    char buffer[BUF_SIZE]{};
    DWORD bytesRead = 0;

    while (g_running) {
        BOOL ok = ReadFile(hPipe, buffer, BUF_SIZE - 1, &bytesRead, nullptr);
        if (!ok || bytesRead == 0) break;
        buffer[bytesRead] = '\0';

        std::string request(buffer);
        // Trim trailing newline / CR
        while (!request.empty() && (request.back() == '\n' || request.back() == '\r'))
            request.pop_back();

        std::string response = ProcessCommand(request) + "\n";
        DWORD written = 0;
        WriteFile(hPipe, response.c_str(), static_cast<DWORD>(response.size()), &written, nullptr);

        if (request == "exit") break;
    }

    FlushFileBuffers(hPipe);
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
}

static HANDLE g_stopEvent = nullptr;

static void StartIpcControlServer() {
    std::cout << "[hinv::headless] IPC server listening on " << "\\\\.\\pipe\\hinv_headless" << "\n";
    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_stopEvent) return;

    while (g_running) {
        HANDLE hPipe = CreateNamedPipeW(
            HINV_PIPE_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            4096,
            4096,
            0,
            nullptr
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            std::cerr << "[hinv::headless] CreateNamedPipe failed: " << GetLastError() << "\n";
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        OVERLAPPED ov{};
        ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!ov.hEvent) { CloseHandle(hPipe); continue; }

        BOOL connected = ConnectNamedPipe(hPipe, &ov);
        DWORD err = GetLastError();
        if (!connected && err == ERROR_IO_PENDING) {
            HANDLE handles[2] = { g_stopEvent, ov.hEvent };
            DWORD wait = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
            if (wait == WAIT_OBJECT_0) {
                CancelIo(hPipe);
                CloseHandle(ov.hEvent);
                CloseHandle(hPipe);
                break;
            }
            connected = TRUE;
        } else if (!connected && err == ERROR_PIPE_CONNECTED) {
            connected = TRUE;
        }
        CloseHandle(ov.hEvent);

        if (connected && g_running) {
            std::thread clientThread(HandleClient, hPipe);
            clientThread.detach();
        } else {
            CloseHandle(hPipe);
        }
    }
    CloseHandle(g_stopEvent);
    g_stopEvent = nullptr;
}

// ---------------------------------------------------------------------------
// Session management
// ---------------------------------------------------------------------------

bool RunHeadlessSession(const HeadlessConfig& config) {
    g_running = true;

    if (!config.byovdDriverPath.empty()) {
        std::lock_guard<std::mutex> lock(g_backendMutex);
        g_backend = byovd::LoadVulnerableDriver(config.byovdDriverPath);
        if (!g_backend) {
            std::cerr << "[hinv::headless] Failed to load BYOVD driver\n";
            g_running = false;
            return false;
        }
        std::wcout << L"[hinv::headless] BYOVD backend loaded: " << config.byovdDriverPath << L"\n";
    }

    if (!config.scriptPath.empty()) {
        ExecuteScriptFile(config.scriptPath);
    }

    std::thread ipcThread(StartIpcControlServer);
    ipcThread.join(); // blocks until exit

    {
        std::lock_guard<std::mutex> lock(g_backendMutex);
        g_backend.reset();
    }

    std::cout << "[hinv::headless] Session ended\n";
    return true;
}

void StopHeadlessSession() {
    g_running = false;
    if (g_stopEvent) SetEvent(g_stopEvent);
}

} // namespace headless
} // namespace hinv
