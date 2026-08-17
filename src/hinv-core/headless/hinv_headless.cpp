#include "hinv_headless.hpp"
#include "../hinv_iat.hpp"
#include "../hinv_vmm.hpp"
#include "../hinv_maintenance.hpp"
#include "../hinv_mapper.hpp"
#include "../hinv_kmem.hpp"
#include "../hinv_util.hpp"

#include <fstream>
#include <iostream>
#include <sstream>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <memory>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <chrono>
#include <algorithm>
#include <cwctype>
#include <unordered_map>
#include <unordered_set>
#include <sddl.h>
#include <aclapi.h>

namespace hinv {
namespace headless {

static std::unique_ptr<byovd::IByovdBackend> g_backend;
static std::mutex g_backendMutex;
static std::mutex g_sessionMutex;
static std::atomic<bool> g_running{ false };
static std::atomic<bool> g_acceptingCommands{ false };
static std::mutex g_stopEventMutex;
static HANDLE g_stopEvent = nullptr;
static std::wstring g_byovdPath; // used by 'process-traces' for the driver file timestamp
static constexpr std::size_t MAX_CLIENTS = 32;
struct ClientSlot {
    std::atomic<bool> done{ false };
    std::thread thread;
};

static std::mutex g_clientThreadsMutex;
static std::condition_variable g_clientThreadsChanged;
static std::vector<std::unique_ptr<ClientSlot>> g_clientThreads;
static std::mutex g_commandAdmissionMutex;
static std::mutex g_requestMutex;
static std::unordered_map<std::string, std::string> g_completedRequests;
static std::unordered_set<std::string> g_activeRequests;
static std::unordered_set<std::wstring> g_loadedDriverPaths;
static std::unordered_map<std::wstring, std::vector<uint8_t>> g_scriptModuleBytes;

static void SignalStop() {
    g_running.store(false);
    g_acceptingCommands.store(false);
    {
        std::lock_guard<std::mutex> lock(g_stopEventMutex);
        if (g_stopEvent) SetEvent(g_stopEvent);
    }
    g_clientThreadsChanged.notify_all();
}

static bool BeginCommand() {
    return g_running.load() && g_acceptingCommands.load();
}

static void BeginShutdownRequest() {
    // Stop admitting new commands before the bye response is written. Existing
    // commands are joined by RunHeadlessSession before the backend is torn
    // down, so they cannot race a reset after the acknowledgement.
    g_acceptingCommands.store(false);
}

static bool PublishStopEvent(HANDLE stopEvent) {
    std::lock_guard<std::mutex> lock(g_stopEventMutex);
    if (g_stopEvent) return false;
    g_stopEvent = stopEvent;
    if (!g_running.load()) SetEvent(stopEvent);
    return true;
}

static void CloseStopEvent(HANDLE stopEvent) {
    std::lock_guard<std::mutex> lock(g_stopEventMutex);
    if (g_stopEvent == stopEvent) g_stopEvent = nullptr;
    CloseHandle(stopEvent);
}

// Remove one completed slot under the lock, then join it after releasing the
// lock. This remains safe if a handler later needs the tracking lock itself.
static void ReapFinishedClients() {
    for (;;) {
        std::unique_ptr<ClientSlot> finished;
        {
            std::lock_guard<std::mutex> lock(g_clientThreadsMutex);
            auto it = g_clientThreads.begin();
            while (it != g_clientThreads.end() && !(*it)->done.load()) ++it;
            if (it == g_clientThreads.end()) return;
            finished = std::move(*it);
            g_clientThreads.erase(it);
        }
        if (finished->thread.joinable()) finished->thread.join();
    }
}

static bool WaitForClientCapacity() {
    for (;;) {
        ReapFinishedClients();
        std::unique_lock<std::mutex> lock(g_clientThreadsMutex);
        if (!g_running.load()) return false;
        if (g_clientThreads.size() < MAX_CLIENTS) return true;
        g_clientThreadsChanged.wait(lock, [] {
            if (!g_running.load()) return true;
            for (const auto& slot : g_clientThreads) {
                if (slot->done.load()) return true;
            }
            return false;
        });
    }
}

static void JoinAllClients() {
    for (;;) {
        std::unique_ptr<ClientSlot> slot;
        {
            std::lock_guard<std::mutex> lock(g_clientThreadsMutex);
            if (g_clientThreads.empty()) return;
            slot = std::move(g_clientThreads.back());
            g_clientThreads.pop_back();
        }
        if (slot->thread.joinable()) slot->thread.join();
    }
}

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

// Everything after "<cmd> " is the literal argument — driver paths may contain
// spaces, so load/process-traces must NOT go through whitespace tokenization (a split
// path could map the WRONG file into the kernel, silently).
static std::string RestAfterCommand(const std::string& line) {
    size_t sp = line.find_first_of(" \t");
    if (sp == std::string::npos) return {};
    size_t start = line.find_first_not_of(" \t", sp + 1);
    if (start == std::string::npos) return {};
    size_t end = line.find_last_not_of(" \t\r\n");
    return line.substr(start, end - start + 1);
}

static std::wstring LoadPathKey(const std::wstring& path) {
    std::error_code error;
    const std::filesystem::path canonical =
        std::filesystem::weakly_canonical(path, error);
    std::wstring key = error ? path : canonical.native();
    std::transform(key.begin(), key.end(), key.begin(), ::towlower);
    return key;
}

static std::string ProcessCommandInternal(
    const std::string& command, bool deferExit, bool* exitRequested) {
    if (exitRequested) *exitRequested = false;
    if (command.size() >= ipc::kMaxMessageBytes) return "ERR command too large";

    auto tokens = Tokenize(command);
    if (tokens.empty()) return "OK";

    const std::string& cmd = tokens[0];

    // Hold admission through the complete command. This makes the check and
    // the privileged operation one critical section relative to `exit`: once
    // bye is accepted, queued commands cannot begin underneath teardown.
    std::unique_lock<std::mutex> admission(g_commandAdmissionMutex);

    if (cmd == "load" || cmd == "load-null-drvobj") {
        if (!BeginCommand()) return "ERR shutting down";
        std::string arg = RestAfterCommand(command);
        if (arg.empty()) {
            return cmd == "load"
                ? "ERR usage: load <utf8-path>"
                : "ERR usage: load-null-drvobj <utf8-path>";
        }
        if (arg.find('\0') != std::string::npos) return "ERR invalid UTF-8 path";
        std::wstring path;
        if (!util::Utf8ToWide(arg, &path)) return "ERR invalid UTF-8 path";
        const std::wstring pathKey = LoadPathKey(path);
        if (g_loadedDriverPaths.find(pathKey) != g_loadedDriverPaths.end())
            return "ERR module already loaded (request may have completed after a timeout)";

        const bool nullDrvObj = cmd == "load-null-drvobj";
        std::lock_guard<std::mutex> lock(g_backendMutex);
        if (!g_backend) return "ERR no BYOVD backend loaded";
        mapper::MappingResult result;
        const auto cachedModule = g_scriptModuleBytes.find(pathKey);
        if (cachedModule != g_scriptModuleBytes.end()) {
            result = mapper::MapDriverBytes(g_backend.get(), cachedModule->second, nullDrvObj);
        } else {
            result = mapper::MapDriver(g_backend.get(), path, nullDrvObj);
        }
        if (!result.success) {
            if (result.imageBase != 0)
                g_loadedDriverPaths.insert(pathKey);
            return "ERR map failed: " + result.error;
        }
        const size_t slash = path.find_last_of(L"\\/");
        const std::wstring fileName = slash == std::wstring::npos
            ? path : path.substr(slash + 1);
        kmem::RegisterMappedModule(fileName, result.imageBase, result.imageSize);
        g_loadedDriverPaths.insert(pathKey);
        std::ostringstream ss;
        ss << "OK image=0x" << std::hex << result.imageBase
           << " status=0x" << result.driverEntryStatus << std::dec;
        return ss.str();
    }

    if (cmd == "process-traces") {
        if (!BeginCommand()) return "ERR shutting down";
        std::string arg = RestAfterCommand(command);
        if (arg.empty()) return "ERR usage: process-traces <utf8-drivername>";
        if (arg.find('\0') != std::string::npos) return "ERR invalid UTF-8 driver name";
        std::wstring name;
        if (!util::Utf8ToWide(arg, &name)) return "ERR invalid UTF-8 driver name";
        std::lock_guard<std::mutex> lock(g_backendMutex);
        if (!g_backend) return "ERR no BYOVD backend loaded";
        uint32_t timestamp = maintenance::GetDriverFileTimestamp(g_byovdPath);
        auto result = maintenance::ProcessDriverTraces(g_backend.get(), name, timestamp);
        if ((!result.piDdbCache && !result.hashBucketList && !result.wdFilter) || !result.complete) {
            std::string error;
            if (!util::WideToUtf8(result.error, &error)) error = "trace processing failed";
            return "ERR " + error;
        }
        return "OK";
    }

    if (cmd == "status") {
        if (!BeginCommand()) return "ERR shutting down";
        std::string backendState;
        {
            std::lock_guard<std::mutex> lock(g_backendMutex);
            backendState = g_backend ? "ready" : "none";
        }
        std::ostringstream ss;
        ss << "OK backend=" << backendState
           << " hyperdbg=" << (vmm::IsVmmDeviceActive() ? "ready" : "none");
        return ss.str();
    }

    if (cmd == "initvmm") {
        if (!BeginCommand()) return "ERR shutting down";
        return vmm::InitializeVmm() ? "OK" : "ERR init failed";
    }

    if (cmd == "exit") {
        if (tokens.size() != 1) return "ERR usage: exit";
        if (!BeginCommand()) return "ERR shutting down";
        BeginShutdownRequest();
        if (exitRequested) *exitRequested = true;
        if (!deferExit) SignalStop();
        return "OK bye";
    }

    return "ERR unknown command";
}

std::string ProcessCommand(const std::string& command) {
    return ProcessCommandInternal(command, false, nullptr);
}

static bool ParseRequestEnvelope(const std::string& request, std::string& id,
                                 std::string& command) {
    id.clear();
    command = request;
    if (request.size() < 3 || request[0] != '@') return true;
    const size_t separator = request.find(' ');
    if (separator <= 1 || separator > 65) return true;
    for (size_t i = 1; i < separator; ++i) {
        const char c = request[i];
        const bool hex = (c >= '0' && c <= '9') ||
                         (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!hex && c != '-') return true;
    }
    id = request.substr(1, separator - 1);
    command = request.substr(separator + 1);
    return !command.empty();
}

static std::string ProcessClientRequest(const std::string& request) {
    std::string id;
    std::string command;
    if (!ParseRequestEnvelope(request, id, command)) return "ERR invalid request envelope";
    if (id.empty()) return ProcessCommandInternal(command, true, nullptr);

    {
        std::lock_guard<std::mutex> lock(g_requestMutex);
        const auto completed = g_completedRequests.find(id);
        if (completed != g_completedRequests.end()) {
            if (completed->second == "OK bye") SignalStop();
            return "@" + id + " " + completed->second;
        }
        if (!g_activeRequests.insert(id).second)
            return "@" + id + " ERR operation in progress";
    }

    std::string response;
    try {
        response = ProcessCommandInternal(command, true, nullptr);
    } catch (...) {
        response = "ERR command processing failed";
    }
    {
        std::lock_guard<std::mutex> lock(g_requestMutex);
        g_activeRequests.erase(id);
        g_completedRequests[id] = response;
        while (g_completedRequests.size() > 256)
            g_completedRequests.erase(g_completedRequests.begin());
    }
    return "@" + id + " " + response;
}

// ---------------------------------------------------------------------------
// Script execution
// ---------------------------------------------------------------------------

static bool ReadScriptFile(const std::filesystem::path& scriptPath,
                           std::vector<std::string>& lines) {
    lines.clear();
    if (scriptPath.empty()) return true;
    std::ifstream file(scriptPath, std::ios::binary);
    if (!file.is_open()) {
        std::wcerr << L"[hinv::headless] Cannot open script: " << scriptPath.native() << L"\n";
        return false;
    }

    bool firstLine = true;
    std::string line;
    while (std::getline(file, line)) {
        if (line.size() >= ipc::kMaxMessageBytes)
            return false;
        if (firstLine) {
            firstLine = false;
            if (line.size() >= 3 &&
                static_cast<unsigned char>(line[0]) == 0xEF &&
                static_cast<unsigned char>(line[1]) == 0xBB &&
                static_cast<unsigned char>(line[2]) == 0xBF)
                line.erase(0, 3);
        }
        lines.push_back(line);
    }
    if (file.bad()) {
        std::wcerr << L"[hinv::headless] Script read error: " << scriptPath.native() << L"\n";
        return false;
    }
    return true;
}

static bool ValidateScriptLines(const std::vector<std::string>& lines) {
    for (const auto& line : lines) {
        if (line.empty() || line[0] == '#') continue;
        const auto tokens = Tokenize(line);
        if (tokens.empty()) continue;
        const std::string& command = tokens[0];
        if (command == "load" || command == "load-null-drvobj") {
            const std::string arg = RestAfterCommand(line);
            std::wstring path;
            std::vector<uint8_t> bytes;
            std::string error;
            if (arg.empty() || !util::Utf8ToWide(arg, &path) ||
                !mapper::ReadDriverFileBytes(path, bytes) ||
                !mapper::ValidateDriverImageBytes(bytes, &error)) {
                std::cerr << "[hinv::headless] Script preflight rejected module: " << arg
                          << " (" << error << ")\n";
                return false;
            }
            g_scriptModuleBytes[LoadPathKey(path)] = std::move(bytes);
            continue;
        }
        if (command == "process-traces") {
            const std::string arg = RestAfterCommand(line);
            std::wstring name;
            if (arg.empty() || !util::Utf8ToWide(arg, &name)) return false;
            continue;
        }
        if (command == "status" || command == "initvmm") {
            if (tokens.size() != 1) return false;
            continue;
        }
        if (command == "exit") {
            if (tokens.size() != 1) return false;
            continue;
        }
        std::cerr << "[hinv::headless] Script contains an unknown command: " << command << "\n";
        return false;
    }
    return true;
}

static bool ExecuteScriptLines(const std::vector<std::string>& lines,
                               bool deferVmmInit = false,
                               bool* vmmInitDeferred = nullptr) {
    const bool stopAware = g_running.load();
    bool firstLine = true;
    for (const auto& originalLine : lines) {
        std::string line = originalLine;
        if (firstLine) firstLine = false;
        if (line.empty() || line[0] == '#') continue;
        bool exitRequested = false;
        const auto tokens = Tokenize(line);
        std::string resp;
        if (deferVmmInit && tokens.size() == 1 && tokens[0] == "initvmm") {
            if (vmmInitDeferred) *vmmInitDeferred = true;
            resp = "OK deferred";
        } else {
            resp = ProcessCommandInternal(line, false, &exitRequested);
        }
        std::cout << "[hinv::headless] [CMD] " << line << " -> " << resp << "\n";
        if (resp.rfind("ERR", 0) == 0) {
            std::cerr << "[hinv::headless] Command failed: " << line << "\n";
            return false;
        }
        if (exitRequested || (stopAware && !g_running.load())) break;
    }
    return true;
}

bool ExecuteScriptFile(const std::filesystem::path& scriptPath) {
    if (scriptPath.empty()) return true;
    std::vector<std::string> lines;
    return ReadScriptFile(scriptPath, lines) &&
           ValidateScriptLines(lines) && ExecuteScriptLines(lines);
}

// ---------------------------------------------------------------------------
// Named Pipe IPC server
// ---------------------------------------------------------------------------

static bool WriteResponse(
    HANDLE hPipe, HANDLE stopEvent, const std::string& response, bool exitRequested) {
    OVERLAPPED overlapped{};
    overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!overlapped.hEvent) return false;

    DWORD written = 0;
    BOOL ok = WriteFile(hPipe, response.data(), static_cast<DWORD>(response.size()),
                        &written, &overlapped);
    const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    if (!ok && error == ERROR_IO_PENDING) {
        DWORD wait = WAIT_FAILED;
        if (exitRequested) {
            // The exit response gets a bounded chance to complete before this
            // handler signals the shared stop event.
            wait = WaitForSingleObject(overlapped.hEvent, ipc::OperationTimeoutMs());
            if (wait == WAIT_OBJECT_0) {
                ok = GetOverlappedResult(hPipe, &overlapped, &written, FALSE);
            }
        } else {
            HANDLE waits[2] = { stopEvent, overlapped.hEvent };
            wait = WaitForMultipleObjects(
                2, waits, FALSE, ipc::OperationTimeoutMs());
            if (wait == WAIT_OBJECT_0 + 1) {
                ok = GetOverlappedResult(hPipe, &overlapped, &written, FALSE);
            }
        }

        if ((!exitRequested && wait != WAIT_OBJECT_0 + 1) ||
            (exitRequested && wait != WAIT_OBJECT_0)) {
            CancelIoEx(hPipe, &overlapped);
            DWORD ignored = 0;
            GetOverlappedResult(hPipe, &overlapped, &ignored, TRUE);
            ok = FALSE;
        }
    }

    CloseHandle(overlapped.hEvent);
    return ok && written == response.size();
}

static void HandleClient(HANDLE hPipe, HANDLE stopEvent) {
    constexpr std::size_t BUF_SIZE = 4096;
    char buffer[BUF_SIZE]{};

    while (g_running.load()) {
        // Read one complete message. In message mode an oversized message
        // arrives as ERROR_MORE_DATA chunks. Check every chunk, including the
        // final successful one, against the shared protocol cap.
        std::string request;
        bool fatal = false;
        for (;;) {
            OVERLAPPED overlapped{};
            overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (!overlapped.hEvent) { fatal = true; break; }

            DWORD bytesRead = 0;
            BOOL ok = ReadFile(
                hPipe, buffer, static_cast<DWORD>(BUF_SIZE), &bytesRead, &overlapped);
            DWORD error = ok ? ERROR_SUCCESS : GetLastError();
            if (!ok && error == ERROR_IO_PENDING) {
                HANDLE handles[2] = { stopEvent, overlapped.hEvent };
                DWORD wait = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
                if (wait != WAIT_OBJECT_0 + 1) {
                    CancelIoEx(hPipe, &overlapped);
                    GetOverlappedResult(hPipe, &overlapped, &bytesRead, TRUE);
                    CloseHandle(overlapped.hEvent);
                    fatal = true;
                    break;
                }
                ok = GetOverlappedResult(hPipe, &overlapped, &bytesRead, FALSE);
                error = ok ? ERROR_SUCCESS : GetLastError();
            }
            CloseHandle(overlapped.hEvent);

            if (bytesRead > ipc::kMaxMessageBytes - request.size()) {
                fatal = true;
                break;
            }
            request.append(buffer, bytesRead);
            if (ok) {
                if (bytesRead == 0) fatal = true;
                break;
            }
            if (error == ERROR_MORE_DATA && bytesRead != 0 &&
                request.size() < ipc::kMaxMessageBytes) {
                continue;
            }
            fatal = true;
            break;
        }
        if (fatal || request.empty()) break;

        while (!request.empty() && (request.back() == '\n' || request.back() == '\r'))
            request.pop_back();

        std::string requestId;
        std::string command;
        ParseRequestEnvelope(request, requestId, command);
        const auto commandTokens = Tokenize(command);
        const bool exitRequested = !commandTokens.empty() && commandTokens[0] == "exit";
        std::string response = ProcessClientRequest(request);
        if (response.size() >= ipc::kMaxMessageBytes)
            response = "ERR response too large";
        response.push_back('\n');

        const bool wroteResponse =
            WriteResponse(hPipe, stopEvent, response, exitRequested);
        if (exitRequested) SignalStop();
        if (!wroteResponse || exitRequested) break;
    }

    // No FlushFileBuffers here: on the server side it blocks until the client
    // drains the response. The bounded overlapped write above is sufficient.
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
}

static bool StartIpcControlServer(HANDLE stopEvent) {
    std::cout << "[hinv::headless] IPC server listening on " << "\\\\.\\pipe\\hinv_headless" << "\n";

    // Restrict pipe access to SYSTEM and Administrators.
    PSECURITY_DESCRIPTOR sd = nullptr;
    auto fail = [&](const char* operation, DWORD error = ERROR_SUCCESS) {
        std::cerr << "[hinv::headless] " << operation << " failed";
        if (error != ERROR_SUCCESS) std::cerr << ": " << error;
        std::cerr << "\n";
        if (sd) LocalFree(sd);
        SignalStop();
        return false;
    };

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &sd, nullptr)) {
        return fail("ConvertStringSecurityDescriptorToSecurityDescriptorW", GetLastError());
    }

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle = FALSE;

    bool firstPipe = true;
    while (g_running.load()) {
        // A listening instance also counts toward nMaxInstances. Do not call
        // CreateNamedPipeW until a tracked handler slot is genuinely free.
        if (!WaitForClientCapacity()) break;
        if (!g_running.load()) break;

        DWORD openMode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
        if (firstPipe) openMode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        HANDLE hPipe = CreateNamedPipeW(
            HINV_PIPE_NAME,
            openMode,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            static_cast<DWORD>(MAX_CLIENTS),
            4096,
            4096,
            0,
            &sa
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            return fail("CreateNamedPipeW", GetLastError());
        }
        firstPipe = false;

        OVERLAPPED overlapped{};
        overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!overlapped.hEvent) {
            const DWORD error = GetLastError();
            CloseHandle(hPipe);
            return fail("CreateEventW(connect)", error);
        }

        BOOL connected = ConnectNamedPipe(hPipe, &overlapped);
        DWORD connectError = connected ? ERROR_SUCCESS : GetLastError();
        DWORD fatalConnectError = ERROR_SUCCESS;
        if (!connected && connectError == ERROR_IO_PENDING) {
            HANDLE handles[2] = { stopEvent, overlapped.hEvent };
            DWORD wait = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
            if (wait == WAIT_OBJECT_0 + 1) {
                DWORD transferred = 0;
                connected = GetOverlappedResult(
                    hPipe, &overlapped, &transferred, FALSE);
                connectError = connected ? ERROR_SUCCESS : GetLastError();
            } else {
                if (wait == WAIT_FAILED) fatalConnectError = GetLastError();
                CancelIoEx(hPipe, &overlapped);
                DWORD ignored = 0;
                GetOverlappedResult(hPipe, &overlapped, &ignored, TRUE);
                connected = FALSE;
                connectError = ERROR_OPERATION_ABORTED;
            }
        } else if (!connected && connectError == ERROR_PIPE_CONNECTED) {
            connected = TRUE;
            connectError = ERROR_SUCCESS;
        }
        CloseHandle(overlapped.hEvent);

        if (fatalConnectError != ERROR_SUCCESS) {
            CloseHandle(hPipe);
            return fail("WaitForMultipleObjects(connect)", fatalConnectError);
        }

        if (!connected) {
            CloseHandle(hPipe);
            if (!g_running.load()) break;
            if (connectError == ERROR_NO_DATA || connectError == ERROR_PIPE_NOT_CONNECTED ||
                connectError == ERROR_OPERATION_ABORTED)
                continue;
            return fail("ConnectNamedPipe", connectError);
        }

        if (g_running.load()) {
            // Track client threads so the session can join them on shutdown;
            // a detached thread could outlive the BYOVD backend it uses.
            std::unique_ptr<ClientSlot> slot;
            try {
                slot = std::make_unique<ClientSlot>();
            } catch (...) {
                CloseHandle(hPipe);
                return fail("client slot allocation");
            }
            ClientSlot* raw = slot.get();
            try {
                raw->thread = std::thread([raw, hPipe, stopEvent]() {
                    try {
                        HandleClient(hPipe, stopEvent);
                    } catch (...) {
                        DisconnectNamedPipe(hPipe);
                        CloseHandle(hPipe);
                    }
                    raw->done.store(true);
                    g_clientThreadsChanged.notify_all();
                });
            } catch (...) {
                CloseHandle(hPipe);
                return fail("client thread creation");
            }

            try {
                std::lock_guard<std::mutex> lock(g_clientThreadsMutex);
                g_clientThreads.push_back(std::move(slot));
            } catch (...) {
                SignalStop();
                if (slot && slot->thread.joinable()) slot->thread.join();
                return fail("client thread tracking");
            }
        } else {
            CloseHandle(hPipe);
        }
    }
    LocalFree(sd);
    // RunHeadlessSession closes stopEvent only after every handler has joined.
    return true;
}

// ---------------------------------------------------------------------------
// Session management
// ---------------------------------------------------------------------------

bool RunHeadlessSession(const HeadlessConfig& config) {
    std::unique_lock<std::mutex> sessionLock(g_sessionMutex, std::try_to_lock);
    if (!sessionLock.owns_lock()) {
        std::cerr << "[hinv::headless] Another session is already running\n";
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(g_backendMutex);
        if (g_backend) {
            std::cerr << "[hinv::headless] Session state is still active\n";
            return false;
        }
    }

    try {
        std::lock_guard<std::mutex> lock(g_clientThreadsMutex);
        if (!g_clientThreads.empty()) {
            std::cerr << "[hinv::headless] Client state is still active\n";
            return false;
        }
        g_clientThreads.reserve(MAX_CLIENTS);
    } catch (...) {
        std::cerr << "[hinv::headless] Cannot allocate client tracking state\n";
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(g_requestMutex);
        g_completedRequests.clear();
        g_activeRequests.clear();
    }
    g_scriptModuleBytes.clear();

    std::vector<std::string> scriptLines;
    if (!config.byovdDriverPath.empty()) {
        std::vector<uint8_t> byovdBytes;
        if (!mapper::ReadDriverFileBytes(config.byovdDriverPath, byovdBytes) ||
            maintenance::GetDriverFileTimestamp(config.byovdDriverPath) == 0) {
            std::cerr << "[hinv::headless] BYOVD preflight failed\n";
            return false;
        }
    }
    if (!config.scriptPath.empty()) {
        // Open and validate the complete script, including every module path,
        // before loading a privileged BYOVD. A typo cannot leave the backend
        // service resident anymore.
        if (!ReadScriptFile(config.scriptPath, scriptLines) ||
            !ValidateScriptLines(scriptLines)) {
            std::cerr << "[hinv::headless] Script preflight failed\n";
            return false;
        }
    }

    g_running.store(true);
    g_acceptingCommands.store(false);
    HANDLE stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!stopEvent) {
        g_running.store(false);
        std::cerr << "[hinv::headless] Cannot create stop event: " << GetLastError() << "\n";
        return false;
    }
    if (!PublishStopEvent(stopEvent)) {
        CloseHandle(stopEvent);
        SignalStop();
        std::cerr << "[hinv::headless] Stop event state is still active\n";
        return false;
    }
    g_acceptingCommands.store(true);

    auto finalizeSession = [stopEvent] {
        SignalStop();
        CloseStopEvent(stopEvent);
        bool backendOk = true;
        {
            std::lock_guard<std::mutex> lock(g_backendMutex);
            if (g_backend) {
                backendOk = g_backend->Shutdown();
                // A false shutdown deliberately leaves the backend reachable
                // for recovery; destroying it would discard the only handle
                // and service ownership state needed for a safe retry.
                if (backendOk) {
                    g_backend.reset();
                    g_byovdPath.clear();
                }
            }
        }
        const bool vmmOk = vmm::ShutdownVmm();
        return backendOk && vmmOk;
    };

    if (g_running.load() && !config.byovdDriverPath.empty()) {
        bool loaded = false;
        {
            std::lock_guard<std::mutex> lock(g_backendMutex);
            g_backend = byovd::LoadVulnerableDriver(config.byovdDriverPath);
            loaded = static_cast<bool>(g_backend);
            if (loaded) g_byovdPath = config.byovdDriverPath;
        }
        if (!loaded) {
            std::cerr << "[hinv::headless] Failed to load BYOVD driver\n";
            const bool finalizeOk = finalizeSession();
            if (!finalizeOk) std::cerr << "[hinv::headless] Session finalization also failed\n";
            return false;
        }
        std::wcout << L"[hinv::headless] BYOVD backend loaded: " << config.byovdDriverPath << L"\n";
    }

    bool vmmInitDeferred = false;
    if (g_running.load() && !scriptLines.empty() &&
        !ExecuteScriptLines(scriptLines, true, &vmmInitDeferred)) {
        std::cerr << "[hinv::headless] Script failed, aborting session\n";
        const bool finalizeOk = finalizeSession();
        if (!finalizeOk) std::cerr << "[hinv::headless] Session finalization also failed\n";
        return false;
    }

    if (g_running.load() && vmmInitDeferred) {
        bool initialized = false;
        try {
            std::thread initThread([&] {
                initialized = vmm::InitializeVmm();
            });
            initThread.join();
        } catch (...) {
            std::cerr << "[hinv::headless] Could not start deferred VMM initialization\n";
        }
        if (!initialized) {
            std::cerr << "[hinv::headless] Deferred VMM initialization failed\n";
            const bool finalizeOk = finalizeSession();
            if (!finalizeOk) std::cerr << "[hinv::headless] Session finalization also failed\n";
            return false;
        }
    }

    bool ipcFailed = false;
    std::thread ipcThread;
    if (g_running.load()) {
        try {
            ipcThread = std::thread([&] {
                try {
                    if (!StartIpcControlServer(stopEvent)) ipcFailed = true;
                } catch (...) {
                    ipcFailed = true;
                    SignalStop();
                }
            });
        } catch (...) {
            SignalStop();
            JoinAllClients();
            const bool finalizeOk = finalizeSession();
            if (!finalizeOk) std::cerr << "[hinv::headless] Session finalization also failed\n";
            return false;
        }
        ipcThread.join(); // blocks until exit, StopHeadlessSession, or IPC failure
    }

    // Signal before joining even if an unexpected server return omitted it.
    // Handlers may be waiting in ReadFile and can still use the backend until
    // their thread exits.
    SignalStop();
    JoinAllClients();

    const bool finalizeOk = finalizeSession();
    if (ipcFailed) {
        std::cerr << "[hinv::headless] IPC server failed\n";
        return false;
    }
    if (!finalizeOk) {
        std::cerr << "[hinv::headless] Session finalization failed\n";
        return false;
    }

    std::cout << "[hinv::headless] Session ended\n";
    return true;
}

void StopHeadlessSession() {
    SignalStop();
}

} // namespace headless
} // namespace hinv
