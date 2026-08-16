#pragma once
#include <windows.h>
#include "hinv_util.hpp"

#include <chrono>
#include <string>
#include <cstdint>
#include <vector>
#include <mutex>
#include <utility>
#include <atomic>
#include <sstream>

namespace hinv {

enum class ClientCommandState {
    Succeeded,
    Failed,
    Unknown,
};

struct ClientCommandResult {
    ClientCommandState state = ClientCommandState::Failed;
    std::string response;

    bool Succeeded() const { return state == ClientCommandState::Succeeded; }
    bool Unknown() const { return state == ClientCommandState::Unknown; }
    // Preserve source compatibility with callers that used `if (LoadDriver())`;
    // callers that need timeout semantics must inspect state/Unknown().
    operator bool() const { return Succeeded(); }
};

// Header-only C++ Client SDK for communicating with hinv headless engine via Named Pipe IPC.
class Client {
public:
    explicit Client(const std::wstring& pipeName = L"\\\\.\\pipe\\hinv_headless")
        : m_pipeName(pipeName),
          m_hPipe(INVALID_HANDLE_VALUE),
          m_cancelEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr)) {}

    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    ~Client() {
        Disconnect();
        if (m_cancelEvent) CloseHandle(m_cancelEvent);
    }

    bool Connect() {
        std::unique_lock<std::mutex> ioLock(m_ioMutex);

        HANDLE oldPipe = INVALID_HANDLE_VALUE;
        bool canStart = false;
        {
            std::lock_guard<std::mutex> stateLock(m_stateMutex);
            oldPipe = m_hPipe;
            m_hPipe = INVALID_HANDLE_VALUE;
            canStart = m_cancelEvent && ResetEvent(m_cancelEvent);
        }
        if (oldPipe != INVALID_HANDLE_VALUE) CloseHandle(oldPipe);
        if (!canStart) return false;

        const auto deadline = Clock::now() +
                              std::chrono::milliseconds(ipc::OperationTimeoutMs());
        for (;;) {
            const DWORD cancelState = WaitForSingleObject(m_cancelEvent, 0);
            if (cancelState != WAIT_TIMEOUT) return false;

            HANDLE pipe = CreateFileW(
                m_pipeName.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                nullptr,
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                nullptr
            );
            if (pipe != INVALID_HANDLE_VALUE) {
                if (!IsElevatedServer(pipe)) {
                    CloseHandle(pipe);
                    return false;
                }

                DWORD mode = PIPE_READMODE_MESSAGE;
                if (!SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr)) {
                    CloseHandle(pipe);
                    return false;
                }

                bool publish = false;
                {
                    std::lock_guard<std::mutex> stateLock(m_stateMutex);
                    publish = WaitForSingleObject(m_cancelEvent, 0) == WAIT_TIMEOUT;
                    if (publish) m_hPipe = pipe;
                }
                if (!publish) {
                    CloseHandle(pipe);
                    return false;
                }
                return true;
            }

            const DWORD error = GetLastError();
            if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PIPE_BUSY) return false;

            const DWORD remaining = RemainingMilliseconds(deadline);
            if (remaining == 0) return false;
            const DWORD slice = remaining < 50 ? remaining : 50;
            if (error == ERROR_PIPE_BUSY) {
                if (!WaitNamedPipeW(m_pipeName.c_str(), slice)) {
                    const DWORD waitError = GetLastError();
                    if (waitError != ERROR_SEM_TIMEOUT && waitError != ERROR_FILE_NOT_FOUND &&
                        waitError != ERROR_PIPE_BUSY)
                        return false;
                }
            } else {
                const DWORD wait = WaitForSingleObject(m_cancelEvent, slice);
                if (wait != WAIT_TIMEOUT) return false;
            }
        }
    }

    void Disconnect() {
        HANDLE pipe = INVALID_HANDLE_VALUE;
        {
            std::lock_guard<std::mutex> stateLock(m_stateMutex);
            if (m_cancelEvent) SetEvent(m_cancelEvent);
            pipe = m_hPipe;
            m_hPipe = INVALID_HANDLE_VALUE;
            if (pipe != INVALID_HANDLE_VALUE) CancelIoEx(pipe, nullptr);
        }

        // SendCommand/Connect own the handle while m_ioMutex is held. Signal
        // and cancel first, then wait for their OVERLAPPED storage to retire.
        std::lock_guard<std::mutex> ioLock(m_ioMutex);
        if (pipe != INVALID_HANDLE_VALUE) CloseHandle(pipe);
    }

    bool IsConnected() const {
        std::lock_guard<std::mutex> lock(m_stateMutex);
        return m_hPipe != INVALID_HANDLE_VALUE;
    }

    // Send a raw command and receive the response line.
    ClientCommandResult SendCommand(const std::string& command,
                                    std::string* outResponse = nullptr) {
        return SendCommandInternal(command, NextRequestId(), outResponse);
    }

    ClientCommandResult ProcessKernelTraces(const std::string& driverName) {
        return SendUtf8Argument("process-traces ", driverName);
    }

    ClientCommandResult ProcessKernelTraces(const std::wstring& driverName) {
        return SendWideArgument("process-traces ", driverName);
    }

    // Narrow path arguments are strict UTF-8. The explicit command used for a
    // real driver object cannot be confused with a path suffix.
    ClientCommandResult LoadDriver(const std::string& driverPath, bool nullDrvObj = false) {
        return SendUtf8Argument(nullDrvObj ? "load-null-drvobj " : "load ", driverPath);
    }

    ClientCommandResult LoadDriver(const std::wstring& driverPath, bool nullDrvObj = false) {
        return SendWideArgument(nullDrvObj ? "load-null-drvobj " : "load ", driverPath);
    }

    ClientCommandResult Status(std::string* outResponse = nullptr) {
        return SendCommand("status", outResponse);
    }

    // Reconnect and resend the same request id after a timeout. The server
    // journals completion by id, so this cannot map the same image twice.
    ClientCommandResult RetryLastUnknown() {
        std::string id;
        std::string command;
        {
            std::lock_guard<std::mutex> lock(m_stateMutex);
            if (m_lastUnknownId.empty() || m_lastUnknownCommand.empty())
                return { ClientCommandState::Failed, {} };
            id = m_lastUnknownId;
            command = m_lastUnknownCommand;
        }
        return RetryUnknownUnlocked(id, command);
    }

private:
    ClientCommandResult SendCommandInternal(const std::string& command,
                                            const std::string& requestId,
                                            std::string* outResponse) {
        if (command.size() + requestId.size() + 2 >= ipc::kMaxMessageBytes)
            return { ClientCommandState::Failed, {} };
        std::unique_lock<std::mutex> ioLock(m_ioMutex);
        HANDLE pipe = INVALID_HANDLE_VALUE;
        {
            std::lock_guard<std::mutex> stateLock(m_stateMutex);
            if (m_hPipe == INVALID_HANDLE_VALUE || !m_cancelEvent || !ResetEvent(m_cancelEvent))
                return { ClientCommandState::Failed, {} };
            pipe = m_hPipe;
        }

        std::string payload;
        if (requestId.empty()) payload = command;
        else payload = "@" + requestId + " " + command;
        payload.push_back('\n');
        const auto deadline = Clock::now() +
                              std::chrono::milliseconds(ipc::OperationTimeoutMs());
        DWORD written = 0;
        DWORD error = ERROR_SUCCESS;
        bool timedOut = false;
        if (!PerformIo(pipe, true, payload.data(), static_cast<DWORD>(payload.size()),
                       &written, &error, deadline, &timedOut) || written != payload.size()) {
            InvalidatePipe(pipe);
            if (timedOut && !requestId.empty()) {
                std::lock_guard<std::mutex> stateLock(m_stateMutex);
                m_lastUnknownId = requestId;
                m_lastUnknownCommand = command;
                return { ClientCommandState::Unknown, {} };
            }
            return { ClientCommandState::Failed, {} };
        }

        // Always consume the response, even when the caller does not need it.
        // Otherwise the next command receives this stale message.
        std::string response;
        char buffer[4096]{};
        for (;;) {
            DWORD bytesRead = 0;
            const bool ok = PerformIo(pipe, false, buffer, static_cast<DWORD>(sizeof(buffer)),
                                      &bytesRead, &error, deadline, &timedOut);
            if (bytesRead > ipc::kMaxMessageBytes - response.size()) {
                InvalidatePipe(pipe);
                return { ClientCommandState::Failed, {} };
            }
            response.append(buffer, bytesRead);
            if (ok) break;
            if (error != ERROR_MORE_DATA || response.size() == ipc::kMaxMessageBytes) {
                InvalidatePipe(pipe);
                if (timedOut && !requestId.empty()) {
                    std::lock_guard<std::mutex> stateLock(m_stateMutex);
                    m_lastUnknownId = requestId;
                    m_lastUnknownCommand = command;
                    return { ClientCommandState::Unknown, {} };
                }
                return { ClientCommandState::Failed, {} };
            }
        }

        const std::size_t first = response.find_first_not_of("\r\n");
        if (first == std::string::npos) response.clear();
        else if (first != 0) response.erase(0, first);
        while (!response.empty() && (response.back() == '\n' || response.back() == '\r'))
            response.pop_back();
        if (!requestId.empty()) {
            const std::string prefix = "@" + requestId + " ";
            if (response.rfind(prefix, 0) != 0) {
                InvalidatePipe(pipe);
                return { ClientCommandState::Unknown, {} };
            }
            response.erase(0, prefix.size());
        }
        const std::string finalResponse = response;
        if (outResponse) *outResponse = finalResponse;
        const bool success = finalResponse == "OK" || finalResponse.rfind("OK ", 0) == 0;
        if (finalResponse == "ERR operation in progress") {
            std::lock_guard<std::mutex> stateLock(m_stateMutex);
            m_lastUnknownId = requestId;
            m_lastUnknownCommand = command;
            return { ClientCommandState::Unknown, finalResponse };
        }
        if (!requestId.empty()) {
            std::lock_guard<std::mutex> stateLock(m_stateMutex);
            if (m_lastUnknownId == requestId) {
                m_lastUnknownId.clear();
                m_lastUnknownCommand.clear();
            }
        }
        return { success ? ClientCommandState::Succeeded : ClientCommandState::Failed,
                 finalResponse };
    }
    using Clock = std::chrono::steady_clock;

    static DWORD RemainingMilliseconds(Clock::time_point deadline) {
        const auto now = Clock::now();
        if (now >= deadline) return 0;
        const auto milliseconds =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        return milliseconds > 0 ? static_cast<DWORD>(milliseconds) : 1;
    }

    static bool IsElevatedServer(HANDLE pipe) {
        ULONG processId = 0;
        if (!GetNamedPipeServerProcessId(pipe, &processId) || processId == 0) return false;

        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
        if (!process) return false;
        HANDLE token = nullptr;
        const BOOL openedToken = OpenProcessToken(process, TOKEN_QUERY, &token);
        CloseHandle(process);
        if (!openedToken) return false;

        bool elevated = false;
        TOKEN_ELEVATION elevation{};
        DWORD returned = 0;
        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &returned))
            elevated = elevation.TokenIsElevated != 0;

        bool localSystem = false;
        DWORD userBytes = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &userBytes);
        if (userBytes != 0 && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            std::vector<std::uintptr_t> userStorage(
                (userBytes + sizeof(std::uintptr_t) - 1) / sizeof(std::uintptr_t));
            if (GetTokenInformation(token, TokenUser, userStorage.data(), userBytes, &userBytes)) {
                alignas(void*) BYTE systemSid[SECURITY_MAX_SID_SIZE]{};
                DWORD systemSidBytes = sizeof(systemSid);
                if (CreateWellKnownSid(WinLocalSystemSid, nullptr, systemSid, &systemSidBytes)) {
                    const auto* user = reinterpret_cast<const TOKEN_USER*>(userStorage.data());
                    localSystem = EqualSid(user->User.Sid, systemSid) != FALSE;
                }
            }
        }

        CloseHandle(token);
        return elevated || localSystem;
    }

    bool PerformIo(HANDLE pipe, bool writeOperation, void* buffer, DWORD bufferSize,
                   DWORD* transferred, DWORD* error, Clock::time_point deadline,
                   bool* timedOut) const {
        *transferred = 0;
        *error = ERROR_SUCCESS;
        if (timedOut) *timedOut = false;
        OVERLAPPED overlapped{};
        overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!overlapped.hEvent) {
            *error = GetLastError();
            return false;
        }

        BOOL ok = writeOperation
            ? WriteFile(pipe, buffer, bufferSize, transferred, &overlapped)
            : ReadFile(pipe, buffer, bufferSize, transferred, &overlapped);
        DWORD operationError = ok ? ERROR_SUCCESS : GetLastError();
        if (!ok && operationError == ERROR_IO_PENDING) {
            const DWORD timeout = RemainingMilliseconds(deadline);
            HANDLE waits[2] = { m_cancelEvent, overlapped.hEvent };
            const DWORD wait = timeout == 0
                ? WAIT_TIMEOUT
                : WaitForMultipleObjects(2, waits, FALSE, timeout);
            if (wait == WAIT_OBJECT_0 + 1) {
                ok = GetOverlappedResult(pipe, &overlapped, transferred, FALSE);
                operationError = ok ? ERROR_SUCCESS : GetLastError();
            } else {
                CancelIoEx(pipe, &overlapped);
                DWORD ignored = 0;
                GetOverlappedResult(pipe, &overlapped, &ignored, TRUE);
                ok = FALSE;
                operationError = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : ERROR_OPERATION_ABORTED;
                if (timedOut && wait == WAIT_TIMEOUT) *timedOut = true;
            }
        }

        CloseHandle(overlapped.hEvent);
        *error = operationError;
        return ok != FALSE;
    }

    void InvalidatePipe(HANDLE pipe) {
        bool closePipe = false;
        {
            std::lock_guard<std::mutex> stateLock(m_stateMutex);
            if (m_hPipe == pipe) {
                m_hPipe = INVALID_HANDLE_VALUE;
                closePipe = true;
            }
        }
        if (closePipe) CloseHandle(pipe);
    }

    ClientCommandResult SendUtf8Argument(const char* commandPrefix, const std::string& argument) {
        if (argument.empty() || argument.find('\0') != std::string::npos)
            return { ClientCommandState::Failed, {} };
        std::wstring decoded;
        if (!util::Utf8ToWide(argument, &decoded))
            return { ClientCommandState::Failed, {} };
        return SendAndCheck(std::string(commandPrefix) + argument);
    }

    ClientCommandResult SendWideArgument(const char* commandPrefix, const std::wstring& argument) {
        if (argument.empty() || argument.find(L'\0') != std::wstring::npos)
            return { ClientCommandState::Failed, {} };
        std::string encoded;
        if (!util::WideToUtf8(argument, &encoded))
            return { ClientCommandState::Failed, {} };
        return SendAndCheck(std::string(commandPrefix) + encoded);
    }

    // Send a command, consume its response, and accept only protocol success
    // responses, not arbitrary non-ERR text.
    ClientCommandResult SendAndCheck(const std::string& command) {
        std::string response;
        return SendCommand(command, &response);
    }

    std::string NextRequestId() {
        std::ostringstream stream;
        stream << std::hex << static_cast<uint64_t>(GetCurrentProcessId())
               << '-' << m_nextRequestId.fetch_add(1);
        return stream.str();
    }

    ClientCommandResult RetryUnknownUnlocked(const std::string& id,
                                              const std::string& command) {
        if (!IsConnected() && !Connect())
            return { ClientCommandState::Unknown, {} };
        return SendCommandInternal(command, id, nullptr);
    }

    std::wstring m_pipeName;
    HANDLE       m_hPipe;
    HANDLE       m_cancelEvent;
    mutable std::mutex m_stateMutex;
    mutable std::mutex m_ioMutex;
    std::atomic<uint64_t> m_nextRequestId{ 1 };
    std::string m_lastUnknownId;
    std::string m_lastUnknownCommand;
};

} // namespace hinv
