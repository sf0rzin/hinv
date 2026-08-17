#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include "hyperdbg_sdk.hpp"

namespace hinv {
namespace vmm {

constexpr const wchar_t* HYPERDBG_DEVICE_NAME = L"\\\\.\\HyperDbgDebuggerDevice";

// HyperDbg reports a successful kernel-side operation with this status value
// (NOT zero). See DEBUGGER_OPERATION_WAS_SUCCESSFUL in HyperDbg's SDK.
constexpr uint32_t DEBUGGER_OPERATION_WAS_SUCCESSFUL = 0xFFFFFFFF;

// HyperDbg v0.23 SDK IOCTL codes (computed from
// HyperDbg/include/SDK/headers/Ioctls.h).
// IOCTL_START_CODE = 0x800, IOCTL_VMM_IOCTL = 0x800 + 0x200 = 0xA00
// CTL_CODE(0x22, function, METHOD_BUFFERED, FILE_ANY_ACCESS) = 0x220000 | (function << 2)
constexpr DWORD IOCTL_HYPERDBG_INIT_VMM                = 0x222004; // 0x801
constexpr DWORD IOCTL_HYPERDBG_READ_MEMORY             = 0x222808; // 0xA02
constexpr DWORD IOCTL_HYPERDBG_READ_OR_WRITE_MSR       = 0x22280C; // 0xA03
constexpr DWORD IOCTL_HYPERDBG_READ_PAGE_TABLE         = 0x222810; // 0xA04
constexpr DWORD IOCTL_HYPERDBG_REGISTER_EVENT          = 0x222814; // 0xA05
constexpr DWORD IOCTL_HYPERDBG_ADD_ACTION_TO_EVENT     = 0x222818; // 0xA06
constexpr DWORD IOCTL_HYPERDBG_VA2PA_AND_PA2VA         = 0x222820; // 0xA08
constexpr DWORD IOCTL_HYPERDBG_EDIT_MEMORY             = 0x222824; // 0xA09
constexpr DWORD IOCTL_HYPERDBG_SEARCH_MEMORY           = 0x222828; // 0xA0a
constexpr DWORD IOCTL_HYPERDBG_MODIFY_EVENTS           = 0x22282C; // 0xA0b
constexpr DWORD IOCTL_HYPERDBG_ATTACH_DETACH_PROCESS   = 0x222834; // 0xA0d
constexpr DWORD IOCTL_HYPERDBG_SEND_USER_COMMANDS      = 0x222858; // 0xA16

// HyperDbg structured packet types.
enum class ReadMemoryType : uint32_t {
    Physical = 0,
    Virtual = 1
};

enum class AddressMode : uint32_t {
    Mode32 = 0,
    Mode64 = 1
};

enum class ReadingType : uint32_t {
    Kernel = 0,
    VmxRoot = 1
};

struct DebugerReadMemoryPacket {
    uint32_t Pid;
    uint64_t Address;
    uint32_t Size;
    uint8_t  GetAddressMode;
    AddressMode AddrMode;
    ReadMemoryType MemType;
    ReadingType ReadType;
    uint32_t ReturnLength;
    uint32_t KernelStatus;
    // data follows
};

struct DebugerEditMemoryPacket {
    uint32_t Result;
    uint64_t Address;
    uint32_t ProcessId;
    uint32_t MemoryType;   // 0 = virtual, 1 = physical
    uint32_t ByteSize;     // 0 = byte, 1 = dword, 2 = qword
    uint32_t CountOf64Chunks;
    uint32_t FinalStructureSize;
    // data follows
};

// Low-level standalone handle API. Do not mix these caller-owned handles with
// SendVmmIoctl's process-shared one-shot session. CloseVmmDevice refuses to
// close that shared handle.
bool IsVmmDeviceActive();
HANDLE OpenVmmDevice();
void CloseVmmDevice(HANDLE hDevice);

// Close the process-owned device session. This does not terminate the VMM or
// send HyperDbg's termination IOCTL, and the one-shot session is not reopened.
bool ShutdownVmm();

// Send a raw DeviceIoControl to HyperDbg.
bool SendVmmIoctl(DWORD ioctlCode, LPVOID inBuffer, DWORD inSize, LPVOID outBuffer, DWORD outSize, LPDWORD bytesReturned = nullptr);

// Initialize the HyperDbg VMM engine.
bool InitializeVmm();

// Structured HyperDbg operations.
bool ReadKernelMemoryHyperDbg(uint64_t address, void* out, size_t size);
bool EditKernelMemoryHyperDbg(uint64_t address, const void* in, size_t size);
bool VirtualToPhysicalHyperDbg(uint64_t virtualAddress, uint64_t& outPhysical);
bool ReadMsrHyperDbg(uint32_t msr, uint32_t core, std::vector<uint64_t>& values);
bool WriteMsrHyperDbg(uint32_t msr, uint64_t value, uint32_t core);
bool ReadPageTableEntriesHyperDbg(
    uint64_t virtualAddress, uint32_t processId,
    sdk::ReadPageTableEntriesDetails& details);
bool SearchMemoryHyperDbg(uint64_t address, uint64_t length, uint32_t processId,
                          sdk::SearchMemoryType memoryType,
                          sdk::SearchMemoryByteSize byteSize,
                          const std::vector<uint64_t>& patterns,
                          std::vector<uint64_t>& results);
bool RegisterEventHyperDbg(sdk::GeneralEventDetail event,
                           const std::vector<uint8_t>& condition);
bool AddActionToEventHyperDbg(sdk::GeneralAction action,
                              const std::vector<uint8_t>& payload);
bool ModifyEventHyperDbg(uint64_t tag, sdk::ModifyEventsType action,
                         bool& isEnabled);
bool AttachProcessHyperDbg(uint32_t processId, uint64_t& token);
bool SwitchProcessHyperDbg(uint32_t processId, uint64_t& token,
                           uint32_t& threadId, bool& isPaused);
bool DetachProcessHyperDbg(uint32_t processId, uint64_t token);
bool PauseProcessHyperDbg(uint64_t token);
bool ContinueProcessHyperDbg(uint64_t token);
bool SendUserDebuggerCommandHyperDbg(
    uint64_t token, uint32_t threadId,
    sdk::UserDebuggerCommandAction action,
    const std::vector<uint8_t>& payload,
    bool applyToAllPausedThreads, bool waitForEventCompletion,
    uint64_t optionalParam1, uint64_t optionalParam2,
    uint64_t optionalParam3, uint64_t optionalParam4,
    std::vector<uint8_t>& response);
bool ReadUserRegisterHyperDbg(
    uint64_t token, uint32_t threadId, uint32_t registerId,
    uint64_t& value);
bool StepUserProcessHyperDbg(uint64_t token, uint32_t threadId,
                             sdk::RemoteSteppingRequest request =
                                 sdk::RemoteSteppingRequest::StepIn);
bool ExecuteCompiledUserScriptHyperDbg(
    uint64_t token, uint32_t threadId,
    const std::vector<uint8_t>& compiledScript,
    uint32_t scriptPointer, bool isFormat,
    uint64_t* formatValue = nullptr);
bool CompileUserScriptHyperDbg(const std::string& script,
                               std::vector<uint8_t>& compiledScript,
                               uint32_t& scriptPointer);
bool ExecuteTextUserScriptHyperDbg(
    uint64_t token, uint32_t threadId, const std::string& script,
    bool isFormat, uint64_t* formatValue = nullptr);

// Structured EPT monitor/execute-detour registration is available to the
// lab smoke path. Text-to-bytecode scripts use the optional v0.23 script-engine
// runtime; interpreter commands (!epthook2, !monitor, !syscall) are separate
// from this API and are intentionally not dispatched through libhyperdbg.

} // namespace vmm
} // namespace hinv
