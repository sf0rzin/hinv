#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace hinv {
namespace vmm {

constexpr const wchar_t* HYPERDBG_DEVICE_NAME = L"\\\\.\\HyperDbgDebuggerDevice";

// HyperDbg SDK IOCTL codes (computed from HyperDbg include/SDK/headers/Ioctls.h)
// CTL_CODE(0x22, function, METHOD_BUFFERED, FILE_ANY_ACCESS) = 0x220000 | (function << 2)
constexpr DWORD IOCTL_HYPERDBG_INIT_VMM                = 0x222004; // 0x801
constexpr DWORD IOCTL_HYPERDBG_READ_MEMORY             = 0x222408; // 0x902
constexpr DWORD IOCTL_HYPERDBG_READ_OR_WRITE_MSR       = 0x22240C; // 0x903
constexpr DWORD IOCTL_HYPERDBG_REGISTER_EVENT          = 0x222414; // 0x905
constexpr DWORD IOCTL_HYPERDBG_ADD_ACTION_TO_EVENT     = 0x222418; // 0x906
constexpr DWORD IOCTL_HYPERDBG_VA2PA_AND_PA2VA         = 0x222420; // 0x908
constexpr DWORD IOCTL_HYPERDBG_EDIT_MEMORY             = 0x222424; // 0x909
constexpr DWORD IOCTL_HYPERDBG_SEARCH_MEMORY           = 0x222428; // 0x90a
constexpr DWORD IOCTL_HYPERDBG_MODIFY_EVENTS           = 0x22242C; // 0x90b
constexpr DWORD IOCTL_HYPERDBG_ATTACH_DETACH_PROCESS   = 0x222434; // 0x90d
constexpr DWORD IOCTL_HYPERDBG_SEND_USER_COMMANDS      = 0x222458; // 0x916

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

#pragma pack(push, 1)
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
#pragma pack(pop)

// Open/close the HyperDbg device handle.
bool IsVmmDeviceActive();
HANDLE OpenVmmDevice();
void CloseVmmDevice(HANDLE hDevice);

// Send a raw DeviceIoControl to HyperDbg.
bool SendVmmIoctl(DWORD ioctlCode, LPVOID inBuffer, DWORD inSize, LPVOID outBuffer, DWORD outSize, LPDWORD bytesReturned = nullptr);

// Initialize the HyperDbg VMM engine.
bool InitializeVmm();

// Structured HyperDbg operations.
bool ReadKernelMemoryHyperDbg(uint64_t address, void* out, size_t size);
bool EditKernelMemoryHyperDbg(uint64_t address, const void* in, size_t size);
bool VirtualToPhysicalHyperDbg(uint64_t virtualAddress, uint64_t& outPhysical);

// Convenience wrappers for EPT / memory cloaking.
// These use structured HyperDbg packets, not text commands.
bool CloakKernelMemory(uint64_t virtualAddress, size_t size);
bool SetEptHiddenHook(uint64_t targetAddress);
bool MonitorMemory(uint64_t virtualAddress, size_t size, bool read, bool write, bool execute);

// Deprecated text-command compatibility shim.
// HyperDbg does not accept raw text over this IOCTL; use structured packets.
// This function is kept for CLI compatibility and will return false for
// commands that require a full script-engine round-trip.
bool SendVmmCommand(const std::string& command);

} // namespace vmm
} // namespace hinv
