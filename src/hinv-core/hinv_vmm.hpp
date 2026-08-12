#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace hinv {
namespace vmm {

constexpr const wchar_t* HYPERDBG_DEVICE_NAME = L"\\\\.\\HyperDbgDebuggerDevice";

// HyperDbg SDK IOCTL codes (computed from HyperDbg include/SDK/headers/Ioctls.h)
constexpr DWORD IOCTL_HYPERDBG_INIT_VMM                = 0x222004;
constexpr DWORD IOCTL_HYPERDBG_SEND_USER_COMMANDS      = 0x222058;
constexpr DWORD IOCTL_HYPERDBG_REGISTER_EVENT          = 0x222014;
constexpr DWORD IOCTL_HYPERDBG_READ_MEMORY             = 0x222008;
constexpr DWORD IOCTL_HYPERDBG_EDIT_MEMORY             = 0x222024;

// Open/close the HyperDbg device handle.
bool IsVmmDeviceActive();
HANDLE OpenVmmDevice();
void CloseVmmDevice(HANDLE hDevice);

// Send a raw DeviceIoControl to HyperDbg.
bool SendVmmIoctl(DWORD ioctlCode, LPVOID inBuffer, DWORD inSize, LPVOID outBuffer, DWORD outSize, LPDWORD bytesReturned = nullptr);

// Send a text command (e.g. "!syscall pid 0x2e18") to HyperDbg.
bool SendVmmCommand(const std::string& command, std::vector<uint8_t>* outResponse = nullptr);

// Initialize the HyperDbg VMM engine.
bool InitializeVmm();

// Convenience wrappers for common EPT / memory operations.
bool CloakKernelMemory(uint64_t virtualAddress, size_t size);
bool SetEptHiddenHook(uint64_t targetAddress, const std::string& action = "");
bool MonitorMemory(uint64_t virtualAddress, size_t size, bool read, bool write, bool execute);

} // namespace vmm
} // namespace hinv
