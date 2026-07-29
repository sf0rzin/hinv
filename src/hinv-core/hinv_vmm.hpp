#pragma once
#include <windows.h>
#include <iostream>
#include <string>

namespace hinv {
    namespace vmm {
        constexpr const wchar_t* HYPERDBG_DEVICE_NAME = L"\\\\.\\HyperDbgDebuggerDevice";

        // Checks if HyperDbg VMM device object is initialized and reachable
        bool IsVmmDeviceActive();

        // Sends IOCTL control request to HyperDbg kernel device
        bool SendVmmIoctl(DWORD ioctlCode, LPVOID inBuffer, DWORD inSize, LPVOID outBuffer, DWORD outSize);

        // Sets up EPT memory cloaking (Shadow Page) for a specified kernel memory range
        bool CloakKernelMemory(uint64_t virtualAddress, size_t size);
    }
}
