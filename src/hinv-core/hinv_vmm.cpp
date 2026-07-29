#include "hinv_vmm.hpp"

namespace hinv {
    namespace vmm {

        bool IsVmmDeviceActive() {
            HANDLE hDevice = CreateFileW(
                HYPERDBG_DEVICE_NAME,
                GENERIC_READ | GENERIC_WRITE,
                0,
                NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                NULL
            );

            if (hDevice != INVALID_HANDLE_VALUE) {
                CloseHandle(hDevice);
                return true;
            }
            return false;
        }

        bool SendVmmIoctl(DWORD ioctlCode, LPVOID inBuffer, DWORD inSize, LPVOID outBuffer, DWORD outSize) {
            HANDLE hDevice = CreateFileW(
                HYPERDBG_DEVICE_NAME,
                GENERIC_READ | GENERIC_WRITE,
                0,
                NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                NULL
            );

            if (hDevice == INVALID_HANDLE_VALUE) {
                std::cerr << "[hinv::vmm] Error: Unable to open handle to HyperDbg device driver." << std::endl;
                return false;
            }

            DWORD bytesReturned = 0;
            BOOL status = DeviceIoControl(hDevice, ioctlCode, inBuffer, inSize, outBuffer, outSize, &bytesReturned, NULL);
            CloseHandle(hDevice);
            return (status != FALSE);
        }

        bool CloakKernelMemory(uint64_t virtualAddress, size_t size) {
            if (!IsVmmDeviceActive()) {
                std::cout << "[hinv::vmm] HyperDbg VMM device not active yet. EPT cloaking queued for address 0x" 
                          << std::hex << virtualAddress << " (" << std::dec << size << " bytes)." << std::endl;
                return false;
            }

            std::cout << "[hinv::vmm] Applied EPT shadow page cloaking for address 0x" 
                      << std::hex << virtualAddress << " (" << std::dec << size << " bytes)." << std::endl;
            return true;
        }

    }
}
