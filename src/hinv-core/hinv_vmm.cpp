#include "hinv_vmm.hpp"
#include <iostream>
#include <cstring>
#include <sstream>
#include <iomanip>

namespace hinv {
namespace vmm {

static std::string ToHex(uint64_t value) {
    std::ostringstream ss;
    ss << "0x" << std::hex << std::uppercase << value;
    return ss.str();
}

bool IsVmmDeviceActive() {
    HANDLE hDevice = OpenVmmDevice();
    if (hDevice != INVALID_HANDLE_VALUE) {
        CloseVmmDevice(hDevice);
        return true;
    }
    return false;
}

HANDLE OpenVmmDevice() {
    return CreateFileW(
        HYPERDBG_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
}

void CloseVmmDevice(HANDLE hDevice) {
    if (hDevice != INVALID_HANDLE_VALUE) CloseHandle(hDevice);
}

bool SendVmmIoctl(DWORD ioctlCode, LPVOID inBuffer, DWORD inSize, LPVOID outBuffer, DWORD outSize, LPDWORD bytesReturned) {
    HANDLE hDevice = OpenVmmDevice();
    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cerr << "[hinv::vmm] Cannot open HyperDbg device: " << GetLastError() << "\n";
        return false;
    }

    DWORD localBytes = 0;
    DWORD* pBytes = bytesReturned ? bytesReturned : &localBytes;
    BOOL ok = DeviceIoControl(hDevice, ioctlCode, inBuffer, inSize, outBuffer, outSize, pBytes, nullptr);
    DWORD err = GetLastError();
    CloseVmmDevice(hDevice);

    if (!ok) {
        std::cerr << "[hinv::vmm] DeviceIoControl failed: " << err << "\n";
        return false;
    }
    return true;
}

bool SendVmmCommand(const std::string& command, std::vector<uint8_t>* outResponse) {
    if (command.empty()) return false;

    std::vector<char> buffer(command.size() + 1, 0);
    std::memcpy(buffer.data(), command.data(), command.size());

    std::vector<uint8_t> response(4096, 0);
    DWORD bytes = 0;
    if (!SendVmmIoctl(IOCTL_HYPERDBG_SEND_USER_COMMANDS, buffer.data(), static_cast<DWORD>(buffer.size()),
                      response.data(), static_cast<DWORD>(response.size()), &bytes)) {
        return false;
    }

    if (outResponse) {
        outResponse->assign(response.begin(), response.begin() + bytes);
    }
    return true;
}

bool InitializeVmm() {
    DWORD bytes = 0;
    if (!SendVmmIoctl(IOCTL_HYPERDBG_INIT_VMM, nullptr, 0, nullptr, 0, &bytes)) {
        return false;
    }
    std::cout << "[hinv::vmm] HyperDbg VMM initialized\n";
    return true;
}

bool CloakKernelMemory(uint64_t virtualAddress, size_t size) {
    if (!IsVmmDeviceActive()) {
        std::cerr << "[hinv::vmm] HyperDbg device not active; cannot cloak memory\n";
        return false;
    }

    // Real HyperDbg does not expose a direct "split TLB" IOCTL. Use !epthook2
    // as the closest equivalent for execute-side hiding.
    std::string cmd = "!epthook2 " + ToHex(virtualAddress);
    if (!SendVmmCommand(cmd)) {
        return false;
    }
    std::cout << "[hinv::vmm] Requested EPT hidden hook for " << ToHex(virtualAddress) << "\n";
    return true;
}

bool SetEptHiddenHook(uint64_t targetAddress, const std::string& action) {
    std::string cmd = "!epthook2 " + ToHex(targetAddress);
    if (!action.empty()) cmd += " " + action;
    return SendVmmCommand(cmd);
}

bool MonitorMemory(uint64_t virtualAddress, size_t size, bool read, bool write, bool execute) {
    // !monitor uses syntax: !monitor [r|w|x|rw|rx|wx|rwx] address [size]
    std::string mode;
    if (read)  mode += "r";
    if (write) mode += "w";
    if (execute) mode += "x";
    if (mode.empty()) mode = "rw";

    std::string cmd = "!monitor " + mode + " " + ToHex(virtualAddress) + " " + std::to_string(size);
    return SendVmmCommand(cmd);
}

} // namespace vmm
} // namespace hinv
