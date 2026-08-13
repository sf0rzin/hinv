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

bool InitializeVmm() {
    uint32_t kernelStatus = 0;
    DWORD bytes = 0;
    if (!SendVmmIoctl(IOCTL_HYPERDBG_INIT_VMM, &kernelStatus, sizeof(kernelStatus),
                      &kernelStatus, sizeof(kernelStatus), &bytes)) {
        return false;
    }
    std::cout << "[hinv::vmm] HyperDbg VMM initialized\n";
    return true;
}

// ---------------------------------------------------------------------------
// Structured HyperDbg operations
// ---------------------------------------------------------------------------

bool ReadKernelMemoryHyperDbg(uint64_t address, void* out, size_t size) {
    if (!out || size == 0 || size > 0x10000) return false;

    std::vector<uint8_t> packet(sizeof(DebugerReadMemoryPacket) + size, 0);
    auto* hdr = reinterpret_cast<DebugerReadMemoryPacket*>(packet.data());
    hdr->Pid = 0; // system process
    hdr->Address = address;
    hdr->Size = static_cast<uint32_t>(size);
    hdr->GetAddressMode = 0;
    hdr->AddrMode = AddressMode::Mode64;
    hdr->MemType = ReadMemoryType::Virtual;
    hdr->ReadType = ReadingType::Kernel;
    hdr->ReturnLength = 0;
    hdr->KernelStatus = 0;

    DWORD bytes = 0;
    if (!SendVmmIoctl(IOCTL_HYPERDBG_READ_MEMORY, packet.data(), static_cast<DWORD>(packet.size()),
                      packet.data(), static_cast<DWORD>(packet.size()), &bytes)) {
        return false;
    }

    if (hdr->KernelStatus != 0) {
        std::cerr << "[hinv::vmm] ReadMemory kernel status: 0x" << std::hex << hdr->KernelStatus << std::dec << "\n";
        return false;
    }
    if (hdr->ReturnLength < size) {
        std::cerr << "[hinv::vmm] ReadMemory returned " << hdr->ReturnLength << " bytes, expected " << size << "\n";
        return false;
    }

    std::memcpy(out, packet.data() + sizeof(DebugerReadMemoryPacket), size);
    return true;
}

bool EditKernelMemoryHyperDbg(uint64_t address, const void* in, size_t size) {
    if (!in || size == 0 || size > 0x10000) return false;

    uint32_t byteSizeCode;
    size_t paddedSize = size;
    if (size == 1) { byteSizeCode = 0; paddedSize = 1; }
    else if (size == 4) { byteSizeCode = 1; paddedSize = 4; }
    else if (size == 8) { byteSizeCode = 2; paddedSize = 8; }
    else {
        byteSizeCode = 2;
        paddedSize = ((size + 7) / 8) * 8; // pad to qword boundary
    }

    std::vector<uint8_t> packet(sizeof(DebugerEditMemoryPacket) + paddedSize, 0);
    auto* hdr = reinterpret_cast<DebugerEditMemoryPacket*>(packet.data());
    hdr->Result = 0;
    hdr->Address = address;
    hdr->ProcessId = 0;
    hdr->MemoryType = 0; // virtual
    hdr->ByteSize = byteSizeCode;
    hdr->CountOf64Chunks = static_cast<uint32_t>(paddedSize / 8);
    hdr->FinalStructureSize = static_cast<uint32_t>(sizeof(DebugerEditMemoryPacket) + paddedSize);

    std::memcpy(packet.data() + sizeof(DebugerEditMemoryPacket), in, size);

    DWORD bytes = 0;
    if (!SendVmmIoctl(IOCTL_HYPERDBG_EDIT_MEMORY, packet.data(), static_cast<DWORD>(packet.size()),
                      packet.data(), static_cast<DWORD>(packet.size()), &bytes)) {
        return false;
    }

    if (hdr->Result != 0) {
        std::cerr << "[hinv::vmm] EditMemory result: 0x" << std::hex << hdr->Result << std::dec << "\n";
        return false;
    }
    return true;
}

bool VirtualToPhysicalHyperDbg(uint64_t virtualAddress, uint64_t& outPhysical) {
    struct Va2PaPacket {
        uint64_t VirtualAddress;
        uint64_t PhysicalAddress;
        uint32_t ProcessId;
        uint8_t  IsVirtual2Physical;
        uint32_t KernelStatus;
    };

    Va2PaPacket packet{};
    packet.VirtualAddress = virtualAddress;
    packet.PhysicalAddress = 0;
    packet.ProcessId = 0;
    packet.IsVirtual2Physical = 1;
    packet.KernelStatus = 0;

    DWORD bytes = 0;
    if (!SendVmmIoctl(IOCTL_HYPERDBG_VA2PA_AND_PA2VA, &packet, sizeof(packet),
                      &packet, sizeof(packet), &bytes)) {
        return false;
    }

    if (packet.KernelStatus != 0) {
        std::cerr << "[hinv::vmm] VA2PA kernel status: 0x" << std::hex << packet.KernelStatus << std::dec << "\n";
        return false;
    }
    outPhysical = packet.PhysicalAddress;
    return true;
}

// ---------------------------------------------------------------------------
// EPT / cloaking wrappers (structured packets)
// ---------------------------------------------------------------------------

bool CloakKernelMemory(uint64_t virtualAddress, size_t size) {
    if (!IsVmmDeviceActive()) {
        std::cerr << "[hinv::vmm] HyperDbg device not active; cannot cloak memory\n";
        return false;
    }

    // EPT cloaking requires registering a DEBUGGER_EVENT with an action
    // buffer. That path is not yet implemented. This function returns false
    // so callers do not assume the operation succeeded.
    (void)virtualAddress;
    (void)size;
    std::cerr << "[hinv::vmm] EPT cloaking not yet implemented; requires DEBUGGER_EVENT registration\n";
    return false;
}

bool SetEptHiddenHook(uint64_t targetAddress) {
    (void)targetAddress;
    std::cerr << "[hinv::vmm] EPT hidden hook not yet implemented\n";
    return false;
}

bool MonitorMemory(uint64_t virtualAddress, size_t size, bool read, bool write, bool execute) {
    (void)virtualAddress;
    (void)size;
    (void)read;
    (void)write;
    (void)execute;
    std::cerr << "[hinv::vmm] Memory monitoring not yet implemented\n";
    return false;
}

bool SendVmmCommand(const std::string& command) {
    // HyperDbg does not accept raw text commands over IOCTL. This shim maps
    // a small subset of common commands to structured packets. Arbitrary
    // script commands require libhyperdbg.
    if (command.empty()) return false;

    if (command.rfind("!syscall", 0) == 0 ||
        command.rfind("!epthook", 0) == 0 ||
        command.rfind("!monitor", 0) == 0) {
        std::cerr << "[hinv::vmm] Text command '" << command
                  << "' requires libhyperdbg script engine; structured packet not implemented\n";
        return false;
    }

    std::cerr << "[hinv::vmm] Unsupported text command: " << command << "\n";
    return false;
}

} // namespace vmm
} // namespace hinv
