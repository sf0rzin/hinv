#include "hinv_vmm.hpp"
#include "hinv_kmem.hpp"
#include <winternl.h>
#include <iostream>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <vector>
#include <mutex>

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

namespace hinv {
namespace vmm {

// Wire format: HyperDbg compiles both user-mode and kernel sides with default
// (natural) alignment, so padding is part of the protocol and matches on both
// ends. These asserts lock the expected layouts (audited against HyperDbg's
// SDK RequestStructures.h field order).
static_assert(sizeof(DebugerReadMemoryPacket) == 48, "DEBUGGER_READ_MEMORY wire size drifted");
static_assert(sizeof(DebugerEditMemoryPacket) == 40, "DEBUGGER_EDIT_MEMORY wire size drifted");

namespace {

// Enumerating an object directory does NOT dispatch IRPs to the device — unlike
// CreateFile, which triggers hyperkd's IRP_MJ_CREATE and burns the one-shot
// log session. This is the only session-safe way to probe for the device.
bool NtDirectoryHasEntry(const wchar_t* dirPath, const wchar_t* entryName) {
    auto NtOpenDirectoryObject = reinterpret_cast<NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)>(
        reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtOpenDirectoryObject")));
    auto NtQueryDirectoryObject = reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG)>(
        reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryDirectoryObject")));
    if (!NtOpenDirectoryObject || !NtQueryDirectoryObject) return false;

    UNICODE_STRING name{};
    name.Buffer = const_cast<PWCH>(dirPath);
    name.Length = static_cast<USHORT>(wcslen(dirPath) * sizeof(wchar_t));
    name.MaximumLength = name.Length;
    OBJECT_ATTRIBUTES oa{};
    oa.Length = sizeof(oa);
    oa.ObjectName = &name;
    oa.Attributes = OBJ_CASE_INSENSITIVE;
    HANDLE hDir = nullptr;
    if (!NT_SUCCESS(NtOpenDirectoryObject(&hDir, 0x0001 /* DIRECTORY_QUERY */, &oa))) return false;

    const size_t wantLen = wcslen(entryName);
    bool found = false;
    std::vector<uint8_t> buf(0x1000);
    ULONG ctx = 0;
    while (NT_SUCCESS(NtQueryDirectoryObject(hDir, buf.data(), static_cast<ULONG>(buf.size()),
                                             TRUE /*ReturnSingleEntry*/, FALSE /*RestartScan*/, &ctx, nullptr))) {
        auto* un = reinterpret_cast<UNICODE_STRING*>(buf.data());
        if (un->Buffer && un->Length / 2 == wantLen &&
            _wcsnicmp(un->Buffer, entryName, wantLen) == 0) {
            found = true;
            break;
        }
    }
    CloseHandle(hDir);
    return found;
}

} // namespace

bool IsVmmDeviceActive() {
    kmem::Trace("vmm: probe device via object directory (no open)");
    // The device object lives in \Device (global namespace, created by
    // IoCreateDevice) — unlike the \DosDevices symlink, which IoCreateSymbolic
    // Link scopes to the loading process's logon session when the driver is
    // manually mapped from usermode context. Session-safe: no handle to the
    // device is ever opened or closed.
    bool ok = NtDirectoryHasEntry(L"\\Device", L"HyperDbgDebuggerDevice");
    kmem::Trace(ok ? "vmm: device present" : "vmm: device absent");
    return ok;
}

HANDLE OpenVmmDevice() {
    // hyperkd's IRP_MJ_CREATE handler enforces SeSinglePrivilegeCheck(
    // SeDebugPrivilege): being elevated is not enough, the privilege must be
    // ENABLED on our token (it ships present-but-disabled for admins).
    static bool privilegeArmed = [] {
        HANDLE token = nullptr;
        bool ok = false;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
            TOKEN_PRIVILEGES tp{};
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            if (LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid) &&
                AdjustTokenPrivileges(token, FALSE, &tp, 0, nullptr, nullptr)) {
                // AdjustTokenPrivileges returns TRUE even when a privilege was
                // not assigned — GetLastError holds ERROR_NOT_ALL_ASSIGNED then.
                ok = (GetLastError() == ERROR_SUCCESS);
            }
            CloseHandle(token);
        }
        if (!ok)
            std::cerr << "[hinv::vmm] WARNING: SeDebugPrivilege not enabled; hyperkd will deny the device open\n";
        return ok;
    }();
    (void)privilegeArmed;

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
    // hyperkd's CREATE handler burns the log session on close (it clears the
    // "session opened" gate while hyperlog can only initialize once per boot),
    // so every open/close pair after the first fails with STATUS_UNSUCCESSFUL.
    // Keep ONE handle for the whole process lifetime instead of open/close
    // per IOCTL. But a magic static would POISON the process forever if the
    // first open happened before hyperkd was loaded — so open lazily and retry
    // while invalid. The mutex also serializes concurrent IOCTLs on the shared
    // (non-overlapped) handle.
    static HANDLE s_device = nullptr;
    static std::mutex s_deviceMutex;
    std::lock_guard<std::mutex> lock(s_deviceMutex);
    if (!s_device || s_device == INVALID_HANDLE_VALUE) {
        s_device = OpenVmmDevice();
        if (s_device == INVALID_HANDLE_VALUE) {
            std::cerr << "[hinv::vmm] Cannot open HyperDbg device: " << GetLastError() << "\n";
            return false;
        }
    }
    HANDLE hDevice = s_device;

    DWORD localBytes = 0;
    DWORD* pBytes = bytesReturned ? bytesReturned : &localBytes;
    BOOL ok = DeviceIoControl(hDevice, ioctlCode, inBuffer, inSize, outBuffer, outSize, pBytes, nullptr);
    DWORD err = GetLastError();

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
    // hyperkd completes the IRP with STATUS_SUCCESS unconditionally — the real
    // outcome lives in these 4 bytes (verified against hyperkd.sys v0.23
    // disassembly): the kernel only arms the VMM IOCTL gate on success.
    if (kernelStatus == 0xC0000063) { // DEBUGGER_ERROR_VMM_ALREADY_INITIALIZED
        std::cout << "[hinv::vmm] HyperDbg VMM already initialized\n";
        return true;
    }
    if (kernelStatus != DEBUGGER_OPERATION_WAS_SUCCESSFUL) {
        std::cerr << "[hinv::vmm] VMM init failed, kernel status: 0x" << std::hex << kernelStatus << std::dec << "\n";
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

    if (hdr->KernelStatus != DEBUGGER_OPERATION_WAS_SUCCESSFUL) {
        std::cerr << "[hinv::vmm] ReadMemory kernel status: 0x" << std::hex << hdr->KernelStatus << std::dec << "\n";
        return false;
    }
    // Payload size is derived from bytes actually returned, like the official
    // library does (bytesReturned - header size); ReturnLength is advisory.
    size_t payloadSize = (bytes >= sizeof(DebugerReadMemoryPacket))
                         ? (bytes - sizeof(DebugerReadMemoryPacket)) : 0;
    if (payloadSize < size) {
        std::cerr << "[hinv::vmm] ReadMemory returned " << payloadSize << " bytes, expected " << size << "\n";
        return false;
    }

    std::memcpy(out, packet.data() + sizeof(DebugerReadMemoryPacket), size);
    return true;
}

bool EditKernelMemoryHyperDbg(uint64_t address, const void* in, size_t size) {
    if (!in || size == 0 || size > 0x10000) return false;

    // Official HyperDbg semantics: CountOf64Chunks is the number of VALUES,
    // each stored in its own 8-byte slot; the kernel writes ByteSize bytes
    // from each slot. Use a single dword/qword slot when the size matches,
    // otherwise one byte per slot so padding can never overwrite neighbors.
    uint32_t byteSizeCode; // 0 = byte, 1 = dword, 2 = qword
    uint32_t count;
    uint32_t bytesPerSlot;
    if (size == 4)      { byteSizeCode = 1; count = 1; bytesPerSlot = 4; }
    else if (size == 8) { byteSizeCode = 2; count = 1; bytesPerSlot = 8; }
    else                { byteSizeCode = 0; count = static_cast<uint32_t>(size); bytesPerSlot = 1; }

    size_t payloadSize = static_cast<size_t>(count) * sizeof(uint64_t);
    std::vector<uint8_t> packet(sizeof(DebugerEditMemoryPacket) + payloadSize, 0);
    auto* hdr = reinterpret_cast<DebugerEditMemoryPacket*>(packet.data());
    hdr->Result = 0;
    hdr->Address = address;
    hdr->ProcessId = 0;
    hdr->MemoryType = 0; // virtual
    hdr->ByteSize = byteSizeCode;
    hdr->CountOf64Chunks = count;
    hdr->FinalStructureSize = static_cast<uint32_t>(sizeof(DebugerEditMemoryPacket) + payloadSize);

    const auto* src = static_cast<const uint8_t*>(in);
    for (uint32_t i = 0; i < count; ++i) {
        std::memcpy(packet.data() + sizeof(DebugerEditMemoryPacket) + i * sizeof(uint64_t),
                    src + static_cast<size_t>(i) * bytesPerSlot, bytesPerSlot);
    }

    DWORD bytes = 0;
    if (!SendVmmIoctl(IOCTL_HYPERDBG_EDIT_MEMORY, packet.data(), static_cast<DWORD>(packet.size()),
                      packet.data(), static_cast<DWORD>(packet.size()), &bytes)) {
        return false;
    }

    if (hdr->Result != DEBUGGER_OPERATION_WAS_SUCCESSFUL) {
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
    // Matches HyperDbg's DEBUGGER_VA2PA_AND_PA2VA_COMMANDS under natural
    // alignment (the protocol is compiled with default packing on both ends).
    static_assert(sizeof(Va2PaPacket) == 32, "VA2PA wire size drifted");

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

    if (packet.KernelStatus != DEBUGGER_OPERATION_WAS_SUCCESSFUL) {
        std::cerr << "[hinv::vmm] VA2PA kernel status: 0x" << std::hex << packet.KernelStatus << std::dec << "\n";
        return false;
    }
    outPhysical = packet.PhysicalAddress;
    return true;
}

} // namespace vmm
} // namespace hinv
