#include "hinv_vmm.hpp"
#include "hinv_kmem.hpp"
#include <winternl.h>
#include <iostream>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <vector>
#include <mutex>
#include <limits>
#include <cstdlib>

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

enum class VmmSessionState {
    Unopened,
    Active,
    Closed
};

constexpr size_t MAX_VMM_TRANSFER_SIZE = 0x10000;
constexpr size_t MAX_HYPERDBG_SCRIPT_SOURCE_SIZE = 1u << 20;
constexpr uint32_t MAX_HYPERDBG_SCRIPT_SYMBOLS = 1u << 20;
constexpr size_t HYPERDBG_SCRIPT_SYMBOL_SIZE = 24;

HANDLE g_vmmDevice = INVALID_HANDLE_VALUE;
std::mutex g_vmmDeviceMutex;
VmmSessionState g_vmmSessionState = VmmSessionState::Unopened;

bool IsValidTransferRange(uint64_t address, size_t size) {
    return size != 0 && size <= MAX_VMM_TRANSFER_SIZE &&
           static_cast<uint64_t>(size) <= std::numeric_limits<uint64_t>::max() - address;
}

uint32_t ActiveProcessorCount() {
    const DWORD count = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    return count == 0 ? 1u : static_cast<uint32_t>(count);
}

bool MsrWritesEnabled() {
    static const bool enabled = [] {
        const char* value = std::getenv("HINV_ENABLE_MSR_WRITE");
        return value && std::strcmp(value, "1") == 0;
    }();
    if (!enabled) {
        std::cerr << "[hinv::vmm] MSR writes are disabled; set "
                     "HINV_ENABLE_MSR_WRITE=1 in the disposable lab VM\n";
    }
    return enabled;
}

struct ScriptSymbolBufferLayout {
    void* Head;
    uint32_t Pointer;
    uint32_t Size;
    char* Message;
};

static_assert(sizeof(ScriptSymbolBufferLayout) == 24);
static_assert(offsetof(ScriptSymbolBufferLayout, Pointer) == 8);
static_assert(offsetof(ScriptSymbolBufferLayout, Message) == 16);

using ScriptEngineParseFn = void* (__cdecl*)(char*);
using RemoveSymbolBufferFn = void (__cdecl*)(void*);

struct ScriptEngineRuntime {
    HMODULE ScriptEngine = nullptr;
    ScriptEngineParseFn Parse = nullptr;
    RemoveSymbolBufferFn Remove = nullptr;
};

template <typename Function>
Function GetRuntimeFunction(HMODULE module, const char* name) {
    const FARPROC raw = GetProcAddress(module, name);
    Function function = nullptr;
    static_assert(sizeof(function) == sizeof(raw));
    std::memcpy(&function, &raw, sizeof(function));
    return function;
}

void AddScriptRuntimeCandidate(std::vector<std::wstring>& candidates,
                               const std::wstring& path) {
    if (path.empty()) return;
    for (const auto& candidate : candidates) {
        if (_wcsicmp(candidate.c_str(), path.c_str()) == 0) return;
    }
    candidates.push_back(path);
}

std::wstring GetExecutableDirectory() {
    wchar_t path[MAX_PATH]{};
    const DWORD length = GetModuleFileNameW(nullptr, path, ARRAYSIZE(path));
    if (length == 0 || length >= ARRAYSIZE(path)) return {};
    std::wstring result(path, length);
    const size_t slash = result.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return {};
    result.resize(slash);
    return result;
}

std::wstring GetParentDirectory(const std::wstring& path) {
    const size_t slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? std::wstring{} : path.substr(0, slash);
}

ScriptEngineRuntime& GetScriptEngineRuntime() {
    static ScriptEngineRuntime runtime;
    static std::once_flag once;
    std::call_once(once, [] {
        std::vector<std::wstring> candidates;
        const wchar_t* explicitPath = _wgetenv(L"HINV_LIBHYPERDBG");
        const wchar_t* explicitDirectory = _wgetenv(L"HINV_LIBHYPERDBG_DIR");
        const std::wstring executableDirectory = GetExecutableDirectory();

        if (explicitDirectory && *explicitDirectory) {
            AddScriptRuntimeCandidate(
                candidates, std::wstring(explicitDirectory) + L"\\script-engine.dll");
        } else if (explicitPath && *explicitPath) {
            const std::wstring directory = GetParentDirectory(explicitPath);
            if (!directory.empty()) {
                AddScriptRuntimeCandidate(
                    candidates, directory + L"\\script-engine.dll");
            }
        }
        if (!executableDirectory.empty()) {
            AddScriptRuntimeCandidate(
                candidates, executableDirectory + L"\\hyperdbg-v0.23\\script-engine.dll");
            AddScriptRuntimeCandidate(
                candidates, executableDirectory + L"\\script-engine.dll");
        }
        AddScriptRuntimeCandidate(candidates, L"script-engine.dll");

        for (const auto& candidate : candidates) {
            HMODULE module = LoadLibraryExW(
                candidate.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
            if (!module) continue;

            runtime.ScriptEngine = module;
            break;
        }

        if (!runtime.ScriptEngine) {
            std::cerr << "[hinv::vmm] HyperDbg script-engine runtime not found; set "
                         "HINV_LIBHYPERDBG_DIR to the v0.23 runtime directory\n";
            return;
        }

        if (runtime.ScriptEngine) {
            runtime.Parse = GetRuntimeFunction<ScriptEngineParseFn>(
                runtime.ScriptEngine, "ScriptEngineParse");
            runtime.Remove = GetRuntimeFunction<RemoveSymbolBufferFn>(
                runtime.ScriptEngine, "RemoveSymbolBuffer");
        }
        if (!runtime.Parse || !runtime.Remove) {
            std::cerr << "[hinv::vmm] HyperDbg v0.23 script-engine exports are incomplete\n";
            runtime.Parse = nullptr;
            runtime.Remove = nullptr;
        }
    });
    return runtime;
}

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
    if (!hDevice || hDevice == INVALID_HANDLE_VALUE) return;

    std::lock_guard<std::mutex> lock(g_vmmDeviceMutex);
    if (g_vmmSessionState == VmmSessionState::Active && hDevice == g_vmmDevice) {
        std::cerr << "[hinv::vmm] Refusing to close the shared HyperDbg session through the raw handle API\n";
        return;
    }
    CloseHandle(hDevice);
}

bool ShutdownVmm() {
    std::lock_guard<std::mutex> lock(g_vmmDeviceMutex);
    if (g_vmmSessionState != VmmSessionState::Active || g_vmmDevice == INVALID_HANDLE_VALUE)
        return true;

    HANDLE hDevice = g_vmmDevice;
    if (!CloseHandle(hDevice)) {
        std::cerr << "[hinv::vmm] Failed to close HyperDbg device session: " << GetLastError() << "\n";
        return false;
    }
    g_vmmDevice = INVALID_HANDLE_VALUE;
    g_vmmSessionState = VmmSessionState::Closed;
    return true;
}

bool SendVmmIoctl(DWORD ioctlCode, LPVOID inBuffer, DWORD inSize, LPVOID outBuffer, DWORD outSize, LPDWORD bytesReturned) {
    // hyperkd's CREATE handler burns the log session on close (it clears the
    // "session opened" gate while hyperlog can only initialize once per boot),
    // so every open/close pair after the first fails with STATUS_UNSUCCESSFUL.
    // Keep ONE handle until explicit session closure instead of open/close per
    // IOCTL. A failed first open must remain retryable if hyperkd was not loaded
    // yet, while a deliberately closed session must never be reopened. The
    // mutex also serializes concurrent IOCTLs on the shared (non-overlapped)
    // handle.
    std::lock_guard<std::mutex> lock(g_vmmDeviceMutex);
    if (g_vmmSessionState == VmmSessionState::Closed) {
        std::cerr << "[hinv::vmm] HyperDbg device session is already closed and cannot be reopened safely\n";
        return false;
    }
    if (g_vmmDevice == INVALID_HANDLE_VALUE) {
        g_vmmDevice = OpenVmmDevice();
        if (g_vmmDevice == INVALID_HANDLE_VALUE) {
            std::cerr << "[hinv::vmm] Cannot open HyperDbg device: " << GetLastError() << "\n";
            return false;
        }
        g_vmmSessionState = VmmSessionState::Active;
    }
    HANDLE hDevice = g_vmmDevice;

    DWORD localBytes = 0;
    DWORD* pBytes = bytesReturned ? bytesReturned : &localBytes;
    *pBytes = 0;
    BOOL ok = DeviceIoControl(hDevice, ioctlCode, inBuffer, inSize, outBuffer, outSize, pBytes, nullptr);

    if (!ok) {
        std::cerr << "[hinv::vmm] DeviceIoControl failed: " << GetLastError() << "\n";
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
    if (bytes != static_cast<DWORD>(sizeof(kernelStatus))) {
        std::cerr << "[hinv::vmm] VMM init returned " << bytes << " bytes, expected "
                  << sizeof(kernelStatus) << "\n";
        return false;
    }
    // hyperkd completes the IRP with STATUS_SUCCESS unconditionally — the real
    // outcome lives in these 4 bytes (verified against hyperkd.sys v0.23
    // disassembly): the kernel only arms the VMM IOCTL gate on success.
    if (kernelStatus != DEBUGGER_OPERATION_WAS_SUCCESSFUL) {
        std::cerr << "[hinv::vmm] VMM init failed, kernel status: 0x" << std::hex << kernelStatus << std::dec << "\n";
        return false;
    }
    std::cout << "[hinv::vmm] HyperDbg VMM initialized\n";
    return true;
}

bool ReadMsrHyperDbg(uint32_t msr, uint32_t core, std::vector<uint64_t>& values) {
    values.clear();
    const uint32_t processorCount = ActiveProcessorCount();
    if (core != sdk::kAllCores && core >= processorCount) return false;

    const size_t valueCount = core == sdk::kAllCores ? processorCount : 1;
    sdk::ReadAndWriteOnMsr request{};
    request.Msr = msr;
    request.CoreNumber = core;
    request.ActionType = sdk::MsrAction::Read;

    values.resize(valueCount);
    DWORD bytes = 0;
    const DWORD outputSize = static_cast<DWORD>(values.size() * sizeof(uint64_t));
    if (!SendVmmIoctl(IOCTL_HYPERDBG_READ_OR_WRITE_MSR,
                      &request, sizeof(request), values.data(), outputSize, &bytes)) {
        values.clear();
        return false;
    }
    if (bytes != outputSize) {
        std::cerr << "[hinv::vmm] RDMSR returned " << bytes
                  << " bytes, expected " << outputSize << "\n";
        values.clear();
        return false;
    }
    return true;
}

bool WriteMsrHyperDbg(uint32_t msr, uint64_t value, uint32_t core) {
    if (!MsrWritesEnabled()) return false;
    const uint32_t processorCount = ActiveProcessorCount();
    if (core != sdk::kAllCores && core >= processorCount) return false;

    sdk::ReadAndWriteOnMsr request{};
    request.Msr = msr;
    request.CoreNumber = core;
    request.ActionType = sdk::MsrAction::Write;
    request.Value = value;

    DWORD bytes = 0;
    if (!SendVmmIoctl(IOCTL_HYPERDBG_READ_OR_WRITE_MSR,
                      &request, sizeof(request), &request, sizeof(request), &bytes))
        return false;
    return bytes == 0 || bytes == sizeof(request);
}

bool ReadPageTableEntriesHyperDbg(
    uint64_t virtualAddress, uint32_t processId,
    sdk::ReadPageTableEntriesDetails& details) {
    details = {};
    details.VirtualAddress = virtualAddress;
    details.ProcessId = processId;

    DWORD bytes = 0;
    if (!SendVmmIoctl(IOCTL_HYPERDBG_READ_PAGE_TABLE,
                      &details, sizeof(details), &details, sizeof(details), &bytes) ||
        bytes != sizeof(details) ||
        details.KernelStatus != DEBUGGER_OPERATION_WAS_SUCCESSFUL)
        return false;
    return true;
}

// ---------------------------------------------------------------------------
// Structured HyperDbg operations
// ---------------------------------------------------------------------------

bool ReadKernelMemoryHyperDbg(uint64_t address, void* out, size_t size) {
    if (!out || !IsValidTransferRange(address, size)) return false;

    std::vector<uint8_t> packet(sizeof(DebugerReadMemoryPacket) + size, 0);
    auto* hdr = reinterpret_cast<DebugerReadMemoryPacket*>(packet.data());
    // HyperDbg still resolves the address in a valid process context for
    // kernel virtual addresses; PID 0 is not a valid EPROCESS lookup here.
    hdr->Pid = GetCurrentProcessId();
    hdr->Address = address;
    hdr->Size = static_cast<uint32_t>(size);
    hdr->GetAddressMode = 0;
    hdr->AddrMode = AddressMode::Mode64;
    hdr->MemType = ReadMemoryType::Virtual;
    hdr->ReadType = ReadingType::Kernel;
    hdr->ReturnLength = 0;
    hdr->KernelStatus = 0;

    DWORD bytes = 0;
    const DWORD headerSize = static_cast<DWORD>(sizeof(DebugerReadMemoryPacket));
    const DWORD packetSize = static_cast<DWORD>(packet.size());
    // The driver consumes the request header and writes the requested bytes
    // into the same trailing payload buffer.
    if (!SendVmmIoctl(IOCTL_HYPERDBG_READ_MEMORY, packet.data(), packetSize,
                       packet.data(), packetSize, &bytes)) {
        return false;
    }

    if (bytes < headerSize || bytes > packetSize) {
        std::cerr << "[hinv::vmm] ReadMemory returned invalid packet size: " << bytes << "\n";
        return false;
    }
    if (hdr->KernelStatus != DEBUGGER_OPERATION_WAS_SUCCESSFUL) {
        std::cerr << "[hinv::vmm] ReadMemory kernel status: 0x" << std::hex << hdr->KernelStatus << std::dec << "\n";
        return false;
    }
    if (bytes != packetSize) {
        std::cerr << "[hinv::vmm] ReadMemory returned " << (bytes - headerSize)
                  << " data bytes, expected " << size << "\n";
        return false;
    }

    std::memcpy(out, packet.data() + sizeof(DebugerReadMemoryPacket), size);
    return true;
}

bool EditKernelMemoryHyperDbg(uint64_t address, const void* in, size_t size) {
    if (!in || !IsValidTransferRange(address, size)) return false;

    std::vector<uint8_t> expected(size);
    std::memcpy(expected.data(), in, size);

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
    hdr->ProcessId = GetCurrentProcessId();
    hdr->MemoryType = 0; // virtual
    hdr->ByteSize = byteSizeCode;
    hdr->CountOf64Chunks = count;
    hdr->FinalStructureSize = static_cast<uint32_t>(sizeof(DebugerEditMemoryPacket) + payloadSize);

    const auto* src = expected.data();
    for (uint32_t i = 0; i < count; ++i) {
        std::memcpy(packet.data() + sizeof(DebugerEditMemoryPacket) + i * sizeof(uint64_t),
                    src + static_cast<size_t>(i) * bytesPerSlot, bytesPerSlot);
    }

    DWORD bytes = 0;
    const DWORD headerSize = static_cast<DWORD>(sizeof(DebugerEditMemoryPacket));
    if (!SendVmmIoctl(IOCTL_HYPERDBG_EDIT_MEMORY, packet.data(), static_cast<DWORD>(packet.size()),
                       packet.data(), headerSize, &bytes)) {
        return false;
    }

    if (bytes != headerSize) {
        std::cerr << "[hinv::vmm] EditMemory returned " << bytes << " bytes, expected "
                  << headerSize << "\n";
        return false;
    }
    if (hdr->Result != DEBUGGER_OPERATION_WAS_SUCCESSFUL) {
        std::cerr << "[hinv::vmm] EditMemory result: 0x" << std::hex << hdr->Result << std::dec << "\n";
        return false;
    }

    // HyperDbg v0.23 reports success even when an unsafe per-chunk write does
    // not complete. Verify the complete bounded write after the IOCTL lock is
    // released by SendVmmIoctl.
    std::vector<uint8_t> actual(size);
    if (!ReadKernelMemoryHyperDbg(address, actual.data(), actual.size())) {
        std::cerr << "[hinv::vmm] EditMemory readback failed\n";
        return false;
    }
    if (std::memcmp(actual.data(), expected.data(), size) != 0) {
        std::cerr << "[hinv::vmm] EditMemory readback did not match requested bytes\n";
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
    packet.ProcessId = GetCurrentProcessId();
    packet.IsVirtual2Physical = 1;
    packet.KernelStatus = 0;

    DWORD bytes = 0;
    if (!SendVmmIoctl(IOCTL_HYPERDBG_VA2PA_AND_PA2VA, &packet, sizeof(packet),
                       &packet, sizeof(packet), &bytes)) {
        return false;
    }

    if (bytes != static_cast<DWORD>(sizeof(packet))) {
        std::cerr << "[hinv::vmm] VA2PA returned " << bytes << " bytes, expected "
                  << sizeof(packet) << "\n";
        return false;
    }
    if (packet.KernelStatus != DEBUGGER_OPERATION_WAS_SUCCESSFUL) {
        std::cerr << "[hinv::vmm] VA2PA kernel status: 0x" << std::hex << packet.KernelStatus << std::dec << "\n";
        return false;
    }
    outPhysical = packet.PhysicalAddress;
    return true;
}

bool SearchMemoryHyperDbg(uint64_t address, uint64_t length, uint32_t processId,
                          sdk::SearchMemoryType memoryType,
                          sdk::SearchMemoryByteSize byteSize,
                          const std::vector<uint64_t>& patterns,
                          std::vector<uint64_t>& results) {
    results.clear();
    if (length == 0 || patterns.empty() ||
        patterns.size() > sdk::kMaximumSearchResults ||
        length > std::numeric_limits<uint64_t>::max() - address ||
        static_cast<uint32_t>(memoryType) >
            static_cast<uint32_t>(sdk::SearchMemoryType::PhysicalFromVirtual) ||
        static_cast<uint32_t>(byteSize) >
            static_cast<uint32_t>(sdk::SearchMemoryByteSize::Qword))
        return false;

    const size_t payloadSize = patterns.size() * sizeof(uint64_t);
    const size_t packetSize = sizeof(sdk::SearchMemoryRequest) + payloadSize;
    if (packetSize > std::numeric_limits<uint32_t>::max()) return false;

    std::vector<uint8_t> packet(packetSize, 0);
    auto* request = reinterpret_cast<sdk::SearchMemoryRequest*>(packet.data());
    request->Address = address;
    request->Length = length;
    request->ProcessId = memoryType == sdk::SearchMemoryType::Physical ? 0 : processId;
    request->MemoryType = memoryType;
    request->ByteSize = byteSize;
    request->CountOf64Chunks = static_cast<uint32_t>(patterns.size());
    request->FinalStructureSize = static_cast<uint32_t>(packetSize);
    std::memcpy(packet.data() + sizeof(*request), patterns.data(), payloadSize);

    std::vector<uint64_t> output(sdk::kMaximumSearchResults, 0);
    DWORD bytes = 0;
    const DWORD outputSize = static_cast<DWORD>(output.size() * sizeof(uint64_t));
    if (!SendVmmIoctl(IOCTL_HYPERDBG_SEARCH_MEMORY,
                      packet.data(), static_cast<DWORD>(packet.size()),
                      output.data(), outputSize, &bytes))
        return false;
    if (bytes != outputSize) {
        std::cerr << "[hinv::vmm] SearchMemory returned " << bytes
                  << " bytes, expected " << outputSize << "\n";
        return false;
    }

    for (const uint64_t result : output) {
        if (result == 0) break;
        results.push_back(result);
    }
    return true;
}

bool RegisterEventHyperDbg(sdk::GeneralEventDetail event,
                           const std::vector<uint8_t>& condition) {
    if (condition.size() > std::numeric_limits<uint32_t>::max() - sizeof(event))
        return false;

    event.ConditionBufferSize = static_cast<uint32_t>(condition.size());
    const size_t packetSize = sizeof(event) + condition.size();
    std::vector<uint8_t> packet(packetSize, 0);
    std::memcpy(packet.data(), &event, sizeof(event));
    if (!condition.empty()) {
        std::memcpy(packet.data() + sizeof(event), condition.data(), condition.size());
    }

    sdk::EventAndActionResult result{};
    DWORD bytes = 0;
    if (!SendVmmIoctl(IOCTL_HYPERDBG_REGISTER_EVENT,
                      packet.data(), static_cast<DWORD>(packet.size()),
                      &result, sizeof(result), &bytes) ||
        bytes != sizeof(result))
        return false;
    if (result.IsSuccessful == 0 || result.Error != 0) {
        std::cerr << "[hinv::vmm] RegisterEvent failed: 0x"
                  << std::hex << result.Error << std::dec << "\n";
    }
    return result.IsSuccessful != 0 && result.Error == 0;
}

bool AddActionToEventHyperDbg(sdk::GeneralAction action,
                              const std::vector<uint8_t>& payload) {
    if (payload.size() > std::numeric_limits<uint32_t>::max() - sizeof(action))
        return false;

    switch (action.ActionType) {
    case sdk::EventActionType::BreakToDebugger:
        if (!payload.empty()) return false;
        action.CustomCodeBufferSize = 0;
        action.ScriptBufferSize = 0;
        break;
    case sdk::EventActionType::RunScript:
        action.CustomCodeBufferSize = 0;
        action.ScriptBufferSize = static_cast<uint32_t>(payload.size());
        break;
    case sdk::EventActionType::RunCustomCode:
        action.CustomCodeBufferSize = static_cast<uint32_t>(payload.size());
        action.ScriptBufferSize = 0;
        break;
    default:
        return false;
    }

    const size_t packetSize = sizeof(action) + payload.size();
    std::vector<uint8_t> packet(packetSize, 0);
    std::memcpy(packet.data(), &action, sizeof(action));
    if (!payload.empty()) {
        std::memcpy(packet.data() + sizeof(action), payload.data(), payload.size());
    }

    sdk::EventAndActionResult result{};
    DWORD bytes = 0;
    if (!SendVmmIoctl(IOCTL_HYPERDBG_ADD_ACTION_TO_EVENT,
                      packet.data(), static_cast<DWORD>(packet.size()),
                      &result, sizeof(result), &bytes) ||
        bytes != sizeof(result))
        return false;
    if (result.IsSuccessful == 0 || result.Error != 0) {
        std::cerr << "[hinv::vmm] AddAction failed: 0x"
                  << std::hex << result.Error << std::dec << "\n";
    }
    return result.IsSuccessful != 0 && result.Error == 0;
}

bool ModifyEventHyperDbg(uint64_t tag, sdk::ModifyEventsType action,
                         bool& isEnabled) {
    sdk::ModifyEventsRequest request{};
    request.Tag = tag;
    request.TypeOfAction = action;
    request.IsEnabled = 0;

    DWORD bytes = 0;
    if (!SendVmmIoctl(IOCTL_HYPERDBG_MODIFY_EVENTS,
                      &request, sizeof(request), &request, sizeof(request), &bytes) ||
        bytes != sizeof(request) ||
        request.KernelStatus != DEBUGGER_OPERATION_WAS_SUCCESSFUL)
        return false;
    isEnabled = request.IsEnabled != 0;
    return true;
}

namespace {

bool SendProcessAction(sdk::AttachDetachProcessRequest& request) {
    DWORD bytes = 0;
    return SendVmmIoctl(IOCTL_HYPERDBG_ATTACH_DETACH_PROCESS,
                        &request, sizeof(request), &request, sizeof(request), &bytes) &&
           bytes == sizeof(request) &&
           request.Result == DEBUGGER_OPERATION_WAS_SUCCESSFUL;
}

} // namespace

bool AttachProcessHyperDbg(uint32_t processId, uint64_t& token) {
    token = 0;
    if (processId == 0) return false;

    sdk::AttachDetachProcessRequest request{};
    request.ProcessId = processId;
    request.CheckCallbackAtFirstInstruction = 0;
    request.Action = sdk::AttachDetachAction::Attach;
    if (!SendProcessAction(request)) return false;

    token = request.Token;
    return token != 0;
}

bool DetachProcessHyperDbg(uint32_t processId, uint64_t token) {
    if (processId == 0 || token == 0) return false;

    sdk::AttachDetachProcessRequest request{};
    request.ProcessId = processId;
    request.Token = token;
    request.Action = sdk::AttachDetachAction::Detach;
    return SendProcessAction(request);
}

bool PauseProcessHyperDbg(uint64_t token) {
    if (token == 0) return false;
    sdk::AttachDetachProcessRequest request{};
    request.Token = token;
    request.Action = sdk::AttachDetachAction::PauseProcess;
    return SendProcessAction(request);
}

bool ContinueProcessHyperDbg(uint64_t token) {
    if (token == 0) return false;
    sdk::AttachDetachProcessRequest request{};
    request.Token = token;
    request.Action = sdk::AttachDetachAction::ContinueProcess;
    return SendProcessAction(request);
}

bool SendUserDebuggerCommandHyperDbg(
    uint64_t token, uint32_t threadId,
    sdk::UserDebuggerCommandAction action,
    const std::vector<uint8_t>& payload,
    bool applyToAllPausedThreads, bool waitForEventCompletion,
    uint64_t optionalParam1, uint64_t optionalParam2,
    uint64_t optionalParam3, uint64_t optionalParam4,
    std::vector<uint8_t>& response) {
    response.clear();
    if (token == 0 || payload.size() >
        std::numeric_limits<uint32_t>::max() - sizeof(sdk::UserDebuggerCommandPacket))
        return false;

    switch (action) {
    case sdk::UserDebuggerCommandAction::Pause:
    case sdk::UserDebuggerCommandAction::RegularStep:
    case sdk::UserDebuggerCommandAction::ReadRegisters:
    case sdk::UserDebuggerCommandAction::ExecuteScriptBuffer:
        break;
    default:
        return false;
    }

    const size_t packetSize = sizeof(sdk::UserDebuggerCommandPacket) + payload.size();
    std::vector<uint8_t> packet(packetSize, 0);
    auto* request = reinterpret_cast<sdk::UserDebuggerCommandPacket*>(packet.data());
    request->UdAction.ActionType = action;
    request->UdAction.OptionalParam1 = optionalParam1;
    request->UdAction.OptionalParam2 = optionalParam2;
    request->UdAction.OptionalParam3 = optionalParam3;
    request->UdAction.OptionalParam4 = optionalParam4;
    request->ProcessDebuggingDetailToken = token;
    request->TargetThreadId = threadId;
    request->ApplyToAllPausedThreads = applyToAllPausedThreads ? 1 : 0;
    request->WaitForEventCompletion = waitForEventCompletion ? 1 : 0;
    if (!payload.empty()) {
        std::memcpy(packet.data() + sizeof(*request), payload.data(), payload.size());
    }

    DWORD bytes = 0;
    if (!SendVmmIoctl(IOCTL_HYPERDBG_SEND_USER_COMMANDS,
                      packet.data(), static_cast<DWORD>(packet.size()),
                      packet.data(), static_cast<DWORD>(packet.size()), &bytes) ||
        bytes != packet.size() ||
        request->Result != DEBUGGER_OPERATION_WAS_SUCCESSFUL)
        return false;

    response.assign(packet.begin() + sizeof(*request), packet.end());
    return true;
}

bool ExecuteCompiledUserScriptHyperDbg(
    uint64_t token, uint32_t threadId,
    const std::vector<uint8_t>& compiledScript,
    uint32_t scriptPointer, bool isFormat,
    uint64_t* formatValue) {
    if (compiledScript.empty() ||
        compiledScript.size() > std::numeric_limits<uint32_t>::max())
        return false;

    sdk::DebuggeeScriptPacket script{};
    script.ScriptBufferSize = static_cast<uint32_t>(compiledScript.size());
    script.ScriptBufferPointer = scriptPointer;
    script.IsFormat = isFormat ? 1 : 0;

    std::vector<uint8_t> payload(sizeof(script) + compiledScript.size(), 0);
    std::memcpy(payload.data(), &script, sizeof(script));
    std::memcpy(payload.data() + sizeof(script),
                compiledScript.data(), compiledScript.size());

    std::vector<uint8_t> response;
    if (!SendUserDebuggerCommandHyperDbg(
            token, threadId, sdk::UserDebuggerCommandAction::ExecuteScriptBuffer,
            payload, false, true, 0, 0, 0, 0, response) ||
        response.size() != payload.size())
        return false;

    std::memcpy(&script, response.data(), sizeof(script));
    if (script.Result != DEBUGGER_OPERATION_WAS_SUCCESSFUL) return false;
    if (formatValue) *formatValue = script.FormatValue;
    return true;
}

bool CompileUserScriptHyperDbg(const std::string& source,
                               std::vector<uint8_t>& compiledScript,
                               uint32_t& scriptPointer) {
    compiledScript.clear();
    scriptPointer = 0;
    if (source.empty() || source.size() > MAX_HYPERDBG_SCRIPT_SOURCE_SIZE ||
        source.find('\0') != std::string::npos)
        return false;

    ScriptEngineRuntime& runtime = GetScriptEngineRuntime();
    if (!runtime.Parse || !runtime.Remove) return false;

    std::vector<char> mutableSource(source.begin(), source.end());
    mutableSource.push_back('\0');
    void* opaqueBuffer = runtime.Parse(mutableSource.data());
    if (!opaqueBuffer) return false;

    auto releaseBuffer = [&] {
        runtime.Remove(opaqueBuffer);
    };

    const auto* buffer = static_cast<const ScriptSymbolBufferLayout*>(opaqueBuffer);
    const uint64_t symbolCount = buffer->Pointer;
    if (!buffer->Head || symbolCount == 0 ||
        symbolCount > MAX_HYPERDBG_SCRIPT_SYMBOLS ||
        symbolCount > buffer->Size ||
        symbolCount > std::numeric_limits<size_t>::max() / HYPERDBG_SCRIPT_SYMBOL_SIZE) {
        releaseBuffer();
        return false;
    }

    const size_t byteSize = static_cast<size_t>(symbolCount) *
                            HYPERDBG_SCRIPT_SYMBOL_SIZE;
    try {
        compiledScript.resize(byteSize);
    } catch (...) {
        releaseBuffer();
        return false;
    }
    std::memcpy(compiledScript.data(), buffer->Head, byteSize);
    scriptPointer = static_cast<uint32_t>(symbolCount);
    releaseBuffer();
    return true;
}

bool ExecuteTextUserScriptHyperDbg(
    uint64_t token, uint32_t threadId, const std::string& source,
    bool isFormat, uint64_t* formatValue) {
    std::vector<uint8_t> compiledScript;
    uint32_t scriptPointer = 0;
    if (!CompileUserScriptHyperDbg(source, compiledScript, scriptPointer))
        return false;
    return ExecuteCompiledUserScriptHyperDbg(
        token, threadId, compiledScript, scriptPointer, isFormat, formatValue);
}

} // namespace vmm
} // namespace hinv
