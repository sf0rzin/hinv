#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <type_traits>
#include <mutex>

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
// Returns 0 on failure. Forwarded exports ("Dll.Func") are chased recursively
// through ResolveKernelExport (depth-capped).
uint64_t GetKernelExport(byovd::IByovdBackend* backend, uint64_t moduleBase, const char* exportName,
                         unsigned depth = 0);

// Resolve a kernel export by module name + export name.
uint64_t ResolveKernelExport(byovd::IByovdBackend* backend, const wchar_t* moduleName, const char* exportName,
                             unsigned depth = 0);

// Windows version info used to pick kernel structure layouts.
struct OsVersionInfo {
    uint32_t major = 0;
    uint32_t minor = 0;
    uint32_t build = 0;
    uint32_t revision = 0;
};

// Get OS version via ntdll!RtlGetVersion.
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

// --- Inverted function table (SEH registration for manually mapped images) ---
//
// Win11 24H2 REMOVED ntoskrnl!RtlAddFunctionTable / RtlDeleteFunctionTable, so
// the only way to make RtlLookupFunctionEntry see a manually mapped image's
// .pdata is to insert into PsInvertedFunctionTable directly. Layout recovered
// from nt!RtlpInsertInvertedFunctionTableEntry / nt!RtlLookupFunctionEntry on
// build 26100 (and stable since Win10 RS1):
//   +0x00 CurrentSize (u32)   +0x04 MaximumSize (u32)
//   +0x08 Epoch (u32; odd while mutating, bumped twice per mutation)
//   +0x0C Overflow (u8; kernel sets it instead of inserting when full)
//   entries at +0x10, stride 0x18, sorted ascending by ImageBase:
//     +0x00 FunctionTable (.pdata VA)   +0x08 ImageBase
//     +0x10 SizeOfImage (u32)           +0x14 SizeOfTable (u32, .pdata bytes)
//
// The table address is recovered at runtime from ntoskrnl!RtlLookupFunctionEntry
// (exported on every build), which reads the fast-path entry through
// PsInvertedFunctionTable+0x18 with a RIP-relative load right after its prologue.

// Resolve PsInvertedFunctionTable. Returns 0 on failure. Result is cached.
uint64_t ResolveInvertedFunctionTable(byovd::IByovdBackend* backend);

// Insert an image's .pdata into the inverted function table (idempotent on
// ImageBase). FALSE means NOT registered — callers must keep the image
// resident, exactly like a failed RtlAddFunctionTable.
bool InsertInvertedFunctionTableEntry(byovd::IByovdBackend* backend, uint64_t functionTableVa,
                                      uint64_t imageBase, uint32_t imageSize, uint32_t tableSize);

// Remove the entry for imageBase. TRUE when the entry is gone (or never
// existed); FALSE when removal could not be confirmed (image must stay
// resident — the table would keep pointing into freed pool).
bool RemoveInvertedFunctionTableEntry(byovd::IByovdBackend* backend, uint64_t imageBase);

namespace detail {

// Unit-testable cores operating on an already-located table address.
uint64_t FindInvertedFunctionTable(byovd::IByovdBackend* backend, uint64_t lookupFnVa);
bool InsertInvertedFunctionTableEntryAt(byovd::IByovdBackend* backend, uint64_t tableVa,
                                        uint64_t functionTableVa, uint64_t imageBase,
                                        uint32_t imageSize, uint32_t tableSize);
bool RemoveInvertedFunctionTableEntryAt(byovd::IByovdBackend* backend, uint64_t tableVa,
                                        uint64_t imageBase);

} // namespace detail

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
// registers intact and the target's RAX becomes our return value.
//
// Return value semantics: TRUE means the target executed (read its result via
// outResult). FALSE only when the hook never installed — the target never ran.
// A FAILED hook removal after a successful call is logged loudly (the NtAddAtom
// patch is left in ntoskrnl text — latent PatchGuard bait) but still returns
// TRUE, because from the caller's perspective the operation DID happen;
// conflating "call failed" with "restore failed" once made callers free pool
// the kernel still referenced.
//
// The hook is a global patch with no trampoline: while installed, ANY thread
// calling NtAddAtom lands on our target. The window is microseconds and the
// syscall is legacy-rare — inherent to the kdmapper design. A static mutex
// keeps concurrent CallKernelFunction users from interleaving hooks.
// No shellcode, no HalDispatchTable, no PTE self-reference games.
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

    static std::mutex s_callMutex; // serialize hook install/call/remove
    std::lock_guard<std::mutex> callLock(s_callMutex);

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

    if (!detail::RemoveCallHook(backend, original)) {
        // The target RAN — its result is valid. The hook staying behind is a
        // critical latent bug (NtAddAtom still jumps at funcVa), so scream:
        Trace("kmem: CRITICAL hook restore FAILED (NtAddAtom left patched)");
    }
    return true; // the target executed regardless of restore outcome
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

// Recover the real kernel DRIVER_OBJECT that owns an already-opened device
// handle (e.g. \\.\Nul). Uses NtQuerySystemInformation(SystemExtendedHandle
// Information) to find our process's FILE_OBJECT, then walks
// FILE_OBJECT->DeviceObject->DriverObject (both at offset 0x8 on x64).
// Needed because the I/O manager rejects device opens whose owning
// DRIVER_OBJECT is not an Object-Manager object (our synthetic pool object
// fails IopParseDevice with ERROR_DEVICE_NOT_CONNECTED). Returns 0 on failure.
uint64_t GetDriverObjectFromHandle(byovd::IByovdBackend* backend, HANDLE deviceHandle);

} // namespace kmem
} // namespace hinv
