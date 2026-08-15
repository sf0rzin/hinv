#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <type_traits>
#include <mutex>
#include <utility>

#include "hinv_byovd.hpp"

namespace hinv {
namespace kmem {

// A kernel call can execute successfully while the global dispatch hook can
// no longer be restored. Callers must not collapse this into bool: freeing a
// buffer after RestorationUncertain can leave the kernel executing freed code.
enum class KernelCallStatus {
    NotExecuted,
    Executed,
    RestorationUncertain,
};

// Once a read-only hook restore is uncertain, no subsequent arbitrary kernel
// call is safe in this process. The caller must retain reachable allocations
// and terminate/leave the backend for manual recovery.
bool KernelCallsUsable();

inline bool CallExecuted(KernelCallStatus status) {
    return status == KernelCallStatus::Executed;
}

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
// Remove a mapped module registration. When base is nonzero, only a matching
// registration is removed, preventing an old owner from deleting a newer one.
void UnregisterMappedModule(const std::wstring& moduleName, uint64_t base = 0);

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

// --- Inverted function table (read-only inspection) ---
//
// Win11 24H2 removed ntoskrnl!RtlAddFunctionTable / RtlDeleteFunctionTable.
// Although the private PsInvertedFunctionTable layout can be located for
// diagnostics, its Epoch is not a writer lock and the real lock/routine is
// build-private. hinv therefore never writes this table; images that require
// dynamic .pdata registration are rejected when the supported API is absent.
// The diagnostic layout below is retained only for unit-testable read-only
// address extraction:
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

// Resolve PsInvertedFunctionTable for read-only diagnostics. Always returns 0
// for the production mutation path.
uint64_t ResolveInvertedFunctionTable(byovd::IByovdBackend* backend);

// Retained for API compatibility with diagnostic callers. Always fails closed;
// no user-mode code may mutate PsInvertedFunctionTable.
bool InsertInvertedFunctionTableEntry(byovd::IByovdBackend* backend, uint64_t functionTableVa,
                                      uint64_t imageBase, uint32_t imageSize, uint32_t tableSize);

// Retained for API compatibility with diagnostic callers. Always fails closed.
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

// Install/remove the temporary ntoskrnl!NtAddAtom hook used by
// CallKernelFunction. The entry is changed with one aligned 8-byte store to a
// relative jump. The jump lands in an executable pool trampoline which checks
// that the call originates on the owner KTHREAD before dispatching the target.
enum class HookInstallStatus {
    Failed,
    Installed,
    Uncertain,
};
HookInstallStatus InstallCallHook(byovd::IByovdBackend* backend, uint64_t gateVa,
                                  uint8_t (&original)[8]);
bool RemoveCallHook(byovd::IByovdBackend* backend, const uint8_t (&original)[8]);

// The hook mutex has an Administrators/SYSTEM DACL and is shared by all
// cooperating hinv processes. It is not used as a substitute for atomic code
// publication; the latter is enforced by WriteReadOnlyMemoryAtomic8.
HANDLE GlobalCallHookMutex();
void MarkHookStateUncertain();

// Configure the executable trampoline while NtAddAtom is restored.
bool ConfigureCallGate(byovd::IByovdBackend* backend, uint64_t gateVa,
                       uint64_t ownerKthread, uint64_t target);

// Allocate and initialize the gate without recursively using the gate itself.
// Called while CallKernelFunction holds both serialization locks.
KernelCallStatus PrepareCallGate(byovd::IByovdBackend* backend, uint64_t& gateVa,
                                 uint64_t& ownerKthread);

// User-mode ntdll!NtAddAtom address (the syscall stub we invoke).
void* UserNtAddAtom();

} // namespace detail

// Call an arbitrary kernel function with up to 4 register arguments,
// kdmapper-style: the first eight bytes of ntoskrnl!NtAddAtom are replaced by
// one atomically published relative jump to a kernel trampoline. The
// trampoline rejects calls from every KTHREAD except this call's owner, then
// jumps to funcVa with the original argument registers intact. ntdll!NtAddAtom
// is invoked from usermode and the target's RAX becomes the return value.
//
// Return value semantics are KernelCallStatus: NotExecuted means no target
// call was dispatched; Executed means the target returned and the hook was
// restored and verified; RestorationUncertain means the target may have run or
// the hook may still be installed. In the last case callers must retain every
// resource reachable by the target.
//
// The hook is still a global code patch, so unsupported backends and
// unaligned/out-of-range targets fail closed. The trampoline's KTHREAD gate
// prevents unrelated NtAddAtom callers from reaching an arbitrary target.
// No shellcode, no HalDispatchTable, no PTE self-reference games.
template<typename T, typename... A>
KernelCallStatus CallKernelFunction(byovd::IByovdBackend* backend, T* outResult,
                                    uint64_t funcVa, A... args) {
    static_assert(sizeof...(A) <= 4, "CallKernelFunction supports at most 4 register arguments");
    constexpr bool isVoid = std::is_same_v<T, void>;

    if constexpr (!isVoid) {
        if (!outResult) return KernelCallStatus::NotExecuted;
    } else {
        (void)outResult;
    }
    if (!backend || !funcVa) return KernelCallStatus::NotExecuted;
    if (!KernelCallsUsable()) return KernelCallStatus::RestorationUncertain;

    static std::mutex s_callMutex; // serialize hook install/call/remove
    std::lock_guard<std::mutex> callLock(s_callMutex);

    HANDLE globalHookMutex = detail::GlobalCallHookMutex();
    if (!globalHookMutex || globalHookMutex == INVALID_HANDLE_VALUE)
        return KernelCallStatus::NotExecuted;
    const DWORD wait = WaitForSingleObject(globalHookMutex, 30000);
    if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED)
        return KernelCallStatus::NotExecuted;
    struct MutexRelease {
        HANDLE handle;
        ~MutexRelease() { ReleaseMutex(handle); }
    } mutexRelease{ globalHookMutex };

    uint64_t gateVa = 0;
    uint64_t ownerKthread = 0;
    const auto gateStatus = detail::PrepareCallGate(backend, gateVa, ownerKthread);
    if (gateStatus != KernelCallStatus::Executed)
        return gateStatus;
    if (!detail::ConfigureCallGate(backend, gateVa, ownerKthread, funcVa))
        return KernelCallStatus::NotExecuted;

    uint8_t original[8]{};
    const auto install = detail::InstallCallHook(backend, gateVa, original);
    if (install == detail::HookInstallStatus::Uncertain)
        return KernelCallStatus::RestorationUncertain;
    if (install != detail::HookInstallStatus::Installed)
        return KernelCallStatus::NotExecuted;

    using Fn = T(__stdcall*)(A...);
    auto fn = reinterpret_cast<Fn>(detail::UserNtAddAtom());
    if (!fn) {
        return detail::RemoveCallHook(backend, original)
            ? KernelCallStatus::NotExecuted
            : KernelCallStatus::RestorationUncertain;
    }
    Trace("kmem: syscall begin");
    if constexpr (isVoid) {
        fn(args...);
    } else {
        *outResult = fn(args...);
    }
    Trace("kmem: syscall returned");

    if (!detail::RemoveCallHook(backend, original)) {
        Trace("kmem: CRITICAL hook restore FAILED (NtAddAtom left patched)");
        return KernelCallStatus::RestorationUncertain;
    }
    return KernelCallStatus::Executed;
}

// Allocate kernel pool memory via ExAllocatePoolWithTag (NonPagedPool; NX on
// Win8+, use ProtectKernelMemory to make it executable when needed).
KernelCallStatus AllocateKernelMemory(byovd::IByovdBackend* backend, size_t size, uint64_t& outKernelVa);

// Free pool memory allocated by AllocateKernelMemory (ExFreePoolWithTag).
KernelCallStatus FreeKernelMemory(byovd::IByovdBackend* backend, uint64_t kernelVa);

// Change page protection of a kernel range via MmSetPageProtection.
KernelCallStatus ProtectKernelMemory(byovd::IByovdBackend* backend, uint64_t kernelVa,
                                     size_t size, uint32_t protect,
                                     bool* outProtected = nullptr);

// Call a driver entry point in Ring 0. Returns the NTSTATUS produced by DriverEntry.
KernelCallStatus CallDriverEntry(byovd::IByovdBackend* backend, uint64_t driverEntryVa,
                                  uint64_t driverObjectVa, uint64_t registryPathVa,
                                  uint32_t& outStatus);

struct RealDriverEntryResult {
    KernelCallStatus callStatus = KernelCallStatus::NotExecuted;
    uint32_t ioCreateStatus = 0xC0000001u;
    uint32_t driverEntryStatus = 0xC0000001u;
    uint64_t driverObject = 0;
    uint64_t callbackStub = 0;
};

// Create an Object-Manager-owned DRIVER_OBJECT through IoCreateDriver and
// invoke the mapped DriverEntry with it. This avoids borrowing and modifying
// a live system driver's object. The returned status is DriverEntry's status
// when the kernel call succeeds, or STATUS_UNSUCCESSFUL otherwise.
RealDriverEntryResult CallDriverEntryWithRealObject(byovd::IByovdBackend* backend,
                                                    uint64_t driverEntryVa);

} // namespace kmem
} // namespace hinv
