#include "hinv_kmem.hpp"
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <psapi.h>
#include <vector>
#include <cwctype>
#include <algorithm>
#include <cstring>
#include <iostream>
#include <mutex>
#include <cstdlib>
#include <cstdio>
#include <array>
#include <limits>
#include <sddl.h>
#include <atomic>

// MinGW does not expose these in winternl.h by default.
#ifndef SystemModuleInformation
#define SystemModuleInformation 11
#endif

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

#ifdef _MSC_VER
#pragma comment(lib, "ntdll.lib") // CMake links ntdll for other toolchains
#endif

namespace hinv {
namespace kmem {

static std::atomic<bool> g_hookStateUncertain{ false };

bool KernelCallsUsable() {
    return !g_hookStateUncertain.load(std::memory_order_acquire);
}

static std::wstring ToLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), ::towlower);
    return s;
}

static bool IsKnownKernelBuild();

// ---------------------------------------------------------------------------
// Module name normalization
// ---------------------------------------------------------------------------

std::wstring NormalizeModuleName(const std::string& moduleName) {
    std::wstring s(moduleName.begin(), moduleName.end());
    return NormalizeModuleName(s);
}

std::wstring NormalizeModuleName(const std::wstring& moduleName) {
    std::wstring s = ToLower(moduleName);

    // Strip path.
    size_t slash = s.find_last_of(L"\\/");
    if (slash != std::wstring::npos) s = s.substr(slash + 1);

    // Strip extension for matching, then map known aliases.
    size_t dot = s.find(L'.');
    std::wstring stem = (dot != std::wstring::npos) ? s.substr(0, dot) : s;

    if (stem == L"ntoskrnl" || stem == L"ntkrnlpa" || stem == L"ntkrnlmp") return L"ntoskrnl.exe";
    if (stem == L"hal") return L"hal.dll";
    if (stem == L"fltmgr") return L"fltmgr.sys";
    if (stem == L"kdcom") return L"kdcom.dll";
    if (stem == L"ndis") return L"ndis.sys";
    if (stem == L"tcpip") return L"tcpip.sys";
    if (stem == L"win32k") return L"win32k.sys";
    if (stem == L"ci") return L"ci.dll";
    if (stem == L"clfs") return L"clfs.sys";

    // Default: assume .sys for kernel modules without extension.
    if (dot == std::wstring::npos) return stem + L".sys";
    return s;
}

// ---------------------------------------------------------------------------
// Module enumeration
// ---------------------------------------------------------------------------

using NtQuerySystemInformationFn = NTSTATUS(NTAPI*)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

std::vector<KernelModule> EnumKernelModules() {
    std::vector<KernelModule> result;
    auto NtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformationFn>(reinterpret_cast<void*>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation")));
    if (!NtQuerySystemInformation) return result;

    ULONG size = 0;
    NtQuerySystemInformation(SystemModuleInformation, nullptr, 0, &size);
    if (size == 0) return result;

    std::vector<uint8_t> buffer(size);
    if (!NT_SUCCESS(NtQuerySystemInformation(SystemModuleInformation, buffer.data(), size, &size)))
        return result;

    auto* info = reinterpret_cast<RTL_PROCESS_MODULES*>(buffer.data());
    for (ULONG i = 0; i < info->NumberOfModules; ++i) {
        const auto& m = info->Modules[i];
        KernelModule km;
        km.base = reinterpret_cast<uint64_t>(m.ImageBase);
        km.size = m.ImageSize;
        std::string asciiName(reinterpret_cast<const char*>(m.FullPathName));
        km.name.assign(asciiName.begin(), asciiName.end());
        // Keep only the file name for display; base/size are what matter.
        size_t slash = km.name.find_last_of(L"\\/");
        if (slash != std::wstring::npos) km.name = km.name.substr(slash + 1);
        result.push_back(km);
    }
    return result;
}

// ---------------------------------------------------------------------------
// Kernel export resolution
// ---------------------------------------------------------------------------

uint64_t GetKernelExport(byovd::IByovdBackend* backend, uint64_t moduleBase, const char* exportName, unsigned depth) {
    if (!backend || !moduleBase || !exportName || depth > 4) return 0;

    IMAGE_DOS_HEADER dos{};
    if (!backend->ReadKernelMemory(moduleBase, &dos, sizeof(dos))) return 0;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;
    // e_lfanew is signed LONG; reject negative/out-of-range before adding.
    int64_t ntOff = static_cast<int64_t>(dos.e_lfanew);
    if (ntOff < static_cast<int64_t>(sizeof(IMAGE_DOS_HEADER)) ||
        ntOff > static_cast<int64_t>(0x100000)) return 0; // NT header never lives past 1 MB

    IMAGE_NT_HEADERS64 nt{};
    if (!backend->ReadKernelMemory(moduleBase + ntOff, &nt, sizeof(nt))) return 0;
    if (nt.Signature != IMAGE_NT_SIGNATURE) return 0;
    if (nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return 0;

    const uint64_t imageSize = nt.OptionalHeader.SizeOfImage;
    if (imageSize == 0 || imageSize > 0x20000000) return 0;

    const auto& exportDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir.VirtualAddress == 0 || exportDir.Size == 0) return 0;
    // The export directory itself must fit the image (64-bit arithmetic).
    if (static_cast<uint64_t>(exportDir.VirtualAddress) + exportDir.Size > imageSize) return 0;
    if (static_cast<uint64_t>(exportDir.VirtualAddress) + sizeof(IMAGE_EXPORT_DIRECTORY) > imageSize) return 0;

    IMAGE_EXPORT_DIRECTORY expDir{};
    if (!backend->ReadKernelMemory(moduleBase + exportDir.VirtualAddress, &expDir, sizeof(expDir))) return 0;

    // Cap the counts BEFORE allocating: a corrupt NumberOfNames would otherwise
    // turn into a gigantic usermode allocation and a wild multi-MB backend read.
    constexpr uint32_t MAX_EXPORTS = 0x100000;
    if (expDir.NumberOfNames > MAX_EXPORTS || expDir.NumberOfFunctions > MAX_EXPORTS) return 0;
    if (expDir.NumberOfNames == 0 || expDir.NumberOfFunctions == 0) return 0;

    // All three arrays must live inside the image (64-bit, overflow-free).
    if (static_cast<uint64_t>(expDir.AddressOfNames) + static_cast<uint64_t>(expDir.NumberOfNames) * 4 > imageSize)
        return 0;
    if (static_cast<uint64_t>(expDir.AddressOfNameOrdinals) + static_cast<uint64_t>(expDir.NumberOfNames) * 2 > imageSize)
        return 0;
    if (static_cast<uint64_t>(expDir.AddressOfFunctions) + static_cast<uint64_t>(expDir.NumberOfFunctions) * 4 > imageSize)
        return 0;

    std::vector<uint32_t> rvas(expDir.NumberOfNames);
    std::vector<uint16_t> ords(expDir.NumberOfNames);
    std::vector<uint32_t> funcs(expDir.NumberOfFunctions);

    if (!backend->ReadKernelMemory(moduleBase + expDir.AddressOfNames, rvas.data(), rvas.size() * sizeof(uint32_t)))
        return 0;
    if (!backend->ReadKernelMemory(moduleBase + expDir.AddressOfNameOrdinals, ords.data(), ords.size() * sizeof(uint16_t)))
        return 0;
    if (!backend->ReadKernelMemory(moduleBase + expDir.AddressOfFunctions, funcs.data(), funcs.size() * sizeof(uint32_t)))
        return 0;

    const uint64_t exportDirEnd = static_cast<uint64_t>(exportDir.VirtualAddress) + exportDir.Size;

    for (uint32_t i = 0; i < expDir.NumberOfNames; ++i) {
        // Names table entry must point inside the image.
        if (!rvas[i] || rvas[i] >= imageSize) continue;
        // Read only up to the image end and require a NUL inside that window.
        size_t maxLen = static_cast<size_t>(imageSize - rvas[i]);
        if (maxLen > 255) maxLen = 255;
        char name[256]{};
        if (!backend->ReadKernelMemory(moduleBase + rvas[i], name, maxLen)) continue;
        name[maxLen] = '\0';
        size_t nameLen = strnlen(name, maxLen);
        if (nameLen == maxLen) continue; // not NUL-terminated within the image
        if (std::strcmp(name, exportName) == 0) {
            uint16_t ord = ords[i];
            if (ord >= expDir.NumberOfFunctions) return 0;
            uint32_t funcRva = funcs[ord];
            // The RVA must land inside the image; anything else is a corrupt
            // table or a hostile image, never a valid export.
            if (!funcRva || funcRva >= imageSize) return 0;
            // Forwarded export: the RVA points back INTO the export directory
            // and holds an "OtherDll.Export" string instead of code. Chase it
            // through the named module (depth-capped against forward loops).
            if (static_cast<uint64_t>(funcRva) >= exportDir.VirtualAddress &&
                static_cast<uint64_t>(funcRva) < exportDirEnd) {
                // The forwarder string must end inside the image.
                size_t fwdMax = static_cast<size_t>(imageSize - funcRva);
                if (fwdMax > 127) fwdMax = 127;
                char fwd[128]{};
                if (!backend->ReadKernelMemory(moduleBase + funcRva, fwd, fwdMax)) return 0;
                fwd[fwdMax] = '\0';
                size_t fwdLen = strnlen(fwd, fwdMax);
                if (fwdLen == fwdMax) return 0; // no NUL within bounds
                std::string fwdStr(fwd, fwdLen);
                size_t dot = fwdStr.find('.');
                if (dot == std::string::npos || dot + 1 >= fwdStr.size()) return 0;
                if (fwdStr[dot + 1] == '#') return 0; // ordinal forwarder: unsupported
                // The forwarder DLL name has no extension ("ntoskrnl" for
                // ntoskrnl.exe, "hal" for hal.dll, "foo" for foo.dll). Try the
                // known aliases via NormalizeModuleName, then the plausible
                // extensions, first hit wins.
                std::string dllName = fwdStr.substr(0, dot);
                std::string fnName = fwdStr.substr(dot + 1);
                std::wstring dllW(dllName.begin(), dllName.end());
                std::wstring aliases[4] = { NormalizeModuleName(dllName),
                                            dllW + L".dll", dllW + L".exe", dllW + L".sys" };
                for (const auto& cand : aliases) {
                    uint64_t addr = ResolveKernelExport(backend, cand.c_str(), fnName.c_str(), depth + 1);
                    if (addr) return addr;
                }
                return 0;
            }
            return moduleBase + funcRva;
        }
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Process-local registry of manually mapped modules
// ---------------------------------------------------------------------------

static std::mutex g_mappedModulesMutex;
static std::vector<MappedModule> g_mappedModules;

void RegisterMappedModule(const std::wstring& moduleName, uint64_t base, uint32_t size) {
    if (moduleName.empty() || !base || !size) return;

    std::wstring name = NormalizeModuleName(moduleName);
    // A mapped image must never shadow a real system module during import
    // resolution. Such a name is either accidental or hostile input.
    if (name == L"ntoskrnl.exe" || name == L"hal.dll" || name == L"ci.dll") return;

    std::lock_guard<std::mutex> lock(g_mappedModulesMutex);
    for (auto& m : g_mappedModules) {
        if (m.name == name) {
            m.base = base;
            m.size = size;
            return;
        }
    }
    g_mappedModules.push_back({ name, base, size });
}

void UnregisterMappedModule(const std::wstring& moduleName, uint64_t base) {
    if (moduleName.empty()) return;
    const std::wstring name = NormalizeModuleName(moduleName);
    std::lock_guard<std::mutex> lock(g_mappedModulesMutex);
    g_mappedModules.erase(
        std::remove_if(g_mappedModules.begin(), g_mappedModules.end(),
                       [&](const MappedModule& module) {
                           return module.name == name && (!base || module.base == base);
                       }),
        g_mappedModules.end());
}

// Returns the base of a registered mapped module, or 0. lowerName must
// already be lowercase file stem + extension (e.g. L"hyperhv.dll").
static uint64_t FindMappedModule(const std::wstring& lowerName) {
    std::lock_guard<std::mutex> lock(g_mappedModulesMutex);
    for (const auto& m : g_mappedModules) {
        if (m.name == lowerName) return m.base;
    }
    return 0;
}

uint64_t ResolveKernelExport(byovd::IByovdBackend* backend, const wchar_t* moduleName, const char* exportName,
                             unsigned depth) {
    if (depth > 4) return 0;
    std::wstring target = ToLower(moduleName);

    // Manually mapped modules never appear in PsLoadedModuleList; check the
    // process-local registry first. GetKernelExport parses the export table
    // from kernel memory through the backend, which works because the mapped
    // image retains its PE headers.
    uint64_t mappedBase = FindMappedModule(target);
    if (mappedBase) return GetKernelExport(backend, mappedBase, exportName, depth);

    auto mods = EnumKernelModules();
    for (const auto& m : mods) {
        if (ToLower(m.name) == target) {
            return GetKernelExport(backend, m.base, exportName, depth);
        }
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Inverted function table (24H2 replacement for RtlAddFunctionTable)
// ---------------------------------------------------------------------------

namespace detail {

// Field offsets inside PsInvertedFunctionTable (see hinv_kmem.hpp).
constexpr uint32_t IFT_CURSIZE   = 0x00;
constexpr uint32_t IFT_MAXSIZE   = 0x04;
constexpr uint32_t IFT_EPOCH     = 0x08;
constexpr uint32_t IFT_OVERFLOW  = 0x0C;
constexpr uint32_t IFT_ENTRIES   = 0x10;
constexpr uint32_t IFT_STRIDE    = 0x18;
constexpr uint32_t IFT_ENT_BASE  = 0x08; // ImageBase inside an entry

// Read and sanity-check the table header. Garbage here means the extracted
// address was wrong — never write through an unvalidated pointer.
static bool ReadIftHeader(byovd::IByovdBackend* backend, uint64_t tableVa,
                          uint32_t& cur, uint32_t& max, uint8_t& overflow) {
    if (!ReadU32(backend, tableVa + IFT_CURSIZE, cur) ||
        !ReadU32(backend, tableVa + IFT_MAXSIZE, max)) return false;
    if (!backend->ReadKernelMemory(tableVa + IFT_OVERFLOW, &overflow, 1)) return false;
    if (max == 0 || max > 0x1000 || cur > max) return false;
    if (overflow != 0 && overflow != 1) return false;
    return true;
}

uint64_t FindInvertedFunctionTable(byovd::IByovdBackend* backend, uint64_t lookupFnVa) {
    if (!backend || !lookupFnVa) return 0;
    uint8_t bytes[0x40]{};
    if (!backend->ReadKernelMemory(lookupFnVa, bytes, sizeof(bytes))) return 0;

    // mov rcx, [rip+disp32] (48 8B 0D) loads PsInvertedFunctionTable+0x18 right
    // after the prologue. Try every candidate; the header check disambiguates.
    for (size_t i = 0; i + 7 <= sizeof(bytes); ++i) {
        if (bytes[i] != 0x48 || bytes[i + 1] != 0x8B || bytes[i + 2] != 0x0D) continue;
        int32_t disp = 0;
        std::memcpy(&disp, bytes + i + 3, sizeof(disp));
        uint64_t fieldVa = lookupFnVa + i + 7 + static_cast<int64_t>(disp);
        if ((fieldVa >> 48) != 0xFFFF || (fieldVa & 7) != 0) continue;
        uint64_t tableVa = fieldVa - 0x18;
        uint32_t cur = 0, max = 0;
        uint8_t overflow = 0;
        if (ReadIftHeader(backend, tableVa, cur, max, overflow)) return tableVa;
    }
    return 0;
}

bool InsertInvertedFunctionTableEntryAt(byovd::IByovdBackend* backend, uint64_t tableVa,
                                        uint64_t functionTableVa, uint64_t imageBase,
                                        uint32_t imageSize, uint32_t tableSize) {
    uint32_t epoch = 0;
    if (!backend || !tableVa || !ReadU32(backend, tableVa + IFT_EPOCH, epoch))
        return false;
    if ((epoch & 1u) != 0) {
        Trace("kmem: refusing PsInvertedFunctionTable insert during odd epoch");
        return false;
    }
    (void)functionTableVa;
    (void)imageBase;
    (void)imageSize;
    (void)tableSize;
    // Epoch is a reader sequence counter, not the writer lock. The private
    // lock/routine that owns this table is build-specific and is not exposed
    // by the supported user-mode/BYOVD interface. Never perform independent
    // writes here: a loader thread could observe a torn table and unwind any
    // kernel thread through attacker-controlled addresses.
    Trace("kmem: refusing unsynchronized PsInvertedFunctionTable insert");
    return false;
}

bool RemoveInvertedFunctionTableEntryAt(byovd::IByovdBackend* backend, uint64_t tableVa,
                                        uint64_t imageBase) {
    uint32_t epoch = 0;
    if (!backend || !tableVa || !ReadU32(backend, tableVa + IFT_EPOCH, epoch))
        return false;
    if ((epoch & 1u) != 0) {
        Trace("kmem: refusing PsInvertedFunctionTable removal during odd epoch");
        return false;
    }
    (void)imageBase;
    Trace("kmem: refusing unsynchronized PsInvertedFunctionTable removal");
    return false;
}

} // namespace detail

uint64_t ResolveInvertedFunctionTable(byovd::IByovdBackend* backend) {
    (void)backend;
    std::cerr << "[hinv::kmem] PsInvertedFunctionTable is read-only to hinv; no private lock is available\n";
    return 0;
}

bool InsertInvertedFunctionTableEntry(byovd::IByovdBackend* backend, uint64_t functionTableVa,
                                      uint64_t imageBase, uint32_t imageSize, uint32_t tableSize) {
    (void)backend;
    (void)functionTableVa;
    (void)imageBase;
    (void)imageSize;
    (void)tableSize;
    std::cerr << "[hinv::kmem] Refusing manual PsInvertedFunctionTable mutation; use a supported loader API\n";
    return false;
}

bool RemoveInvertedFunctionTableEntry(byovd::IByovdBackend* backend, uint64_t imageBase) {
    (void)backend;
    (void)imageBase;
    return false;
}

// ---------------------------------------------------------------------------
// OS version detection
// ---------------------------------------------------------------------------

OsVersionInfo GetOsVersion() {
    OsVersionInfo info{};
    using RtlGetVersionFn = NTSTATUS(NTAPI*)(PRTL_OSVERSIONINFOW);
    auto RtlGetVersion = reinterpret_cast<RtlGetVersionFn>(reinterpret_cast<void*>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion")));
    if (RtlGetVersion) {
        RTL_OSVERSIONINFOW os{};
        os.dwOSVersionInfoSize = sizeof(os);
        if (NT_SUCCESS(RtlGetVersion(&os))) {
            info.major = os.dwMajorVersion;
            info.minor = os.dwMinorVersion;
            info.build = os.dwBuildNumber;
            // RTL_OSVERSIONINFOW has no revision field. Do not expose
            // dwPlatformId as if it were one.
            info.revision = 0;
        }
    }
    return info;
}

// ---------------------------------------------------------------------------
// Arbitrary kernel function calls (kdmapper-style NtAddAtom hook)
// ---------------------------------------------------------------------------
//
// Replaces the old HalDispatchTable shellcode machinery (which needed the
// randomized PTE self-reference index and bugchecked this machine three
// times). Instead, we overwrite the first bytes of ntoskrnl!NtAddAtom with
// `mov rax, target; jmp rax` through the backend's read-only write primitive
// (physical mapping on the Intel backend), then invoke ntdll!NtAddAtom from
// usermode: the syscall lands in our hook with the original argument
// registers, so the target runs in Ring 0 with our args and its return value
// comes back in RAX. The prologue is always restored.

void Trace(const char* stage) {
    static const std::string path = [] {
        const char* p = std::getenv("HINV_TRACE");
        return p ? std::string(p) : std::string();
    }();
    if (path.empty()) return;
    // Write-through is the whole point: FILE_FLAG_WRITE_THROUGH commits data
    // and metadata to disk before WriteFile returns, so lines already written
    // survive an immediate bugcheck (buffered stdio loses them).
    HANDLE h = CreateFileA(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_ALWAYS, FILE_FLAG_WRITE_THROUGH, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    char line[256];
    int n = snprintf(line, sizeof(line), "%s\n", stage);
    // snprintf returns what WOULD have been written; clamp or a long stage
    // reads past the buffer into the trace file.
    if (n > 0) {
        if (n >= static_cast<int>(sizeof(line))) n = static_cast<int>(sizeof(line)) - 1;
        DWORD written = 0;
        WriteFile(h, line, static_cast<DWORD>(n), &written, nullptr);
    }
    CloseHandle(h);
}

namespace detail {

static uint64_t KernelNtAddAtom(byovd::IByovdBackend* backend) {
    static uint64_t cached = 0;
    if (!cached) cached = ResolveKernelExport(backend, L"ntoskrnl.exe", "NtAddAtom");
    return cached;
}

void* UserNtAddAtom() {
    return reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtAddAtom"));
}

HANDLE GlobalCallHookMutex() {
    static HANDLE mutex = [] {
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:P(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1,
                &descriptor, nullptr))
            return static_cast<HANDLE>(nullptr);

        SECURITY_ATTRIBUTES attributes{};
        attributes.nLength = sizeof(attributes);
        attributes.lpSecurityDescriptor = descriptor;
        attributes.bInheritHandle = FALSE;
        HANDLE handle = CreateMutexW(&attributes, FALSE, L"Global\\hinv_NtAddAtomHook");
        LocalFree(descriptor);
        return handle;
    }();
    return mutex;
}

HookInstallStatus InstallCallHook(byovd::IByovdBackend* backend, uint64_t target,
                                  uint8_t (&original)[8]) {
    Trace("kmem: hook install begin");
    uint64_t ntAddAtom = KernelNtAddAtom(backend);
    if (!ntAddAtom || !UserNtAddAtom() || (ntAddAtom & 7) != 0) {
        Trace("kmem: hook install failed (resolve/alignment)");
        return HookInstallStatus::Failed;
    }

    if (!backend->ReadKernelMemory(ntAddAtom, original, sizeof(original))) {
        Trace("kmem: hook install failed (read)");
        return HookInstallStatus::Failed;
    }

    // A pre-existing relative jump means another instance already owns the
    // global patch. Do not overwrite it or lose the bytes needed for its
    // restore. NtAddAtom itself does not begin with this form on supported
    // builds.
    if (original[0] == 0xE9) {
        Trace("kmem: hook install refused (already patched)");
        return HookInstallStatus::Failed;
    }

    const int64_t delta = static_cast<int64_t>(target) -
                          static_cast<int64_t>(ntAddAtom + 5);
    if (delta < static_cast<int64_t>(std::numeric_limits<int32_t>::min()) ||
        delta > static_cast<int64_t>(std::numeric_limits<int32_t>::max())) {
        Trace("kmem: hook install refused (target outside rel32 range)");
        return HookInstallStatus::Failed;
    }

    // The first five bytes are a relative jump. The remaining three bytes are
    // copied from the original prologue and are never executed after a
    // successful fetch of the atomically published instruction bundle.
    uint8_t patch[8]{};
    patch[0] = 0xE9;
    const int32_t relative = static_cast<int32_t>(delta);
    std::memcpy(patch + 1, &relative, sizeof(relative));
    std::memcpy(patch + 5, original + 5, 3);
    uint64_t atomicPatch = 0;
    std::memcpy(&atomicPatch, patch, sizeof(atomicPatch));

    // A false return is treated as uncertain. The backend contract requires a
    // single aligned store, but this caller cannot prove whether an external
    // driver failed after touching the physical mapping.
    if (!backend->WriteReadOnlyMemoryAtomic8(ntAddAtom, atomicPatch)) {
        MarkHookStateUncertain();
        Trace("kmem: CRITICAL hook install state uncertain");
        return HookInstallStatus::Uncertain;
    }

    uint8_t verify[8]{};
    if (backend->ReadKernelMemory(ntAddAtom, verify, sizeof(verify)) &&
        std::memcmp(verify, patch, sizeof(patch)) == 0) {
        Trace("kmem: hook installed atomically");
        return HookInstallStatus::Installed;
    }

    uint64_t originalValue = 0;
    std::memcpy(&originalValue, original, sizeof(originalValue));
    const bool restored = backend->WriteReadOnlyMemoryAtomic8(ntAddAtom, originalValue);
    Trace(restored ? "kmem: hook install rolled back" :
                     "kmem: CRITICAL hook install rollback FAILED");
    if (!restored) MarkHookStateUncertain();
    return restored ? HookInstallStatus::Failed : HookInstallStatus::Uncertain;
}

bool RemoveCallHook(byovd::IByovdBackend* backend, const uint8_t (&original)[8]) {
    Trace("kmem: hook remove begin");
    uint64_t ntAddAtom = KernelNtAddAtom(backend);
    if (!ntAddAtom) return false;

    uint64_t originalValue = 0;
    std::memcpy(&originalValue, original, sizeof(originalValue));
    bool ok = false;
    for (int attempt = 0; attempt < 3 && !ok; ++attempt) {
        if (!backend->WriteReadOnlyMemoryAtomic8(ntAddAtom, originalValue)) continue;
        uint8_t verify[8]{};
        ok = backend->ReadKernelMemory(ntAddAtom, verify, sizeof(verify)) &&
             std::memcmp(verify, original, sizeof(verify)) == 0;
    }
    if (!ok) MarkHookStateUncertain();
    Trace(ok ? "kmem: hook removed" : "kmem: hook remove failed");
    return ok;
}

template<typename T, typename... A>
static KernelCallStatus DirectKernelCall(byovd::IByovdBackend* backend, T* outResult,
                                         uint64_t target, A... args) {
    if (!KernelCallsUsable()) return KernelCallStatus::RestorationUncertain;
    uint8_t original[8]{};
    const auto install = InstallCallHook(backend, target, original);
    if (install == HookInstallStatus::Uncertain)
        return KernelCallStatus::RestorationUncertain;
    if (install != HookInstallStatus::Installed)
        return KernelCallStatus::NotExecuted;

    using Fn = T(__stdcall*)(A...);
    auto fn = reinterpret_cast<Fn>(UserNtAddAtom());
    if (!fn)
        return RemoveCallHook(backend, original)
            ? KernelCallStatus::NotExecuted
            : KernelCallStatus::RestorationUncertain;

    if constexpr (std::is_same_v<T, void>) {
        (void)outResult;
        fn(args...);
    } else {
        if (!outResult) {
            return RemoveCallHook(backend, original)
                ? KernelCallStatus::NotExecuted
                : KernelCallStatus::RestorationUncertain;
        }
        *outResult = fn(args...);
    }

    return RemoveCallHook(backend, original)
        ? KernelCallStatus::Executed
        : KernelCallStatus::RestorationUncertain;
}

static uint64_t g_callGate = 0;

KernelCallStatus PrepareCallGate(byovd::IByovdBackend* backend, uint64_t& gateVa,
                                 uint64_t& ownerKthread) {
    if (!backend) return KernelCallStatus::NotExecuted;

    uint64_t threadFn = ResolveKernelExport(backend, L"ntoskrnl.exe", "PsGetCurrentThread");
    if (!threadFn) {
        Trace("kmem: call gate failed (PsGetCurrentThread unresolved)");
        return KernelCallStatus::NotExecuted;
    }

    if (!g_callGate) {
        const uint64_t allocFn = ResolveKernelExport(
            backend, L"ntoskrnl.exe", "ExAllocatePoolWithTag");
        if (!allocFn) return KernelCallStatus::NotExecuted;

        // NonPagedPoolExecute avoids a second arbitrary call while the global
        // hook is still in bootstrap mode. The allocation target is benign for
        // unrelated NtAddAtom calls (they cannot dereference caller pointers).
        uint64_t allocated = 0;
        const auto allocation = DirectKernelCall(
            backend, &allocated, allocFn, 4ULL, 0x100ULL, 0x766E6968ULL);
        if (allocation != KernelCallStatus::Executed)
            return allocation;
        if (!allocated) return KernelCallStatus::NotExecuted;

        const uint64_t ntAddAtom = KernelNtAddAtom(backend);
        const int64_t gateDelta = static_cast<int64_t>(allocated) -
                                  static_cast<int64_t>(ntAddAtom + 5);
        if ((allocated & 7) != 0 ||
            gateDelta < static_cast<int64_t>(std::numeric_limits<int32_t>::min()) ||
            gateDelta > static_cast<int64_t>(std::numeric_limits<int32_t>::max())) {
            Trace("kmem: call gate refused (alignment/range)");
            return KernelCallStatus::NotExecuted;
        }
        g_callGate = allocated;
    }

    uint64_t currentThread = 0;
    const auto threadCall = DirectKernelCall(backend, &currentThread, threadFn);
    if (threadCall != KernelCallStatus::Executed)
        return threadCall;
    if (!currentThread) return KernelCallStatus::NotExecuted;

    gateVa = g_callGate;
    ownerKthread = currentThread;
    return KernelCallStatus::Executed;
}

bool ConfigureCallGate(byovd::IByovdBackend* backend, uint64_t gateVa,
                       uint64_t ownerKthread, uint64_t target) {
    if (!backend || !gateVa || !ownerKthread || !target) return false;

    std::array<uint8_t, 64> code{};
    size_t p = 0;
    code[p++] = 0x51; // push rcx; preserve the first target argument
    const uint8_t currentThread[] = { 0x65, 0x48, 0x8B, 0x04, 0x25,
                                      0x88, 0x01, 0x00, 0x00 };
    std::memcpy(code.data() + p, currentThread, sizeof(currentThread));
    p += sizeof(currentThread);
    code[p++] = 0x48; code[p++] = 0xB9; // mov rcx, ownerKthread
    std::memcpy(code.data() + p, &ownerKthread, sizeof(ownerKthread));
    p += sizeof(ownerKthread);
    code[p++] = 0x48; code[p++] = 0x39; code[p++] = 0xC8; // cmp rax, rcx
    code[p++] = 0x59; // pop rcx
    code[p++] = 0x75; code[p++] = 0x0C; // reject if a different KTHREAD calls
    code[p++] = 0x48; code[p++] = 0xB8; // mov rax, target
    std::memcpy(code.data() + p, &target, sizeof(target));
    p += sizeof(target);
    code[p++] = 0xFF; code[p++] = 0xE0; // jmp rax
    code[p++] = 0xB8; // mov eax, STATUS_ACCESS_VIOLATION
    const uint32_t rejected = 0xC0000005u;
    std::memcpy(code.data() + p, &rejected, sizeof(rejected));
    p += sizeof(rejected);
    code[p++] = 0xC3; // ret

    if (!backend->WriteKernelMemory(gateVa, code.data(), p)) return false;
    std::array<uint8_t, 64> verify{};
    return backend->ReadKernelMemory(gateVa, verify.data(), p) &&
           std::memcmp(code.data(), verify.data(), p) == 0;
}

void MarkHookStateUncertain() {
    g_hookStateUncertain.store(true, std::memory_order_release);
}

} // namespace detail

// ---------------------------------------------------------------------------
// Kernel pattern scanning (in-image reads only — always safe through the
// backend because every byte of a loaded module's image is resident/mapped)
// ---------------------------------------------------------------------------

static uint64_t FindPatternInSectionKernel(byovd::IByovdBackend* backend, uint64_t moduleBase,
                                           const char* sectionName,
                                           const std::vector<uint8_t>& pattern,
                                           const std::vector<bool>& mask) {
    if (!backend || pattern.empty() || pattern.size() != mask.size()) return 0;

    IMAGE_DOS_HEADER dos{};
    if (!backend->ReadKernelMemory(moduleBase, &dos, sizeof(dos))) return 0;
    IMAGE_NT_HEADERS64 nt{};
    if (!backend->ReadKernelMemory(moduleBase + dos.e_lfanew, &nt, sizeof(nt))) return 0;

    uint16_t numSections = nt.FileHeader.NumberOfSections;
    std::vector<IMAGE_SECTION_HEADER> sections(numSections);
    uint64_t sectionTable = moduleBase + dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + nt.FileHeader.SizeOfOptionalHeader;
    if (!backend->ReadKernelMemory(sectionTable, sections.data(), numSections * sizeof(IMAGE_SECTION_HEADER))) return 0;

    uint64_t secVa = 0;
    uint32_t secSize = 0;
    for (const auto& sec : sections) {
        if (std::strncmp(reinterpret_cast<const char*>(sec.Name), sectionName, IMAGE_SIZEOF_SHORT_NAME) == 0) {
            secVa = moduleBase + sec.VirtualAddress;
            secSize = sec.Misc.VirtualSize;
            break;
        }
    }
    if (!secVa || !secSize) return 0;

    constexpr size_t CHUNK = 0x1000;
    std::vector<uint8_t> buffer(CHUNK + pattern.size());
    for (uint32_t off = 0; off < secSize; off += CHUNK) {
        uint32_t readSize = (off + CHUNK > secSize) ? (secSize - off) : CHUNK;
        readSize = static_cast<uint32_t>(readSize + pattern.size());
        if (off + readSize > secSize) readSize = secSize - off;
        if (!backend->ReadKernelMemory(secVa + off, buffer.data(), readSize)) continue;

        for (size_t i = 0; i + pattern.size() <= readSize; ++i) {
            bool match = true;
            for (size_t j = 0; j < pattern.size(); ++j) {
                if (mask[j] && buffer[i + j] != pattern[j]) { match = false; break; }
            }
            if (match) return secVa + off + i;
        }
    }
    return 0;
}

static uint64_t GetNtoskrnlBase() {
    for (const auto& m : EnumKernelModules()) {
        if (ToLower(m.name).find(L"ntoskrnl") != std::wstring::npos) return m.base;
    }
    return 0;
}

static bool IsKnownKernelBuild() {
    const auto os = GetOsVersion();
    switch (os.build) {
        case 19041: case 19042: case 19043: case 19044: case 19045:
        case 22000: case 22621: case 22631: case 26100: case 26200:
            return os.major == 10;
        default:
            return false;
    }
}

// MmSetPageProtection is documented since 1803 but not always exported. When
// the export is missing, recover it with kdmapper's PAGELK pattern: a
// `cmovcc + lea + call` sequence whose final E8 calls MmSetPageProtection.
static uint64_t ResolveMmSetPageProtection(byovd::IByovdBackend* backend) {
    static uint64_t cached = 0;
    if (cached) return cached;

    uint64_t addr = ResolveKernelExport(backend, L"ntoskrnl.exe", "MmSetPageProtection");
    if (addr) { cached = addr; return addr; }

    uint64_t ntosBase = GetNtoskrnlBase();
    if (!ntosBase) return 0;
    if (!IsKnownKernelBuild()) {
        std::cerr << "[hinv::kmem] Refusing MmSetPageProtection pattern scan on unknown Windows build\n";
        return 0;
    }

    IMAGE_NT_HEADERS64 nt{};
    {
        IMAGE_DOS_HEADER dos{};
        if (!backend->ReadKernelMemory(ntosBase, &dos, sizeof(dos))) return 0;
        if (!backend->ReadKernelMemory(ntosBase + dos.e_lfanew, &nt, sizeof(nt))) return 0;
    }
    uint64_t imageEnd = ntosBase + nt.OptionalHeader.SizeOfImage;

    // Pattern 1: 0F 45 ?? ?? 8D ?? ?? ?? FF FF E8 — E8 sits at match+10.
    {
        std::vector<uint8_t> pat = { 0x0F, 0x45, 0x00, 0x00, 0x8D, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xE8 };
        std::vector<bool>   msk = { true, true, false, false, true, false, false, false, true, true, true };
        uint64_t m = FindPatternInSectionKernel(backend, ntosBase, "PAGELK", pat, msk);
        if (m) {
            int32_t rel = 0;
            if (ReadU32(backend, m + 11, reinterpret_cast<uint32_t&>(rel))) {
                uint64_t target = m + 10 + 5 + rel;
                if (target >= ntosBase && target < imageEnd) { cached = target; return target; }
            }
        }
    }

    // Pattern 2 (some builds keep an extra mov in the middle):
    // 0F 45 ?? ?? 45 8B ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? ?? FF FF E8 — E8 at match+19.
    {
        std::vector<uint8_t> pat = { 0x0F, 0x45, 0x00, 0x00, 0x45, 0x8B, 0x00, 0x00, 0x00, 0x00,
                                     0x8D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xE8 };
        std::vector<bool>   msk = { true, true, false, false, true, true, false, false, false, false,
                                    true, false, false, false, false, false, false, true, true, true };
        uint64_t m = FindPatternInSectionKernel(backend, ntosBase, "PAGELK", pat, msk);
        if (m) {
            int32_t rel = 0;
            if (ReadU32(backend, m + 20, reinterpret_cast<uint32_t&>(rel))) {
                uint64_t target = m + 19 + 5 + rel;
                if (target >= ntosBase && target < imageEnd) { cached = target; return target; }
            }
        }
    }

    return 0;
}

// ---------------------------------------------------------------------------
// Kernel memory allocation / protection / driver entry
// ---------------------------------------------------------------------------

KernelCallStatus AllocateKernelMemory(byovd::IByovdBackend* backend, size_t size,
                                      uint64_t& outKernelVa) {
    outKernelVa = 0;
    if (!backend || size == 0) return KernelCallStatus::NotExecuted;

    // Same primitive kdmapper uses: ExAllocatePoolWithTag(NonPagedPool, ...).
    // The pool is NX on Win8+; callers that execute from it must flip
    // protection with ProtectKernelMemory.
    uint64_t allocFn = ResolveKernelExport(backend, L"ntoskrnl.exe", "ExAllocatePoolWithTag");
    if (!allocFn) {
        std::cerr << "[hinv::kmem] ExAllocatePoolWithTag not found\n";
        return KernelCallStatus::NotExecuted;
    }

    constexpr uint64_t NonPagedPool = 0;
    constexpr uint64_t HinvTag = 0x766E6968; // 'hinv'
    uint64_t allocated = 0;
    const auto call = CallKernelFunction(backend, &allocated, allocFn, NonPagedPool,
                                         static_cast<uint64_t>(size), HinvTag);
    if (call != KernelCallStatus::Executed) return call;

    outKernelVa = allocated;
    return KernelCallStatus::Executed;
}

KernelCallStatus FreeKernelMemory(byovd::IByovdBackend* backend, uint64_t kernelVa) {
    if (!backend || !kernelVa) return KernelCallStatus::NotExecuted;

    uint64_t freeFn = ResolveKernelExport(backend, L"ntoskrnl.exe", "ExFreePoolWithTag");
    if (!freeFn) {
        std::cerr << "[hinv::kmem] ExFreePoolWithTag not found\n";
        return KernelCallStatus::NotExecuted;
    }

    constexpr uint64_t HinvTag = 0x766E6968; // 'hinv'
    return CallKernelFunction<void>(backend, nullptr, freeFn, kernelVa, HinvTag);
}

KernelCallStatus ProtectKernelMemory(byovd::IByovdBackend* backend, uint64_t kernelVa,
                                     size_t size, uint32_t protect, bool* outProtected) {
    if (outProtected) *outProtected = false;
    if (!backend || !kernelVa || !size) return KernelCallStatus::NotExecuted;

    uint64_t setProtFn = ResolveMmSetPageProtection(backend);
    if (!setProtFn) {
        std::cerr << "[hinv::kmem] MmSetPageProtection not found\n";
        return KernelCallStatus::NotExecuted;
    }

    uint8_t ok = 0; // BOOLEAN
    const auto call = CallKernelFunction(backend, &ok, setProtFn, kernelVa,
                                         static_cast<uint64_t>(size), static_cast<uint64_t>(protect));
    if (outProtected) *outProtected = ok != 0;
    return call;
}

KernelCallStatus CallDriverEntry(byovd::IByovdBackend* backend, uint64_t driverEntryVa,
                                 uint64_t driverObjectVa, uint64_t registryPathVa,
                                 uint32_t& outStatus) {
    outStatus = STATUS_UNSUCCESSFUL;
    if (!backend || !driverEntryVa) return KernelCallStatus::NotExecuted;

    const auto call = CallKernelFunction(backend, &outStatus, driverEntryVa,
                                         driverObjectVa, registryPathVa);
    if (call != KernelCallStatus::Executed) {
        std::cerr << "[hinv::kmem] CallDriverEntry: kernel call failed\n";
    }
    return call;
}

RealDriverEntryResult CallDriverEntryWithRealObject(byovd::IByovdBackend* backend,
                                                    uint64_t driverEntryVa) {
    RealDriverEntryResult result{};
    if (!backend || !driverEntryVa) return result;

    uint64_t ioCreateDriver = ResolveKernelExport(backend, L"ntoskrnl.exe", "IoCreateDriver");
    if (!ioCreateDriver) {
        std::cerr << "[hinv::kmem] IoCreateDriver not found\n";
        return result;
    }

    // The callback receives the object created by IoCreateDriver in RCX. A
    // tiny executable callback records that pointer and DriverEntry's status
    // before returning to IoCreateDriver. Without this wrapper the mapper
    // cannot safely retain devices created by the real driver object.
    constexpr size_t kCaptureSize = 0x20;
    uint64_t captureVa = 0;
    const auto captureAlloc = AllocateKernelMemory(backend, kCaptureSize, captureVa);
    if (captureAlloc != KernelCallStatus::Executed || !captureVa) {
        result.callStatus = captureAlloc;
        return result;
    }
    std::array<uint8_t, kCaptureSize> zeros{};
    if (!backend->WriteKernelMemory(captureVa, zeros.data(), zeros.size())) {
        FreeKernelMemory(backend, captureVa);
        return result;
    }

    uint64_t callbackVa = 0;
    const auto callbackAlloc = AllocateKernelMemory(backend, 0x40, callbackVa);
    if (callbackAlloc != KernelCallStatus::Executed || !callbackVa) {
        FreeKernelMemory(backend, captureVa);
        result.callStatus = callbackAlloc;
        return result;
    }

    std::array<uint8_t, 0x40> callback{};
    size_t p = 0;
    // mov rax, capture; mov [rax], rcx
    callback[p++] = 0x48; callback[p++] = 0xB8;
    std::memcpy(callback.data() + p, &captureVa, sizeof(captureVa)); p += 8;
    callback[p++] = 0x48; callback[p++] = 0x89; callback[p++] = 0x08;
    // mov rax, driverEntry; call rax
    callback[p++] = 0x48; callback[p++] = 0xB8;
    std::memcpy(callback.data() + p, &driverEntryVa, sizeof(driverEntryVa)); p += 8;
    callback[p++] = 0xFF; callback[p++] = 0xD0;
    // mov rdx, capture; mov [rdx+8], rax; ret
    callback[p++] = 0x48; callback[p++] = 0xBA;
    std::memcpy(callback.data() + p, &captureVa, sizeof(captureVa)); p += 8;
    callback[p++] = 0x48; callback[p++] = 0x89; callback[p++] = 0x42; callback[p++] = 0x08;
    callback[p++] = 0xC3;
    if (!backend->WriteKernelMemory(callbackVa, callback.data(), p)) {
        const auto captureFree = FreeKernelMemory(backend, captureVa);
        const auto callbackFree = FreeKernelMemory(backend, callbackVa);
        if (captureFree != KernelCallStatus::Executed ||
            callbackFree != KernelCallStatus::Executed)
            result.callStatus = KernelCallStatus::RestorationUncertain;
        return result;
    }
    bool protectedCallback = false;
    const auto protect = ProtectKernelMemory(backend, callbackVa, 0x40,
                                             PAGE_EXECUTE_READ, &protectedCallback);
    if (protect != KernelCallStatus::Executed || !protectedCallback) {
        const auto captureFree = protect == KernelCallStatus::RestorationUncertain
            ? KernelCallStatus::RestorationUncertain
            : FreeKernelMemory(backend, captureVa);
        KernelCallStatus callbackFree = KernelCallStatus::Executed;
        if (protect != KernelCallStatus::RestorationUncertain &&
            (protect == KernelCallStatus::NotExecuted || !protectedCallback))
            callbackFree = FreeKernelMemory(backend, callbackVa);
        if (captureFree != KernelCallStatus::Executed ||
            callbackFree != KernelCallStatus::Executed)
            result.callStatus = KernelCallStatus::RestorationUncertain;
        return result;
    }

    result.callbackStub = callbackVa;
    uint32_t ioStatus = STATUS_UNSUCCESSFUL;
    result.callStatus = CallKernelFunction(backend, &ioStatus, ioCreateDriver,
                                           0ULL, callbackVa);
    result.ioCreateStatus = ioStatus;
    if (result.callStatus != KernelCallStatus::Executed) return result;

    uint64_t capturedObject = 0;
    uint32_t capturedStatus = STATUS_UNSUCCESSFUL;
    if (!ReadU64(backend, captureVa, capturedObject) ||
        !ReadU32(backend, captureVa + 8, capturedStatus)) {
        result.callStatus = KernelCallStatus::RestorationUncertain;
        return result;
    }
    result.driverObject = capturedObject;
    result.driverEntryStatus = capturedStatus;
    // The callback stub remains resident because DRIVER_OBJECT.DriverInit may
    // retain its address after IoCreateDriver returns. The capture slot is no
    // longer referenced and can be released after a confirmed call.
    const auto captureFree = FreeKernelMemory(backend, captureVa);
    if (captureFree != KernelCallStatus::Executed)
        result.callStatus = KernelCallStatus::RestorationUncertain;
    return result;
}

} // namespace kmem
} // namespace hinv
