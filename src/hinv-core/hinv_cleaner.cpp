#include "hinv_cleaner.hpp"
#include "hinv_kmem.hpp"
#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <cwctype>
#include <algorithm>
#include <cstring>
#include <cstddef>

#ifndef _WINDOWS_
typedef struct _LSA_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;
#endif

namespace hinv {
namespace cleaner {

static std::wstring ToLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), ::towlower);
    return s;
}

// ---------------------------------------------------------------------------
// Pattern scanning helper. '?' is wildcard.
// ---------------------------------------------------------------------------

static bool PatternMatch(const uint8_t* data, const std::vector<uint8_t>& pattern, const std::vector<bool>& mask) {
    for (size_t i = 0; i < pattern.size(); ++i) {
        if (mask[i] && data[i] != pattern[i]) return false;
    }
    return true;
}

static uint64_t FindPattern(byovd::IByovdBackend* backend, uint64_t begin, uint32_t size,
                            const std::vector<uint8_t>& pattern, const std::vector<bool>& mask,
                            int32_t ripOffset = 0) {
    if (pattern.size() != mask.size() || pattern.empty()) return 0;

    constexpr size_t CHUNK = 0x1000;
    std::vector<uint8_t> buffer(CHUNK + pattern.size());

    for (uint32_t off = 0; off < size; off += CHUNK) {
        uint32_t readSize = (off + CHUNK > size) ? (size - off) : CHUNK;
        readSize = static_cast<uint32_t>(readSize + pattern.size());
        if (off + readSize > size) readSize = size - off;

        if (!backend->ReadKernelMemory(begin + off, buffer.data(), readSize)) continue;

        for (size_t i = 0; i + pattern.size() <= readSize; ++i) {
            if (PatternMatch(buffer.data() + i, pattern, mask)) {
                uint64_t matchVa = begin + off + i;
                if (ripOffset != 0) {
                    int32_t rel = *reinterpret_cast<int32_t*>(buffer.data() + i + ripOffset);
                    return matchVa + ripOffset + 4 + rel;
                }
                return matchVa;
            }
        }
    }
    return 0;
}

static uint64_t FindNtoskrnlSection(byovd::IByovdBackend* backend, const char* sectionName, uint32_t& outSize) {
    auto mods = kmem::EnumKernelModules();
    uint64_t ntosBase = 0;
    for (const auto& m : mods) {
        if (ToLower(m.name).find(L"ntoskrnl") != std::wstring::npos) {
            ntosBase = m.base;
            break;
        }
    }
    if (!ntosBase) return 0;

    IMAGE_DOS_HEADER dos{};
    if (!backend->ReadKernelMemory(ntosBase, &dos, sizeof(dos))) return 0;
    IMAGE_NT_HEADERS64 nt{};
    if (!backend->ReadKernelMemory(ntosBase + dos.e_lfanew, &nt, sizeof(nt))) return 0;

    uint16_t numSections = nt.FileHeader.NumberOfSections;
    std::vector<IMAGE_SECTION_HEADER> sections(numSections);
    uint64_t sectionTable = ntosBase + dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + nt.FileHeader.SizeOfOptionalHeader;
    if (!backend->ReadKernelMemory(sectionTable, sections.data(), numSections * sizeof(IMAGE_SECTION_HEADER))) return 0;

    for (const auto& sec : sections) {
        if (std::strncmp(reinterpret_cast<const char*>(sec.Name), sectionName, IMAGE_SIZEOF_SHORT_NAME) == 0) {
            outSize = sec.Misc.VirtualSize;
            return ntosBase + sec.VirtualAddress;
        }
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Locate kernel globals
// ---------------------------------------------------------------------------

static uint64_t FindMmUnloadedDrivers(byovd::IByovdBackend* backend) {
    // Try exported symbol first.
    uint64_t addr = kmem::ResolveKernelExport(backend, L"ntoskrnl.exe", "MmUnloadedDrivers");
    if (addr) return addr;

    // Fallback pattern scan.
    uint32_t textSize = 0;
    uint64_t textBase = FindNtoskrnlSection(backend, ".text", textSize);
    if (!textBase) return 0;

    // lea rcx, MmUnloadedDrivers ; add rcx, 18h
    // 48 8D 0D ? ? ? ? 48 83 C1 18
    std::vector<uint8_t> pat = { 0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC1, 0x18 };
    std::vector<bool> mask = { true, true, true, false, false, false, false, true, true, true, true };
    return FindPattern(backend, textBase, textSize, pat, mask, 3);
}

static uint64_t FindPiDDBCacheTable(byovd::IByovdBackend* backend) {
    uint64_t addr = kmem::ResolveKernelExport(backend, L"ntoskrnl.exe", "PiDDBCacheTable");
    if (addr) return addr;

    uint32_t textSize = 0;
    uint64_t textBase = FindNtoskrnlSection(backend, ".text", textSize);
    if (!textBase) return 0;

    // lea rcx, PiDDBCacheTable ; call
    // 48 8D 0D ? ? ? ? E8 ? ? ? ? 8B F0
    std::vector<uint8_t> pat = { 0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x8B, 0xF0 };
    std::vector<bool> mask = { true, true, true, false, false, false, false, true, false, false, false, false, true, true };
    return FindPattern(backend, textBase, textSize, pat, mask, 3);
}

static uint64_t FindPiDDBLock(byovd::IByovdBackend* backend) {
    return kmem::ResolveKernelExport(backend, L"ntoskrnl.exe", "PiDDBLock");
}

// ---------------------------------------------------------------------------
// MmUnloadedDrivers cleaner — FAIL-CLOSED (disabled)
// ---------------------------------------------------------------------------
//
// Disabled pending per-build/symbol layout verification. The previous
// heuristic probe could not distinguish "array of pointers" from "inline array
// of MM_UNLOADED_DRIVER records": when the global points at an array of
// records, the first bytes are a UNICODE_STRING (Length/MaximumLength), not a
// pointer, so the code kept treating the global itself as the record array and
// could zero MmUnloadedDrivers itself when the first record matched.

bool ClearUnloadedDriverEntry(byovd::IByovdBackend* backend, const std::wstring& driverName) {
    uint64_t globalVa = FindMmUnloadedDrivers(backend);
    if (!globalVa) {
        std::wcerr << L"[hinv::cleaner] MmUnloadedDrivers not located\n";
        return false;
    }
    std::wcerr << L"[hinv::cleaner] MmUnloadedDrivers cleaner is DISABLED (fail-closed): "
               << L"layout is build-dependent and was not verified for this build; "
               << L"refusing to erase traces for " << driverName
               << L" (global at 0x" << std::hex << globalVa << std::dec << L")\n";
    return false;
}

// ---------------------------------------------------------------------------
// PiDDBCacheTable cleaner — FAIL-CLOSED (disabled)
// ---------------------------------------------------------------------------
//
// Disabled: PiDDBCacheTable is an RTL_AVL_TABLE on current Windows builds, not
// a LIST_ENTRY head. The previous walker rewrote Flink/Blink and zeroed
// records without unlinking nodes from the AVL tree, which corrupts kernel
// metadata and computes write addresses from misinterpreted fields. Also,
// PiDDBLock is not exported on current builds, so locating it via the export
// table alone makes the feature silently inert. Re-enable only with a real
// RtlEnumerateGenericTableAvl-style traversal and a per-build/symbol lock
// location.

bool ClearPiDddbCache(byovd::IByovdBackend* backend, const std::wstring& driverName) {
    uint64_t tableVa = FindPiDDBCacheTable(backend);
    uint64_t lockVa = FindPiDDBLock(backend);
    std::wcerr << L"[hinv::cleaner] PiDDBCacheTable cleaner is DISABLED (fail-closed): "
               << L"table is RTL_AVL_TABLE; safe removal is not implemented. "
               << L"Refusing to erase traces for " << driverName
               << L" (table=0x" << std::hex << tableVa << L" lock=0x" << lockVa << std::dec << L")\n";
    if (!tableVa) std::wcerr << L"[hinv::cleaner] PiDDBCacheTable not located\n";
    if (!lockVa)  std::wcerr << L"[hinv::cleaner] PiDDBLock not located (not exported on this build)\n";
    return false;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

CleanResult CleanDriverTraces(byovd::IByovdBackend* backend, const std::wstring& driverName) {
    CleanResult result{};
    if (!backend) {
        result.error = L"invalid backend";
        return result;
    }

    std::wcout << L"[hinv::cleaner] Sanitizing traces for " << driverName << L"\n";
    result.mmUnloadedDrivers = ClearUnloadedDriverEntry(backend, driverName);
    result.piDdbCache = ClearPiDddbCache(backend, driverName);

    if (!result.mmUnloadedDrivers && !result.piDdbCache) {
        result.error = L"trace cleaners are disabled (fail-closed) or globals not located; see log";
    }
    return result;
}

} // namespace cleaner
} // namespace hinv
