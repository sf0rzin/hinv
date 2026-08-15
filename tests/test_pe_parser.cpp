// PE parser tests for hinv.
// Exercises BuildMappedImage directly so section/import/relocation bounds and
// the fail-closed malformed-input paths are actually covered. No assert() —
// works in Release too.

#include <windows.h>
#include <cstdint>
#include <vector>
#include <iostream>
#include <cstring>
#include <string>
#include <cstdio>
#include <fstream>

#include "../src/hinv-core/hinv_mapper.hpp"
#include "../src/hinv-core/hinv_kmem.hpp"
#include "../src/hinv-core/hinv_byovd.hpp"
#include "../src/hinv-core/hinv_cleaner.hpp"

// A mock backend that does nothing; used to test PE parsing logic without kernel access.
class MockBackend : public hinv::byovd::IByovdBackend {
public:
    bool Initialize(const std::wstring&) override { return true; }
    void Shutdown() override {}
    bool IsReady() const override { return true; }
    bool ReadKernelMemory(uint64_t, void*, size_t) override { return false; }
    bool WriteKernelMemory(uint64_t, const void*, size_t) override { return false; }
};

// A mock backend that serves reads from a local buffer, standing in for a
// manually mapped module living in "kernel memory" at a fake base.
class FakeKernelMemoryBackend : public MockBackend {
public:
    uint64_t base = 0;
    std::vector<uint8_t> mem;

    bool ReadKernelMemory(uint64_t va, void* out, size_t size) override {
        if (va < base || va - base + size > mem.size()) return false;
        std::memcpy(out, mem.data() + (va - base), size);
        return true;
    }
};

// Serves two fake modules at once (forwarder chasing needs a second module).
class TwoModuleBackend : public MockBackend {
public:
    uint64_t base1 = 0, base2 = 0;
    std::vector<uint8_t> mem1, mem2;

    bool ReadKernelMemory(uint64_t va, void* out, size_t size) override {
        for (int w = 0; w < 2; ++w) {
            uint64_t b = w ? base2 : base1;
            const auto& mm = w ? mem2 : mem1;
            if (b && va >= b && va - b + size <= mm.size()) {
                std::memcpy(out, mm.data() + (va - b), size);
                return true;
            }
        }
        return false;
    }
};

namespace {

constexpr uint32_t E_LFANEW = 0x80;
constexpr uint32_t SECTION_RAW_OFF = 0x200;
constexpr uint32_t SECTION_RVA = 0x1000;
constexpr uint64_t PREFERRED_BASE = 0x10000;
constexpr uint64_t FAKE_KERNEL_BASE = 0x140000000000ULL;

void W16(std::vector<uint8_t>& b, size_t off, uint16_t v) { std::memcpy(b.data() + off, &v, 2); }
void W32(std::vector<uint8_t>& b, size_t off, uint32_t v) { std::memcpy(b.data() + off, &v, 4); }
void W64(std::vector<uint8_t>& b, size_t off, uint64_t v) { std::memcpy(b.data() + off, &v, 8); }

// RVA -> raw file offset (single .text section layout used by all fixtures).
size_t RvaToOff(uint32_t rva) { return SECTION_RAW_OFF + (rva - SECTION_RVA); }

// --- Inverted function table fixtures (Win11 24H2 SEH registration path) ---
constexpr uint64_t IFT_TABLE_VA = 0xFFFFF803EB200020ULL; // mirrors build 26100
constexpr uint64_t IFT_LFE_VA   = 0xFFFFF803EA232140ULL; // fake RtlLookupFunctionEntry

// Serves two ranges: the fake RtlLookupFunctionEntry bytes and a fake
// PsInvertedFunctionTable. Writes only land on the table.
class IftBackend : public MockBackend {
public:
    std::vector<uint8_t> func;  // at IFT_LFE_VA
    std::vector<uint8_t> table; // at IFT_TABLE_VA
    bool failWrites = false;

    bool ReadKernelMemory(uint64_t va, void* out, size_t size) override {
        if (va >= IFT_LFE_VA && va - IFT_LFE_VA + size <= func.size()) {
            std::memcpy(out, func.data() + (va - IFT_LFE_VA), size);
            return true;
        }
        if (va >= IFT_TABLE_VA && va - IFT_TABLE_VA + size <= table.size()) {
            std::memcpy(out, table.data() + (va - IFT_TABLE_VA), size);
            return true;
        }
        return false;
    }
    bool WriteKernelMemory(uint64_t va, const void* in, size_t size) override {
        if (failWrites) return false;
        if (va >= IFT_TABLE_VA && va - IFT_TABLE_VA + size <= table.size()) {
            std::memcpy(table.data() + (va - IFT_TABLE_VA), in, size);
            return true;
        }
        return false;
    }
};

void IftHeader(std::vector<uint8_t>& t, uint32_t cur, uint32_t max, uint32_t epoch, uint8_t overflow) {
    W32(t, 0x0, cur); W32(t, 0x4, max); W32(t, 0x8, epoch); t[0xC] = overflow;
}
void IftEntry(std::vector<uint8_t>& t, uint32_t idx, uint64_t ft, uint64_t base,
              uint32_t imgSize, uint32_t tblSize) {
    size_t off = 0x10 + idx * 0x18;
    W64(t, off + 0, ft); W64(t, off + 8, base); W32(t, off + 0x10, imgSize); W32(t, off + 0x14, tblSize);
}
uint32_t IftCur(const std::vector<uint8_t>& t)   { uint32_t v; std::memcpy(&v, t.data() + 0x0, 4); return v; }
uint32_t IftEpoch(const std::vector<uint8_t>& t) { uint32_t v; std::memcpy(&v, t.data() + 0x8, 4); return v; }
uint64_t IftEntryBase(const std::vector<uint8_t>& t, uint32_t idx) {
    uint64_t v; std::memcpy(&v, t.data() + 0x10 + idx * 0x18 + 8, 8); return v;
}
// Build the fake RtlLookupFunctionEntry prologue: 8 filler bytes, then
// mov rcx, [rip+disp32] landing on IFT_TABLE_VA + 0x18 (as on build 26100).
std::vector<uint8_t> IftMakeLookupBytes() {
    std::vector<uint8_t> f(0x40, 0x90);
    f[0] = 0x40; f[1] = 0x53; // push rbx-ish filler; content before the load is irrelevant
    uint32_t disp = static_cast<uint32_t>(
        static_cast<int64_t>(IFT_TABLE_VA + 0x18) - static_cast<int64_t>(IFT_LFE_VA + 8 + 7));
    f[8] = 0x48; f[9] = 0x8B; f[10] = 0x0D;
    std::memcpy(f.data() + 11, &disp, 4);
    return f;
}

// Build a minimal PE64 with one .text section covering [SECTION_RVA, SECTION_RVA + rawSize - SECTION_RAW_OFF).
std::vector<uint8_t> MakePe(uint32_t imageSize, size_t rawSize) {
    std::vector<uint8_t> pe(rawSize, 0);

    pe[0] = 'M';
    pe[1] = 'Z';
    W32(pe, 0x3C, E_LFANEW);

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(pe.data() + E_LFANEW);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.NumberOfSections = 1;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    nt->OptionalHeader.SizeOfImage = imageSize;
    nt->OptionalHeader.SizeOfHeaders = 0x200;
    nt->OptionalHeader.ImageBase = PREFERRED_BASE;

    auto* sec = reinterpret_cast<IMAGE_SECTION_HEADER*>(
        pe.data() + E_LFANEW + 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64));
    std::memcpy(sec->Name, ".text", 5);
    sec->VirtualAddress = SECTION_RVA;
    sec->Misc.VirtualSize = static_cast<uint32_t>(rawSize - SECTION_RAW_OFF);
    sec->PointerToRawData = SECTION_RAW_OFF;
    sec->SizeOfRawData = static_cast<uint32_t>(rawSize - SECTION_RAW_OFF);

    return pe;
}

void SetDataDirectory(std::vector<uint8_t>& pe, uint32_t index, uint32_t va, uint32_t size) {
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(pe.data() + E_LFANEW);
    nt->OptionalHeader.DataDirectory[index].VirtualAddress = va;
    nt->OptionalHeader.DataDirectory[index].Size = size;
}

int failures = 0;

void Check(bool condition, const char* testName) {
    if (condition) {
        std::cout << "[PASS] " << testName << "\n";
    } else {
        std::cout << "[FAIL] " << testName << "\n";
        ++failures;
    }
}

} // namespace

int main() {
    MockBackend backend;
    std::vector<uint8_t> mapped;

    // --- MapDriverBytes front-door validation (unchanged behavior) ---------

    // Valid PE passes parsing and fails only at kernel allocation with the mock.
    auto validPe = MakePe(0x2000, 0x400);
    auto result = hinv::mapper::MapDriverBytes(&backend, validPe);
    Check(!result.success && result.error == "kernel allocation failed",
          "valid PE reaches allocation (fails only with mock backend)");

    result = hinv::mapper::MapDriverBytes(&backend, {});
    Check(!result.success && result.error == "invalid arguments", "empty input rejected");

    std::vector<uint8_t> tiny(32, 0);
    tiny[0] = 'M';
    tiny[1] = 'Z';
    result = hinv::mapper::MapDriverBytes(&backend, tiny);
    Check(!result.success && result.error == "invalid arguments", "tiny input rejected");

    auto badPe = MakePe(0x2000, 0x400);
    W32(badPe, 0x3C, 0x1000);
    result = hinv::mapper::MapDriverBytes(&backend, badPe);
    Check(!result.success && result.error == "invalid e_lfanew", "bad e_lfanew rejected");

    badPe = MakePe(0x2000, 0x400);
    W32(badPe, E_LFANEW, 0xDEADBEEF);
    result = hinv::mapper::MapDriverBytes(&backend, badPe);
    Check(!result.success && result.error == "invalid NT signature", "bad NT signature rejected");

    badPe = MakePe(0x2000, 0x400);
    badPe[0] = 'X';
    badPe[1] = 'X';
    result = hinv::mapper::MapDriverBytes(&backend, badPe);
    Check(!result.success && result.error == "invalid DOS signature", "bad DOS signature rejected");

    // Negative e_lfanew must not wrap past validation: e_lfanew is a signed
    // LONG, and promoting it to size_t used to bypass both bounds checks.
    badPe = MakePe(0x2000, 0x400);
    W32(badPe, 0x3C, 0xFFFFFF80); // e_lfanew = -128 as signed LONG
    result = hinv::mapper::MapDriverBytes(&backend, badPe);
    Check(!result.success && result.error == "invalid e_lfanew", "negative e_lfanew rejected");

    // --- BuildMappedImage: signed e_lfanew, strict sections, reloc types ----

    {
        auto pe = MakePe(0x2000, 0x400);
        W32(pe, 0x3C, 0xFFFFFF80); // negative e_lfanew
        Check(!hinv::mapper::BuildMappedImage(&backend, pe, FAKE_KERNEL_BASE, mapped),
              "negative e_lfanew rejected by BuildMappedImage");
    }

    {
        auto pe = MakePe(0x2000, 0x400);
        auto* sec = reinterpret_cast<IMAGE_SECTION_HEADER*>(
            pe.data() + E_LFANEW + 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64));
        sec->VirtualAddress = 0x2000; // == SizeOfImage
        Check(!hinv::mapper::BuildMappedImage(&backend, pe, FAKE_KERNEL_BASE, mapped),
              "section RVA beyond image rejected");
    }

    {
        auto pe = MakePe(0x2000, 0x400);
        auto* sec = reinterpret_cast<IMAGE_SECTION_HEADER*>(
            pe.data() + E_LFANEW + 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64));
        sec->PointerToRawData = 0x800; // beyond end of file
        Check(!hinv::mapper::BuildMappedImage(&backend, pe, FAKE_KERNEL_BASE, mapped),
              "section raw pointer beyond EOF rejected");
    }

    {
        auto pe = MakePe(0x2000, 0x400);
        auto* sec = reinterpret_cast<IMAGE_SECTION_HEADER*>(
            pe.data() + E_LFANEW + 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64));
        sec->SizeOfRawData = 0x800; // raw data overruns the file
        Check(!hinv::mapper::BuildMappedImage(&backend, pe, FAKE_KERNEL_BASE, mapped),
              "section raw data overrun rejected");
    }

    {
        auto pe = MakePe(0x2000, 0x400);
        SetDataDirectory(pe, IMAGE_DIRECTORY_ENTRY_BASERELOC, 0x1080, 0x0C);
        W32(pe, RvaToOff(0x1080), 0x1000);
        W32(pe, RvaToOff(0x1084), 0x0C);
        W16(pe, RvaToOff(0x1088), 0x7000); // relocation type 7: unknown on AMD64
        Check(!hinv::mapper::BuildMappedImage(&backend, pe, FAKE_KERNEL_BASE, mapped),
              "unknown relocation type rejected");
    }

    // --- BuildMappedImage: machine type, optional header layout, BSS --------

    {
        auto pe = MakePe(0x2000, 0x400);
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(pe.data() + E_LFANEW);
        nt->FileHeader.Machine = IMAGE_FILE_MACHINE_ARM64;
        Check(!hinv::mapper::BuildMappedImage(&backend, pe, FAKE_KERNEL_BASE, mapped),
              "non-AMD64 machine rejected");
        result = hinv::mapper::MapDriverBytes(&backend, pe);
        Check(!result.success && result.error == "unsupported machine type (need AMD64)",
              "non-AMD64 machine rejected at front door");
    }

    {
        auto pe = MakePe(0x2000, 0x400);
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(pe.data() + E_LFANEW);
        nt->FileHeader.SizeOfOptionalHeader = 0;
        Check(!hinv::mapper::BuildMappedImage(&backend, pe, FAKE_KERNEL_BASE, mapped),
              "wrong SizeOfOptionalHeader rejected");
    }

    {
        auto pe = MakePe(0x2000, 0x400);
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(pe.data() + E_LFANEW);
        nt->OptionalHeader.NumberOfRvaAndSizes = 0xFFFFFFFF;
        Check(!hinv::mapper::BuildMappedImage(&backend, pe, FAKE_KERNEL_BASE, mapped),
              "oversized NumberOfRvaAndSizes rejected");
    }

    {
        // A directory index beyond NumberOfRvaAndSizes must be treated as
        // absent: the relocation below is well-formed but must NOT be applied.
        auto pe = MakePe(0x2000, 0x400);
        W64(pe, RvaToOff(0x1000), PREFERRED_BASE + 0x2000);
        SetDataDirectory(pe, IMAGE_DIRECTORY_ENTRY_BASERELOC, 0x1080, 0x0C);
        W32(pe, RvaToOff(0x1080), 0x1000);
        W32(pe, RvaToOff(0x1084), 0x0C);
        W16(pe, RvaToOff(0x1088), 0xA000); // DIR64, offset 0
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(pe.data() + E_LFANEW);
        nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_DIRECTORY_ENTRY_BASERELOC; // 5 < 6
        bool ok = hinv::mapper::BuildMappedImage(&backend, pe, FAKE_KERNEL_BASE, mapped);
        uint64_t val = 0;
        if (ok) std::memcpy(&val, mapped.data() + 0x1000, 8);
        Check(ok, "image with truncated directory count still builds");
        Check(ok && val == PREFERRED_BASE + 0x2000,
              "relocation beyond NumberOfRvaAndSizes not applied");
    }

    {
        auto pe = MakePe(0x3000, 0x400);
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(pe.data() + E_LFANEW);
        nt->FileHeader.NumberOfSections = 2;
        auto* sec = reinterpret_cast<IMAGE_SECTION_HEADER*>(
            pe.data() + E_LFANEW + 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64));
        auto* bss = sec + 1;
        std::memcpy(bss->Name, ".bss", 4);
        bss->VirtualAddress = 0x2000;
        bss->Misc.VirtualSize = 0x800;
        bss->PointerToRawData = 0;
        bss->SizeOfRawData = 0;
        Check(hinv::mapper::BuildMappedImage(&backend, pe, FAKE_KERNEL_BASE, mapped),
              "BSS section within image accepted");
    }

    {
        auto pe = MakePe(0x2000, 0x400);
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(pe.data() + E_LFANEW);
        nt->FileHeader.NumberOfSections = 2;
        auto* sec = reinterpret_cast<IMAGE_SECTION_HEADER*>(
            pe.data() + E_LFANEW + 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64));
        auto* bss = sec + 1;
        std::memcpy(bss->Name, ".bss", 4);
        bss->VirtualAddress = 0x1800;
        bss->Misc.VirtualSize = 0x1000; // 0x1800 + 0x1000 > SizeOfImage (0x2000)
        bss->PointerToRawData = 0;
        bss->SizeOfRawData = 0;
        Check(!hinv::mapper::BuildMappedImage(&backend, pe, FAKE_KERNEL_BASE, mapped),
              "BSS section beyond image rejected");
    }

    {
        auto pe = MakePe(0x2000, 0x400);
        auto* sec = reinterpret_cast<IMAGE_SECTION_HEADER*>(
            pe.data() + E_LFANEW + 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64));
        sec->PointerToRawData = 0; // SizeOfRawData stays nonzero
        Check(!hinv::mapper::BuildMappedImage(&backend, pe, FAKE_KERNEL_BASE, mapped),
              "raw size without raw pointer rejected");
    }

    // --- BuildMappedImage: sections -----------------------------------------

    {
        auto pe = MakePe(0x2000, 0x400);
        for (size_t i = SECTION_RAW_OFF; i < pe.size(); ++i) pe[i] = 0x41;
        bool ok = hinv::mapper::BuildMappedImage(&backend, pe, FAKE_KERNEL_BASE, mapped);
        Check(ok, "valid PE builds mapped image");
        Check(ok && mapped.size() == 0x2000, "mapped image has SizeOfImage bytes");
        Check(ok && mapped[SECTION_RVA] == 0x41 && mapped[SECTION_RVA + 0x1FF] == 0x41,
              "section raw data copied to section RVA");
    }

    // --- BuildMappedImage: relocations --------------------------------------

    {
        auto pe = MakePe(0x2000, 0x400);
        // DIR64 entry patching the qword at RVA 0x1000.
        W64(pe, RvaToOff(0x1000), PREFERRED_BASE + 0x2000);
        SetDataDirectory(pe, IMAGE_DIRECTORY_ENTRY_BASERELOC, 0x1080, 0x0C);
        W32(pe, RvaToOff(0x1080), 0x1000);  // block page RVA
        W32(pe, RvaToOff(0x1084), 0x0C);    // block size
        W16(pe, RvaToOff(0x1088), 0xA000);  // IMAGE_REL_BASED_DIR64, offset 0
        bool ok = hinv::mapper::BuildMappedImage(&backend, pe, FAKE_KERNEL_BASE, mapped);
        uint64_t patched = 0;
        if (ok) std::memcpy(&patched, mapped.data() + 0x1000, 8);
        Check(ok, "valid relocation block accepted");
        Check(ok && patched == FAKE_KERNEL_BASE + 0x2000, "DIR64 relocation applied with delta");
    }

    {
        auto pe = MakePe(0x2000, 0x400);
        SetDataDirectory(pe, IMAGE_DIRECTORY_ENTRY_BASERELOC, 0x1000, 0x2000); // 0x3000 > SizeOfImage
        Check(!hinv::mapper::BuildMappedImage(&backend, pe, FAKE_KERNEL_BASE, mapped),
              "relocation directory out of bounds rejected");
    }

    {
        auto pe = MakePe(0x2000, 0x400);
        // VirtualAddress + Size overflows 32 bits (wraps to 0); must not pass.
        SetDataDirectory(pe, IMAGE_DIRECTORY_ENTRY_BASERELOC, 0xFFFF0000, 0x00010000);
        Check(!hinv::mapper::BuildMappedImage(&backend, pe, FAKE_KERNEL_BASE, mapped),
              "relocation directory 32-bit overflow rejected");
    }

    {
        auto pe = MakePe(0x2000, 0x400);
        SetDataDirectory(pe, IMAGE_DIRECTORY_ENTRY_BASERELOC, 0x1080, 0x08);
        W32(pe, RvaToOff(0x1080), 0x1000);
        W32(pe, RvaToOff(0x1084), 0x0C); // block claims more than the directory holds
        Check(!hinv::mapper::BuildMappedImage(&backend, pe, FAKE_KERNEL_BASE, mapped),
              "truncated relocation block rejected");
    }

    // --- BuildMappedImage: imports ------------------------------------------

    {
        // One descriptor with an empty thunk list, terminated by a null descriptor.
        auto pe = MakePe(0x2000, 0x400);
        SetDataDirectory(pe, IMAGE_DIRECTORY_ENTRY_IMPORT, 0x1000, 0x28);
        W32(pe, RvaToOff(0x1000), 0x1110); // OriginalFirstThunk (zero thunk)
        W32(pe, RvaToOff(0x100C), 0x1100); // Name
        W32(pe, RvaToOff(0x1010), 0x1118); // FirstThunk (zero thunk)
        std::memcpy(pe.data() + RvaToOff(0x1100), "a.dll", 6);
        Check(hinv::mapper::BuildMappedImage(&backend, pe, FAKE_KERNEL_BASE, mapped),
              "import descriptor chain with empty thunks accepted");
    }

    {
        auto pe = MakePe(0x2000, 0x400);
        SetDataDirectory(pe, IMAGE_DIRECTORY_ENTRY_IMPORT, 0x1000, 0x14);
        W32(pe, RvaToOff(0x100C), 0x2000); // Name >= SizeOfImage
        Check(!hinv::mapper::BuildMappedImage(&backend, pe, FAKE_KERNEL_BASE, mapped),
              "import descriptor with out-of-bounds Name rejected");
    }

    {
        // Second descriptor falls outside the image; only the first was checked before.
        auto pe = MakePe(0x1400, 0x600); // .text covers RVA 0x1000..0x1400
        SetDataDirectory(pe, IMAGE_DIRECTORY_ENTRY_IMPORT, 0x13EC, 0x28);
        W32(pe, RvaToOff(0x13EC), 0x1110); // OriginalFirstThunk (zero thunk)
        W32(pe, RvaToOff(0x13F8), 0x1100); // Name
        W32(pe, RvaToOff(0x13FC), 0x1118); // FirstThunk
        std::memcpy(pe.data() + RvaToOff(0x1100), "a.dll", 6);
        Check(!hinv::mapper::BuildMappedImage(&backend, pe, FAKE_KERNEL_BASE, mapped),
              "second import descriptor out of bounds rejected");
    }

    {
        // DLL name is not NUL-terminated within the image.
        auto pe = MakePe(0x2000, 0x1200); // .text covers RVA 0x1000..0x2000
        SetDataDirectory(pe, IMAGE_DIRECTORY_ENTRY_IMPORT, 0x1000, 0x14);
        W32(pe, RvaToOff(0x1000), 0x1110);
        W32(pe, RvaToOff(0x100C), 0x1FFC); // Name near end of image
        W32(pe, RvaToOff(0x1010), 0x1118);
        std::memcpy(pe.data() + RvaToOff(0x1FFC), "a.dl", 4); // no NUL in [0x1FFC, 0x2000)
        Check(!hinv::mapper::BuildMappedImage(&backend, pe, FAKE_KERNEL_BASE, mapped),
              "unterminated DLL name rejected");
    }

    {
        // Thunk array start is in bounds but the full 8 bytes are not.
        auto pe = MakePe(0x2000, 0x1200);
        SetDataDirectory(pe, IMAGE_DIRECTORY_ENTRY_IMPORT, 0x1000, 0x14);
        W32(pe, RvaToOff(0x1000), 0x1FFC); // OriginalFirstThunk: 0x1FFC + 8 > 0x2000
        W32(pe, RvaToOff(0x100C), 0x1100); // Name
        W32(pe, RvaToOff(0x1010), 0x1118); // FirstThunk
        std::memcpy(pe.data() + RvaToOff(0x1100), "a.dll", 6);
        Check(!hinv::mapper::BuildMappedImage(&backend, pe, FAKE_KERNEL_BASE, mapped),
              "truncated thunk rejected");
    }

    // --- Mapped-module registry ---------------------------------------------

    {
        // Emulate a module that was manually mapped into kernel memory: it is
        // not in EnumKernelModules, but its PE headers live at its base, so
        // ResolveKernelExport must find it through the registry.
        FakeKernelMemoryBackend fb;
        fb.base = 0xFFFFF80012340000ULL;
        fb.mem.assign(0x400, 0);
        auto& m = fb.mem;
        m[0] = 'M';
        m[1] = 'Z';
        W32(m, 0x3C, E_LFANEW);
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(m.data() + E_LFANEW);
        nt->Signature = IMAGE_NT_SIGNATURE;
        nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        nt->OptionalHeader.SizeOfImage = 0x3000; // must contain the export RVA below
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = 0x200;
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = 0x100;
        W32(m, 0x214, 1);      // NumberOfFunctions
        W32(m, 0x218, 1);      // NumberOfNames
        W32(m, 0x21C, 0x250);  // AddressOfFunctions
        W32(m, 0x220, 0x240);  // AddressOfNames
        W32(m, 0x224, 0x248);  // AddressOfNameOrdinals
        W32(m, 0x240, 0x260);  // name RVA
        W16(m, 0x248, 0);      // name ordinal
        W32(m, 0x250, 0x2000); // function RVA (< SizeOfImage)
        std::memcpy(m.data() + 0x260, "TestExport", 11);

        hinv::kmem::RegisterMappedModule(L"FakeKd.DLL", fb.base, static_cast<uint32_t>(fb.mem.size()));
        uint64_t addr = hinv::kmem::ResolveKernelExport(&fb, L"fakekd.dll", "TestExport");
        Check(addr == fb.base + 0x2000,
              "export resolved from registered mapped module (case-insensitive)");

        addr = hinv::kmem::ResolveKernelExport(&fb, L"fakekd.dll", "NoSuchExport");
        Check(addr == 0, "missing export in mapped module returns 0");

        // Out-of-image export RVA must be rejected, not returned: a corrupt or
        // hostile table must never become a wild kernel pointer.
        W32(m, 0x250, 0x3000); // function RVA == SizeOfImage (just past the end)
        addr = hinv::kmem::ResolveKernelExport(&fb, L"fakekd.dll", "TestExport");
        Check(addr == 0, "export RVA beyond image rejected");

        // Forwarded export: the RVA points back into the export directory and
        // holds a "Dll.Func" string. The string sits at 0x280 — past the
        // IMAGE_EXPORT_DIRECTORY header and our arrays, inside the directory's
        // declared [0x200, 0x300) range — so the fixture stays well-formed.
        // A second fake module is the forward target; we verify the FINAL
        // resolved address, so an implementation that blindly rejects all
        // forwarders would fail this check.
        TwoModuleBackend fb2;
        fb2.base1 = fb.base;
        fb2.mem1 = fb.mem;
        fb2.base2 = 0xFFFFF80056780000ULL;
        fb2.mem2.assign(0x400, 0);
        {
            auto& t = fb2.mem2;
            t[0] = 'M';
            t[1] = 'Z';
            W32(t, 0x3C, E_LFANEW);
            auto* nt2 = reinterpret_cast<IMAGE_NT_HEADERS64*>(t.data() + E_LFANEW);
            nt2->Signature = IMAGE_NT_SIGNATURE;
            nt2->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
            nt2->OptionalHeader.SizeOfImage = 0x3000;
            nt2->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = 0x200;
            nt2->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = 0x100;
            W32(t, 0x214, 1);      // NumberOfFunctions
            W32(t, 0x218, 1);      // NumberOfNames
            W32(t, 0x21C, 0x250);  // AddressOfFunctions
            W32(t, 0x220, 0x240);  // AddressOfNames
            W32(t, 0x224, 0x248);  // AddressOfNameOrdinals
            W32(t, 0x240, 0x260);  // name RVA
            W16(t, 0x248, 0);      // ordinal
            W32(t, 0x250, 0x1800); // RealFunc RVA
            std::memcpy(t.data() + 0x260, "RealFunc", 9);
        }
        hinv::kmem::RegisterMappedModule(L"faketarget.dll", fb2.base2, static_cast<uint32_t>(fb2.mem2.size()));

        W32(m, 0x250, 0x280); // TestExport now forwards into the export dir
        std::memcpy(m.data() + 0x280, "faketarget.RealFunc", 19); // PE forwarder names carry no extension
        fb2.mem1 = fb.mem;    // refresh the copy held by the backend
        uint64_t fwd = hinv::kmem::ResolveKernelExport(&fb2, L"fakekd.dll", "TestExport");
        Check(fwd == fb2.base2 + 0x1800, "forwarded export chased to target module");

        // A forwarder whose target does not exist must fail to 0 (never a
        // pointer to the text string).
        std::memcpy(m.data() + 0x280, "faketarget.NoSuchFunc", 21);
        fb2.mem1 = fb.mem;
        fwd = hinv::kmem::ResolveKernelExport(&fb2, L"fakekd.dll", "TestExport");
        Check(fwd == 0, "forwarder with missing target returns 0");
    }

    // --- Import resolution: the happy path (thunk actually gets patched) -----

    {
        // A module exporting HappyFunc at RVA 0x1500, registered as mapped.
        FakeKernelMemoryBackend imp;
        imp.base = 0xFFFFF80099990000ULL;
        imp.mem.assign(0x400, 0);
        auto& im = imp.mem;
        im[0] = 'M';
        im[1] = 'Z';
        W32(im, 0x3C, E_LFANEW);
        auto* int_ = reinterpret_cast<IMAGE_NT_HEADERS64*>(im.data() + E_LFANEW);
        int_->Signature = IMAGE_NT_SIGNATURE;
        int_->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        int_->OptionalHeader.SizeOfImage = 0x3000;
        int_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = 0x200;
        int_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = 0x100;
        W32(im, 0x214, 1);      // NumberOfFunctions
        W32(im, 0x218, 1);      // NumberOfNames
        W32(im, 0x21C, 0x250);  // AddressOfFunctions
        W32(im, 0x220, 0x240);  // AddressOfNames
        W32(im, 0x224, 0x248);  // AddressOfNameOrdinals
        W32(im, 0x240, 0x260);  // name RVA
        W16(im, 0x248, 0);      // ordinal
        W32(im, 0x250, 0x1500); // HappyFunc RVA
        std::memcpy(im.data() + 0x260, "HappyFunc", 10);
        hinv::kmem::RegisterMappedModule(L"happyimp.dll", imp.base, static_cast<uint32_t>(imp.mem.size()));

        // A PE importing happyimp.dll!HappyFunc by name.
        auto pe = MakePe(0x2000, 0x1200);
        SetDataDirectory(pe, IMAGE_DIRECTORY_ENTRY_IMPORT, 0x1000, 0x28);
        // Import descriptor at RVA 0x1000:
        W32(pe, RvaToOff(0x1000), 0x1040); // OriginalFirstThunk (ILT)
        W32(pe, RvaToOff(0x100C), 0x1060); // Name
        W32(pe, RvaToOff(0x1010), 0x1080); // FirstThunk (IAT)
        std::memcpy(pe.data() + RvaToOff(0x1060), "happyimp.dll", 13);
        // ILT[0] -> IMAGE_IMPORT_BY_NAME at RVA 0x10A0; ILT[1] = 0.
        W64(pe, RvaToOff(0x1040), 0x10A0);
        W64(pe, RvaToOff(0x1048), 0);
        // IMAGE_IMPORT_BY_NAME: Hint=0, Name="HappyFunc".
        W16(pe, RvaToOff(0x10A0), 0);
        std::memcpy(pe.data() + RvaToOff(0x10A2), "HappyFunc", 10);

        std::vector<uint8_t> impMapped;
        Check(hinv::mapper::BuildMappedImage(&imp, pe, FAKE_KERNEL_BASE, impMapped),
              "import by name: build succeeds with registered module");
        uint64_t patched = 0;
        std::memcpy(&patched, impMapped.data() + 0x1080, 8); // IAT[0]
        Check(patched == imp.base + 0x1500,
              "import by name: FirstThunk patched with resolved address");

        // Ordinal import is deliberately unsupported: the whole map must fail
        // (fail-closed), not patch garbage.
        auto peOrd = MakePe(0x2000, 0x1200);
        SetDataDirectory(peOrd, IMAGE_DIRECTORY_ENTRY_IMPORT, 0x1000, 0x28);
        W32(peOrd, RvaToOff(0x1000), 0x1040);
        W32(peOrd, RvaToOff(0x100C), 0x1060);
        W32(peOrd, RvaToOff(0x1010), 0x1080);
        std::memcpy(peOrd.data() + RvaToOff(0x1060), "happyimp.dll", 13);
        W64(peOrd, RvaToOff(0x1040), 0x8000000000000005ULL); // ordinal 5
        W64(peOrd, RvaToOff(0x1048), 0);
        Check(!hinv::mapper::BuildMappedImage(&imp, peOrd, FAKE_KERNEL_BASE, impMapped),
              "ordinal import rejected (fail-closed)");

        // OriginalFirstThunk == 0: the lookup must fall back to FirstThunk.
        auto peFt = MakePe(0x2000, 0x1200);
        SetDataDirectory(peFt, IMAGE_DIRECTORY_ENTRY_IMPORT, 0x1000, 0x28);
        W32(peFt, RvaToOff(0x1000), 0);      // OriginalFirstThunk = 0
        W32(peFt, RvaToOff(0x100C), 0x1060);
        W32(peFt, RvaToOff(0x1010), 0x1040); // FirstThunk doubles as the lookup
        std::memcpy(peFt.data() + RvaToOff(0x1060), "happyimp.dll", 13);
        W64(peFt, RvaToOff(0x1040), 0x10A0);
        W64(peFt, RvaToOff(0x1048), 0);
        W16(peFt, RvaToOff(0x10A0), 0);
        std::memcpy(peFt.data() + RvaToOff(0x10A2), "HappyFunc", 10);
        Check(hinv::mapper::BuildMappedImage(&imp, peFt, FAKE_KERNEL_BASE, impMapped),
              "import with OriginalFirstThunk=0 uses FirstThunk as lookup");
        std::memcpy(&patched, impMapped.data() + 0x1040, 8);
        Check(patched == imp.base + 0x1500,
              "fallback lookup: FirstThunk patched with resolved address");
    }

    // --- New primitives: normalization, backend detection, timestamps -------

    {
        // PiDDB lookup key: TimeDateStamp must come from the file on disk.
        // (C stdio for the fixture's own file I/O; the project links the C++
        // runtime statically because a foreign libstdc++-6.dll earlier in PATH
        // — e.g. Git for Windows' — ABI-crashes fstream at runtime)
        auto pe = MakePe(0x2000, 0x400);
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(pe.data() + E_LFANEW);
        nt->FileHeader.TimeDateStamp = 0xDEADBEEF;
        const char* tmpA = "hinv_test_timestamp.sys";
        if (FILE* f = std::fopen(tmpA, "wb")) {
            std::fwrite(pe.data(), 1, pe.size(), f);
            std::fclose(f);
        }
        uint32_t ts = hinv::cleaner::GetDriverFileTimestamp(L"hinv_test_timestamp.sys");
        Check(ts == 0xDEADBEEF, "driver timestamp read from disk");
        std::remove(tmpA);
        Check(hinv::cleaner::GetDriverFileTimestamp(L"no_such_file.sys") == 0,
              "missing file timestamp is 0");
    }

    Check(hinv::kmem::NormalizeModuleName(L"ntoskrnl") == L"ntoskrnl.exe",
          "normalize: ntoskrnl alias");
    Check(hinv::kmem::NormalizeModuleName(L"C:\\Windows\\System32\\drivers\\iqvw64e.sys") == L"iqvw64e.sys",
          "normalize: path stripped, extension kept");
    Check(hinv::kmem::NormalizeModuleName(L"hyperhv") == L"hyperhv.sys",
          "normalize: bare name gets .sys");
    Check(hinv::kmem::NormalizeModuleName(L"HAL") == L"hal.dll",
          "normalize: hal alias lowercased");
    Check(hinv::kmem::NormalizeModuleName(L"CI.dll") == L"ci.dll",
          "normalize: ci.dll lowercased");
    Check(hinv::kmem::NormalizeModuleName(L"kdcom.dll") == L"kdcom.dll",
          "normalize: kdcom alias");

    {
        auto intel = hinv::byovd::DetectProfile(L"iqvw64e.sys");
        Check(intel.type == hinv::byovd::BackendType::Intel && intel.devicePath == L"\\\\.\\Nal",
              "detect: intel backend + Nal device");
        auto dell = hinv::byovd::DetectProfile(L"dbutil_2_3.sys");
        Check(dell.type == hinv::byovd::BackendType::DbUtil && dell.readIoc == 0x9B0C1EC4,
              "detect: dbutil backend + IOCTLs");
        auto fallback = hinv::byovd::DetectProfile(L"unknown_driver.sys");
        Check(fallback.type == hinv::byovd::BackendType::Unknown,
              "detect: unknown driver name rejected (no silent dbutil fallback)");
    }
    // --- Inverted function table (24H2 SEH registration) --------------------

    {
        IftBackend ift;
        ift.func = IftMakeLookupBytes();
        ift.table.assign(0x10 + 4 * 0x18, 0);
        IftHeader(ift.table, 0, 4, 10, 0);

        Check(hinv::kmem::detail::FindInvertedFunctionTable(&ift, IFT_LFE_VA) == IFT_TABLE_VA,
              "ift: table address extracted from RtlLookupFunctionEntry bytes");

        IftBackend noPattern;
        noPattern.func.assign(0x40, 0x90);
        noPattern.table = ift.table;
        Check(hinv::kmem::detail::FindInvertedFunctionTable(&noPattern, IFT_LFE_VA) == 0,
              "ift: no RIP-relative candidate -> 0");

        IftBackend badHeader;
        badHeader.func = IftMakeLookupBytes();
        badHeader.table.assign(0x10 + 4 * 0x18, 0); // max = 0: never valid
        Check(hinv::kmem::detail::FindInvertedFunctionTable(&badHeader, IFT_LFE_VA) == 0,
              "ift: invalid header rejected (wrong address never written through)");

        // Insert into empty table.
        Check(hinv::kmem::detail::InsertInvertedFunctionTableEntryAt(
                  &ift, IFT_TABLE_VA, 0xAAAA0000, 0x100000000, 0x2000, 0x60),
              "ift: insert into empty table");
        Check(IftCur(ift.table) == 1 && IftEpoch(ift.table) == 12,
              "ift: insert bumps CurrentSize and Epoch(+2)");
        Check(IftEntryBase(ift.table, 0) == 0x100000000, "ift: entry 0 image base stored");

        // Ordered insert in the middle: existing 0x1000, 0x5000; add 0x3000.
        IftBackend ord;
        ord.table.assign(0x10 + 6 * 0x18, 0);
        IftHeader(ord.table, 2, 6, 20, 0);
        IftEntry(ord.table, 0, 0xF1, 0x1000, 0x100, 0x24);
        IftEntry(ord.table, 1, 0xF2, 0x5000, 0x100, 0x24);
        Check(hinv::kmem::detail::InsertInvertedFunctionTableEntryAt(
                  &ord, IFT_TABLE_VA, 0xF3, 0x3000, 0x100, 0x24),
              "ift: ordered middle insert");
        Check(IftCur(ord.table) == 3 &&
              IftEntryBase(ord.table, 0) == 0x1000 &&
              IftEntryBase(ord.table, 1) == 0x3000 &&
              IftEntryBase(ord.table, 2) == 0x5000,
              "ift: entries stay ascending by ImageBase after insert");

        // Idempotent on same ImageBase.
        Check(hinv::kmem::detail::InsertInvertedFunctionTableEntryAt(
                  &ord, IFT_TABLE_VA, 0xF3, 0x3000, 0x100, 0x24),
              "ift: duplicate ImageBase insert is a no-op success");
        Check(IftCur(ord.table) == 3 && IftEpoch(ord.table) == 22,
              "ift: duplicate insert leaves table and epoch untouched");

        // Full table and overflowed table both fail closed.
        IftBackend full;
        full.table.assign(0x10 + 2 * 0x18, 0);
        IftHeader(full.table, 2, 2, 0, 0);
        Check(!hinv::kmem::detail::InsertInvertedFunctionTableEntryAt(
                  &full, IFT_TABLE_VA, 0xF4, 0x9000, 0x100, 0x24),
              "ift: full table insert fails closed");
        IftBackend ovw = full;
        IftHeader(ovw.table, 0, 2, 0, 1);
        Check(!hinv::kmem::detail::InsertInvertedFunctionTableEntryAt(
                  &ovw, IFT_TABLE_VA, 0xF4, 0x9000, 0x100, 0x24),
              "ift: overflowed table insert fails closed");

        // Removal from the middle shifts the tail down.
        Check(hinv::kmem::detail::RemoveInvertedFunctionTableEntryAt(&ord, IFT_TABLE_VA, 0x3000),
              "ift: remove middle entry");
        Check(IftCur(ord.table) == 2 &&
              IftEntryBase(ord.table, 0) == 0x1000 &&
              IftEntryBase(ord.table, 1) == 0x5000,
              "ift: removal shifts tail down");
        Check(IftEpoch(ord.table) == 24, "ift: removal bumps Epoch(+2)");

        // Removing a missing entry is a no-op success.
        Check(hinv::kmem::detail::RemoveInvertedFunctionTableEntryAt(&ord, IFT_TABLE_VA, 0xDEAD),
              "ift: remove missing entry succeeds (nothing to remove)");
        Check(IftCur(ord.table) == 2, "ift: missing removal leaves CurrentSize");

        // Backend write failure must surface as failure, never as success.
        IftBackend wfail;
        wfail.table.assign(0x10 + 4 * 0x18, 0);
        IftHeader(wfail.table, 0, 4, 0, 0);
        wfail.failWrites = true;
        Check(!hinv::kmem::detail::InsertInvertedFunctionTableEntryAt(
                  &wfail, IFT_TABLE_VA, 0xF5, 0x1000, 0x100, 0x24),
              "ift: write failure propagates as insert failure");

        // Entry [0] is the kernel MRU slot and is NOT in sorted order: a base
        // smaller than everything must insert at [1], never shift [0].
        IftBackend hot;
        hot.table.assign(0x10 + 6 * 0x18, 0);
        IftHeader(hot.table, 2, 6, 30, 0);
        IftEntry(hot.table, 0, 0xF0, 0x9000, 0x100, 0x24); // hot (out of order)
        IftEntry(hot.table, 1, 0xF2, 0x5000, 0x100, 0x24);
        Check(hinv::kmem::detail::InsertInvertedFunctionTableEntryAt(
                  &hot, IFT_TABLE_VA, 0xF1, 0x1000, 0x100, 0x24),
              "ift: smallest base inserts below MRU slot");
        Check(IftEntryBase(hot.table, 0) == 0x9000 &&
              IftEntryBase(hot.table, 1) == 0x1000 &&
              IftEntryBase(hot.table, 2) == 0x5000,
              "ift: MRU slot [0] never shifted by insert");
    }


    std::cout << "[TEST] " << (failures == 0 ? "All tests passed" : "Some tests failed") << "\n";
    return failures == 0 ? 0 : 1;
}
