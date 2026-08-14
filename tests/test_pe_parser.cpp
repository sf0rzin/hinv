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

#include "../src/hinv-core/hinv_mapper.hpp"
#include "../src/hinv-core/hinv_kmem.hpp"

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
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = 0x200;
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = 0x100;
        W32(m, 0x214, 1);      // NumberOfFunctions
        W32(m, 0x218, 1);      // NumberOfNames
        W32(m, 0x21C, 0x250);  // AddressOfFunctions
        W32(m, 0x220, 0x240);  // AddressOfNames
        W32(m, 0x224, 0x248);  // AddressOfNameOrdinals
        W32(m, 0x240, 0x260);  // name RVA
        W16(m, 0x248, 0);      // name ordinal
        W32(m, 0x250, 0x2000); // function RVA
        std::memcpy(m.data() + 0x260, "TestExport", 11);

        hinv::kmem::RegisterMappedModule(L"FakeKd.DLL", fb.base, static_cast<uint32_t>(fb.mem.size()));
        uint64_t addr = hinv::kmem::ResolveKernelExport(&fb, L"fakekd.dll", "TestExport");
        Check(addr == fb.base + 0x2000,
              "export resolved from registered mapped module (case-insensitive)");

        addr = hinv::kmem::ResolveKernelExport(&fb, L"fakekd.dll", "NoSuchExport");
        Check(addr == 0, "missing export in mapped module returns 0");
    }

    std::cout << "[TEST] " << (failures == 0 ? "All tests passed" : "Some tests failed") << "\n";
    return failures == 0 ? 0 : 1;
}
