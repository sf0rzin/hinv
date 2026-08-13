// Basic PE parser test for hinv.
// Validates that malformed inputs are rejected safely.

#include <windows.h>
#include <cstdint>
#include <vector>
#include <iostream>
#include <cassert>

#include "../src/hinv-core/hinv_mapper.hpp"

// A mock backend that does nothing; used to test PE parsing logic without kernel access.
class MockBackend : public hinv::byovd::IByovdBackend {
public:
    bool Initialize(const std::wstring&) override { return true; }
    void Shutdown() override {}
    bool IsReady() const override { return true; }
    bool ReadKernelMemory(uint64_t, void*, size_t) override { return false; }
    bool WriteKernelMemory(uint64_t, const void*, size_t) override { return false; }
};

static std::vector<uint8_t> MakeValidPe() {
    std::vector<uint8_t> pe(0x400, 0);

    // DOS header
    pe[0] = 'M';
    pe[1] = 'Z';
    *reinterpret_cast<uint32_t*>(pe.data() + 0x3C) = 0x80; // e_lfanew

    // NT headers at 0x80
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(pe.data() + 0x80);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.NumberOfSections = 1;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt->OptionalHeader.SizeOfImage = 0x2000;
    nt->OptionalHeader.SizeOfHeaders = 0x200;
    nt->OptionalHeader.ImageBase = 0x10000;

    // Section table
    auto* sec = reinterpret_cast<IMAGE_SECTION_HEADER*>(pe.data() + 0x80 + 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64));
    std::memcpy(sec->Name, ".text", 5);
    sec->VirtualAddress = 0x1000;
    sec->Misc.VirtualSize = 0x100;
    sec->PointerToRawData = 0x200;
    sec->SizeOfRawData = 0x100;

    return pe;
}

int main() {
    MockBackend backend;

    // Test 1: valid PE should be accepted by MapDriverBytes (will fail at allocation, but not at parsing).
    auto validPe = MakeValidPe();
    auto result = hinv::mapper::MapDriverBytes(&backend, validPe);
    std::cout << "[TEST] Valid PE: error=" << result.error << "\n";

    // Test 2: empty input must fail safely.
    result = hinv::mapper::MapDriverBytes(&backend, {});
    assert(!result.success && result.error == "invalid arguments");
    std::cout << "[TEST] Empty input: rejected\n";

    // Test 3: too small input must fail safely.
    result = hinv::mapper::MapDriverBytes(&backend, { 0x4D, 0x5A });
    assert(!result.success && result.error == "invalid DOS signature");
    std::cout << "[TEST] Tiny input: rejected\n";

    // Test 4: bad e_lfanew must fail safely.
    auto badPe = MakeValidPe();
    *reinterpret_cast<uint32_t*>(badPe.data() + 0x3C) = 0x1000; // out of bounds
    result = hinv::mapper::MapDriverBytes(&backend, badPe);
    assert(!result.success);
    std::cout << "[TEST] Bad e_lfanew: rejected\n";

    // Test 5: bad NT signature must fail safely.
    badPe = MakeValidPe();
    *reinterpret_cast<uint32_t*>(badPe.data() + 0x80) = 0xDEADBEEF;
    result = hinv::mapper::MapDriverBytes(&backend, badPe);
    assert(!result.success && result.error == "invalid NT signature");
    std::cout << "[TEST] Bad NT signature: rejected\n";

    std::cout << "[TEST] All parser safety tests passed\n";
    return 0;
}
