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
// Fail-closed: any malformed structure causes the whole build to fail.
// ---------------------------------------------------------------------------

bool BuildMappedImage(byovd::IByovdBackend* backend, const std::vector<uint8_t>& raw,
                      uint64_t imageBase, std::vector<uint8_t>& mapped) {
    if (raw.size() < sizeof(IMAGE_DOS_HEADER)) return false;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(raw.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    // Validate e_lfanew before dereferencing the NT header. e_lfanew is a
    // signed LONG: compare in the signed 64-bit domain so a negative value
    // cannot wrap past the bounds checks into a read before the buffer.
    const int64_t ntHeaderOffset = static_cast<int64_t>(dos->e_lfanew);
    if (ntHeaderOffset < static_cast<int64_t>(sizeof(IMAGE_DOS_HEADER)) ||
        ntHeaderOffset + static_cast<int64_t>(sizeof(IMAGE_NT_HEADERS64)) > static_cast<int64_t>(raw.size()))
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
    uint64_t sectionTableEnd = dos->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader
                               + nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    if (sectionTableEnd > raw.size()) return false;

    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (sec[i].PointerToRawData == 0 || sec[i].SizeOfRawData == 0) continue;

        // Fail-closed: a section claiming data outside the file or the image
        // is malformed — reject it instead of skipping or truncating.
        if (sec[i].VirtualAddress >= imageSize) return false;
        if (sec[i].PointerToRawData >= raw.size()) return false;
        size_t rawSize = sec[i].SizeOfRawData;
        if (static_cast<uint64_t>(sec[i].PointerToRawData) + rawSize > raw.size()) return false;
        if (static_cast<uint64_t>(sec[i].VirtualAddress) + rawSize > imageSize) return false;

        std::memcpy(mapped.data() + sec[i].VirtualAddress,
                    raw.data() + sec[i].PointerToRawData,
                    rawSize);
    }

    // Fix base relocation table.
    const auto& relocDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir.VirtualAddress != 0 && relocDir.Size != 0) {
        // Use 64-bit arithmetic: the directory RVA + size can overflow 32 bits.
        if (static_cast<uint64_t>(relocDir.VirtualAddress) + relocDir.Size > imageSize) return false;
        uint64_t delta = imageBase - preferredBase;
        uint32_t relocOffset = 0;
        while (relocOffset < relocDir.Size) {
            if (static_cast<uint64_t>(relocDir.VirtualAddress) + relocOffset + sizeof(IMAGE_BASE_RELOCATION) > imageSize)
                return false;
            auto* block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(mapped.data() + relocDir.VirtualAddress + relocOffset);
            uint32_t pageRva = block->VirtualAddress;
            uint32_t blockSize = block->SizeOfBlock;
            if (blockSize < sizeof(IMAGE_BASE_RELOCATION) || blockSize > relocDir.Size - relocOffset) return false;
            if (pageRva >= imageSize) return false;

            uint32_t numEntries = (blockSize - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
            auto* entries = reinterpret_cast<uint16_t*>(reinterpret_cast<uint8_t*>(block) + sizeof(IMAGE_BASE_RELOCATION));
            for (uint32_t j = 0; j < numEntries; ++j) {
                uint16_t type = (entries[j] >> 12) & 0xF;
                uint16_t offset = entries[j] & 0xFFF;
                uint64_t entryRva = static_cast<uint64_t>(pageRva) + offset;
                if (entryRva >= imageSize) return false;
                uint8_t* addr = mapped.data() + entryRva;
                switch (type) {
                    case IMAGE_REL_BASED_ABSOLUTE:
                        break; // padding entry, nothing to do
                    case IMAGE_REL_BASED_HIGHLOW:
                        if (entryRva + sizeof(uint32_t) > imageSize) return false;
                        *reinterpret_cast<uint32_t*>(addr) += static_cast<uint32_t>(delta);
                        break;
                    case IMAGE_REL_BASED_DIR64:
                        if (entryRva + sizeof(uint64_t) > imageSize) return false;
                        *reinterpret_cast<uint64_t*>(addr) += delta;
                        break;
                    case IMAGE_REL_BASED_HIGH:
                        if (entryRva + sizeof(uint16_t) > imageSize) return false;
                        *reinterpret_cast<uint16_t*>(addr) += static_cast<uint16_t>(delta >> 16);
                        break;
                    case IMAGE_REL_BASED_LOW:
                        if (entryRva + sizeof(uint16_t) > imageSize) return false;
                        *reinterpret_cast<uint16_t*>(addr) += static_cast<uint16_t>(delta);
                        break;
                    default:
                        return false; // unknown relocation type: reject fail-closed
                }
            }
            relocOffset += blockSize;
        }
    }

    // Resolve imports.
    const auto& importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress != 0 && importDir.Size != 0) {
        if (importDir.VirtualAddress >= imageSize) return false;
        size_t guard = 0;
        for (size_t descIdx = 0; ; ++descIdx) {
            if (guard++ >= 4096) return false;
            // Bounds-check EVERY descriptor before dereferencing it.
            uint64_t descOff = static_cast<uint64_t>(importDir.VirtualAddress) + descIdx * sizeof(IMAGE_IMPORT_DESCRIPTOR);
            if (descOff + sizeof(IMAGE_IMPORT_DESCRIPTOR) > imageSize) return false;
            auto* importDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(mapped.data() + descOff);
            if (importDesc->Name == 0) break; // end of the descriptor array

            if (importDesc->Name >= imageSize) return false;
            const char* dllNamePtr = reinterpret_cast<const char*>(mapped.data() + importDesc->Name);
            size_t dllMaxLen = imageSize - importDesc->Name;
            size_t dllNameLen = strnlen(dllNamePtr, dllMaxLen);
            if (dllNameLen == dllMaxLen) return false; // not NUL-terminated within the image
            std::string dllName(dllNamePtr, dllNameLen);

            uint32_t lookupRva = importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk;
            if (lookupRva >= imageSize || importDesc->FirstThunk >= imageSize) return false;

            size_t thunkGuard = 0;
            for (size_t idx = 0; ; ++idx) {
                if (thunkGuard++ >= 8192) return false;
                // Require the FULL 8-byte thunk to be in bounds, not just its start.
                uint64_t lookupOff = static_cast<uint64_t>(lookupRva) + idx * sizeof(IMAGE_THUNK_DATA64);
                uint64_t firstOff = static_cast<uint64_t>(importDesc->FirstThunk) + idx * sizeof(IMAGE_THUNK_DATA64);
                if (lookupOff + sizeof(IMAGE_THUNK_DATA64) > imageSize ||
                    firstOff + sizeof(IMAGE_THUNK_DATA64) > imageSize) return false;
                auto* lookupThunk = reinterpret_cast<IMAGE_THUNK_DATA64*>(mapped.data() + lookupOff);
                auto* firstThunk = reinterpret_cast<IMAGE_THUNK_DATA64*>(mapped.data() + firstOff);
                uint64_t thunkValue = lookupThunk->u1.AddressOfData;
                if (thunkValue == 0) break; // end of the thunk array

                bool byOrdinal = (thunkValue & IMAGE_ORDINAL_FLAG64) != 0;
                uint16_t ordinal = byOrdinal ? static_cast<uint16_t>(thunkValue & 0xFFFF) : 0;
                std::string procName;
                if (!byOrdinal) {
                    if (thunkValue >= imageSize) return false;
                    if (imageSize - thunkValue < sizeof(uint16_t) + 1) return false;
                    size_t maxLen = imageSize - thunkValue - sizeof(uint16_t);
                    const auto* importByName = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(mapped.data() + thunkValue);
                    const char* namePtr = reinterpret_cast<const char*>(importByName->Name);
                    size_t nameLen = strnlen(namePtr, maxLen);
                    if (nameLen == maxLen) return false; // name runs past the image
                    procName.assign(namePtr, nameLen);
                }

                uint64_t resolved = ResolveImport(backend, dllName, procName, ordinal, byOrdinal);
                if (resolved == 0) {
                    std::cerr << "[hinv::mapper] Unresolved import: " << dllName << "!" << procName << "\n";
                    return false;
                }
                firstThunk->u1.Function = resolved;
            }
        }
    }

    return true;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

MappingResult MapDriverBytes(byovd::IByovdBackend* backend, const std::vector<uint8_t>& rawImage) {
    MappingResult result{};
    if (!backend || rawImage.size() < sizeof(IMAGE_DOS_HEADER)) {
        result.error = "invalid arguments";
        return result;
    }

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(rawImage.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        result.error = "invalid DOS signature";
        return result;
    }
    // e_lfanew is a signed LONG; validate in the signed 64-bit domain (as in
    // BuildMappedImage) so a negative value cannot wrap past the checks.
    const int64_t ntHeaderOffset = static_cast<int64_t>(dos->e_lfanew);
    if (ntHeaderOffset < static_cast<int64_t>(sizeof(IMAGE_DOS_HEADER)) ||
        ntHeaderOffset + static_cast<int64_t>(sizeof(IMAGE_NT_HEADERS64)) > static_cast<int64_t>(rawImage.size())) {
        result.error = "invalid e_lfanew";
        return result;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(rawImage.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        result.error = "invalid NT signature";
        return result;
    }
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        result.error = "not a PE32+ image";
        return result;
    }

    uint32_t imageSize = nt->OptionalHeader.SizeOfImage;
    if (imageSize == 0 || imageSize > 0x20000000) {
        result.error = "invalid SizeOfImage";
        return result;
    }
    if (nt->OptionalHeader.AddressOfEntryPoint >= imageSize) {
        result.error = "AddressOfEntryPoint out of bounds";
        return result;
    }
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
        kmem::DereferenceObject(backend, nullObject);
        kmem::FreeKernelMemory(backend, kernelBase);
        return result;
    }
    bool startWritten = false;
    bool sizeWritten = false;
    if (kmem::WriteU64(backend, nullObject + OFF_DRIVER_START, kernelBase)) {
        startWritten = true;
    }
    if (kmem::WriteU32(backend, nullObject + OFF_DRIVER_SIZE, imageSize)) {
        sizeWritten = true;
    }

    if (!startWritten || !sizeWritten) {
        result.error = "failed to patch DriverObject fields";
        result.imageBase = kernelBase;
        // Restore whatever was written. If a restore fails the object still
        // references our pool, so the pool must NOT be freed.
        bool rollbackOk = true;
        if (startWritten && !kmem::WriteU64(backend, nullObject + OFF_DRIVER_START, origStart)) rollbackOk = false;
        if (sizeWritten && !kmem::WriteU32(backend, nullObject + OFF_DRIVER_SIZE, origSize)) rollbackOk = false;
        if (!rollbackOk) result.error += "; rollback failed, mapped pool left allocated to avoid dangling pointers";
        kmem::DereferenceObject(backend, nullObject);
        if (rollbackOk) {
            kmem::FreeKernelMemory(backend, kernelBase);
            result.imageBase = 0;
        }
        return result;
    }

    // Call DriverEntry(DriverObject, RegistryPath = NULL).
    uint32_t status = kmem::CallDriverEntry(backend, driverEntryVa, nullObject, 0);
    std::cout << "[hinv::mapper] DriverEntry returned 0x" << std::hex << status << std::dec << "\n";

    // Restore original fields to keep \\Driver\\Null consistent. Restore
    // failures are real failures: while the object still points at our pool,
    // freeing the pool would leave a dangling kernel pointer.
    bool restoreStartOk = kmem::WriteU64(backend, nullObject + OFF_DRIVER_START, origStart);
    bool restoreSizeOk = kmem::WriteU32(backend, nullObject + OFF_DRIVER_SIZE, origSize);
    bool restored = restoreStartOk && restoreSizeOk;

    // Drop the reference we took with ObReferenceObjectByName.
    kmem::DereferenceObject(backend, nullObject);

    result.imageBase = kernelBase;
    result.driverObject = nullObject;
    result.driverEntryStatus = status;
    result.imageSize = imageSize;

    if (!restored) {
        result.success = false;
        result.error = "failed to restore \\Driver\\Null DriverObject; mapped pool left allocated to avoid dangling pointers";
        return result;
    }

    result.success = (status == 0); // STATUS_SUCCESS
    if (!result.success) {
        result.error = "DriverEntry returned failure";
        // On failure, free the mapped image to avoid leaking pool memory.
        kmem::FreeKernelMemory(backend, kernelBase);
        result.imageBase = 0;
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
    auto result = MapDriverBytes(backend, raw);
    if (result.success) {
        // Register the mapped module so later chain-mapped modules can resolve
        // imports from it (it is invisible to EnumKernelModules).
        size_t pos = driverPath.find_last_of(L"\\/");
        std::wstring fileName = (pos == std::wstring::npos) ? driverPath : driverPath.substr(pos + 1);
        kmem::RegisterMappedModule(fileName, result.imageBase, result.imageSize);
        std::wcout << L"[hinv::mapper] Registered mapped module " << fileName << L" at 0x"
                   << std::hex << result.imageBase << std::dec << L"\n";
    }
    return result;
}

} // namespace mapper
} // namespace hinv
