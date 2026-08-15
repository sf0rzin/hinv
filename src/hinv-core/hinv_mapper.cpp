#include "hinv_mapper.hpp"
#include "hinv_kmem.hpp"
#include <fstream>
#include <iostream>
#include <cstring>
#include <cwctype>
#include <algorithm>

namespace hinv {
namespace mapper {

static bool ReadFileBytes(const std::wstring& path, std::vector<uint8_t>& out) {
    std::ifstream file(path.c_str(), std::ios::binary | std::ios::ate);
    if (!file.is_open()) return false;
    auto size = file.tellg();
    file.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(size));
    file.read(reinterpret_cast<char*>(out.data()), size);
    return file.good();
}

// ---------------------------------------------------------------------------
// Resolve a single import name to a kernel virtual address.
// ---------------------------------------------------------------------------

static uint64_t ResolveImport(byovd::IByovdBackend* backend, const std::string& dllName,
                              const std::string& procName, uint16_t ordinal, bool byOrdinal) {
    if (byOrdinal) {
        // Ordinal imports are deliberately unsupported (fail-closed upstream).
        std::cerr << "[hinv::mapper] Unresolved import: " << dllName << "!#" << ordinal
                  << " (ordinal imports unsupported)\n";
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
    // Only AMD64 is supported: anything else would be mapped and executed
    // with the wrong ABI. Also pin the optional header layout we rely on.
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return false;
    if (nt->FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER64)) return false;
    // Directories past NumberOfRvaAndSizes must be treated as absent, and a
    // count larger than the fixed array is malformed.
    if (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return false;
    const uint32_t numDataDirs = nt->OptionalHeader.NumberOfRvaAndSizes;

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
        // Fail-closed: every section's virtual range must fit the image, even
        // uninitialized (BSS) sections that occupy no file bytes.
        if (sec[i].Misc.VirtualSize != 0) {
            if (sec[i].VirtualAddress >= imageSize) return false;
            if (static_cast<uint64_t>(sec[i].VirtualAddress) + sec[i].Misc.VirtualSize > imageSize)
                return false;
        }

        if (sec[i].SizeOfRawData == 0) continue;
        // A section with raw data must point at it; per the PE spec,
        // uninitialized data is marked by SizeOfRawData == 0, so raw size
        // without a raw pointer is malformed.
        if (sec[i].PointerToRawData == 0) return false;
        if (sec[i].PointerToRawData >= raw.size()) return false;
        size_t rawSize = sec[i].SizeOfRawData;
        if (static_cast<uint64_t>(sec[i].PointerToRawData) + rawSize > raw.size()) return false;
        if (sec[i].VirtualAddress >= imageSize) return false;
        if (static_cast<uint64_t>(sec[i].VirtualAddress) + rawSize > imageSize) return false;

        std::memcpy(mapped.data() + sec[i].VirtualAddress,
                    raw.data() + sec[i].PointerToRawData,
                    rawSize);
    }

    // Fix base relocation table.
    const auto& relocDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (numDataDirs > IMAGE_DIRECTORY_ENTRY_BASERELOC &&
        relocDir.VirtualAddress != 0 && relocDir.Size != 0) {
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
    if (numDataDirs > IMAGE_DIRECTORY_ENTRY_IMPORT &&
        importDir.VirtualAddress != 0 && importDir.Size != 0) {
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

// Best-effort counterpart of the function table registration done after
// ProtectKernelMemory. Returns true when removal is CONFIRMED (or there was
// nothing to remove). Callers must not free the image on false: the kernel's
// function table would keep pointing into freed pool.
static bool UnregisterFunctionTable(byovd::IByovdBackend* backend, uint64_t functionTableVa,
                                    uint64_t imageBase) {
    if (!functionTableVa) return true;
    // Builds that still export RtlAddFunctionTable also export its remover.
    if (uint64_t delFn = kmem::ResolveKernelExport(backend, L"ntoskrnl.exe", "RtlDeleteFunctionTable")) {
        uint8_t ok = 0;
        if (!kmem::CallKernelFunction(backend, &ok, delFn, functionTableVa)) return false;
        return ok != 0;
    }
    // 24H2+: registration went straight into PsInvertedFunctionTable.
    return kmem::RemoveInvertedFunctionTableEntry(backend, imageBase);
}

MappingResult MapDriverBytes(byovd::IByovdBackend* backend, const std::vector<uint8_t>& rawImage,
                             bool hijackNullDriverObject) {
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
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        result.error = "unsupported machine type (need AMD64)";
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

    kmem::Trace("mapper: allocate begin");
    uint64_t kernelBase = 0;
    if (!kmem::AllocateKernelMemory(backend, imageSize, kernelBase) || !kernelBase) {
        result.error = "kernel allocation failed";
        return result;
    }
    kmem::Trace("mapper: allocate ok");
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
    kmem::Trace("mapper: image written");

    // Locate DriverEntry RVA.
    uint32_t entryRva = nt->OptionalHeader.AddressOfEntryPoint;

    // Pool memory is NX since Windows 8; flip the whole image to RWX before
    // calling into it (kdmapper applies per-section protections the same way,
    // via MmSetPageProtection). Companion kernel DLLs need this too: their
    // code runs when a chain-mapped driver calls their exports.
    kmem::Trace("mapper: protect begin");
    if (!kmem::ProtectKernelMemory(backend, kernelBase, imageSize, PAGE_EXECUTE_READWRITE)) {
        result.error = "failed to make mapped image executable";
        result.imageBase = kernelBase;
        kmem::FreeKernelMemory(backend, kernelBase);
        return result;
    }
    kmem::Trace("mapper: protect ok");

    // Register the exception directory (.pdata) as a dynamic function table.
    // RtlLookupFunctionEntry only walks PsLoadedModuleList plus registered
    // dynamic tables — a manually mapped image is in neither, so ANY exception
    // inside it would blow past its SEH handlers and bugcheck. (That is what
    // turned HyperDbg's SEH-guarded MSR scan into KMODE_EXCEPTION_NOT_HANDLED.)
    uint64_t functionTableVa = 0;
    uint32_t functionTableCount = 0;
    const uint32_t numDataDirs = nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_NUMBEROF_DIRECTORY_ENTRIES
                                     ? nt->OptionalHeader.NumberOfRvaAndSizes
                                     : IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    const auto& excDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (numDataDirs > IMAGE_DIRECTORY_ENTRY_EXCEPTION && excDir.VirtualAddress != 0 && excDir.Size != 0) {
        // A declared-but-out-of-bounds .pdata is a malformed PE, not "no SEH":
        // silently skipping registration would recreate the exact bugcheck
        // scenario this block exists to prevent. Fail closed.
        if (static_cast<uint64_t>(excDir.VirtualAddress) + excDir.Size > imageSize) {
            result.error = "exception directory out of bounds";
            result.imageBase = kernelBase;
            kmem::FreeKernelMemory(backend, kernelBase);
            return result;
        }
        functionTableVa = kernelBase + excDir.VirtualAddress;
        functionTableCount = excDir.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
        uint64_t addFn = kmem::ResolveKernelExport(backend, L"ntoskrnl.exe", "RtlAddFunctionTable");
        if (addFn) {
            // Official path (present up to Win11 23H2).
            // Kernel RtlAddFunctionTable(FunctionTable, EntryCount, Base, End).
            uint8_t ok = 0;
            if (!kmem::CallKernelFunction(backend, &ok, addFn, functionTableVa,
                                          static_cast<uint64_t>(functionTableCount),
                                          kernelBase, kernelBase + imageSize) || !ok) {
                result.error = "RtlAddFunctionTable failed";
                result.imageBase = kernelBase;
                kmem::FreeKernelMemory(backend, kernelBase);
                return result;
            }
            kmem::Trace("mapper: function table registered");
        } else {
            // Win11 24H2 removed RtlAddFunctionTable: insert into
            // PsInvertedFunctionTable directly. Fail closed either way — an
            // image with SEH but no registered table bugchecks on the first
            // exception (HyperDbg's MSR scan proved it twice).
            if (!kmem::InsertInvertedFunctionTableEntry(backend, functionTableVa, kernelBase,
                                                        imageSize, excDir.Size)) {
                result.error = "function table registration failed (no RtlAddFunctionTable, inverted-table insert failed)";
                result.imageBase = kernelBase;
                kmem::FreeKernelMemory(backend, kernelBase);
                return result;
            }
            std::cout << "[hinv::mapper] Registered .pdata via PsInvertedFunctionTable (24H2 path)\n";
            kmem::Trace("mapper: function table registered (inverted)");
        }
    }

    // Kernel-mode DLLs (e.g. HyperDbg companions hyperlog.dll / hyperhv.dll)
    // have no entry point: the loader's job ends at mapping. Calling base+0
    // would execute the DOS header as code, so skip DriverEntry entirely.
    // Their exports are consumed by chain-mapped drivers via the registry.
    if (entryRva == 0) {
        kmem::Trace("mapper: no entry point (kernel DLL), skipping DriverEntry");
        result.imageBase = kernelBase;
        result.driverEntryStatus = 0;
        result.imageSize = imageSize;
        result.success = true;
        return result;
    }
    uint64_t driverEntryVa = kernelBase + entryRva;

    // DriverEntry's first argument: either the real DRIVER_OBJECT of
    // \Driver\Null (hijack mode, for drivers that call IoCreateDevice) or a
    // minimal synthetic object in kernel pool.
    uint64_t drvObj = 0;
    bool borrowedObj = false;
    uint64_t savedUnload = 0;
    uint64_t savedDispatch[28]{}; // MajorFunction[0..27]
    if (hijackNullDriverObject) {
        kmem::Trace("mapper: null drvobj resolve begin");
        HANDLE hNul = CreateFileW(L"\\\\.\\Nul", GENERIC_READ,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hNul != INVALID_HANDLE_VALUE) {
            drvObj = kmem::GetDriverObjectFromHandle(backend, hNul);
            CloseHandle(hNul);
        }
        if (!drvObj) {
            result.error = "failed to obtain \\Driver\\Null DRIVER_OBJECT";
            result.imageBase = kernelBase;
            if (UnregisterFunctionTable(backend, functionTableVa, kernelBase)) {
                kmem::FreeKernelMemory(backend, kernelBase);
                result.imageBase = 0;
            } else {
                std::cerr << "[hinv::mapper] Function table removal unconfirmed; image left resident\n";
            }
            return result;
        }
        borrowedObj = true;
        // Back up null.sys's DriverUnload and entire MajorFunction table before
        // DriverEntry overwrites them. If the entry point fails, we restore
        // null.sys first and only then free the image — otherwise the null
        // driver's IRP dispatch would point into freed pool (kernel UAF).
        bool backupOk = kmem::ReadU64(backend, drvObj + 0x68, savedUnload); // DriverUnload
        for (int i = 0; backupOk && i < 28; ++i)
            backupOk = kmem::ReadU64(backend, drvObj + 0x70 + i * 8, savedDispatch[i]);
        if (!backupOk) {
            result.error = "failed to back up \\Driver\\Null dispatch table";
            result.imageBase = kernelBase;
            if (UnregisterFunctionTable(backend, functionTableVa, kernelBase)) {
                kmem::FreeKernelMemory(backend, kernelBase);
                result.imageBase = 0;
            } else {
                std::cerr << "[hinv::mapper] Function table removal unconfirmed; image left resident\n";
            }
            return result;
        }
        std::cout << "[hinv::mapper] Borrowing \\Driver\\Null DRIVER_OBJECT at 0x"
                  << std::hex << drvObj << std::dec << "\n";
        kmem::Trace("mapper: null drvobj ok");
    } else {
        // Minimal synthetic DRIVER_OBJECT in kernel pool (no \Driver\Null
        // hijack): only DriverStart/DriverSize are populated.
        // DRIVER_OBJECT (x64): DriverStart @ 0x18, DriverSize @ 0x20.
        kmem::Trace("mapper: drvobj alloc begin");
        constexpr size_t DRV_OBJ_SIZE = 0x200;
        if (!kmem::AllocateKernelMemory(backend, DRV_OBJ_SIZE, drvObj) || !drvObj) {
            result.error = "failed to allocate synthetic DRIVER_OBJECT";
            result.imageBase = kernelBase;
            if (UnregisterFunctionTable(backend, functionTableVa, kernelBase)) {
                kmem::FreeKernelMemory(backend, kernelBase);
                result.imageBase = 0;
            } else {
                std::cerr << "[hinv::mapper] Function table removal unconfirmed; image left resident\n";
            }
            return result;
        }
        std::vector<uint8_t> zeros(DRV_OBJ_SIZE, 0);
        if (!backend->WriteKernelMemory(drvObj, zeros.data(), zeros.size()) ||
            !kmem::WriteU64(backend, drvObj + 0x18, kernelBase) ||
            !kmem::WriteU32(backend, drvObj + 0x20, imageSize)) {
            result.error = "failed to initialize synthetic DRIVER_OBJECT";
            result.imageBase = kernelBase;
            if (UnregisterFunctionTable(backend, functionTableVa, kernelBase)) {
                kmem::FreeKernelMemory(backend, drvObj);
                kmem::FreeKernelMemory(backend, kernelBase);
                result.imageBase = 0;
            } else {
                std::cerr << "[hinv::mapper] Function table removal unconfirmed; image left resident\n";
            }
            return result;
        }
    }

    // Call DriverEntry(DriverObject, RegistryPath = NULL).
    kmem::Trace("mapper: driverentry call begin");
    uint32_t status = kmem::CallDriverEntry(backend, driverEntryVa, drvObj, 0);
    kmem::Trace("mapper: driverentry returned");
    std::cout << "[hinv::mapper] DriverEntry returned 0x" << std::hex << status << std::dec << "\n";

    result.imageBase = kernelBase;
    result.driverEntryStatus = status;
    result.imageSize = imageSize;

    result.success = (status == 0); // STATUS_SUCCESS
    if (!result.success) {
        result.error = "DriverEntry returned failure";
        // Once DriverEntry ran, the driver may already have created devices and
        // installed handlers pointing into this image, and there is NO real
        // rundown for IRPs potentially in flight — so on entry failure we keep
        // BOTH the image and the DRIVER_OBJECT resident. A pool leak on the
        // failure path beats a use-after-free.
        if (borrowedObj) {
            // Restore null.sys's dispatch table, with every write checked. Even
            // with a perfect restore, an IRP may still be executing a handler
            // from this image right now — another reason nothing is freed here.
            bool restoreOk = true;
            for (int i = 0; i < 28; ++i)
                restoreOk = kmem::WriteU64(backend, drvObj + 0x70 + i * 8, savedDispatch[i]) && restoreOk;
            restoreOk = kmem::WriteU64(backend, drvObj + 0x68, savedUnload) && restoreOk;
            kmem::Trace(restoreOk ? "mapper: null dispatch restored after failure"
                                  : "mapper: null dispatch restore INCOMPLETE");
            if (!restoreOk)
                std::cerr << "[hinv::mapper] WARNING: null.sys dispatch restore failed\n";
        }
        std::cerr << "[hinv::mapper] DriverEntry failed; image left resident to avoid UAF\n";
        return result;
    }

    // On success the driver is resident, so its DRIVER_OBJECT must stay too:
    // a driver that called IoCreateDevice has DeviceObject->DriverObject
    // pointing here, and the I/O manager dereferences MajorFunction through
    // it on every IRP. Freeing it would be a kernel use-after-free on the
    // first IOCTL. Deliberate 0x200-byte pool leak per mapped driver
    // (a borrowed null.sys object needs no cleanup by definition).
    result.driverObject = drvObj;

    // Replicate IopLoadDriver: devices created in DriverEntry come out of
    // IoCreateDevice with DO_DEVICE_INITIALIZING set, and the normal loader
    // clears it after a successful entry. We ARE the loader, so clear it
    // ourselves — otherwise IopParseDevice rejects every open with
    // STATUS_DEVICE_NOT_CONNECTED (this is why HyperDbg's device refused
    // CreateFile with Win32 error 433).
    {
        uint64_t dev = 0;
        if (kmem::ReadU64(backend, drvObj + 0x8, dev)) { // DRIVER_OBJECT.DeviceObject
            for (int n = 0; dev && n < 16; ++n) {
                uint32_t flags = 0;
                if (kmem::ReadU32(backend, dev + 0x30, flags) && (flags & 0x80)) {
                    if (kmem::WriteU32(backend, dev + 0x30, flags & ~0x80u)) {
                        std::cout << "[hinv::mapper] Cleared DO_DEVICE_INITIALIZING on device 0x"
                                  << std::hex << dev << std::dec << "\n";
                    } else {
                        // Without this clear the device rejects every open with
                        // STATUS_DEVICE_NOT_CONNECTED — never claim otherwise.
                        std::cerr << "[hinv::mapper] WARNING: failed to clear DO_DEVICE_INITIALIZING on device 0x"
                                  << std::hex << dev << std::dec << " — opens will fail with 433\n";
                    }
                }
                if (!kmem::ReadU64(backend, dev + 0x10, dev)) break; // DEVICE_OBJECT.NextDevice
            }
        }
    }
    kmem::Trace("mapper: drvobj kept resident");
    return result;
}

MappingResult MapDriver(byovd::IByovdBackend* backend, const std::wstring& driverPath,
                        bool hijackNullDriverObject) {
    std::vector<uint8_t> raw;
    if (!ReadFileBytes(driverPath, raw)) {
        MappingResult r{};
        r.error = "failed to read driver file";
        return r;
    }
    auto result = MapDriverBytes(backend, raw, hijackNullDriverObject);
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
