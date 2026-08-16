#include "hinv_mapper.hpp"
#include "hinv_kmem.hpp"
#include <fstream>
#include <iostream>
#include <cstring>
#include <cwctype>
#include <algorithm>
#include <array>
#include <limits>
#include <exception>

namespace hinv {
namespace mapper {

bool ReadDriverFileBytes(const std::wstring& path, std::vector<uint8_t>& out) {
    std::ifstream file(path.c_str(), std::ios::binary | std::ios::ate);
    if (!file.is_open()) return false;
    auto size = file.tellg();
    if (size < 0 || static_cast<uint64_t>(size) > 0x40000000ULL ||
        static_cast<uint64_t>(size) > std::numeric_limits<size_t>::max())
        return false;
    file.seekg(0, std::ios::beg);
    try {
        out.resize(static_cast<size_t>(size));
    } catch (...) {
        return false;
    }
    if (size == 0) return true;
    file.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(size));
    return file.gcount() == static_cast<std::streamsize>(size);
}

static bool RangeWithin(uint64_t offset, uint64_t size, uint64_t limit) {
    return offset <= limit && size <= limit - offset;
}

static bool HasExecutableEntryPoint(const IMAGE_NT_HEADERS64* nt, const std::vector<uint8_t>& raw) {
    if (!nt || raw.empty()) return false;
    const uint32_t entryRva = nt->OptionalHeader.AddressOfEntryPoint;
    if (entryRva == 0) return true; // explicitly supported kernel DLL path

    const auto ntOffset = reinterpret_cast<const uint8_t*>(nt) - raw.data();
    if (ntOffset < static_cast<ptrdiff_t>(sizeof(IMAGE_DOS_HEADER))) return false;
    const uint64_t sectionTableOffset = 4 + sizeof(IMAGE_FILE_HEADER) +
                                        nt->FileHeader.SizeOfOptionalHeader;
    if (!RangeWithin(static_cast<uint64_t>(ntOffset), sectionTableOffset, raw.size())) return false;
    const uint64_t sectionTable = static_cast<uint64_t>(ntOffset) + sectionTableOffset;
    const uint64_t sectionBytes = static_cast<uint64_t>(nt->FileHeader.NumberOfSections) *
                                  sizeof(IMAGE_SECTION_HEADER);
    if (!RangeWithin(sectionTable, sectionBytes, raw.size())) return false;

    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER section{};
        std::memcpy(&section, raw.data() + sectionTable +
                    static_cast<uint64_t>(i) * sizeof(section), sizeof(section));
        if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0 ||
            entryRva < section.VirtualAddress)
            continue;

        const uint64_t sectionOffset = static_cast<uint64_t>(entryRva) - section.VirtualAddress;
        if (sectionOffset < section.SizeOfRawData && section.PointerToRawData != 0 &&
            RangeWithin(section.VirtualAddress, section.SizeOfRawData,
                        nt->OptionalHeader.SizeOfImage) &&
            RangeWithin(section.PointerToRawData, section.SizeOfRawData, raw.size()))
            return true;
    }
    return false;
}

static bool HasValidRuntimeBounds(const IMAGE_RUNTIME_FUNCTION_ENTRY& entry,
                                  uint32_t imageSize) {
    return entry.BeginAddress < entry.EndAddress && entry.EndAddress <= imageSize &&
           entry.UnwindInfoAddress != 0 && entry.UnwindInfoAddress < imageSize;
}

static bool ValidateUnwindInfo(const std::vector<uint8_t>& mapped, uint32_t imageSize,
                               uint32_t unwindInfoRva) {
    constexpr uint8_t kSupportedVersion = 1;
    constexpr uint8_t kExceptionHandler = 0x1;
    constexpr uint8_t kUnwindHandler = 0x2;
    constexpr uint8_t kChainInfo = 0x4;
    constexpr uint8_t kSupportedFlags = kExceptionHandler | kUnwindHandler | kChainInfo;
    constexpr uint64_t kHeaderSize = 4;
    constexpr size_t kMaxChainDepth = 256;
    std::array<uint32_t, kMaxChainDepth> visited{};
    size_t visitedCount = 0;

    for (;;) {
        if ((unwindInfoRva & 3) != 0 || visitedCount == visited.size()) return false;
        for (size_t i = 0; i < visitedCount; ++i) {
            if (visited[i] == unwindInfoRva) return false;
        }
        visited[visitedCount++] = unwindInfoRva;

        if (!RangeWithin(unwindInfoRva, kHeaderSize, imageSize)) return false;
        uint8_t header[kHeaderSize]{};
        std::memcpy(header, mapped.data() + unwindInfoRva, sizeof(header));

        const uint8_t version = header[0] & 0x7;
        const uint8_t flags = header[0] >> 3;
        if (version != kSupportedVersion || (flags & ~kSupportedFlags) != 0 ||
            ((flags & kChainInfo) != 0 &&
             (flags & (kExceptionHandler | kUnwindHandler)) != 0))
            return false;

        const uint8_t prologSize = header[1];
        const uint8_t codeCount = header[2];
        const uint64_t alignedCodeSlots =
            (static_cast<uint64_t>(header[2]) + 1) & ~uint64_t{1};
        const uint64_t codeBytes = alignedCodeSlots * 2;
        const uint64_t codeRva = static_cast<uint64_t>(unwindInfoRva) + kHeaderSize;
        if (!RangeWithin(codeRva, codeBytes, imageSize)) return false;
        const uint64_t trailingDataRva = codeRva + codeBytes;

        // Decode every UNWIND_CODE, including the extra slots consumed by
        // large allocations and far saves. Bounds-checking only the byte
        // array lets a malformed opcode make the kernel unwinder consume the
        // next structure as an immediate value.
        constexpr uint8_t kUwopPushNonvol = 0;
        constexpr uint8_t kUwopAllocLarge = 1;
        constexpr uint8_t kUwopAllocSmall = 2;
        constexpr uint8_t kUwopSetFpReg = 3;
        constexpr uint8_t kUwopSaveNonvol = 4;
        constexpr uint8_t kUwopSaveNonvolFar = 5;
        constexpr uint8_t kUwopSaveXmm128 = 8;
        constexpr uint8_t kUwopSaveXmm128Far = 9;
        constexpr uint8_t kUwopPushMachframe = 10;
        uint8_t previousCodeOffset = 0xFF;
        for (uint32_t slot = 0; slot < codeCount;) {
            const uint64_t slotRva = codeRva + static_cast<uint64_t>(slot) * 2;
            if (!RangeWithin(slotRva, 2, imageSize)) return false;
            const uint8_t codeOffset = mapped[slotRva];
            const uint8_t opInfoByte = mapped[slotRva + 1];
            const uint8_t unwindOp = opInfoByte & 0x0F;
            const uint8_t opInfo = opInfoByte >> 4;
            if (codeOffset > prologSize || codeOffset > previousCodeOffset)
                return false;
            previousCodeOffset = codeOffset;

            uint32_t slotsUsed = 1;
            switch (unwindOp) {
                case kUwopPushNonvol:
                    break;
                case kUwopAllocLarge:
                    if (opInfo == 0) slotsUsed = 2;
                    else if (opInfo == 1) slotsUsed = 3;
                    else return false;
                    break;
                case kUwopAllocSmall:
                    break;
                case kUwopSetFpReg:
                    if (opInfo != 0) return false;
                    break;
                case kUwopSaveNonvol:
                    slotsUsed = 2;
                    break;
                case kUwopSaveNonvolFar:
                    slotsUsed = 3;
                    break;
                case kUwopSaveXmm128:
                    slotsUsed = 2;
                    break;
                case kUwopSaveXmm128Far:
                    slotsUsed = 3;
                    break;
                case kUwopPushMachframe:
                    if (opInfo > 1) return false;
                    break;
                default:
                    return false;
            }
            if (slotsUsed > static_cast<uint32_t>(codeCount) - slot)
                return false;
            slot += slotsUsed;
        }

        if ((flags & (kExceptionHandler | kUnwindHandler)) != 0) {
            uint32_t handlerRva = 0;
            if (!RangeWithin(trailingDataRva, sizeof(handlerRva), imageSize)) return false;
            std::memcpy(&handlerRva, mapped.data() + trailingDataRva, sizeof(handlerRva));
            return handlerRva != 0 && handlerRva < imageSize;
        }
        if ((flags & kChainInfo) == 0) return true;

        IMAGE_RUNTIME_FUNCTION_ENTRY chained{};
        if (!RangeWithin(trailingDataRva, sizeof(chained), imageSize)) return false;
        std::memcpy(&chained, mapped.data() + trailingDataRva, sizeof(chained));
        if (!HasValidRuntimeBounds(chained, imageSize)) return false;
        unwindInfoRva = chained.UnwindInfoAddress;
    }
}

static bool ValidateRuntimeFunctionTable(const std::vector<uint8_t>& mapped,
                                         const IMAGE_DATA_DIRECTORY& directory,
                                         uint32_t imageSize) {
    if (directory.VirtualAddress == 0 || directory.Size == 0) return true;
    if (mapped.size() < imageSize || (directory.VirtualAddress & 3) != 0 ||
        !RangeWithin(directory.VirtualAddress, directory.Size, imageSize) ||
        directory.Size % sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY) != 0)
        return false;

    const size_t count = directory.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
    uint32_t previousBegin = 0;
    uint32_t previousEnd = 0;
    for (size_t i = 0; i < count; ++i) {
        IMAGE_RUNTIME_FUNCTION_ENTRY entry{};
        std::memcpy(&entry, mapped.data() + directory.VirtualAddress +
                    i * sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), sizeof(entry));
        if (!HasValidRuntimeBounds(entry, imageSize) ||
            (i != 0 && entry.BeginAddress < previousBegin) ||
            (i != 0 && entry.BeginAddress < previousEnd) ||
            !ValidateUnwindInfo(mapped, imageSize, entry.UnwindInfoAddress))
            return false;
        previousBegin = entry.BeginAddress;
        previousEnd = entry.EndAddress;
    }
    return true;
}

bool ValidateDriverImageBytes(const std::vector<uint8_t>& raw, std::string* error) {
    auto fail = [&](const char* message) {
        if (error) *error = message;
        return false;
    };
    if (error) error->clear();
    if (raw.size() < sizeof(IMAGE_DOS_HEADER)) return fail("invalid DOS header");

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(raw.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return fail("invalid DOS signature");
    const int64_t ntOffset = static_cast<int64_t>(dos->e_lfanew);
    if (ntOffset < static_cast<int64_t>(sizeof(IMAGE_DOS_HEADER)) ||
        ntOffset + static_cast<int64_t>(sizeof(IMAGE_NT_HEADERS64)) >
            static_cast<int64_t>(raw.size()))
        return fail("invalid e_lfanew");

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(raw.data() + ntOffset);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return fail("invalid NT signature");
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return fail("not a PE32+ image");
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        return fail("unsupported machine type (need AMD64)");
    if (nt->FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER64) ||
        nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
        return fail("invalid optional header layout");

    const uint32_t imageSize = nt->OptionalHeader.SizeOfImage;
    if (imageSize == 0 || imageSize > 0x20000000u) return fail("invalid SizeOfImage");
    if (nt->OptionalHeader.AddressOfEntryPoint >= imageSize ||
        !HasExecutableEntryPoint(nt, raw))
        return fail("AddressOfEntryPoint is not in an executable section");
    const uint32_t headersSize = nt->OptionalHeader.SizeOfHeaders;
    if (headersSize == 0 || headersSize > imageSize || headersSize > raw.size())
        return fail("invalid SizeOfHeaders");

    const uint64_t sectionTable = static_cast<uint64_t>(ntOffset) + 4 +
                                  sizeof(IMAGE_FILE_HEADER) +
                                  nt->FileHeader.SizeOfOptionalHeader;
    const uint64_t sectionBytes = static_cast<uint64_t>(nt->FileHeader.NumberOfSections) *
                                  sizeof(IMAGE_SECTION_HEADER);
    if (!RangeWithin(sectionTable, sectionBytes, raw.size()))
        return fail("section table out of bounds");

    std::vector<uint8_t> mapped;
    try {
        mapped.assign(imageSize, 0);
    } catch (...) {
        return fail("image is too large");
    }
    std::memcpy(mapped.data(), raw.data(), headersSize);
    const auto* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(raw.data() + sectionTable);
    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        const auto& section = sections[i];
        if (section.Misc.VirtualSize != 0 &&
            (!RangeWithin(section.VirtualAddress, section.Misc.VirtualSize, imageSize)))
            return fail("section virtual range out of bounds");
        if (section.SizeOfRawData == 0) continue;
        if (section.PointerToRawData == 0 ||
            !RangeWithin(section.PointerToRawData, section.SizeOfRawData, raw.size()) ||
            !RangeWithin(section.VirtualAddress, section.SizeOfRawData, imageSize))
            return fail("section raw range out of bounds");
        std::memcpy(mapped.data() + section.VirtualAddress,
                    raw.data() + section.PointerToRawData, section.SizeOfRawData);
    }

    const auto& reloc = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if ((nt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) != 0 ||
        nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_BASERELOC ||
        reloc.VirtualAddress == 0 || reloc.Size == 0 ||
        !RangeWithin(reloc.VirtualAddress, reloc.Size, imageSize))
        return fail("image has no base relocation table; fixed-base images are unsafe to map");
    for (uint32_t offset = 0; offset < reloc.Size;) {
        if (reloc.Size - offset < sizeof(IMAGE_BASE_RELOCATION))
            return fail("truncated relocation block");
        const auto* block = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(
            mapped.data() + reloc.VirtualAddress + offset);
        if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
            block->SizeOfBlock > reloc.Size - offset ||
            (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) % sizeof(uint16_t) != 0 ||
            block->VirtualAddress >= imageSize)
            return fail("invalid relocation block");
        const uint32_t count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
                               sizeof(uint16_t);
        const auto* entries = reinterpret_cast<const uint16_t*>(
            reinterpret_cast<const uint8_t*>(block) + sizeof(IMAGE_BASE_RELOCATION));
        for (uint32_t i = 0; i < count; ++i) {
            const uint16_t type = entries[i] >> 12;
            const uint32_t rva = block->VirtualAddress + (entries[i] & 0x0FFFu);
            if (type != IMAGE_REL_BASED_ABSOLUTE && type != IMAGE_REL_BASED_DIR64)
                return fail("unsupported relocation type");
            if (type == IMAGE_REL_BASED_DIR64 && !RangeWithin(rva, sizeof(uint64_t), imageSize))
                return fail("relocation target out of bounds");
        }
        offset += block->SizeOfBlock;
    }

    const auto& imports = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT &&
        imports.VirtualAddress != 0 && imports.Size != 0) {
        if (imports.Size < sizeof(IMAGE_IMPORT_DESCRIPTOR) ||
            !RangeWithin(imports.VirtualAddress, imports.Size, imageSize))
            return fail("import directory out of bounds");
        bool terminated = false;
        for (size_t index = 0; index < 4096; ++index) {
            const uint64_t descriptorRva = static_cast<uint64_t>(imports.VirtualAddress) +
                                           index * sizeof(IMAGE_IMPORT_DESCRIPTOR);
            if (descriptorRva + sizeof(IMAGE_IMPORT_DESCRIPTOR) >
                    static_cast<uint64_t>(imports.VirtualAddress) + imports.Size)
                return fail("unterminated import descriptor array");
            IMAGE_IMPORT_DESCRIPTOR descriptor{};
            std::memcpy(&descriptor, mapped.data() + descriptorRva, sizeof(descriptor));
            if (descriptor.Name == 0) {
                terminated = descriptor.OriginalFirstThunk == 0 &&
                            descriptor.FirstThunk == 0 && descriptor.TimeDateStamp == 0 &&
                            descriptor.ForwarderChain == 0;
                if (!terminated) return fail("partially null import terminator");
                break;
            }
            if (descriptor.Name >= imageSize || descriptor.FirstThunk >= imageSize)
                return fail("import descriptor pointer out of bounds");
            const size_t nameMax = imageSize - descriptor.Name;
            if (strnlen(reinterpret_cast<const char*>(mapped.data() + descriptor.Name), nameMax) == nameMax)
                return fail("unterminated import module name");
            const uint32_t lookupRva = descriptor.OriginalFirstThunk
                ? descriptor.OriginalFirstThunk : descriptor.FirstThunk;
            if (lookupRva >= imageSize) return fail("import thunk pointer out of bounds");
            bool thunkTerminated = false;
            for (size_t thunk = 0; thunk < 8192; ++thunk) {
                const uint64_t lookup = static_cast<uint64_t>(lookupRva) +
                                        thunk * sizeof(IMAGE_THUNK_DATA64);
                const uint64_t first = static_cast<uint64_t>(descriptor.FirstThunk) +
                                       thunk * sizeof(IMAGE_THUNK_DATA64);
                if (!RangeWithin(lookup, sizeof(IMAGE_THUNK_DATA64), imageSize) ||
                    !RangeWithin(first, sizeof(IMAGE_THUNK_DATA64), imageSize))
                    return fail("import thunk array out of bounds");
                IMAGE_THUNK_DATA64 value{};
                std::memcpy(&value, mapped.data() + lookup, sizeof(value));
                if (value.u1.AddressOfData == 0) {
                    thunkTerminated = true;
                    break;
                }
                if ((value.u1.Ordinal & IMAGE_ORDINAL_FLAG64) != 0)
                    return fail("ordinal imports are unsupported");
                const uint64_t nameRva = value.u1.AddressOfData;
                if (!RangeWithin(nameRva, sizeof(uint16_t) + 1, imageSize))
                    return fail("import name pointer out of bounds");
                const size_t maxName = imageSize - nameRva - sizeof(uint16_t);
                if (strnlen(reinterpret_cast<const char*>(mapped.data() + nameRva + sizeof(uint16_t)),
                            maxName) == maxName)
                    return fail("unterminated import name");
            }
            if (!thunkTerminated) return fail("unterminated import thunk array");
        }
        if (!terminated) return fail("unterminated import descriptor array");
    }

    if (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXCEPTION &&
        !ValidateRuntimeFunctionTable(
            mapped, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION], imageSize))
        return fail("malformed exception directory");
    return true;
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
    mapped.clear();
    try {
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
    if (!HasExecutableEntryPoint(nt, raw)) return false;
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
            if (blockSize < sizeof(IMAGE_BASE_RELOCATION) ||
                blockSize > relocDir.Size - relocOffset ||
                (blockSize - sizeof(IMAGE_BASE_RELOCATION)) % sizeof(uint16_t) != 0)
                return false;
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
        const uint64_t importEnd = static_cast<uint64_t>(importDir.VirtualAddress) + importDir.Size;
        if (importDir.VirtualAddress >= imageSize || importEnd > imageSize ||
            importDir.Size < sizeof(IMAGE_IMPORT_DESCRIPTOR)) return false;
        size_t guard = 0;
        for (size_t descIdx = 0; ; ++descIdx) {
            if (guard++ >= 4096) return false;
            // Bounds-check EVERY descriptor before dereferencing it.
            uint64_t descOff = static_cast<uint64_t>(importDir.VirtualAddress) + descIdx * sizeof(IMAGE_IMPORT_DESCRIPTOR);
            if (descOff + sizeof(IMAGE_IMPORT_DESCRIPTOR) > importEnd ||
                descOff + sizeof(IMAGE_IMPORT_DESCRIPTOR) > imageSize) return false;
            IMAGE_IMPORT_DESCRIPTOR importDesc{};
            std::memcpy(&importDesc, mapped.data() + descOff, sizeof(importDesc));
            if (importDesc.Name == 0) {
                for (size_t i = 0; i < sizeof(importDesc); ++i) {
                    if (mapped[descOff + i] != 0) return false;
                }
                break;
            }

            if (importDesc.Name >= imageSize) return false;
            const char* dllNamePtr = reinterpret_cast<const char*>(mapped.data() + importDesc.Name);
            size_t dllMaxLen = imageSize - importDesc.Name;
            size_t dllNameLen = strnlen(dllNamePtr, dllMaxLen);
            if (dllNameLen == dllMaxLen) return false; // not NUL-terminated within the image
            std::string dllName(dllNamePtr, dllNameLen);

            uint32_t lookupRva = importDesc.OriginalFirstThunk ? importDesc.OriginalFirstThunk : importDesc.FirstThunk;
            if (lookupRva >= imageSize || importDesc.FirstThunk >= imageSize) return false;

            size_t thunkGuard = 0;
            for (size_t idx = 0; ; ++idx) {
                if (thunkGuard++ >= 8192) return false;
                // Require the FULL 8-byte thunk to be in bounds, not just its start.
                uint64_t lookupOff = static_cast<uint64_t>(lookupRva) + idx * sizeof(IMAGE_THUNK_DATA64);
                uint64_t firstOff = static_cast<uint64_t>(importDesc.FirstThunk) + idx * sizeof(IMAGE_THUNK_DATA64);
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

    if (numDataDirs > IMAGE_DIRECTORY_ENTRY_EXCEPTION &&
        !ValidateRuntimeFunctionTable(
            mapped, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION], imageSize))
        return false;

    return true;
    } catch (const std::exception&) {
        mapped.clear();
        return false;
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// Best-effort counterpart of the function table registration done after
// ProtectKernelMemory. Returns true when removal is CONFIRMED (or there was
// nothing to remove). Callers must not free the image on false: the kernel's
// function table would keep pointing into freed pool.
static kmem::KernelCallStatus UnregisterFunctionTable(byovd::IByovdBackend* backend,
                                                       uint64_t functionTableVa,
                                                       uint64_t imageBase,
                                                       bool registered) {
    if (!registered) return kmem::KernelCallStatus::Executed;
    if (!functionTableVa) return kmem::KernelCallStatus::NotExecuted;
    // Builds that still export RtlAddFunctionTable also export its remover.
    if (uint64_t delFn = kmem::ResolveKernelExport(backend, L"ntoskrnl.exe", "RtlDeleteFunctionTable")) {
        uint8_t ok = 0;
        const auto status = kmem::CallKernelFunction(backend, &ok, delFn, functionTableVa);
        if (status != kmem::KernelCallStatus::Executed) return status;
        return ok != 0 ? kmem::KernelCallStatus::Executed
                       : kmem::KernelCallStatus::RestorationUncertain;
    }
    // 24H2+ has no supported user-mode API in this project. No manual IFT
    // registration is ever marked as successful, so reaching this branch is
    // an invariant violation rather than a license to edit the table.
    (void)imageBase;
    return kmem::KernelCallStatus::RestorationUncertain;
}

static bool ReleaseImageAfterFailure(byovd::IByovdBackend* backend, uint64_t kernelBase,
                                     uint64_t functionTableVa, uint64_t imageBase,
                                     bool functionTableRegistered) {
    const auto unregister = UnregisterFunctionTable(
        backend, functionTableVa, imageBase, functionTableRegistered);
    if (unregister != kmem::KernelCallStatus::Executed) return false;
    return kmem::FreeKernelMemory(backend, kernelBase) == kmem::KernelCallStatus::Executed;
}

static bool NtSuccess(uint32_t status) {
    return static_cast<int32_t>(status) >= 0;
}

MappingResult MapDriverBytes(byovd::IByovdBackend* backend, const std::vector<uint8_t>& rawImage,
                             bool hijackNullDriverObject) {
    MappingResult result{};
    if (!backend || rawImage.size() < sizeof(IMAGE_DOS_HEADER)) {
        result.error = "invalid arguments";
        return result;
    }

    // Keep the byte-oriented entry point safe on its own as well as through
    // MapDriver(). No privileged allocation or write should happen before the
    // complete usermode PE preflight succeeds.
    std::string validationError;
    if (!ValidateDriverImageBytes(rawImage, &validationError)) {
        result.error = validationError.empty() ? "driver preflight failed" : validationError;
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
    if (nt->FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER64) ||
        nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_NUMBEROF_DIRECTORY_ENTRIES) {
        result.error = "invalid optional header layout";
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
    if (!HasExecutableEntryPoint(nt, rawImage)) {
        result.error = "AddressOfEntryPoint is not in an executable section";
        return result;
    }

    const bool hasRelocations =
        nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC &&
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0 &&
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size != 0;
    if (nt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED || !hasRelocations) {
        result.error = "image has no base relocation table; fixed-base images are unsafe to map";
        return result;
    }
    std::cout << "[hinv::mapper] Image size: " << imageSize << " bytes, preferred base: 0x"
              << std::hex << nt->OptionalHeader.ImageBase << std::dec << "\n";

    kmem::Trace("mapper: allocate begin");
    uint64_t kernelBase = 0;
    const auto allocation = kmem::AllocateKernelMemory(backend, imageSize, kernelBase);
    if (allocation != kmem::KernelCallStatus::Executed || !kernelBase) {
        result.error = "kernel allocation failed";
        if (allocation == kmem::KernelCallStatus::RestorationUncertain)
            result.error += " (allocation state uncertain)";
        return result;
    }
    kmem::Trace("mapper: allocate ok");
    std::cout << "[hinv::mapper] Allocated kernel memory at 0x" << std::hex << kernelBase << std::dec << "\n";

    std::vector<uint8_t> mapped;
    if (!BuildMappedImage(backend, rawImage, kernelBase, mapped)) {
        result.error = "failed to build mapped image";
        if (kmem::FreeKernelMemory(backend, kernelBase) != kmem::KernelCallStatus::Executed)
            result.imageBase = kernelBase;
        return result;
    }

    const uint32_t mappedNumDataDirs = nt->OptionalHeader.NumberOfRvaAndSizes;
    if (mappedNumDataDirs > IMAGE_DIRECTORY_ENTRY_EXCEPTION) {
        const auto& mappedExcDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (!ValidateRuntimeFunctionTable(mapped, mappedExcDir, imageSize)) {
            result.error = "malformed exception directory";
            result.imageBase = kernelBase;
            if (kmem::FreeKernelMemory(backend, kernelBase) == kmem::KernelCallStatus::Executed)
                result.imageBase = 0;
            return result;
        }
    }

    // Write prepared image to kernel memory page by page.
    constexpr size_t CHUNK = 0x1000;
    for (size_t off = 0; off < mapped.size(); off += CHUNK) {
        size_t sz = (off + CHUNK > mapped.size()) ? (mapped.size() - off) : CHUNK;
        if (!backend->WriteKernelMemory(kernelBase + off, mapped.data() + off, sz)) {
            result.error = "kernel write failed at offset " + std::to_string(off);
            result.imageBase = kernelBase;
            if (kmem::FreeKernelMemory(backend, kernelBase) == kmem::KernelCallStatus::Executed)
                result.imageBase = 0;
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
    bool protectedImage = false;
    const auto protectStatus = kmem::ProtectKernelMemory(
        backend, kernelBase, imageSize, PAGE_EXECUTE_READWRITE, &protectedImage);
    if (protectStatus != kmem::KernelCallStatus::Executed || !protectedImage) {
        result.error = "failed to make mapped image executable";
        result.imageBase = kernelBase;
        if (protectStatus != kmem::KernelCallStatus::RestorationUncertain &&
            kmem::FreeKernelMemory(backend, kernelBase) == kmem::KernelCallStatus::Executed)
            result.imageBase = 0;
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
    bool functionTableRegistered = false;
    const uint32_t numDataDirs = nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_NUMBEROF_DIRECTORY_ENTRIES
                                     ? nt->OptionalHeader.NumberOfRvaAndSizes
                                     : IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    const auto& excDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (numDataDirs > IMAGE_DIRECTORY_ENTRY_EXCEPTION && excDir.VirtualAddress != 0 && excDir.Size != 0) {
        // A declared-but-out-of-bounds .pdata is a malformed PE, not "no SEH":
        // silently skipping registration would recreate the exact bugcheck
        // scenario this block exists to prevent. Fail closed.
        if (static_cast<uint64_t>(excDir.VirtualAddress) + excDir.Size > imageSize ||
            excDir.Size % sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY) != 0) {
            result.error = "exception directory out of bounds";
            result.imageBase = kernelBase;
            if (kmem::FreeKernelMemory(backend, kernelBase) == kmem::KernelCallStatus::Executed)
                result.imageBase = 0;
            return result;
        }
        functionTableVa = kernelBase + excDir.VirtualAddress;
        functionTableCount = excDir.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
        uint64_t addFn = kmem::ResolveKernelExport(backend, L"ntoskrnl.exe", "RtlAddFunctionTable");
        if (addFn) {
            // Official path (present up to Win11 23H2).
            // RtlAddFunctionTable(FunctionTable, EntryCount, Base).
            uint8_t ok = 0;
            const auto addStatus = kmem::CallKernelFunction(
                backend, &ok, addFn, functionTableVa,
                static_cast<uint64_t>(functionTableCount), kernelBase);
            if (addStatus != kmem::KernelCallStatus::Executed) {
                result.error = "RtlAddFunctionTable failed";
                result.imageBase = kernelBase;
                if (addStatus == kmem::KernelCallStatus::RestorationUncertain)
                    std::cerr << "[hinv::mapper] Function table state is uncertain; image left resident\n";
                else if (ReleaseImageAfterFailure(backend, kernelBase, functionTableVa,
                                                   kernelBase, false))
                    result.imageBase = 0;
                return result;
            }
            if (!ok) {
                // A confirmed FALSE means no registration was created. Do not
                // retain one image for every failed load attempt.
                result.error = "RtlAddFunctionTable failed";
                result.imageBase = kernelBase;
                if (ReleaseImageAfterFailure(backend, kernelBase, functionTableVa,
                                              kernelBase, false))
                    result.imageBase = 0;
                return result;
            }
            functionTableRegistered = true;
            kmem::Trace("mapper: function table registered");
        } else {
            // 24H2 removed the public registration API. The private IFT lock
            // is not exposed and this project must not edit the table with an
            // epoch-only protocol. Reject before DriverEntry and release the
            // image because no kernel reference was created.
            result.error = "no supported function-table registration API on this Windows build";
            result.imageBase = kernelBase;
            if (ReleaseImageAfterFailure(backend, kernelBase, functionTableVa,
                                          kernelBase, false))
                result.imageBase = 0;
            return result;
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

    // DriverEntry's first argument: either an Object-Manager-owned object
    // created by IoCreateDriver, or a minimal synthetic object in kernel pool.
    uint64_t drvObj = 0;
    uint32_t status = 0xC0000001u; // STATUS_UNSUCCESSFUL
    auto releaseMappedImage = [&](bool freeDriverObject) {
        if (freeDriverObject && drvObj) {
            if (kmem::FreeKernelMemory(backend, drvObj) != kmem::KernelCallStatus::Executed)
                return false;
            drvObj = 0;
        }
        return ReleaseImageAfterFailure(backend, kernelBase, functionTableVa,
                                         kernelBase, functionTableRegistered);
    };
    if (hijackNullDriverObject) {
        // IoCreateDriver creates and registers a real object, then invokes the
        // supplied initialization routine. No live system driver's dispatch
        // table is borrowed or overwritten.
        kmem::Trace("mapper: real drvobj create begin");
        const auto real = kmem::CallDriverEntryWithRealObject(backend, driverEntryVa);
        status = real.driverEntryStatus;
        drvObj = real.driverObject;
        kmem::Trace("mapper: real drvobj create returned");
        if (real.callStatus != kmem::KernelCallStatus::Executed) {
            result.error = "IoCreateDriver callback result is uncertain";
            result.imageBase = kernelBase;
            if (real.callStatus == kmem::KernelCallStatus::NotExecuted &&
                releaseMappedImage(false))
                result.imageBase = 0;
            return result;
        }
        if (!drvObj) {
            result.error = "IoCreateDriver did not provide a DRIVER_OBJECT";
            result.imageBase = kernelBase;
            if (releaseMappedImage(false)) result.imageBase = 0;
            return result;
        }
    } else {
        // Minimal synthetic DRIVER_OBJECT in kernel pool: only
        // DriverStart/DriverSize are populated.
        // DRIVER_OBJECT (x64): DriverStart @ 0x18, DriverSize @ 0x20.
        kmem::Trace("mapper: drvobj alloc begin");
        constexpr size_t DRV_OBJ_SIZE = 0x200;
        const auto objectAlloc = kmem::AllocateKernelMemory(backend, DRV_OBJ_SIZE, drvObj);
        if (objectAlloc != kmem::KernelCallStatus::Executed || !drvObj) {
            result.error = "failed to allocate synthetic DRIVER_OBJECT";
            result.imageBase = kernelBase;
            if (objectAlloc != kmem::KernelCallStatus::RestorationUncertain &&
                releaseMappedImage(false)) {
                result.imageBase = 0;
            }
            return result;
        }
        std::array<uint8_t, DRV_OBJ_SIZE> zeros{};
        if (!backend->WriteKernelMemory(drvObj, zeros.data(), zeros.size()) ||
            !kmem::WriteU64(backend, drvObj + 0x18, kernelBase) ||
            !kmem::WriteU32(backend, drvObj + 0x20, imageSize)) {
            result.error = "failed to initialize synthetic DRIVER_OBJECT";
            result.imageBase = kernelBase;
            if (releaseMappedImage(true)) {
                result.imageBase = 0;
            }
            return result;
        }

        // Call DriverEntry(DriverObject, RegistryPath = NULL).
        kmem::Trace("mapper: driverentry call begin");
        const auto entryCall = kmem::CallDriverEntry(
            backend, driverEntryVa, drvObj, 0, status);
        if (entryCall != kmem::KernelCallStatus::Executed) {
            result.error = "DriverEntry call result is uncertain";
            result.imageBase = kernelBase;
            // A non-executed call cannot have created a device. An uncertain
            // hook restore, however, means the image and object must remain.
            if (entryCall == kmem::KernelCallStatus::NotExecuted &&
                releaseMappedImage(true))
                result.imageBase = 0;
            return result;
        }
    }
    kmem::Trace("mapper: driverentry returned");
    std::cout << "[hinv::mapper] DriverEntry returned 0x" << std::hex << status << std::dec << "\n";

    result.imageBase = kernelBase;
    result.driverEntryStatus = status;
    result.imageSize = imageSize;

    result.success = NtSuccess(status);
    if (!result.success) {
        result.error = "DriverEntry returned failure";
        std::cerr << "[hinv::mapper] DriverEntry failed; image left resident to avoid UAF\n";
        return result;
    }

    // On success the driver is resident, so its DRIVER_OBJECT must stay too:
    // a driver that called IoCreateDevice has DeviceObject->DriverObject
    // pointing here, and the I/O manager dereferences MajorFunction through
    // it on every IRP. Freeing it would be a kernel use-after-free on the
    // first IOCTL. Deliberate 0x200-byte pool leak per mapped driver when the
    // synthetic path is used. IoCreateDriver owns the real object otherwise.
    result.driverObject = drvObj;

    // Replicate IopLoadDriver: devices created in DriverEntry come out of
    // IoCreateDevice with DO_DEVICE_INITIALIZING set, and the normal loader
    // clears it after a successful entry. We ARE the loader, so clear it
    // ourselves — otherwise IopParseDevice rejects every open with
    // STATUS_DEVICE_NOT_CONNECTED (this is why HyperDbg's device refused
    // CreateFile with Win32 error 433).
    {
        uint64_t dev = 0;
        if (drvObj && kmem::ReadU64(backend, drvObj + 0x8, dev)) { // DRIVER_OBJECT.DeviceObject
            for (int n = 0; dev && n < 16; ++n) {
                uint32_t flags = 0;
                if (kmem::ReadU32(backend, dev + 0x30, flags) && (flags & 0x80)) {
                    if (kmem::WriteU32(backend, dev + 0x30, flags & ~0x80u)) {
                        std::cout << "[hinv::mapper] Updated DO_DEVICE_INITIALIZING on device 0x"
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
    if (!ReadDriverFileBytes(driverPath, raw)) {
        MappingResult r{};
        r.error = "failed to read driver file";
        return r;
    }
    std::string validationError;
    if (!ValidateDriverImageBytes(raw, &validationError)) {
        MappingResult r{};
        r.error = validationError.empty() ? "driver preflight failed" : validationError;
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
