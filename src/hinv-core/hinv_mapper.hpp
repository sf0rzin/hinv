#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <memory>

#include "hinv_byovd.hpp"

namespace hinv {
namespace mapper {

struct MappingResult {
    bool     success = false;
    uint64_t imageBase = 0;
    uint64_t driverObject = 0;
    uint32_t driverEntryStatus = 0;
    uint32_t imageSize = 0;
    std::string error;
};

// Manually map a kernel driver (.sys) into kernel memory using the supplied BYOVD backend.
// The driver object of \\Driver\\Null is borrowed/hijacked for the DriverEntry call.
MappingResult MapDriver(byovd::IByovdBackend* backend, const std::wstring& driverPath);

// Same, but accepts the raw file bytes already loaded in memory.
MappingResult MapDriverBytes(byovd::IByovdBackend* backend, const std::vector<uint8_t>& rawImage);

// Internal: build the mapped image (sections, relocations, imports) from raw
// PE bytes for the target kernel base. Fail-closed: returns false on any
// malformed structure. Exposed for unit tests.
bool BuildMappedImage(byovd::IByovdBackend* backend, const std::vector<uint8_t>& raw,
                      uint64_t imageBase, std::vector<uint8_t>& mapped);

} // namespace mapper
} // namespace hinv
