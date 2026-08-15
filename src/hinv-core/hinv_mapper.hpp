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

// Read and validate a module before any privileged backend is initialized.
// The returned bytes can then be passed to MapDriverBytes, avoiding a
// second path-based open after the TOCTOU-sensitive preflight.
bool ReadDriverFileBytes(const std::wstring& path, std::vector<uint8_t>& out);
bool ValidateDriverImageBytes(const std::vector<uint8_t>& raw, std::string* error = nullptr);

// Manually map a kernel driver (.sys) into kernel memory using the supplied BYOVD backend.
// When hijackNullDriverObject is true, DriverEntry receives a real
// Object-Manager-owned DRIVER_OBJECT created through IoCreateDriver instead of
// a synthetic pool object. The historical parameter/CLI flag name is retained
// for compatibility, but no existing system driver's object is modified.
MappingResult MapDriver(byovd::IByovdBackend* backend, const std::wstring& driverPath,
                        bool hijackNullDriverObject = false);

// Same, but accepts the raw file bytes already loaded in memory.
MappingResult MapDriverBytes(byovd::IByovdBackend* backend, const std::vector<uint8_t>& rawImage,
                             bool hijackNullDriverObject = false);

// Internal: build the mapped image (sections, relocations, imports) from raw
// PE bytes for the target kernel base. Fail-closed: returns false on any
// malformed structure. Exposed for unit tests.
bool BuildMappedImage(byovd::IByovdBackend* backend, const std::vector<uint8_t>& raw,
                      uint64_t imageBase, std::vector<uint8_t>& mapped);

} // namespace mapper
} // namespace hinv
